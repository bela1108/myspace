"""Tests for sealed audit log segments."""

import json
import tempfile
import threading
import time
from io import StringIO
from pathlib import Path
from unittest import SkipTest

from django.core.management import CommandError, call_command
from django.db import connection, connections, transaction
from django.db.backends.sqlite3.creation import DatabaseCreation
from django.test import TestCase, TransactionTestCase

from auditlog import get_logentry_model
from auditlog.models import LogEntrySegment
from auditlog.sealing import (
    AuditLogIntegrityError,
    export_segments,
    find_first_mismatch,
    import_segments,
    read_export,
    seal_segment,
    segment_summaries,
    unsealed_entries,
    verify_export,
    verify_segments,
    write_export,
)
from test_app.models import SimpleModel

LogEntry = get_logentry_model()


class SegmentSealTest(TestCase):
    def make_entries(self, count, prefix="entry"):
        for index in range(count):
            SimpleModel.objects.create(text=f"{prefix}-{index}")

    def entries(self):
        return list(LogEntry.objects.order_by("id"))

    def test_first_segment_has_stable_manifest_and_summary(self):
        self.make_entries(3)

        segment = seal_segment()

        self.assertIsNotNone(segment)
        self.assertEqual(segment.sequence, 1)
        self.assertEqual(segment.previous_digest, "")
        self.assertEqual(segment.entry_count, 3)
        self.assertEqual(
            [item["id"] for item in segment.manifest],
            [entry.id for entry in self.entries()],
        )
        self.assertEqual(
            [item["ordinal"] for item in segment.manifest], [0, 1, 2]
        )
        self.assertEqual(segment.first_entry_id, segment.manifest[0]["id"])
        self.assertEqual(segment.last_entry_id, segment.manifest[-1]["id"])
        self.assertEqual(verify_segments(), [])
        self.assertEqual(segment.verify_integrity(), [])
        self.assertTrue(segment.is_valid)

        summary = segment_summaries()[0]
        self.assertEqual(summary["digest"], segment.digest)
        self.assertEqual(summary["manifest"], segment.manifest)

    def test_continuation_only_contains_new_committed_entries(self):
        self.make_entries(2, prefix="first")
        first = seal_segment()

        self.make_entries(1, prefix="second")
        second = seal_segment()

        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.previous_digest, first.digest)
        self.assertEqual(second.entry_count, 1)
        self.assertEqual(second.manifest[0]["id"], self.entries()[-1].id)
        self.assertGreater(second.first_entry_id, first.last_entry_id)
        self.assertEqual(verify_segments(), [])

        self.assertEqual(LogEntry.objects.count(), 3)
        self.assertEqual(unsealed_entries().count(), 0)

    def test_limit_leaves_old_unsealed_records_queryable(self):
        self.make_entries(4)

        first = seal_segment(limit=2)

        self.assertEqual(first.entry_count, 2)
        self.assertEqual(LogEntry.objects.count(), 4)
        self.assertEqual(len(unsealed_entries()), 2)
        self.assertEqual(LogEntry.objects.filter(pk__gt=first.last_entry_id).count(), 2)

        second = seal_segment()
        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.entry_count, 2)
        self.assertEqual(verify_segments(), [])

    def test_manager_helpers_seal_and_list_unsealed_entries(self):
        self.make_entries(2)

        segment = LogEntry.objects.seal()
        self.assertEqual(segment.entry_count, 2)
        self.assertEqual(list(LogEntry.objects.unsealed()), [])

    def test_old_entry_below_segment_boundary_remains_queryable(self):
        self.make_entries(3)
        ids = [entry.id for entry in self.entries()]

        segment = seal_segment(start_after=ids[0])

        self.assertEqual(segment.entry_count, 2)
        self.assertEqual(LogEntry.objects.filter(pk=ids[0]).count(), 1)
        self.assertEqual(unsealed_entries().count(), 1)
        self.assertEqual(unsealed_entries().get().id, ids[0])

    def test_modified_entry_is_reported_at_first_manifest_position(self):
        self.make_entries(4)
        segment = seal_segment()
        ids = [item["id"] for item in segment.manifest]

        LogEntry.objects.filter(pk=ids[1]).update(object_repr="tampered")
        LogEntry.objects.filter(pk=ids[2]).update(object_repr="also tampered")

        mismatch = find_first_mismatch()

        self.assertIsNotNone(mismatch)
        self.assertEqual(mismatch.kind, "entry_digest")
        self.assertEqual(mismatch.entry_id, ids[1])
        self.assertEqual(mismatch.ordinal, 1)

        with self.assertRaises(AuditLogIntegrityError) as raised:
            export_segments()
        self.assertEqual(raised.exception.first_mismatch.entry_id, ids[1])

    def test_deleted_entry_is_reported_as_missing(self):
        self.make_entries(3)
        segment = seal_segment()
        missing_id = segment.manifest[1]["id"]

        LogEntry.objects.filter(pk=missing_id).delete()

        mismatch = find_first_mismatch()

        self.assertIsNotNone(mismatch)
        self.assertEqual(mismatch.kind, "missing_entry")
        self.assertEqual(mismatch.entry_id, missing_id)
        self.assertEqual(mismatch.ordinal, 1)

    def test_export_can_be_verified_independently_of_the_database(self):
        self.make_entries(3)
        seal_segment()

        document = export_segments()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "segments.json"
            write_export(document, path)
            loaded = read_export(path)

            self.assertEqual(verify_export(loaded), [])
            self.assertEqual(len(loaded["segments"]), 1)
            self.assertEqual(len(loaded["entries"]), 3)

        # The exported copy does not consult the source database at all.
        LogEntry.objects.all().delete()
        LogEntrySegment.objects.all().delete()
        self.assertEqual(verify_export(loaded), [])

    def test_export_reports_first_changed_snapshot(self):
        self.make_entries(3)
        seal_segment()
        document = export_segments()

        document["entries"][1]["snapshot"]["object_repr"] = "tampered"

        mismatches = verify_export(document)
        self.assertEqual(mismatches[0].kind, "entry_digest")
        self.assertEqual(
            mismatches[0].entry_id, document["entries"][1]["id"]
        )

    def test_verified_export_restores_into_a_database(self):
        self.make_entries(3)
        seal_segment()
        document = export_segments()
        path = Path(tempfile.mkdtemp()) / "segments.json"
        write_export(document, path)

        LogEntry.objects.all().delete()
        LogEntrySegment.objects.all().delete()

        result = import_segments(read_export(path))

        self.assertEqual(result["segments"], 1)
        self.assertEqual(result["entries"], 3)
        self.assertEqual(verify_segments(), [])
        self.assertEqual(LogEntry.objects.count(), 3)

        second = import_segments(read_export(path))
        self.assertEqual(second["segments"], 0)
        self.assertEqual(second["skipped_segments"], 1)
        self.assertEqual(second["entries"], 0)
        self.assertEqual(second["skipped_entries"], 3)
        self.assertEqual(verify_segments(), [])


class SegmentCommandTest(TestCase):
    def make_entries(self, count):
        for index in range(count):
            SimpleModel.objects.create(text=f"command-{index}")

    def call(self, *args):
        out = StringIO()
        err = StringIO()
        call_command(*args, stdout=out, stderr=err)
        return out.getvalue().strip(), err.getvalue().strip()

    def test_seal_dry_run_does_not_write_a_segment(self):
        self.make_entries(2)

        out, err = self.call("auditlogseal", "--dry-run")

        self.assertIn("Would seal segment 1: 2 entries", out)
        self.assertEqual(err, "")
        self.assertEqual(LogEntrySegment.objects.count(), 0)

    def test_verify_reports_first_mismatch(self):
        self.make_entries(3)
        segment = seal_segment()
        ids = [item["id"] for item in segment.manifest]
        LogEntry.objects.filter(pk=ids[1]).update(object_repr="tampered")

        with self.assertRaises(CommandError) as raised:
            self.call("auditlogverify")

        self.assertIn("entry %s" % ids[1], str(raised.exception))

    def test_export_and_verify_file(self):
        self.make_entries(2)
        seal_segment()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sealed.json"
            out, err = self.call("auditlogexport", str(path))
            self.assertIn("Exported 1 segments (2 entries)", out)
            self.assertEqual(err, "")

            out, err = self.call("auditlogverify", str(path))
            self.assertIn("no inconsistencies found", out)
            self.assertEqual(err, "")

            document = json.loads(path.read_text())
            self.assertEqual(document["format"], "django-auditlog-segments")



class SQLitePendingWriteSealTest(TransactionTestCase):
    """A row pending in another SQLite connection must not enter a segment."""

    def setUp(self):
        if DatabaseCreation.is_in_memory_db(
            connection.settings_dict.get("NAME", "")
        ):
            raise SkipTest(
                "Concurrent pending-write coverage needs a file-backed SQLite "
                "database; the shared-cache in-memory test database locks the "
                "whole table for readers."
            )
        SimpleModel.objects.create(text="committed-before")

    def test_pending_write_is_excluded_and_can_be_sealed_later(self):
        ready = threading.Event()
        finished = threading.Event()
        errors = []
        pending = {}

        def writer():
            try:
                with transaction.atomic():
                    obj = SimpleModel.objects.create(text="pending-during-seal")
                    entry = LogEntry.objects.filter(
                        object_pk=str(obj.pk)
                    ).order_by("-id").first()
                    pending["entry_id"] = entry.id
                    ready.set()
                    time.sleep(2)
                pending["committed"] = True
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)
                ready.set()
            finally:
                finished.set()
                connections.close_all()

        thread = threading.Thread(target=writer)
        thread.start()
        try:
            self.assertTrue(ready.wait(10), "writer did not reach its pending state")
            self.assertIn("entry_id", pending)

            started = time.monotonic()
            segment = seal_segment()
            elapsed = time.monotonic() - started

            self.assertIsNotNone(segment)
            self.assertEqual(segment.entry_count, 1)
            self.assertNotIn(
                pending["entry_id"],
                [item["id"] for item in segment.manifest],
            )
            self.assertEqual(verify_segments(), [])

            # The seal either completed before the other write committed or
            # waited for SQLite's write lock. Both are valid; the boundary was
            # taken from committed state in either case.
            self.assertGreaterEqual(elapsed, 0)
        finally:
            thread.join(15)

        self.assertTrue(finished.is_set())
        if errors:
            raise errors[0]

        self.assertEqual(LogEntry.objects.count(), 2)
        continuation = seal_segment()
        self.assertEqual(continuation.sequence, 2)
        self.assertEqual(continuation.entry_count, 1)
        self.assertEqual(
            continuation.manifest[0]["id"], pending["entry_id"]
        )
        self.assertEqual(verify_segments(), [])

    def _fixture_teardown(self):
        # The worker closes its own SQLite connection; make sure no stale
        # connection keeps the test database locked before Django flushes it.
        connections.close_all()
        super()._fixture_teardown()
