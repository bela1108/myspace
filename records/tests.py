import json
import subprocess
import sys
from pathlib import Path

from django.db import connections, transaction
from django.test import TestCase

from .models import LifecycleStatus, OriginStatus, RoutingError, StatusEvent, TrackedObject
from .router import ExplicitOriginRouter
from .services import change_status, create_tracked_object, find_tracked_object


class MultiDatabaseRoutingTests(TestCase):
    databases = {"default", "archive"}

    def test_same_primary_key_keeps_separate_origins(self):
        object_id = 1001
        create_tracked_object(
            object_id=object_id,
            name="business copy",
            status=LifecycleStatus.PENDING,
            origin_db="default",
        )
        create_tracked_object(
            object_id=object_id,
            name="archive copy",
            status=LifecycleStatus.ARCHIVED,
            origin_db="archive",
        )

        unresolved = find_tracked_object(
            object_id=object_id,
            search_aliases=("default", "archive"),
        )
        self.assertEqual(unresolved.origin_status, OriginStatus.UNRESOLVED)
        self.assertIsNone(unresolved.origin_db)
        self.assertEqual(
            [candidate.database for candidate in unresolved.candidates],
            ["default", "archive"],
        )

        known = find_tracked_object(
            object_id=object_id,
            search_aliases=("default", "archive"),
            origin_db="archive",
        )
        self.assertEqual(known.origin_status, OriginStatus.KNOWN)
        self.assertEqual(known.origin_db, "archive")
        self.assertEqual(known.candidates[0].object.name, "archive copy")

    def test_status_change_receipt_matches_instance_signal_and_event(self):
        receipt = create_tracked_object(
            object_id=2002,
            name="receipt copy",
            status=LifecycleStatus.PENDING,
            origin_db="archive",
        )
        updated = change_status(
            object_id=2002,
            to_status=LifecycleStatus.ACTIVE,
            origin_db="archive",
        )

        self.assertEqual(updated.database, "archive")
        self.assertEqual(updated.signal.signal_db, "archive")
        self.assertEqual(updated.signal.instance_state_db, "archive")
        self.assertEqual(updated.signal.origin_db, "archive")
        self.assertFalse(updated.signal.created)
        self.assertEqual(updated.event_id, receipt.event_id + 1)

        instance = TrackedObject.objects.using("archive").get(id=2002)
        self.assertEqual(instance.status, LifecycleStatus.ACTIVE)
        self.assertEqual(instance.origin_db, "archive")
        self.assertEqual(instance._state.db, "archive")

        events = list(
            StatusEvent.objects.using("archive")
            .filter(object_id=2002)
            .order_by("id")
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1].from_status, LifecycleStatus.PENDING)
        self.assertEqual(events[1].to_status, LifecycleStatus.ACTIVE)
        self.assertEqual(events[1].signal_db, "archive")
        self.assertEqual(events[1].router_allowed, "archive")
        self.assertFalse(
            StatusEvent.objects.using("default").filter(object_id=2002).exists()
        )

    def test_write_requires_explicit_route_and_cannot_fall_back_to_default(self):
        instance = TrackedObject(
            id=3003,
            name="no route",
            status=LifecycleStatus.PENDING,
            origin_db="archive",
        )

        with self.assertRaises(RoutingError):
            instance.save()

        router = ExplicitOriginRouter()
        with self.assertRaises(RuntimeError):
            router.db_for_write(TrackedObject)

        self.assertFalse(TrackedObject.objects.using("default").filter(id=3003).exists())
        self.assertFalse(TrackedObject.objects.using("archive").filter(id=3003).exists())

    def test_queryset_writes_also_require_explicit_database(self):
        create_tracked_object(
            object_id=5005,
            name="queryset guard",
            status=LifecycleStatus.PENDING,
            origin_db="archive",
        )

        with self.assertRaises(RoutingError):
            TrackedObject.objects.bulk_create([])
        with self.assertRaises(RoutingError):
            TrackedObject.objects.filter(id=5005).update(
                status=LifecycleStatus.ACTIVE
            )
        with self.assertRaises(RoutingError):
            TrackedObject.objects.filter(id=5005).delete()

        TrackedObject.objects.using("archive").filter(id=5005).update(
            status=LifecycleStatus.ACTIVE
        )
        self.assertEqual(
            TrackedObject.objects.using("archive").get(id=5005).status,
            LifecycleStatus.ACTIVE,
        )
        TrackedObject.objects.using("archive").filter(id=5005).delete()
        self.assertFalse(
            TrackedObject.objects.using("archive").filter(id=5005).exists()
        )
        self.assertFalse(
            TrackedObject.objects.using("default").filter(id=5005).exists()
        )

    def test_missing_historical_record_remains_unresolved(self):
        receipt = find_tracked_object(
            object_id=6006,
            search_aliases=("default", "archive"),
        )

        self.assertEqual(receipt.origin_status, OriginStatus.UNRESOLVED)
        self.assertIsNone(receipt.origin_db)
        self.assertEqual(receipt.candidates, ())

    def test_transaction_uses_named_database_connection(self):
        with transaction.atomic(using="archive"):
            self.assertEqual(connections["archive"].alias, "archive")
            create_tracked_object(
                object_id=4004,
                name="transaction copy",
                status=LifecycleStatus.PENDING,
                origin_db="archive",
            )

        self.assertTrue(TrackedObject.objects.using("archive").filter(id=4004).exists())
        self.assertFalse(TrackedObject.objects.using("default").filter(id=4004).exists())

    def test_named_transaction_rolls_back_without_default_fallback(self):
        with self.assertRaises(RuntimeError):
            with transaction.atomic(using="archive"):
                create_tracked_object(
                    object_id=7007,
                    name="rolled back copy",
                    status=LifecycleStatus.PENDING,
                    origin_db="archive",
                )
                raise RuntimeError("force rollback")

        self.assertFalse(TrackedObject.objects.using("archive").filter(id=7007).exists())
        self.assertFalse(TrackedObject.objects.using("default").filter(id=7007).exists())

    def test_read_only_sqlite_demo_command(self):
        manage_py = Path(__file__).resolve().parent.parent / "manage.py"
        completed = subprocess.run(
            [sys.executable, str(manage_py), "read_only_sqlite_demo", "--json"],
            check=True,
            capture_output=True,
            text=True,
            cwd=manage_py.parent,
        )
        result = json.loads(completed.stdout)

        self.assertIn("readonly database", result["compliance_write_error"])
        self.assertEqual(result["initial_origin_status"], OriginStatus.UNRESOLVED)
        self.assertEqual(result["business_write_receipt"]["database"], "business")
        self.assertEqual(result["business_write_receipt"]["signal_db"], "business")
        self.assertEqual(result["final_business_origin_status"], OriginStatus.KNOWN)
        self.assertEqual(result["final_business_status"], LifecycleStatus.ACTIVE)
