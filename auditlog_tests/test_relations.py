from unittest import skipUnless

from django.conf import settings
from django.contrib.admin.sites import AdminSite
from django.db import transaction
from django.test import TransactionTestCase
from relation_test_app.models import (
    SnapshotAlternateApprover,
    SnapshotApprover,
    SnapshotOwner,
)

from auditlog import get_logentry_model
from auditlog.admin import LogEntryAdmin

LogEntry = get_logentry_model()
HAS_SECOND_DATABASE = "other" in settings.DATABASES


class RelationSnapshotTest(TransactionTestCase):
    databases = {"default", "other"} if HAS_SECOND_DATABASE else {"default"}

    def setUp(self):
        self.approver = SnapshotApprover.objects.create(
            key="shared", name="Alice", email="alice@example.com"
        )
        self.alternate = SnapshotAlternateApprover.objects.create(
            key="shared", name="Bob"
        )
        self.owner = SnapshotOwner.objects.create(
            approver=self.approver,
            alternate_approver=self.alternate,
            label="first",
        )

    def _create_log(self):
        return self.owner.history.filter(action=LogEntry.Action.CREATE).get()

    def test_snapshot_is_used_instead_of_current_target(self):
        log = self._create_log()
        snapshot = log.relation_snapshots["alternate_approver"]["new"]
        self.assertEqual(
            snapshot["model"], "relation_test_app.snapshotalternateapprover"
        )
        self.assertEqual(snapshot["pk"], "shared")
        self.assertEqual(snapshot["db"], "default")
        self.assertEqual(snapshot["display"], "Bob")

        self.alternate.name = "Robert"
        self.alternate.save()

        values = log.changes_display_dict["alternate approver"]
        self.assertEqual(values, ["None", "Bob"])

    def test_same_pk_different_target_model_is_not_confused(self):
        log = self._create_log()
        approver_snapshot = log.relation_snapshots["approver"]["new"]
        alternate_snapshot = log.relation_snapshots["alternate_approver"]["new"]
        self.assertEqual(approver_snapshot["pk"], alternate_snapshot["pk"])
        self.assertNotEqual(approver_snapshot["model"], alternate_snapshot["model"])

    def test_masked_target_fields_are_masked_in_snapshot(self):
        snapshot = self._create_log().relation_snapshots["approver"]["new"]
        self.assertNotEqual(snapshot["fields"]["name"], "Alice")
        self.assertEqual(snapshot["fields"]["name"], "**ice")
        self.assertEqual(snapshot["fields"]["email"], "alice@example.com")
        self.assertEqual(snapshot["display"], "**ice")

    def test_deleted_target_keeps_snapshot_and_none_stays_distinct(self):
        log = self._create_log()
        self.approver.delete()

        values = log.changes_display_dict["approver"]
        self.assertEqual(values, ["None", "**ice"])

    def test_missing_snapshot_is_reported_as_evidence_gap(self):
        log = self._create_log()
        log.relation_snapshots = None
        log.save()

        values = log.changes_display_dict["alternate approver"]
        self.assertEqual(values[0], "None")
        self.assertIn("Evidence gap", values[1])

    @skipUnless(HAS_SECOND_DATABASE, "A second database alias is required")
    def test_snapshot_uses_business_database_alias(self):
        approver = SnapshotApprover.objects.using("other").create(
            key="other", name="Carol"
        )
        owner = SnapshotOwner.objects.using("other").create(
            approver=approver,
            label="other db",
        )
        log = (
            LogEntry.objects.using("other")
            .filter(object_pk=str(owner.pk))
            .get()
        )
        self.assertEqual(log.relation_snapshots["approver"]["new"]["db"], "other")
        self.assertEqual(log.content_type.app_label, "relation_test_app")

    @skipUnless(HAS_SECOND_DATABASE, "A second database alias is required")
    def test_rollback_does_not_leave_a_log_entry(self):
        before = LogEntry.objects.using("other").count()
        with self.assertRaises(RuntimeError):
            with transaction.atomic(using="other"):
                SnapshotOwner.objects.using("other").create(label="rolled back")
                raise RuntimeError("boom")
        self.assertEqual(LogEntry.objects.using("other").count(), before)

    def test_admin_renders_snapshot_and_evidence_gap(self):
        admin = LogEntryAdmin(LogEntry, AdminSite())
        log = self._create_log()
        rendered = admin.msg(log)
        self.assertIn("Bob", rendered)
        self.assertNotIn("Evidence gap", rendered)

        log.relation_snapshots = None
        log.save()
        rendered = admin.msg(log)
        self.assertIn("Evidence gap", rendered)

    def test_admin_marks_a_recorded_target_that_is_now_unavailable(self):
        admin = LogEntryAdmin(LogEntry, AdminSite())
        log = self._create_log()
        self.alternate.delete()
        rendered = admin.msg(log)
        self.assertIn("Bob", rendered)
        self.assertIn("target no longer available", rendered)
