from datetime import datetime, timedelta

from django.contrib import admin
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import BadRequest, PermissionDenied
from django.core.signing import Signer
from django.test import RequestFactory, TestCase
from django.utils import timezone
from test_app.models import SimpleModel, UUIDPrimaryKeyModel

from auditlog import get_logentry_model
from auditlog.mixins import AuditlogHistoryAdminMixin
from auditlog.pagination import (
    AuditLogCursorPaginator,
    AuditLogScope,
    export_audit_log_page,
    iter_audit_log_export,
)

LogEntry = get_logentry_model()


class TestModelAdmin(AuditlogHistoryAdminMixin, admin.ModelAdmin):
    model = SimpleModel
    auditlog_history_per_page = 2


class AuditLogCursorPaginatorTests(TestCase):
    def setUp(self):
        self.model = SimpleModel.objects.create(text="test")
        self.content_type = ContentType.objects.get_for_model(SimpleModel)
        self.creation_entry = LogEntry.objects.get(
            content_type=self.content_type, object_id=self.model.pk
        )
        self.timestamp = timezone.make_aware(datetime(2026, 1, 1, 12, 0, 0))
        self.entries = [
            self.create_entry(1, self.timestamp),
            self.create_entry(2, self.timestamp),
            self.create_entry(3, self.timestamp - timedelta(minutes=1)),
        ]
        self.scope = AuditLogScope(
            key="simplemodel",
            revision="v1",
            queryset_filter={
                "content_type": self.content_type,
                "object_id": self.model.pk,
            },
        )

    def create_entry(self, number, timestamp):
        return LogEntry.objects.create(
            content_type=self.content_type,
            object_pk=str(self.model.pk),
            object_id=self.model.pk,
            object_repr=str(self.model),
            action=LogEntry.Action.UPDATE,
            changes={"number": [number - 1, number]},
            timestamp=timestamp,
        )

    def paginator(self, scope=None):
        return AuditLogCursorPaginator(
            LogEntry.objects.exclude(pk=self.creation_entry.pk),
            2,
            scope or self.scope,
        )

    def test_same_timestamp_boundary_uses_pk_as_stable_tiebreaker(self):
        page = self.paginator().get_first_page()

        self.assertEqual(list(page.object_list), [self.entries[1], self.entries[0]])
        self.assertTrue(page.has_next)

        next_page = self.paginator().get_page(page.next_cursor)

        self.assertEqual(list(next_page.object_list), [self.entries[2]])
        self.assertFalse(next_page.has_next)

    def test_previous_cursor_returns_stable_first_page(self):
        page = self.paginator().get_first_page()
        next_page = self.paginator().get_page(page.next_cursor)

        previous_page = self.paginator().get_page(next_page.previous_cursor)

        self.assertEqual(list(previous_page.object_list), list(page.object_list))

    def test_snapshot_keeps_new_records_out_of_old_pages(self):
        page = self.paginator().get_first_page()
        new_entry = self.create_entry(4, self.timestamp + timedelta(minutes=1))

        next_page = self.paginator().get_page(page.next_cursor)

        self.assertNotIn(new_entry, list(next_page.object_list))
        self.assertEqual(list(next_page.object_list), [self.entries[2]])

    def test_tightened_scope_rejects_old_cursor(self):
        page = self.paginator().get_first_page()
        narrowed_scope = AuditLogScope(
            key="simplemodel",
            revision="v2",
            queryset_filter=self.scope.queryset_filter,
        )

        with self.assertRaises(PermissionDenied):
            self.paginator(narrowed_scope).get_page(page.next_cursor)

    def test_invalid_cursor_is_rejected(self):
        with self.assertRaises(BadRequest):
            self.paginator().get_page("not-a-signed-cursor")

    def test_malformed_cursor_payload_is_rejected(self):
        signer = Signer(salt=AuditLogCursorPaginator.salt)
        cursor = signer.sign_object(
            {
                "scope_key": self.scope.key,
                "scope_revision": self.scope.revision,
                "scope_fingerprint": self.scope.get_fingerprint(),
                "snapshot_pk": self.entries[-1].pk,
                "position": "invalid",
                "direction": "next",
                "number": 2,
            }
        )

        with self.assertRaises(BadRequest):
            self.paginator().get_page(cursor)

    def test_narrowed_filter_does_not_return_revoked_objects_from_old_cursor(self):
        other_model = SimpleModel.objects.create(text="other")
        other_creation_entry = LogEntry.objects.get(
            content_type=self.content_type, object_id=other_model.pk
        )
        other_entry = LogEntry.objects.create(
            content_type=self.content_type,
            object_pk=str(other_model.pk),
            object_id=other_model.pk,
            object_repr=str(other_model),
            action=LogEntry.Action.UPDATE,
            changes={},
            timestamp=self.timestamp,
        )
        broad_scope = AuditLogScope(
            key="all-simple-models",
            revision="v1",
            queryset_filter={"content_type": self.content_type},
        )
        broad_paginator = AuditLogCursorPaginator(
            LogEntry.objects.exclude(pk=self.creation_entry.pk).exclude(
                pk=other_creation_entry.pk
            ),
            2,
            broad_scope,
        )
        page = broad_paginator.get_first_page()
        narrowed_scope = AuditLogScope(
            key="all-simple-models",
            revision="v1",
            queryset_filter={
                "content_type": self.content_type,
                "object_id": other_model.pk,
            },
        )

        with self.assertRaises(PermissionDenied):
            self.paginator(narrowed_scope).get_page(page.next_cursor)

        narrowed_paginator = AuditLogCursorPaginator(
            LogEntry.objects.exclude(pk=other_creation_entry.pk),
            2,
            narrowed_scope,
        )
        first_narrowed_page = narrowed_paginator.get_first_page()
        self.assertEqual(list(first_narrowed_page.object_list), [other_entry])

    def test_query_and_export_share_scope_and_cursor_contract(self):
        paginator = self.paginator()
        query_page = paginator.get_first_page()
        export_page = export_audit_log_page(
            LogEntry.objects.exclude(pk=self.creation_entry.pk),
            self.scope,
            2,
            query_page.next_cursor,
        )

        self.assertEqual(list(export_page.object_list), [self.entries[2]])
        self.assertEqual(
            list(
                iter_audit_log_export(
                    LogEntry.objects.exclude(pk=self.creation_entry.pk),
                    self.scope,
                    2,
                )
            ),
            [self.entries[1], self.entries[0], self.entries[2]],
        )


class AuditlogHistoryAdminMixinPaginationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="admin", is_staff=True, is_superuser=True, is_active=True
        )
        self.site = AdminSite()
        self.admin = TestModelAdmin(SimpleModel, self.site)
        self.obj = SimpleModel.objects.create(text="test")
        self.content_type = ContentType.objects.get_for_model(SimpleModel)
        self.timestamp = timezone.now()
        self.entries = [
            self.create_entry(self.timestamp),
            self.create_entry(self.timestamp),
            self.create_entry(self.timestamp - timedelta(minutes=1)),
        ]
        self.creation_entry = LogEntry.objects.exclude(
            pk__in=[entry.pk for entry in self.entries]
        ).get(content_type=self.content_type, object_id=self.obj.pk)

    def create_entry(self, timestamp):
        return LogEntry.objects.create(
            content_type=self.content_type,
            object_pk=str(self.obj.pk),
            object_id=self.obj.pk,
            object_repr=str(self.obj),
            action=LogEntry.Action.UPDATE,
            changes={},
            timestamp=timestamp,
        )

    def request(self, **query):
        request = RequestFactory().get("/", query)
        request.user = self.user
        return request

    def test_admin_uses_cursor_pagination_with_same_timestamp_page_boundary(self):
        response = self.admin.auditlog_history_view(self.request(), str(self.obj.pk))
        page = response.context_data["log_entries"]

        self.assertEqual(list(page), [self.entries[1], self.entries[0]])
        self.assertTrue(response.context_data["pagination_required"])

        response = self.admin.auditlog_history_view(
            self.request(cursor=page.next_cursor), str(self.obj.pk)
        )

        self.assertEqual(
            list(response.context_data["log_entries"]),
            [self.creation_entry, self.entries[2]],
        )

    def test_admin_rejects_cursor_when_scope_revision_changes(self):
        response = self.admin.auditlog_history_view(self.request(), str(self.obj.pk))
        cursor = response.context_data["log_entries"].next_cursor
        self.admin.get_auditlog_scope_revision = lambda request, obj: "v2"

        with self.assertRaises(PermissionDenied):
            self.admin.auditlog_history_view(
                self.request(cursor=cursor), str(self.obj.pk)
            )

    def test_admin_rejects_cursor_when_scope_filter_tightens(self):
        response = self.admin.auditlog_history_view(self.request(), str(self.obj.pk))
        cursor = response.context_data["log_entries"].next_cursor
        original_filter = self.admin.get_auditlog_scope_filter
        self.admin.get_auditlog_scope_filter = (
            lambda request, obj: {
                **original_filter(request, obj),
                "pk__in": [self.entries[1].pk],
            }
        )

        with self.assertRaises(PermissionDenied):
            self.admin.auditlog_history_view(
                self.request(cursor=cursor), str(self.obj.pk)
            )


class AuditLogScopeFilterTests(TestCase):
    def test_admin_scope_supports_non_integer_primary_key(self):
        model = UUIDPrimaryKeyModel.objects.create(text="uuid")
        content_type = ContentType.objects.get_for_model(UUIDPrimaryKeyModel)
        site = AdminSite()

        class UUIDModelAdmin(AuditlogHistoryAdminMixin, admin.ModelAdmin):
            model = UUIDPrimaryKeyModel

        model_admin = UUIDModelAdmin(UUIDPrimaryKeyModel, site)
        request = RequestFactory().get("/")
        scope_filter = model_admin.get_auditlog_scope_filter(request, model)

        self.assertEqual(
            scope_filter,
            {
                "content_type": content_type,
                "object_pk": str(model.pk),
            },
        )
        entries = LogEntry.objects.filter(**scope_filter)
        self.assertEqual(entries.count(), 1)
