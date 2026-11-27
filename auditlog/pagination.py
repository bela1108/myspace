from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone
from typing import Any, Iterable, Mapping

from django.core.exceptions import BadRequest, PermissionDenied, ValidationError
from django.core.signing import BadSignature, JSONSerializer, Signer
from django.db.models import Q, QuerySet
from django.utils import timezone
from django.utils.encoding import force_str


class AuditLogScopeError(PermissionDenied):
    pass


class AuditLogCursorError(BadRequest):
    pass


@dataclass(frozen=True)
class AuditLogScope:
    key: str
    revision: Any = None
    queryset_filter: Mapping[str, Any] | None = None

    def get_revision(self) -> Any:
        return self.revision

    def get_fingerprint(self) -> str:
        if self.queryset_filter is None:
            return "all"
        normalized_filter = {
            key: self._serialize_filter_value(value)
            for key, value in sorted(self.queryset_filter.items())
        }
        encoded_filter = json.dumps(normalized_filter, sort_keys=True, default=str)
        return hashlib.sha256(encoded_filter.encode()).hexdigest()

    @staticmethod
    def _serialize_filter_value(value):
        if hasattr(value, "pk"):
            return {"model": value._meta.label, "pk": force_str(value.pk)}
        if isinstance(value, Mapping):
            return {
                key: AuditLogScope._serialize_filter_value(item)
                for key, item in sorted(value.items())
            }
        if isinstance(value, (list, tuple, set)):
            serialized_value = [
                AuditLogScope._serialize_filter_value(item) for item in value
            ]
            return sorted(serialized_value, key=repr)
        return value

    def apply_to_queryset(self, queryset: QuerySet) -> QuerySet:
        queryset_filter = self.queryset_filter
        if queryset_filter is None:
            return queryset
        return queryset.filter(**queryset_filter)


@dataclass(frozen=True)
class FrozenAuditLogScope:
    key: str
    revision: Any
    fingerprint: str

    def validate(self, scope: AuditLogScope) -> None:
        if (
            scope.key != self.key
            or scope.get_revision() != self.revision
            or scope.get_fingerprint() != self.fingerprint
        ):
            raise AuditLogScopeError("Audit log authorization scope has changed.")


@dataclass(frozen=True)
class AuditLogPage:
    object_list: list
    next_cursor: str | None
    previous_cursor: str | None
    has_next: bool
    has_previous: bool
    number: int

    def __iter__(self):
        return iter(self.object_list)

    def __len__(self):
        return len(self.object_list)

    def __getitem__(self, index):
        return self.object_list[index]


class AuditLogCursorPaginator:
    cursor_param = "cursor"
    salt = "auditlog.pagination.AuditLogCursorPaginator"

    def __init__(
        self,
        queryset: QuerySet,
        per_page: int,
        scope: AuditLogScope,
        signer: Signer | None = None,
    ):
        if per_page < 1:
            raise ValueError("per_page must be greater than zero.")

        self.queryset = queryset.order_by()
        self.per_page = per_page
        self.scope = scope
        self.signer = signer or Signer(salt=self.salt)

    def get_first_page(self) -> AuditLogPage:
        snapshot_pk = self._get_snapshot_pk()
        page = self._fetch_page(None, snapshot_pk, "next")
        return self._build_page(page, None, snapshot_pk, "next", 1)

    def get_page(self, cursor: str | None) -> AuditLogPage:
        if not cursor:
            return self.get_first_page()

        token = self._decode_cursor(cursor)
        frozen_scope = FrozenAuditLogScope(
            key=token["scope_key"],
            revision=token["scope_revision"],
            fingerprint=token["scope_fingerprint"],
        )
        frozen_scope.validate(self.scope)

        direction = token.get("direction", "next")
        if direction not in {"next", "previous"}:
            raise AuditLogCursorError("Invalid audit log page direction.")

        try:
            snapshot_pk = self._queryset_pk.get_prep_value(token["snapshot_pk"])
        except (TypeError, ValueError, ValidationError) as exc:
            raise AuditLogCursorError("Invalid audit log page cursor.") from exc
        position = token.get("position")
        try:
            number = max(int(token.get("number", 1)), 1)
        except (TypeError, ValueError, OverflowError) as exc:
            raise AuditLogCursorError("Invalid audit log page cursor.") from exc
        entries = self._fetch_page(position, snapshot_pk, direction)
        return self._build_page(entries, position, snapshot_pk, direction, number)

    def get_export_page(self, cursor: str | None = None) -> AuditLogPage:
        return self.get_page(cursor)

    def _get_snapshot_pk(self):
        scoped_queryset = self.scope.apply_to_queryset(self.queryset)
        latest_entry = (
            scoped_queryset.order_by("-pk").values_list("pk", flat=True).first()
        )
        return latest_entry

    def _fetch_page(
        self,
        position: list | None,
        snapshot_pk,
        direction: str,
    ) -> list:
        if snapshot_pk is None:
            return []

        queryset = self.scope.apply_to_queryset(self.queryset).filter(
            pk__lte=snapshot_pk
        )
        if position is not None:
            queryset = queryset.filter(self._position_filter(position, direction))

        if direction == "previous":
            queryset = queryset.order_by("timestamp", "pk")
        else:
            queryset = queryset.order_by("-timestamp", "-pk")

        return list(queryset[: self.per_page + 1])

    def _position_filter(self, position: list, direction: str):
        if not isinstance(position, list) or len(position) != 2:
            raise AuditLogCursorError("Invalid audit log page cursor.")
        timestamp = self._decode_datetime(position[0])
        try:
            pk = self._queryset_pk.get_prep_value(position[1])
        except (TypeError, ValueError, ValidationError) as exc:
            raise AuditLogCursorError("Invalid audit log page cursor.") from exc

        if direction == "previous":
            return Q(timestamp__gt=timestamp) | Q(timestamp=timestamp, pk__gt=pk)
        return Q(timestamp__lt=timestamp) | Q(timestamp=timestamp, pk__lt=pk)

    @property
    def _queryset_pk(self):
        return self.queryset.model._meta.pk

    def _build_page(
        self,
        entries: list,
        position: list | None,
        snapshot_pk,
        direction: str,
        number: int,
    ) -> AuditLogPage:
        has_more = len(entries) > self.per_page
        visible_entries = entries[: self.per_page]

        if direction == "previous":
            visible_entries = list(reversed(visible_entries))

        previous_cursor = None
        next_cursor = None

        if visible_entries:
            first = visible_entries[0]
            last = visible_entries[-1]
            if number > 1 or direction == "previous":
                previous_cursor = self._encode_cursor(
                    self._cursor_payload(
                        [self._encode_datetime(first.timestamp), first.pk],
                        snapshot_pk,
                        "previous",
                        max(number - 1, 1),
                    )
                )
            if has_more:
                next_cursor = self._encode_cursor(
                    self._cursor_payload(
                        [self._encode_datetime(last.timestamp), last.pk],
                        snapshot_pk,
                        "next",
                        number + 1,
                    )
                )

        return AuditLogPage(
            object_list=visible_entries,
            next_cursor=next_cursor,
            previous_cursor=previous_cursor,
            has_next=next_cursor is not None,
            has_previous=previous_cursor is not None,
            number=number,
        )

    def _cursor_payload(
        self, position: list, snapshot_pk, direction: str, number: int
    ) -> dict:
        return {
            "scope_key": self.scope.key,
            "scope_revision": self.scope.get_revision(),
            "scope_fingerprint": self.scope.get_fingerprint(),
            "snapshot_pk": snapshot_pk,
            "position": position,
            "direction": direction,
            "number": number,
        }

    def _encode_cursor(self, payload: dict) -> str:
        return self.signer.sign_object(payload, serializer=JSONSerializer)

    def _decode_cursor(self, cursor: str) -> dict:
        try:
            payload = self.signer.unsign_object(
                cursor, serializer=JSONSerializer
            )
        except BadSignature as exc:
            raise AuditLogCursorError("Invalid audit log page cursor.") from exc

        required_keys = {
            "scope_key",
            "scope_revision",
            "scope_fingerprint",
            "snapshot_pk",
            "direction",
        }
        if not required_keys.issubset(payload):
            raise AuditLogCursorError("Invalid audit log page cursor.")

        return payload

    @staticmethod
    def _encode_datetime(value: datetime) -> str:
        return value.isoformat()

    @staticmethod
    def _decode_datetime(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value)
        except (TypeError, ValueError) as exc:
            raise AuditLogCursorError("Invalid audit log page cursor.") from exc

        if timezone.is_naive(parsed):
            return timezone.make_aware(parsed, datetime_timezone.utc)
        return timezone.localtime(parsed, datetime_timezone.utc)


def export_audit_log_page(
    queryset: QuerySet,
    scope: AuditLogScope,
    per_page: int,
    cursor: str | None = None,
) -> AuditLogPage:
    return AuditLogCursorPaginator(queryset, per_page, scope).get_export_page(cursor)


def iter_audit_log_export(
    queryset: QuerySet, scope: AuditLogScope, per_page: int
) -> Iterable:
    paginator = AuditLogCursorPaginator(queryset, per_page, scope)
    page = paginator.get_first_page()
    while True:
        yield from page.object_list
        if not page.has_next:
            break
        page = paginator.get_page(page.next_cursor)
