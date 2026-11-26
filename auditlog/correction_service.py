from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from hashlib import sha256
from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from auditlog import get_logentry_model
from auditlog.correction_models import DisplayCorrection, DisplayCorrectionBatch
from auditlog.diff import get_mask_function


class StaleDisplayCorrectionError(ValidationError):
    pass


def _normalized_items(items: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for index, item in enumerate(items):
        missing = {
            "log_entry_id",
            "field_name",
            "value_position",
            "expected_value",
            "display_value",
        }.difference(item)
        if missing:
            raise ValidationError(
                f"Correction item {index} is missing: {', '.join(sorted(missing))}"
            )
        normalized.append(
            {
                "log_entry_id": item["log_entry_id"],
                "field_name": str(item["field_name"]),
                "value_position": str(item["value_position"]),
                "expected_value": item["expected_value"],
                "display_value": item["display_value"],
                "reason": str(item.get("reason", "")),
            }
        )
    return normalized


def _fingerprint(items: Sequence[dict[str, Any]]) -> str:
    payload = json.dumps(items, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(payload.encode("utf-8")).hexdigest()


def submit_display_correction_batch(
    items: Sequence[dict[str, Any]],
    *,
    batch_id: str | None = None,
    auto_approve: bool = False,
    actor=None,
) -> DisplayCorrectionBatch:
    normalized_items = _normalized_items(items)
    fingerprint = _fingerprint(normalized_items)

    if batch_id is not None:
        existing = DisplayCorrectionBatch.objects.filter(batch_id=batch_id).first()
        if existing is not None:
            if existing.fingerprint != fingerprint:
                raise ValidationError("Batch id was already used with different items.")
            return existing

    duplicate = (
        DisplayCorrectionBatch.objects.filter(fingerprint=fingerprint)
        .order_by("created_at")
        .first()
    )
    if duplicate is not None:
        return duplicate

    with transaction.atomic():
        batch = DisplayCorrectionBatch.objects.create(
            batch_id=batch_id or fingerprint,
            fingerprint=fingerprint,
            total_count=len(normalized_items),
            status=DisplayCorrectionBatch.Status.PROCESSING,
            submitted_by=actor if getattr(actor, "pk", None) else None,
        )
        DisplayCorrection.objects.bulk_create(
            [
                DisplayCorrection(
                    batch=batch,
                    log_entry_id=item["log_entry_id"],
                    field_name=item["field_name"],
                    value_position=item["value_position"],
                    expected_value=item["expected_value"],
                    display_value=item["display_value"],
                    reason=item["reason"],
                    status=DisplayCorrection.Status.PENDING,
                )
                for item in normalized_items
            ]
        )

    if auto_approve:
        return process_display_correction_batch(batch)
    return process_display_correction_batch(batch)


def process_display_correction_batch(
    batch: DisplayCorrectionBatch | str,
) -> DisplayCorrectionBatch:
    if isinstance(batch, str):
        batch = DisplayCorrectionBatch.objects.get(batch_id=batch)

    if batch.status == DisplayCorrectionBatch.Status.COMPLETED:
        return batch

    with transaction.atomic():
        batch = (
            DisplayCorrectionBatch.objects.select_for_update()
            .select_related("submitted_by", "approved_by")
            .get(pk=batch.pk)
        )
        if batch.status == DisplayCorrectionBatch.Status.COMPLETED:
            return batch

        pending_items = list(
            batch.items.select_for_update().filter(
                status=DisplayCorrection.Status.PENDING
            )
        )
        for item in pending_items:
            try:
                _validate_precondition(item)
            except StaleDisplayCorrectionError as exc:
                item.status = DisplayCorrection.Status.QUARANTINED
                item.error_detail = {"detail": exc.messages}
                item.save(update_fields=["status", "error_detail", "updated_at"])

        batch.refresh_from_db()
        if batch.pending_count == 0:
            batch.status = (
                DisplayCorrectionBatch.Status.QUARANTINED
                if batch.quarantined_count
                else DisplayCorrectionBatch.Status.PROCESSED
            )
            batch.finished_at = timezone.now()
            batch.save(update_fields=["status", "finished_at", "updated_at"])
    return batch


def approve_display_correction_batch(
    batch: DisplayCorrectionBatch | str, actor=None
) -> DisplayCorrectionBatch:
    if isinstance(batch, str):
        batch = DisplayCorrectionBatch.objects.get(batch_id=batch)

    process_display_correction_batch(batch)
    with transaction.atomic():
        batch = (
            DisplayCorrectionBatch.objects.select_for_update()
            .select_related("submitted_by", "approved_by")
            .get(pk=batch.pk)
        )
        approvable = list(
            batch.items.select_for_update().filter(
                status=DisplayCorrection.Status.PENDING
            )
        )
        for item in approvable:
            _approve_item(item, actor)

        batch.refresh_from_db()
        if batch.pending_count == 0:
            batch.status = (
                DisplayCorrectionBatch.Status.QUARANTINED
                if batch.quarantined_count
                else DisplayCorrectionBatch.Status.COMPLETED
            )
            batch.approved_by = actor if getattr(actor, "pk", None) else None
            batch.approved_at = timezone.now()
            batch.finished_at = timezone.now()
            batch.save(
                update_fields=[
                    "status",
                    "approved_by",
                    "approved_at",
                    "finished_at",
                    "updated_at",
                ]
            )
    return batch


def _validate_precondition(item: DisplayCorrection) -> None:
    changes = item.log_entry.changes_dict
    if item.field_name not in changes:
        raise StaleDisplayCorrectionError(
            f"Field {item.field_name} is not present in log entry {item.log_entry_id}."
        )

    change = changes[item.field_name]
    if isinstance(change, dict):
        raise StaleDisplayCorrectionError(
            f"Field {item.field_name} does not contain an old/new value."
        )

    try:
        position = int(item.value_position)
        current_value = change[position]
    except (TypeError, ValueError, IndexError) as exc:
        raise StaleDisplayCorrectionError(
            f"Invalid value position {item.value_position}."
        ) from exc

    if current_value != item.expected_value:
        raise StaleDisplayCorrectionError(
            f"Expected {item.expected_value!r}, but current value is {current_value!r}."
        )


def _approve_item(item: DisplayCorrection, actor=None) -> DisplayCorrection:
    _validate_precondition(item)
    now = timezone.now()
    active_targets = (
        DisplayCorrection.objects.select_for_update()
        .filter(
            log_entry=item.log_entry,
            field_name=item.field_name,
            value_position=item.value_position,
            status=DisplayCorrection.Status.APPROVED,
        )
        .select_related("supersedes")
    )
    previous = active_targets.order_by("-approved_at", "-id").first()
    for active in active_targets:
        active.status = DisplayCorrection.Status.SUPERSEDED
        active.superseded_at = now
        active.save(update_fields=["status", "superseded_at", "updated_at"])

    item.status = DisplayCorrection.Status.APPROVED
    item.supersedes = previous
    item.approved_by = actor if getattr(actor, "pk", None) else None
    item.approved_at = now
    item.error_detail = None
    item.save(
        update_fields=[
            "status",
            "supersedes",
            "approved_by",
            "approved_at",
            "error_detail",
            "updated_at",
        ]
    )
    return item


def get_display_changes(
    log_entry,
    *,
    as_of=None,
    include_correction_chain: bool = False,
) -> dict[str, Any]:
    changes = log_entry.changes_dict
    if include_correction_chain:
        return changes

    queryset = DisplayCorrection.objects.filter(
        log_entry=log_entry, status=DisplayCorrection.Status.APPROVED
    )
    if as_of is not None:
        queryset = queryset.filter(
            approved_at__lte=as_of, effective_from__lte=as_of
        )

    result: dict[str, Any] = {}
    grouped: dict[tuple[str, str], list[DisplayCorrection]] = {}
    for correction in queryset:
        grouped.setdefault(
            (correction.field_name, correction.value_position), []
        ).append(correction)

    for field_name, change in changes.items():
        if isinstance(change, dict):
            result[field_name] = change
            continue
        displayed_values = list(change)
        for index, value in enumerate(displayed_values):
            corrections = grouped.get((field_name, str(index)), [])
            if not corrections:
                continue
            correction = max(
                corrections,
                key=lambda candidate: (candidate.effective_from, candidate.pk),
            )
            displayed_values[index] = _mask_display_value(
                log_entry, field_name, correction.display_value
            )
        result[field_name] = displayed_values
    return result


def _mask_display_value(log_entry, field_name: str, value: Any) -> Any:
    from auditlog.registry import auditlog

    model = log_entry.content_type.model_class()
    if model is None or not auditlog.contains(model._meta.model):
        return value
    model_fields = auditlog.get_model_fields(model._meta.model)
    if field_name not in model_fields["mask_fields"] or not isinstance(value, str):
        return value
    mask_func = get_mask_function(model_fields.get("mask_callable"))
    return mask_func(value)


def get_correction_chain(log_entry) -> dict[str, list[DisplayCorrection]]:
    grouped: dict[str, list[DisplayCorrection]] = {}
    corrections = (
        DisplayCorrection.objects.filter(log_entry=log_entry)
        .exclude(status=DisplayCorrection.Status.PENDING)
        .order_by("field_name", "value_position", "created_at", "id")
        .select_related("batch", "supersedes", "approved_by")
    )
    for correction in corrections:
        key = f"{correction.field_name}[{correction.value_position}]"
        grouped.setdefault(key, []).append(correction)
    return grouped


def get_display_value(
    log_entry, field_name: str, value_position: int, *, as_of=None
) -> Any:
    return get_display_changes(log_entry, as_of=as_of)[field_name][value_position]


def iter_batched(items: Iterable[dict[str, Any]], size: int):
    batch = []
    for item in items:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch
