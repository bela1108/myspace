import hashlib
import json

from django.conf import settings
from django.db import models
from django.utils import timezone as django_timezone
from django.utils.translation import gettext_lazy as _

from auditlog import get_logentry_model


class DisplayCorrectionBatch(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", _("pending")
        PROCESSING = "processing", _("processing")
        COMPLETED = "completed", _("completed")
        PARTIALLY_COMPLETED = "partially_completed", _("partially completed")
        FAILED = "failed", _("failed")

    fingerprint = models.CharField(max_length=64, unique=True, db_index=True)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    auto_approved = models.BooleanField(default=False)
    failure_reason = models.TextField(blank=True)
    created_at = models.DateTimeField(default=django_timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    approved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        verbose_name = _("display correction batch")
        verbose_name_plural = _("display correction batches")

    def __str__(self):
        return f"{self._meta.verbose_name} #{self.pk}"

    @staticmethod
    def calculate_fingerprint(items):
        payload = json.dumps(items, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class DisplayCorrection(models.Model):
    class Position(models.TextChoices):
        OLD = "old", _("old value")
        NEW = "new", _("new value")

    class Status(models.TextChoices):
        PENDING = "pending", _("pending")
        EFFECTIVE = "effective", _("effective")
        REJECTED = "rejected", _("rejected")
        QUARANTINED = "quarantined", _("quarantined")
        SUPERSEDED = "superseded", _("superseded")

    batch = models.ForeignKey(
        DisplayCorrectionBatch,
        on_delete=models.CASCADE,
        related_name="items",
    )
    log_entry = models.ForeignKey(
        get_logentry_model(),
        on_delete=models.PROTECT,
        related_name="display_corrections",
    )
    field_name = models.CharField(max_length=255)
    value_position = models.CharField(
        max_length=8,
        choices=Position.choices,
        default=Position.NEW,
    )
    expected_value = models.JSONField(null=True)
    corrected_value = models.JSONField(null=True)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    replaces = models.ForeignKey(
        "self",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="replacements",
    )
    failure_reason = models.TextField(blank=True)
    effective_from = models.DateTimeField(null=True, blank=True, db_index=True)
    effective_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=django_timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["log_entry", "field_name", "value_position"],
                condition=models.Q(status="effective"),
                name="unique_effective_display_correction",
            )
        ]
        verbose_name = _("display correction")
        verbose_name_plural = _("display corrections")

    def __str__(self):
        return f"{self.field_name} ({self.get_value_position_display()})"

    @property
    def target_key(self):
        return (
            self.log_entry_id,
            self.field_name,
            self.value_position,
        )
