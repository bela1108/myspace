from django.db import models

from auditlog.models import AuditlogHistoryField
from auditlog.registry import auditlog


@auditlog.register(mask_fields=["name"])
class SnapshotApprover(models.Model):
    key = models.CharField(primary_key=True, max_length=20)
    name = models.CharField(max_length=100)
    email = models.EmailField(blank=True)

    def __str__(self):
        return self.name


@auditlog.register()
class SnapshotAlternateApprover(models.Model):
    key = models.CharField(primary_key=True, max_length=20)
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


@auditlog.register(
    relation_fields={
        "approver": {"fields": ["name", "email"], "display": "name"},
        "alternate_approver": {"fields": ["name"], "display": "name"},
    }
)
class SnapshotOwner(models.Model):
    approver = models.ForeignKey(
        SnapshotApprover, null=True, blank=True, on_delete=models.SET_NULL
    )
    alternate_approver = models.ForeignKey(
        SnapshotAlternateApprover,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    label = models.CharField(max_length=100, blank=True)

    history = AuditlogHistoryField(delete_related=True)
