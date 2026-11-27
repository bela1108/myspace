import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auditlog", "0017_add_actor_email"),
    ]

    operations = [
        migrations.CreateModel(
            name="LogEntrySegment",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "sequence",
                    models.PositiveIntegerField(
                        db_index=True, unique=True, verbose_name="sequence"
                    ),
                ),
                (
                    "previous_digest",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=128,
                        verbose_name="previous digest",
                    ),
                ),
                (
                    "digest",
                    models.CharField(
                        db_index=True, max_length=128, verbose_name="digest"
                    ),
                ),
                ("manifest", models.JSONField(default=list, verbose_name="manifest")),
                (
                    "entry_count",
                    models.PositiveIntegerField(default=0, verbose_name="entry count"),
                ),
                (
                    "first_entry_id",
                    models.BigIntegerField(
                        blank=True, null=True, verbose_name="first entry id"
                    ),
                ),
                (
                    "last_entry_id",
                    models.BigIntegerField(
                        blank=True,
                        db_index=True,
                        null=True,
                        verbose_name="last entry id",
                    ),
                ),
                (
                    "sealed_at",
                    models.DateTimeField(
                        db_index=True,
                        default=django.utils.timezone.now,
                        verbose_name="sealed at",
                    ),
                ),
                (
                    "algorithm",
                    models.CharField(
                        default="sha256",
                        max_length=32,
                        verbose_name="digest algorithm",
                    ),
                ),
                (
                    "source_alias",
                    models.CharField(
                        blank=True,
                        default="",
                        max_length=100,
                        verbose_name="source database alias",
                    ),
                ),
            ],
            options={
                "verbose_name": "log entry segment",
                "verbose_name_plural": "log entry segments",
                "ordering": ["sequence"],
                "get_latest_by": "sequence",
            },
        ),
    ]
