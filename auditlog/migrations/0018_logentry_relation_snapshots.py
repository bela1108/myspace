from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auditlog", "0017_add_actor_email"),
    ]

    operations = [
        migrations.AddField(
            model_name="logentry",
            name="relation_snapshots",
            field=models.JSONField(
                blank=True,
                null=True,
                verbose_name="related object snapshots",
            ),
        ),
    ]
