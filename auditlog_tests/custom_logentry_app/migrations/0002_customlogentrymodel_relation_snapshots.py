from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("custom_logentry_app", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="customlogentrymodel",
            name="relation_snapshots",
            field=models.JSONField(
                blank=True,
                null=True,
                verbose_name="related object snapshots",
            ),
        ),
    ]
