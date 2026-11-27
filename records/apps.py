from django.apps import AppConfig


class RecordsConfig(AppConfig):
    default_auto_field = "django.db.models.AutoField"
    name = "records"

    def ready(self):
        from . import signals  # noqa: F401
