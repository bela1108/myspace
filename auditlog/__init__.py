from __future__ import annotations

from importlib.metadata import version

from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

__version__ = version("django-auditlog")


def get_logentry_model():
    model_string = getattr(settings, "AUDITLOG_LOGENTRY_MODEL", "auditlog.LogEntry")
    try:
        return django_apps.get_model(model_string, require_ready=False)
    except ValueError:
        raise ImproperlyConfigured(
            "AUDITLOG_LOGENTRY_MODEL must be of the form 'app_label.model_name'"
        )
    except LookupError:
        raise ImproperlyConfigured(
            "AUDITLOG_LOGENTRY_MODEL refers to model '%s' that has not been installed"
            % model_string
        )


def get_segment_model():
    return django_apps.get_model("auditlog", "LogEntrySegment", require_ready=False)


def seal_segment(*args, **kwargs):
    from auditlog.sealing import seal_segment as _seal_segment

    return _seal_segment(*args, **kwargs)


def verify_segments(*args, **kwargs):
    from auditlog.sealing import verify_segments as _verify_segments

    return _verify_segments(*args, **kwargs)


def export_segments(*args, **kwargs):
    from auditlog.sealing import export_segments as _export_segments

    return _export_segments(*args, **kwargs)
