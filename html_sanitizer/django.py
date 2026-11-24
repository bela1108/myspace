from functools import lru_cache

from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured
from django.dispatch import receiver
from django.test.signals import setting_changed

from .policy import SanitizationService
from .sanitizer import Sanitizer


def _get_sanitizer(name="default"):
    sanitizers = getattr(settings, "HTML_SANITIZERS", {})
    if name in sanitizers:
        return Sanitizer(sanitizers[name])
    elif name == "default":
        return Sanitizer()
    raise ImproperlyConfigured(
        f"Unknown sanitizer {name!r}, did you define HTML_SANITIZERS[{name!r}] in your"
        " Django settings module?"
    )


get_sanitizer = lru_cache(maxsize=None)(_get_sanitizer)


# Shared service coordinating request-scoped policy snapshots and the
# generation-aware output cache. Policies are pushed from the
# HTML_SANITIZERS setting and replaced atomically on changes.
sanitization_service = SanitizationService()


def _sync_policies():
    for name, config in getattr(settings, "HTML_SANITIZERS", {}).items():
        sanitization_service.registry.update_policy(config, tenant=name)


if settings.configured:
    _sync_policies()


@receiver(setting_changed)
def reload_policies(*, setting, **kwargs):
    """Apply HTML_SANITIZERS changes to live sanitizers, atomically."""
    if setting == "HTML_SANITIZERS":
        get_sanitizer.cache_clear()
        _sync_policies()


def begin_sanitizer_request(request, tenant="default"):
    """
    Capture the request-scoped policy snapshot and attach it to the request.

    Every sanitize call of the request reuses this snapshot, so a policy
    hot-update or revocation halfway through cannot mix old and new rules
    within one response.
    """
    snapshot = sanitization_service.begin_request(tenant)
    request.html_sanitizer_snapshot = snapshot
    return snapshot


def sanitize_request(request, html, *, document_version, tenant="default"):
    """
    Sanitize HTML for a request under its own policy snapshot.

    Cached output is only reused when the snapshot proves the same
    tenant, policy generation, revocation epoch and document version.
    """
    snapshot = getattr(request, "html_sanitizer_snapshot", None)
    if snapshot is None or snapshot.tenant != tenant:
        snapshot = begin_sanitizer_request(request, tenant)
    return sanitization_service.sanitize(
        html,
        snapshot=snapshot,
        tenant=tenant,
        document_version=document_version,
    )


@checks.register()
def check_configuration(app_configs, **kwargs):
    errors = []
    sanitizers = ["default"] + list(getattr(settings, "HTML_SANITIZERS", {}))
    for name in sorted(set(sanitizers)):
        try:
            _get_sanitizer(name)
        except TypeError as exc:
            errors.append(
                checks.Error(
                    f"Invalid sanitizer configuration '{name}': {exc}",
                    id="html_sanitizer.E001",
                )
            )

    return errors
