from functools import lru_cache

from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured

from .sanitizer import Sanitizer
from .publish import BlockPublishCache, RuleRegistry


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


def _get_publish_cache():
    """
    Build the block-level publish cache from
    ``settings.HTML_SANITIZER_PUBLISH_RULES``, a mapping of
    ``{document_kind: {rule_version: sanitizer_settings}}``.
    """
    registry = RuleRegistry()
    rules = getattr(settings, "HTML_SANITIZER_PUBLISH_RULES", {})
    for kind, versions in rules.items():
        for version, sanitizer_settings in versions.items():
            registry.register(kind, version, sanitizer_settings)
    return BlockPublishCache(registry)


get_publish_cache = lru_cache(maxsize=None)(_get_publish_cache)


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
