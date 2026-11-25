import contextlib
import importlib


__version__ = "2.7.0"


with contextlib.suppress(ImportError):
    from .sanitizer import *  # noqa: F403


_LAZY_OFFLINE_EXPORTS = frozenset(
    {
        "ComparisonReport",
        "Diagnostic",
        "MarkerDecision",
        "OfflineComparisonError",
        "SourceDecision",
        "ViewAnalysis",
        "analyze_view",
        "canonical_visible_text",
        "compare_outputs",
        "compare_views",
        "format_report",
    }
)


def __getattr__(name):
    if name in _LAZY_OFFLINE_EXPORTS:
        return getattr(importlib.import_module(".offline_compare", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
