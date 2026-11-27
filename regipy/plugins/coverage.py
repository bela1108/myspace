"""Plugin evidence-coverage assessment.

An empty plugin result is ambiguous on its own: the plugin may have run over a
complete hive and genuinely found nothing, it may never have run because the
hive type was not recognized, or it may have run over an acquisition that only
covers part of the original hive.  The helpers in this module describe those
cases explicitly so a consumer (or a human reviewer) can tell them apart.

Coverage is opt-in: :func:`regipy.plugins.utils.run_relevant_plugins` only
attaches it when ``include_coverage=True``.  Default result shapes are unchanged.
"""

from dataclasses import dataclass
from typing import Any, Optional

# Status values returned in ``coverage[status]``.  They are stable strings so
# they can be compared across runs and between two acquisitions.
STATUS_RESULTS = "results"
STATUS_NO_RESULTS = "no_results"
STATUS_PARTIAL_SCOPE = "partial_scope"
STATUS_NOT_CHECKED = "not_checked"
STATUS_ERROR = "error"

COVERAGE_STATUSES = (
    STATUS_RESULTS,
    STATUS_NO_RESULTS,
    STATUS_PARTIAL_SCOPE,
    STATUS_NOT_CHECKED,
    STATUS_ERROR,
)

# ``reason_code`` is machine-readable; ``reason`` is meant for an evidence
# summary and is deliberately explicit about what is (and is not) covered.
REASON_RESULTS_FOUND = "records_found"
REASON_EMPTY_FULL_SCOPE = "no_records_in_full_scope"
REASON_PARTIAL_HIVE_SCOPE = "partial_hive_scope"
REASON_UNRECOGNIZED_HIVE_TYPE = "unrecognized_hive_type"
REASON_INCOMPATIBLE_HIVE_TYPE = "incompatible_hive_type"
REASON_UNVALIDATED_PLUGIN = "unvalidated_plugin"
REASON_PLUGIN_NOT_RUN = "plugin_not_run"
REASON_MISSING_DEPENDENCY = "missing_dependency"
REASON_PLUGIN_ERROR = "plugin_error"


@dataclass(frozen=True)
class PluginCoverage:
    """Coverage metadata for one plugin in one run.

    ``checked`` says whether the plugin actually executed.  ``conclusive`` says
    whether the returned entries support an absence/presence conclusion for the
    whole logical hive.  ``partial_hive_path`` records the acquired scope, so a
    reviewer can see why a result is partial even when ``entries`` is empty.
    """

    plugin_name: str
    status: str
    reason_code: str
    reason: str
    checked: bool
    conclusive: bool
    entries_found: bool
    scope: str
    partial_hive_path: Optional[str]
    hive_type: Optional[str]
    compatible_hive: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "label": coverage_status_label(self.status),
            "reason_code": self.reason_code,
            "reason": self.reason,
            "checked": self.checked,
            "conclusive": self.conclusive,
            "entries_found": self.entries_found,
            "scope": self.scope,
            "partial_hive_path": self.partial_hive_path,
            "hive_type": self.hive_type,
            "compatible_hive": self.compatible_hive,
        }


def assess_plugin_coverage(
    plugin,
    *,
    executed: bool,
    error: Optional[BaseException] = None,
    skip_reason: Optional[str] = None,
    skip_reason_code: Optional[str] = None,
) -> PluginCoverage:
    """Build coverage metadata for a plugin instance.

    :param plugin: a :class:`regipy.plugins.plugin.Plugin` instance
    :param executed: whether ``run()`` was called
    :param error: the exception raised while running, if any
    :param skip_reason: human-readable reason the plugin was not run
    :param skip_reason_code: a ``REASON_*`` code for a pre-run skip
    """
    registry_hive = plugin.registry_hive
    hive_type = registry_hive.hive_type
    partial_hive_path = registry_hive.partial_hive_path
    scope = "partial" if partial_hive_path else "full"
    compatible_hive = plugin.COMPATIBLE_HIVE

    def build(
        status: str,
        reason_code: str,
        reason: str,
        *,
        checked: bool,
        conclusive: bool,
        entries_found: bool = False,
    ) -> PluginCoverage:
        return PluginCoverage(
            plugin_name=plugin.NAME or plugin.__class__.__name__,
            status=status,
            reason_code=reason_code,
            reason=reason,
            checked=checked,
            conclusive=conclusive,
            entries_found=entries_found,
            scope=scope,
            partial_hive_path=partial_hive_path,
            hive_type=hive_type,
            compatible_hive=compatible_hive,
        )

    if error is not None:
        reason_code = REASON_MISSING_DEPENDENCY if isinstance(error, ModuleNotFoundError) else REASON_PLUGIN_ERROR
        if isinstance(error, ModuleNotFoundError):
            reason = f"Plugin could not run because a dependency is missing: {error}"
        else:
            reason = f"Plugin failed before a complete result could be assessed: {error}"
        return build(STATUS_ERROR, reason_code, reason, checked=False, conclusive=False)

    if skip_reason is not None:
        return build(
            STATUS_NOT_CHECKED,
            skip_reason_code or REASON_PLUGIN_NOT_RUN,
            skip_reason,
            checked=False,
            conclusive=False,
        )

    if not plugin.can_run():
        if hive_type is None:
            reason_code = REASON_UNRECOGNIZED_HIVE_TYPE
            reason = (
                "Hive type could not be recognized, so this plugin was not run; "
                "the absence of records cannot be concluded from this hive."
            )
        else:
            reason_code = REASON_INCOMPATIBLE_HIVE_TYPE
            reason = (
                f"Hive type '{hive_type}' is not compatible with this plugin "
                f"(requires '{compatible_hive}'), so it was not run; the absence "
                "of records cannot be concluded from this hive."
            )
        return build(STATUS_NOT_CHECKED, reason_code, reason, checked=False, conclusive=False)

    if not executed:
        return build(
            STATUS_NOT_CHECKED,
            REASON_PLUGIN_NOT_RUN,
            "Plugin was not run, so its output cannot be interpreted.",
            checked=False,
            conclusive=False,
        )

    entries_found = plugin.has_results()

    if partial_hive_path:
        reason = (
            f"Plugin ran, but the acquisition only covers '{partial_hive_path}'. "
            "Records outside that scope were not checked, so an empty or "
            "non-empty result is not conclusive for the full hive."
        )
        return build(
            STATUS_PARTIAL_SCOPE,
            REASON_PARTIAL_HIVE_SCOPE,
            reason,
            checked=True,
            conclusive=False,
            entries_found=entries_found,
        )

    if entries_found:
        return build(
            STATUS_RESULTS,
            REASON_RESULTS_FOUND,
            "Plugin ran over the full hive and returned matching records.",
            checked=True,
            conclusive=True,
            entries_found=True,
        )

    return build(
        STATUS_NO_RESULTS,
        REASON_EMPTY_FULL_SCOPE,
        "Plugin ran over the full hive and returned no records; absence is conclusive for this hive.",
        checked=True,
        conclusive=True,
    )


def build_coverage_report(registry_hive, plugin_coverage: dict[str, PluginCoverage]) -> dict[str, Any]:
    """Wrap per-plugin coverage with the hive/scope context and a summary."""
    partial_hive_path = registry_hive.partial_hive_path
    summary = dict.fromkeys(COVERAGE_STATUSES, 0)
    for coverage in plugin_coverage.values():
        summary[coverage.status] = summary.get(coverage.status, 0) + 1

    return {
        "hive": {
            "hive_type": registry_hive.hive_type,
            "hive_type_recognized": registry_hive.hive_type is not None,
            "scope": "partial" if partial_hive_path else "full",
            "partial_hive_path": partial_hive_path,
            "file_name": getattr(registry_hive, "name", None),
        },
        "summary": summary,
        "plugins": {name: coverage.to_dict() for name, coverage in plugin_coverage.items()},
    }


def coverage_status_label(status: str) -> str:
    """Return a short reviewer-facing label for a status."""
    return {
        STATUS_RESULTS: "checked: records found",
        STATUS_NO_RESULTS: "checked: no records",
        STATUS_PARTIAL_SCOPE: "partial scope: not conclusive",
        STATUS_NOT_CHECKED: "not checked: no precondition",
        STATUS_ERROR: "check failed",
    }.get(status, status)
