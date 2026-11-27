import logging
from typing import Any, Optional, Union

from regipy.registry import RegistryHive

PLUGINS: set[type] = set()

logger = logging.getLogger(__name__)


class Plugin:
    NAME: Optional[str] = None
    DESCRIPTION: Optional[str] = None
    COMPATIBLE_HIVE: Optional[str] = None

    def __init_subclass__(cls) -> None:
        PLUGINS.add(cls)

    def __init__(self, registry_hive: RegistryHive, as_json=False, trim_values=False):
        self.registry_hive = registry_hive
        self.as_json = as_json
        self.trim_values = trim_values

        self.partial_hive_path = registry_hive.partial_hive_path

        # This variable should always hold the final result - in order to use it in anomaly detection and timeline gen.
        # Can be either a list of dicts (most plugins) or a dict (some plugins that organize by key path)
        self.entries: Union[list[dict[str, Any]], dict[str, Any]] = []

        # Execution/coverage bookkeeping.  These attributes are only consulted
        # by the opt-in coverage report; they do not alter ``entries``.
        self.executed = False
        self.error: Optional[BaseException] = None
        self.skip_reason: Optional[str] = None
        self.skip_reason_code: Optional[str] = None

    def can_run(self):
        """
        Whether the plugin can run or not, according to specific checks
        :return:
        """
        return self.registry_hive.hive_type == self.COMPATIBLE_HIVE

    def run(self):
        """
        Execute the plugin
        :return:
        """

    def execute(self) -> Union[list[dict[str, Any]], dict[str, Any]]:
        """Run the plugin while recording execution state for coverage assessment.

        Exceptions are re-raised unchanged; the method only records whether the
        plugin actually ran and, if it failed, the exception that escaped.
        """
        self.executed = True
        self.error = None
        try:
            self.run()
        except Exception as ex:
            self.error = ex
            raise
        return self.entries

    def has_results(self) -> bool:
        """Whether ``entries`` contains actual records rather than only metadata.

        Some plugins (for example ``typed_paths``) return a wrapper dict with a
        ``last_write`` timestamp and an ``entries`` list.  An empty list there
        means no records, even though the wrapper dict itself is truthy.
        """
        entries = self.entries
        if isinstance(entries, dict) and "entries" in entries:
            return bool(entries["entries"])
        return bool(entries)

    def get_coverage(self) -> dict[str, Any]:
        """Return this plugin's coverage metadata after ``execute()`` or after
        the plugin was skipped by :func:`run_relevant_plugins`."""
        from regipy.plugins.coverage import assess_plugin_coverage

        return assess_plugin_coverage(
            self,
            executed=self.executed,
            error=self.error,
            skip_reason=self.skip_reason,
            skip_reason_code=self.skip_reason_code,
        ).to_dict()

    def generate_timeline_artifacts(self):
        """
        Run on the output of a plugin and generate timeline entries
        :return:
        """
        pass

    def detect_anomalies(self):
        """
        Run on the output of a plugin and detect possible anomalies
        :return:
        """
        pass
