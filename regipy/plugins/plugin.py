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

    def __init__(
        self,
        registry_hive: RegistryHive,
        as_json=False,
        trim_values=False,
        snapshots=None,
        observed_at=None,
        include_history=False,
        history=None,
        historical_snapshots=None,
        **kwargs,
    ):
        self.registry_hive = registry_hive
        self.as_json = as_json
        self.trim_values = trim_values

        self.partial_hive_path = registry_hive.partial_hive_path

        # Historical snapshot comparison is opt-in.  When it is not requested
        # the plugin keeps its original single-hive behavior and output shape.
        if snapshots is None:
            snapshots = kwargs.get("history_snapshots") or kwargs.get("snapshot_history")
        if observed_at is None:
            observed_at = kwargs.get("acquisition_time") or kwargs.get("snapshot_time")
        if history is None:
            history = kwargs.get("history_report")
        self.snapshots = snapshots
        self.historical_snapshots = historical_snapshots
        self.observed_at = observed_at
        self.include_history = include_history or any(value is not None for value in (snapshots, historical_snapshots, history))
        self.history = history
        self.history_report = None
        self.value_timelines = []
        self.comparisons = []
        self.breakpoints = []

        # This variable should always hold the final result - in order to use it in anomaly detection and timeline gen.
        # Can be either a list of dicts (most plugins) or a dict (some plugins that organize by key path)
        self.entries: Union[list[dict[str, Any]], dict[str, Any]] = []

    def _history_snapshot_inputs(self):
        """
        Resolve the snapshots supplied to the plugin.

        A pre-built report is returned as-is. When no snapshots were supplied,
        the plugin own hive is used as a single observation. An explicitly
        supplied snapshot collection is treated as complete.
        """
        if self.history_report is not None:
            return self.history_report
        if self.history is not None and hasattr(self.history, "key_histories"):
            return self.history

        supplied = self.snapshots if self.snapshots is not None else self.historical_snapshots
        if supplied is None and self.history is not None and not hasattr(self.history, "key_histories"):
            supplied = self.history
        if supplied is None:
            if self.observed_at is not None:
                supplied = [(self.observed_at, self.registry_hive)]
            else:
                supplied = [(None, self.registry_hive)]
        elif self.observed_at is not None and isinstance(supplied, dict):
            snapshot_fields = {"observed_at", "captured_at", "acquisition_time", "hive", "keys"}
            if not snapshot_fields.intersection(supplied):
                supplied = {"observed_at": self.observed_at, "keys": supplied}
        return supplied

    def build_history_report(self, analyzer, snapshots=None):
        """Return an existing report or run ``analyzer`` over the snapshots."""
        if snapshots is not None:
            self.snapshots = snapshots
            self.include_history = True
        existing = self._history_snapshot_inputs()
        if hasattr(existing, "key_histories"):
            return existing
        return analyzer(existing, as_json=self.as_json)

    def set_history_report(self, report):
        """Store a history report on the plugin and expose its main views."""
        self.history_report = report
        self.history = report
        self.value_timelines = report.value_timelines
        self.value_evidence = self.value_timelines
        self.timelines = self.value_timelines
        self.comparisons = report.comparisons
        self.breakpoints = report.breakpoints
        self.parent_only_changes = report.parent_only_changes
        self.key_history = report.key_histories
        return report

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
