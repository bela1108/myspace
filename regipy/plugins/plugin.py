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

        self.partial_hive_path = getattr(registry_hive, "partial_hive_path", None)

        # This variable should always hold the final result - in order to use it in anomaly detection and timeline gen.
        # Can be either a list of dicts (most plugins) or a dict (some plugins that organize by key path)
        self.entries: Union[list[dict[str, Any]], dict[str, Any]] = []

    def can_run(self):
        """
        Whether the plugin can run or not, according to specific checks
        :return:
        """
        return self.registry_hive.hive_type == self.COMPATIBLE_HIVE

    def snapshot_key_paths(self):
        """
        Registry key paths whose key clock and values should be tracked when
        this plugin is used with :func:`regipy.snapshots.compare_snapshots`.

        Plugins that support historical snapshot comparisons override this.
        """
        return []

    def decode_snapshot_value(self, key_path, value_name, value):
        """
        Optionally decode a raw registry value for snapshot evidence output.

        The returned object must be JSON serializable.  Returning ``None``
        keeps the default raw-value representation.
        """
        return None

    @classmethod
    def compare_snapshots(cls, snapshots, as_json=True, **kwargs):
        """
        Build historical per-value evidence for this plugin across snapshots.

        This is opt-in: the regular ``run()`` behavior and output of a single
        hive are unchanged.
        """
        from regipy.snapshots import compare_snapshots

        return compare_snapshots(snapshots, plugins=[cls], as_json=as_json, **kwargs)

    def run_with_snapshots(self, snapshots, as_json=None, **kwargs):
        """Run this plugin's snapshot comparison and store the result in ``entries``."""
        if as_json is None:
            as_json = self.as_json
        self.entries = type(self).compare_snapshots(snapshots, as_json=as_json, **kwargs)
        return self.entries

    def get_snapshot_evidence(self, snapshots, as_json=None, **kwargs):
        """Alias for :meth:`run_with_snapshots` that does not overwrite ``entries``."""
        if as_json is None:
            as_json = self.as_json
        return type(self).compare_snapshots(snapshots, as_json=as_json, **kwargs)

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
