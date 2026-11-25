"""
Offline execution engine for candidate plugins.

The engine runs each candidate plugin directly against the synthetic corpus,
bypassing global filters and network verification, so the evaluation stays
deterministic and hermetic. A plugin that raises while scanning any file is
not allowed to abort the whole run: the error is captured and reported
separately as a failed plugin.
"""
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Type

from ..core.plugins.util import get_mapping_from_secret_type_to_class
from ..plugins.base import BasePlugin
from .dataset import LabeledDataset
from .matching import Hit
from .matching import PluginName


def resolve_plugin_class(plugin_name: str) -> Type[BasePlugin]:
    """Resolve a plugin by class name (e.g. AWSKeyDetector) or secret type.

    :raises: KeyError when no matching plugin is installed.
    """
    mapping = get_mapping_from_secret_type_to_class()
    if plugin_name in mapping:
        return mapping[plugin_name]
    for plugin_class in mapping.values():
        if plugin_class.__name__ == plugin_name:
            return plugin_class
    raise KeyError(plugin_name)


def _instantiate(plugin_name: str, config: Optional[dict]) -> BasePlugin:
    plugin_class = resolve_plugin_class(plugin_name)
    if config:
        return plugin_class(**config)
    return plugin_class()


def _locate_span(line: str, value: str, search_from: int) -> tuple:
    """Find the character span of a hit value on one line.

    The same value can legitimately appear several times on a line, so the
    search position advances to avoid every duplicate landing on the first
    occurrence. Returns (start, end), or (None, None) if not found.
    """
    if not value:
        return (None, None)
    position = line.find(value, search_from)
    if position < 0:
        return (None, None)
    return (position, position + len(value))


def run_plugin(
    plugin: BasePlugin,
    dataset: LabeledDataset,
) -> List[Hit]:
    """Run one healthy plugin over every file in the dataset."""
    hits: List[Hit] = []
    plugin_name = plugin.__class__.__name__

    for labeled_file in dataset.files:
        lines = dataset.read_lines(labeled_file)
        cursor_per_line: Dict[int, int] = {}

        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip()
            secrets = plugin.analyze_line(
                filename=labeled_file.path,
                line=line,
                line_number=line_number,
            )

            for secret in secrets or ():
                value = secret.secret_value or ""
                cursor = cursor_per_line.get(line_number, 0)
                start, end = _locate_span(line, value, cursor)
                if start is not None:
                    cursor_per_line[line_number] = end
                hits.append(
                    Hit(
                        plugin=plugin_name,
                        path=labeled_file.path,
                        family=labeled_file.family,
                        line_number=line_number,
                        value=value,
                        start=start,
                        end=end,
                    ),
                )
    return hits


def run_all(
    dataset: LabeledDataset,
    plugin_specs: Sequence[Dict[str, object]],
) -> tuple:
    """Run every requested plugin, isolating failures.

    :param plugin_specs: mappings shaped like baseline plugin config, e.g.
        ``{"name": "AWSKeyDetector"}`` or with an extra ``options`` map.
    :returns: ``(plugin_hits, failures)`` where failures maps a plugin name
        to a short error message. Failed plugins never appear in hits.
    """
    plugin_hits: Dict[PluginName, List[Hit]] = {}
    failures: Dict[PluginName, str] = {}

    for spec in plugin_specs:
        plugin_name = str(spec["name"])
        options = spec.get("options")
        try:
            plugin = _instantiate(plugin_name, options)
            plugin_hits[plugin_name] = run_plugin(plugin, dataset)
        except Exception as exc:
            failures[plugin_name] = "{}: {}".format(
                exc.__class__.__name__,
                exc,
            )

    return (plugin_hits, failures)


def available_plugin_names() -> List[str]:
    """Sorted class names of every installed, instantiable plugin."""
    return sorted(plugin_class.__name__ for plugin_class in
                  get_mapping_from_secret_type_to_class().values())
