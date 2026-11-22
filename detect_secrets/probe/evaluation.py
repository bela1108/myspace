"""
Recovery probes hold each plugin accountable against a known set of test samples.

A probe sample carries an explicit expected contribution: every plugin named as an
owner of a positive sample must detect it, while every other enabled plugin must
ignore it. Because markers can be swept up by *any* plugin, aggregate counts across
all plugins are not enough -- this module keeps the books per plugin, so a disabled
plugin whose markers are still found by its neighbours cannot hide behind the
healthy-looking totals of the rest of the fleet.
"""
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import List
from typing import Set

from ..settings import get_plugins
from ..util.code_snippet import get_code_snippet
from .manifest import TestSample


@dataclass
class PluginContribution:
    """How one plugin answered the probe roll call."""

    plugin_name: str
    secret_type: str = None
    enabled: bool = True
    true_positives: int = 0
    shared_true_positives: int = 0
    missed_positives: int = 0
    false_positives: int = 0
    ignored_negatives: int = 0
    missed_sample_ids: List[str] = field(default_factory=list)
    false_positive_sample_ids: List[str] = field(default_factory=list)

    @property
    def expected_positives(self) -> int:
        return self.true_positives + self.shared_true_positives + self.missed_positives

    @property
    def expected_negatives(self) -> int:
        return self.ignored_negatives + self.false_positives

    @property
    def is_healthy(self) -> bool:
        return (
            self.enabled
            and not self.missed_positives
            and not self.false_positives
        )

    def json(self) -> Dict[str, Any]:
        return {
            'secret-type': self.secret_type,
            'enabled': self.enabled,
            'positives': {
                'expected': self.expected_positives,
                'own': self.true_positives,
                'shared': self.shared_true_positives,
                'missed': self.missed_positives,
            },
            'negatives': {
                'expected': self.expected_negatives,
                'ignored': self.ignored_negatives,
                'false-positives': self.false_positives,
            },
            'missed-samples': self.missed_sample_ids,
            'false-positive-samples': self.false_positive_sample_ids,
            'healthy': self.is_healthy,
        }

    def __str__(self) -> str:
        newline = chr(10)
        return (
            f'Plugin: {self.plugin_name} (enabled={self.enabled}){newline}'
            f'  Positives: expected={self.expected_positives}, '
            f'own={self.true_positives}, shared={self.shared_true_positives}, '
            f'missed={self.missed_positives}{newline}'
            f'  Negatives: expected={self.expected_negatives}, '
            f'ignored={self.ignored_negatives}, '
            f'false-positives={self.false_positives}{newline}'
            f'  Healthy: {self.is_healthy}'
        )


def run_probe(samples: List[TestSample]) -> 'ProbeReport':
    """Scan every sample with the plugins currently enabled in settings.

    Plugins named by a sample but absent from the enabled plugin set are kept on
    the books as disabled contributions, so a turned-off plugin can never be made
    invisible by the plugins that happen to sweep up its markers.
    """
    enabled_plugins = list(get_plugins())
    plugins_by_name = {
        plugin.__class__.__name__: plugin
        for plugin in enabled_plugins
    }

    contributions: Dict[str, PluginContribution] = {
        name: PluginContribution(
            plugin_name=name,
            secret_type=plugin.secret_type,
        )
        for name, plugin in plugins_by_name.items()
    }
    for sample in samples:
        for plugin_name in sample.expected_plugins:
            if plugin_name not in contributions:
                contributions[plugin_name] = PluginContribution(
                    plugin_name=plugin_name,
                    enabled=False,
                )

    detections: Dict[str, Set[str]] = {}
    for sample in samples:
        context = get_code_snippet(lines=[sample.value], line_number=1)
        found_names: Set[str] = set()
        for plugin in enabled_plugins:
            for secret in plugin.analyze_line(
                filename=sample.filename,
                line=sample.value,
                line_number=1,
                context=context,
            ):
                found_names.add(plugin.__class__.__name__)
        detections[sample.id] = found_names

    for sample in samples:
        found_names = detections[sample.id]
        owners = sample.expected_plugins
        for plugin_name in owners:
            contribution = contributions[plugin_name]
            if not contribution.enabled:
                contribution.missed_positives += 1
                contribution.missed_sample_ids.append(sample.id)
            elif plugin_name in found_names:
                if len(owners) > 1:
                    contribution.shared_true_positives += 1
                else:
                    contribution.true_positives += 1
            else:
                contribution.missed_positives += 1
                contribution.missed_sample_ids.append(sample.id)

        for plugin_name, plugin in plugins_by_name.items():
            if plugin_name in owners:
                continue

            contribution = contributions[plugin_name]
            if plugin_name in found_names:
                contribution.false_positives += 1
                contribution.false_positive_sample_ids.append(sample.id)
            else:
                contribution.ignored_negatives += 1

    return ProbeReport(contributions=contributions)


@dataclass
class ProbeReport:
    """Per-plugin accounting produced by a single, freshly verified probe run."""

    contributions: Dict[str, PluginContribution]

    @property
    def failures(self) -> List[str]:
        output: List[str] = []
        for plugin_name, contribution in sorted(self.contributions.items()):
            if not contribution.enabled:
                output.append(f'{plugin_name}: plugin is not enabled')
            if contribution.missed_positives:
                output.append(
                    f'{plugin_name}: missed {contribution.missed_positives} '
                    f'positive sample(s): {", ".join(contribution.missed_sample_ids)}',
                )
            if contribution.false_positives:
                output.append(
                    f'{plugin_name}: flagged {contribution.false_positives} '
                    f'negative sample(s): '
                    f'{", ".join(contribution.false_positive_sample_ids)}',
                )
        return output

    @property
    def all_healthy(self) -> bool:
        return all(
            contribution.is_healthy
            for contribution in self.contributions.values()
        )

    def json(self) -> Dict[str, Any]:
        return {
            'release-verified': self.all_healthy,
            'plugins': {
                plugin_name: contribution.json()
                for plugin_name, contribution in sorted(self.contributions.items())
            },
            'failures': self.failures,
        }

    def __str__(self) -> str:
        divider = '-' * 60
        output = ['Recovery probe report', divider]
        for plugin_name in sorted(self.contributions):
            output.append(str(self.contributions[plugin_name]))
            output.append('')
        output.append(divider)
        if self.all_healthy:
            verdict = 'PASS: release allowed'
        else:
            verdict = 'FAIL: release blocked'
        output.append(f'Recovery decision: {verdict}')
        for failure in self.failures:
            output.append(f'  - {failure}')
        return chr(10).join(output)
