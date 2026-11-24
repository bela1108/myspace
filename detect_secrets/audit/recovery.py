"""
Recovery probes hold each plugin accountable against a known set of test samples.

A probe manifest identifies a handful of labelled markers. When a recovery scan runs,
every plugin is expected to:

* catch its own positive samples (including the samples it shares with other plugins),
* leave the negative samples alone.

Without this per-plugin accounting, aggregate numbers can look healthy even when a
plugin is dead: a surviving plugin that shares a marker happily reports the findings
of the missing one.
"""
import os
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import yaml

from ..core.plugins.util import get_mapping_from_secret_type_to_class
from ..core.potential_secret import PotentialSecret
from ..core.scan import scan_file
from ..core.secrets_collection import SecretsCollection
from ..exceptions import InvalidBaselineError
from ..settings import transient_settings
from .common import get_baseline_from_file


class RecoveryProbeError(ValueError):
    """Raised when a probe manifest cannot be interpreted."""


class RecoveryCheckFailed(Exception):
    """Raised when a release gate fails its recovery probe."""


@dataclass(frozen=True)
class ProbeSample:
    """A single labelled marker that the probe knows how to identify."""

    id: str
    marker: str
    filename: str
    line_number: int
    expected_plugins: Tuple[str, ...]
    is_negative: bool
    secret_hash: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProbeSample':
        try:
            sample_id = str(data['id'])
            marker = str(data['marker'])
            expected_plugins = tuple(str(name) for name in data['expected_plugins'])
        except (KeyError, TypeError) as e:
            raise RecoveryProbeError(
                f'Probe sample {data!r} is missing a required field ({e}).',
            )

        filename = str(data.get('filename', ''))
        line_number = int(data.get('line_number', 0))
        is_negative = bool(data.get('is_negative', False))
        if not expected_plugins:
            raise RecoveryProbeError(
                f'Probe sample {sample_id!r} names no plugins to hold accountable.',
            )
        secret_hash = str(
            data.get('hashed_secret') or PotentialSecret.hash_secret(marker),
        )

        return cls(
            id=sample_id,
            marker=marker,
            filename=filename,
            line_number=line_number,
            expected_plugins=expected_plugins,
            is_negative=is_negative,
            secret_hash=secret_hash,
        )


@dataclass
class ProbeManifest:
    """The parsed contents of a probe manifest."""

    version: str
    samples: Tuple[ProbeSample, ...]
    plugins_used: List[Dict[str, Any]] = field(default_factory=list)
    root: str = ''

    @property
    def sample_files(self) -> Tuple[str, ...]:
        return tuple(
            sorted({
                sample.filename
                for sample in self.samples
                if sample.filename
            }),
        )

    @property
    def expected_plugin_names(self) -> Tuple[str, ...]:
        return tuple(
            sorted({
                plugin_name
                for sample in self.samples
                for plugin_name in sample.expected_plugins
            }),
        )

    def get_sample(self, secret_hash: str) -> Optional[ProbeSample]:
        for sample in self.samples:
            if sample.secret_hash == secret_hash:
                return sample

        return None


def load_probe_manifest(filename: str) -> ProbeManifest:
    """
    :raises: RecoveryProbeError
    """
    try:
        with open(filename) as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        raise RecoveryProbeError(f'Unable to read probe manifest {filename!r}: {e}')

    if not isinstance(data, dict) or 'samples' not in data:
        raise RecoveryProbeError(
            f'Probe manifest {filename!r} needs a top-level samples list.',
        )

    probe_root = os.path.dirname(os.path.abspath(filename))
    try:
        samples = tuple(
            ProbeSample.from_dict(sample_data)
            for sample_data in data['samples']
        )
    except RecoveryProbeError:
        raise
    except TypeError as e:
        raise RecoveryProbeError(
            f'Probe manifest {filename!r} has malformed samples: {e}',
        )

    sample_ids = [sample.id for sample in samples]
    if len(sample_ids) != len(set(sample_ids)):
        raise RecoveryProbeError(
            f'Probe manifest {filename!r} contains duplicate sample ids.',
        )

    plugins_used = data.get('plugins_used', [])
    if not isinstance(plugins_used, list):
        raise RecoveryProbeError(
            f'Probe manifest {filename!r} has a malformed plugins_used section.',
        )

    return ProbeManifest(
        version=str(data.get('version', '1.0.0')),
        samples=samples,
        plugins_used=list(plugins_used),
        root=probe_root,
    )


@dataclass(frozen=True)
class PluginDetection:
    """A marker hash observed by a plugin during the recovery scan."""

    plugin_classname: str
    secret_hash: str


@dataclass
class PluginAccounting:
    """Per-plugin tally against the identified probe samples."""

    plugin_classname: str
    expected_positive: int = 0
    exclusive_positive: int = 0
    shared_positive: int = 0
    detected_positive: int = 0
    missed_positive: int = 0
    expected_negative: int = 0
    ignored_negative: int = 0
    flagged_negative: int = 0
    sample_ids: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.missed_positive and not self.flagged_negative

    @property
    def failure_reason(self) -> Optional[str]:
        reasons = []
        if self.missed_positive:
            reasons.append(f'missed {self.missed_positive} positive sample(s)')
        if self.flagged_negative:
            reasons.append(f'flagged {self.flagged_negative} negative sample(s)')
        if not reasons:
            return None

        return f'{self.plugin_classname} {" and ".join(reasons)}'

    def json(self) -> Dict[str, Any]:
        return {
            'expected-positive': self.expected_positive,
            'exclusive-positive': self.exclusive_positive,
            'shared-positive': self.shared_positive,
            'detected-positive': self.detected_positive,
            'missed-positive': self.missed_positive,
            'expected-negative': self.expected_negative,
            'ignored-negative': self.ignored_negative,
            'flagged-negative': self.flagged_negative,
            'sample-ids': self.sample_ids,
            'passed': self.passed,
        }

    def __str__(self) -> str:
        return (
            f'  {self.plugin_classname}:\n'
            f'    Positives: {self.detected_positive}/{self.expected_positive} detected '
            f'(exclusive: {self.exclusive_positive}, shared: {self.shared_positive}, '
            f'missed: {self.missed_positive})\n'
            f'    Negatives: {self.ignored_negative}/{self.expected_negative} correctly '
            f'ignored (flagged: {self.flagged_negative})\n'
            f'    Samples: {", ".join(self.sample_ids)}\n'
            f'    Verdict: {"PASS" if self.passed else "FAIL"}\n'
        )


@dataclass
class RecoveryReport:
    """The per-plugin verdict of a recovery probe run."""

    manifest_version: str
    plugins: Tuple[PluginAccounting, ...]
    failures: List[str] = field(default_factory=list)
    comparison_baseline: Optional[str] = None
    comparison_only: bool = False

    @property
    def passed(self) -> bool:
        return not self.failures and not self.comparison_only

    def json(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            'manifest-version': self.manifest_version,
            'passed': self.passed,
            'plugins': {
                plugin.plugin_classname: plugin.json()
                for plugin in self.plugins
            },
            'failures': list(self.failures),
        }
        if self.comparison_baseline is not None:
            output['comparison-baseline'] = self.comparison_baseline
            output['comparison-only'] = self.comparison_only
        return output

    def __str__(self) -> str:
        lines = ['Recovery probe report', '===================', '']
        if self.comparison_baseline is not None:
            lines.append(
                f'Comparison baseline (not eligible for release): {self.comparison_baseline}',
            )
            lines.append('')
        for plugin in self.plugins:
            lines.append(str(plugin))
        if self.failures:
            lines.append('Failures:')
            lines.extend(f'  - {reason}' for reason in self.failures)
        else:
            lines.append('All plugins accounted for every probe sample.')
        lines.append(f'Overall verdict: {"PASS" if self.passed else "FAIL"}')
        return '\n'.join(lines)


class ProbeAccounting:
    """Reconciles observed detections with the labelled probe samples."""

    def __init__(self, manifest: ProbeManifest) -> None:
        self.manifest = manifest
        self._samples_by_hash = {
            sample.secret_hash: sample
            for sample in manifest.samples
        }
        self._detected_hashes_by_plugin: Dict[str, Set[str]] = {}

    def record_detection(self, detection: PluginDetection) -> None:
        sample = self._samples_by_hash.get(detection.secret_hash)
        if sample is None:
            # Only detections that correspond to an identified probe sample count:
            # anything else is unrelated repository noise.
            return
        self._detected_hashes_by_plugin.setdefault(
            detection.plugin_classname, set(),
        ).add(detection.secret_hash)

    def evaluate_plugin(self, plugin_classname: str) -> PluginAccounting:
        accounting = PluginAccounting(plugin_classname=plugin_classname)
        detected = self._detected_hashes_by_plugin.get(plugin_classname, set())

        for sample in self.manifest.samples:
            if plugin_classname not in sample.expected_plugins:
                continue

            accounting.sample_ids.append(sample.id)
            if sample.is_negative:
                accounting.expected_negative += 1
                if sample.secret_hash in detected:
                    accounting.flagged_negative += 1
                else:
                    accounting.ignored_negative += 1
            else:
                accounting.expected_positive += 1
                if len(sample.expected_plugins) == 1:
                    accounting.exclusive_positive += 1
                else:
                    accounting.shared_positive += 1

                if sample.secret_hash in detected:
                    accounting.detected_positive += 1
                else:
                    accounting.missed_positive += 1

        return accounting


def evaluate_recovery(
    manifest: ProbeManifest,
    detections: 'Generator[PluginDetection, None, None]',
) -> RecoveryReport:
    accounting = ProbeAccounting(manifest)
    for detection in detections:
        accounting.record_detection(detection)

    plugin_results = [
        accounting.evaluate_plugin(plugin_classname)
        for plugin_classname in manifest.expected_plugin_names
    ]
    report = RecoveryReport(
        manifest_version=manifest.version,
        plugins=tuple(plugin_results),
    )
    report.failures.extend(
        reason
        for plugin in plugin_results
        if (reason := plugin.failure_reason) is not None
    )
    return report


def _load_historical_baseline(filename: str) -> SecretsCollection:
    try:
        return get_baseline_from_file(filename)
    except (InvalidBaselineError, OSError, KeyError, ValueError):
        raise RecoveryProbeError(f'Unable to read comparison baseline {filename!r}.')


def _detections_from_baseline(
    manifest: ProbeManifest,
    collection: SecretsCollection,
) -> Generator[PluginDetection, None, None]:
    sample_hashes = {sample.secret_hash for sample in manifest.samples}
    for file_secrets in collection.data.values():
        for secret in file_secrets:
            if secret.secret_hash not in sample_hashes:
                continue
            yield PluginDetection(
                plugin_classname=_classname_for_secret_type(secret.type),
                secret_hash=secret.secret_hash,
            )


def compare_historical_baseline(probe_path: str, baseline_filename: str) -> RecoveryReport:
    manifest = load_probe_manifest(probe_path)
    plugin_config = [
        {
            'name': plugin['classname'],
            'path': (
                'file://'
                + os.path.abspath(os.path.join(manifest.root, plugin['path']))
            ),
        }
        for plugin in manifest.plugins_used
    ]
    with transient_settings({'plugins_used': plugin_config}):
        get_mapping_from_secret_type_to_class.cache_clear()
        collection = _load_historical_baseline(baseline_filename)
        report = evaluate_recovery(
            manifest,
            _detections_from_baseline(manifest, collection),
        )
    report.comparison_baseline = baseline_filename
    report.comparison_only = True
    return report


def run_recovery_probe(probe_path: str) -> RecoveryReport:
    manifest = load_probe_manifest(probe_path)
    plugin_config = [
        {
            'name': plugin['classname'],
            'path': (
                'file://'
                + os.path.abspath(os.path.join(manifest.root, plugin['path']))
            ),
        }
        for plugin in manifest.plugins_used
    ]
    with transient_settings({'plugins_used': plugin_config}):
        get_mapping_from_secret_type_to_class.cache_clear()
        registered = _registered_plugin_classnames()
        report = evaluate_recovery(manifest, _scan_probe_samples(manifest))

    missing = [
        classname
        for classname in manifest.expected_plugin_names
        if classname not in registered
    ]
    for classname in missing:
        report.failures.append(
            f'{classname} did not run: it is absent from the active plugin set.',
        )

    return report


def _registered_plugin_classnames() -> Set[str]:
    return {
        plugin_class.__name__
        for plugin_class in get_mapping_from_secret_type_to_class().values()
    }


def _scan_probe_samples(
    manifest: ProbeManifest,
) -> Generator[PluginDetection, None, None]:
    for relative_path in manifest.sample_files:
        for secret in scan_file(os.path.join(manifest.root, relative_path)):
            yield PluginDetection(
                plugin_classname=_classname_for_secret_type(secret.type),
                secret_hash=secret.secret_hash,
            )


def _classname_for_secret_type(secret_type: str) -> str:
    try:
        return get_mapping_from_secret_type_to_class()[secret_type].__name__
    except KeyError:
        return secret_type
