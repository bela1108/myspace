"""
Per-family effectiveness metrics for the offline plugin evaluation.

The evaluation answers three questions about every plugin on every file family
of a synthetic labeled dataset:

* **incremental findings** -- how many labeled secrets does this plugin add on
  top of every plugin ranked ahead of it?
* **duplicate coverage** -- how often does the plugin re-report a truth label
  that earlier plugins already covered?
* **unmeasurable share** -- which labeled secrets can no plugin in the suite
  detect at all?

Families are derived from the labeled files (see :class:`LabeledFile`), so a
global score can improve while a single family regresses: the family report
keeps those per-family numbers visible.
"""
from dataclasses import dataclass
from dataclasses import field
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

from .dataset import LabeledDataset
from .dataset import LabeledFile
from .dataset import TruthLabel
from .matching import Family
from .matching import match_dataset
from .matching import MatchResult
from .engine import run_all
from .matching import PluginName
from .matching import TruthId


@dataclass
class PluginFamilyMetrics:
    """Effectiveness of one plugin against the labels of one file family."""

    plugin: PluginName
    family: Family
    labels: int = 0
    found: int = 0
    missed: int = 0
    duplicate_hits: int = 0
    false_positives: int = 0
    incremental: int = 0

    @property
    def coverage(self) -> float:
        return self.found / self.labels if self.labels else 0.0

    @property
    def precision(self) -> float:
        judged = self.found + self.false_positives
        return self.found / judged if judged else 0.0

    @property
    def duplicate_rate(self) -> float:
        return self.duplicate_hits / self.found if self.found else 0.0

    def as_row(self) -> Dict[str, object]:
        return {
            'plugin': self.plugin,
            'family': self.family,
            'labels': self.labels,
            'found': self.found,
            'incremental': self.incremental,
            'duplicate_hits': self.duplicate_hits,
            'duplicate_rate': round(self.duplicate_rate, 4),
            'false_positives': self.false_positives,
            'missed': self.missed,
            'coverage': round(self.coverage, 4),
            'precision': round(self.precision, 4),
        }


@dataclass
class FamilySummary:
    """Suite-wide numbers for one file family, plus unmeasurable labels."""

    family: Family
    labels: int = 0
    covered: int = 0
    unmeasurable: int = 0
    unmeasurable_ids: List[TruthId] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        return self.covered / self.labels if self.labels else 0.0

    def as_row(self) -> Dict[str, object]:
        return {
            'family': self.family,
            'labels': self.labels,
            'covered': self.covered,
            'unmeasurable': self.unmeasurable,
            'unmeasurable_ids': list(self.unmeasurable_ids),
            'coverage': round(self.coverage, 4),
        }

@dataclass
class PluginFailure:
    """A plugin that could not be evaluated, kept separate from healthy ones."""

    plugin: PluginName
    error: str
    families: List[Family] = field(default_factory=list)

    def as_row(self) -> Dict[str, object]:
        return {
            'plugin': self.plugin,
            'error': self.error,
            'families': list(self.families),
        }

@dataclass
class ConfigurationComparison:
    """Side-by-side per-family coverage of two plugin configurations."""

    family: Family
    baseline_coverage: float
    candidate_coverage: float
    baseline_found: int
    candidate_found: int
    labels: int

    @property
    def delta(self) -> float:
        return self.candidate_coverage - self.baseline_coverage

    @property
    def regressed(self) -> bool:
        return self.delta < 0

    def as_row(self) -> Dict[str, object]:
        return {
            'family': self.family,
            'labels': self.labels,
            'baseline_found': self.baseline_found,
            'candidate_found': self.candidate_found,
            'baseline_coverage': round(self.baseline_coverage, 4),
            'candidate_coverage': round(self.candidate_coverage, 4),
            'delta': round(self.delta, 4),
            'regressed': self.regressed,
        }

@dataclass
class EvaluationReport:
    """Full, JSON-serializable result of an offline evaluation run."""

    dataset: str
    plugin_order: List[PluginName]
    plugin_family_metrics: List[PluginFamilyMetrics]
    family_summaries: List[FamilySummary]
    failures: List[PluginFailure]
    comparisons: List[ConfigurationComparison] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            'dataset': self.dataset,
            'plugin_order': list(self.plugin_order),
            'plugin_family_metrics': [row.as_row() for row in self.plugin_family_metrics],
            'family_summaries': [row.as_row() for row in self.family_summaries],
            'failures': [row.as_row() for row in self.failures],
            'comparisons': [row.as_row() for row in self.comparisons],
        }

def _family_of(labeled_file: LabeledFile) -> Family:
    return labeled_file.family

def _families(dataset: LabeledDataset) -> List[Family]:
    families = {_family_of(labeled_file) for labeled_file in dataset.files}
    return sorted(families)

def _labels_by_family(
    dataset: LabeledDataset,
) -> Dict[Family, List[TruthLabel]]:
    output: Dict[Family, List[TruthLabel]] = {}
    for labeled_file in dataset.files:
        output.setdefault(_family_of(labeled_file), []).extend(labeled_file.labels)
    return output

def evaluate(
    dataset: LabeledDataset,
    match_result: MatchResult,
    plugin_order: Optional[Sequence[PluginName]] = None,
) -> EvaluationReport:
    """Build per-family metrics from a dataset and its plugin match result.

    :param plugin_order: ranking used for the incremental column. Earlier
        plugins take credit for shared labels. Defaults to ranking plugins by
        total labels found (descending), then by name for stable output.
    """
    families = _families(dataset)
    labels_by_family = _labels_by_family(dataset)

    ranked = list(plugin_order) if plugin_order else _rank_plugins(match_result)
    healthy = {name for name in match_result.metrics if name in ranked}
    ranked = [name for name in ranked if name in healthy]
    ranked.extend(sorted(healthy.difference(ranked)))

    rows: List[PluginFamilyMetrics] = []
    family_covered: Dict[Family, set] = {family: set() for family in families}
    for family in families:
        labels = labels_by_family.get(family, [])
        label_ids = {label.identifier for label in labels}
        claimed: set = set()

        for plugin in ranked:
            metrics = match_result.metrics[plugin].by_family.get(family)
            found_ids = set(metrics.found_labels) if metrics else set()
            duplicate_ids = set(metrics.duplicate_labels) if metrics else set()
            fp_count = len(metrics.false_positives) if metrics else 0

            incremental_ids = found_ids.difference(claimed)
            claimed.update(found_ids)
            family_covered[family].update(found_ids)

            rows.append(
                PluginFamilyMetrics(
                    plugin=plugin,
                    family=family,
                    labels=len(label_ids),
                    found=len(found_ids),
                    missed=len(label_ids.difference(found_ids)),
                    duplicate_hits=len(duplicate_ids),
                    false_positives=fp_count,
                    incremental=len(incremental_ids),
                ),
            )

    summaries = _build_family_summaries(dataset, families, labels_by_family, family_covered)
    failures = _build_failures(match_result, families)

    return EvaluationReport(
        dataset=dataset.name,
        plugin_order=ranked,
        plugin_family_metrics=rows,
        family_summaries=summaries,
        failures=failures,
    )

def compare_configurations(
    dataset: LabeledDataset,
    baseline: MatchResult,
    candidate: MatchResult,
) -> List[ConfigurationComparison]:
    """Per-family coverage comparison, surfacing families that regressed."""
    labels_by_family = _labels_by_family(dataset)
    rows: List[ConfigurationComparison] = []
    for family in sorted(labels_by_family):
        label_ids = {label.identifier for label in labels_by_family[family]}

        baseline_found = _covered_labels(baseline, family)
        candidate_found = _covered_labels(candidate, family)
        total = len(label_ids)

        rows.append(
            ConfigurationComparison(
                family=family,
                labels=total,
                baseline_found=len(baseline_found),
                candidate_found=len(candidate_found),
                baseline_coverage=len(baseline_found) / total if total else 0.0,
                candidate_coverage=len(candidate_found) / total if total else 0.0,
            ),
        )
    return rows

def _covered_labels(match_result: MatchResult, family: Family) -> set:
    covered: set = set()
    for per_family in match_result.metrics.values():
        metrics = per_family.by_family.get(family)
        if metrics:
            covered.update(metrics.found_labels)
    return covered

def _rank_plugins(match_result: MatchResult) -> List[PluginName]:
    def score(plugin: PluginName) -> Tuple[int, PluginName]:
        total_found = sum(
            len(metrics.found_labels)
            for metrics in match_result.metrics[plugin].by_family.values()
        )
        return (-total_found, plugin)

    return sorted(match_result.metrics, key=score)

def _build_family_summaries(
    dataset: LabeledDataset,
    families: List[Family],
    labels_by_family: Dict[Family, List[TruthLabel]],
    family_covered: Dict[Family, set],
) -> List[FamilySummary]:
    summaries: List[FamilySummary] = []
    for family in families:
        label_ids = {label.identifier for label in labels_by_family.get(family, [])}
        unmeasurable = sorted(label_ids.difference(family_covered[family]))
        summaries.append(
            FamilySummary(
                family=family,
                labels=len(label_ids),
                covered=len(label_ids.intersection(family_covered[family])),
                unmeasurable=len(unmeasurable),
                unmeasurable_ids=unmeasurable,
            ),
        )
    return summaries

def _build_failures(match_result: MatchResult, families: List[Family]) -> List[PluginFailure]:
    failures: List[PluginFailure] = []
    for plugin, error in sorted(match_result.failures.items()):
        failures.append(
            PluginFailure(
                plugin=plugin,
                error=error,
                families=list(families),
            ),
        )
    return failures



def evaluate_dataset(
    dataset: LabeledDataset,
    plugin_specs: Sequence[Dict[str, object]],
    plugin_order: Optional[Sequence[PluginName]] = None,
) -> EvaluationReport:
    """Run the plugin specs, then evaluate them in one convenience call."""
    plugin_hits, failures = run_all(dataset, plugin_specs)
    match_result = match_dataset(dataset, plugin_hits, failures)
    return evaluate(dataset, match_result, plugin_order)
