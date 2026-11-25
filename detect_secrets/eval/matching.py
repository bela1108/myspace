"""
Offline attribution of plugin findings to synthetic ground-truth labels.

One ground-truth secret may be reported by a plugin at several overlapping
positions, for example when a regex matches both a bare token and a quoted
super-string. Those findings all describe the same truth, so they are
attributed to exactly one TruthLabel and counted once towards discovery.
Every extra match on an already-attributed label is recorded as duplicate
coverage instead. Findings that match no label are false positives.
"""
from dataclasses import dataclass
from dataclasses import field
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from .dataset import LabeledDataset
from .dataset import TruthLabel

Family = str
PluginName = str
TruthId = str


@dataclass(frozen=True)
class Hit:
    """A single secret value observed from one plugin on one file."""

    plugin: PluginName
    path: str
    family: Family
    line_number: int
    value: str
    start: Optional[int] = None
    end: Optional[int] = None


@dataclass
class FamilyMatch:
    """Attributed findings of one plugin within one file family."""

    found_labels: Set[TruthId] = field(default_factory=set)
    duplicate_labels: Set[TruthId] = field(default_factory=set)
    false_positives: List[Hit] = field(default_factory=list)
    raw_hit_count: int = 0


@dataclass
class PluginMatchResult:
    """Per-plugin findings, broken down by file family."""

    plugin: PluginName
    by_family: Dict[Family, FamilyMatch] = field(default_factory=dict)


@dataclass
class MatchResult:
    """Attribution for every healthy plugin, plus isolated failures."""

    metrics: Dict[PluginName, PluginMatchResult] = field(default_factory=dict)
    failures: Dict[PluginName, str] = field(default_factory=dict)


def _spans_overlap(hit: Hit, truth: TruthLabel) -> bool:
    """Whether a hit sits on the labelled span of one truth.

    Character-span overlap is the rule: even partial overlap means the hit
    describes the same embedded secret, so overlapping positions never
    inflate discovery beyond the single owning truth.
    """
    if hit.start is None or hit.end is None:
        return False
    return hit.start < truth.end and hit.end > truth.start



def _attribute_hit(hit: Hit, truths_on_line: List[TruthLabel]) -> Optional[TruthId]:
    """Map one hit onto the first overlapping label on the same line."""
    for truth in truths_on_line:
        if hit.path != truth.path or hit.line_number != truth.line:
            continue
        if _spans_overlap(hit, truth):
            return truth.identifier
    return None


def match_dataset(
    dataset: LabeledDataset,
    plugin_hits: Dict[PluginName, List[Hit]],
    failures: Optional[Dict[PluginName, str]] = None,
) -> MatchResult:
    """Attribute every plugin hit to the labels of one synthetic dataset.

    Hits landing on overlapping positions of the same truth collapse into a
    single discovery; further hits on that truth become duplicate coverage.
    Hits without an overlapping label are false positives.
    """
    result = MatchResult()
    if failures:
        result.failures.update(failures)

    truths_by_file = {}
    for labeled_file in dataset.files:
        truths_by_file[labeled_file.path] = labeled_file.labels

    for plugin in sorted(plugin_hits):
        plugin_result = PluginMatchResult(plugin=plugin)
        seen_by_family: Dict[Family, Set[TruthId]] = {}

        for hit in plugin_hits[plugin]:
            family_match = plugin_result.by_family.setdefault(hit.family, FamilyMatch())
            family_match.raw_hit_count += 1
            truths = truths_by_file.get(hit.path, [])
            truth_id = _attribute_hit(hit, truths)

            if truth_id is None:
                family_match.false_positives.append(hit)
                continue

            discovered = seen_by_family.setdefault(hit.family, set())
            if truth_id in discovered:
                family_match.duplicate_labels.add(truth_id)
            else:
                discovered.add(truth_id)
                family_match.found_labels.add(truth_id)

        result.metrics[plugin] = plugin_result

    return result
