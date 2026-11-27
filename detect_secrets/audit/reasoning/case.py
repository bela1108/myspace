"""Mutable audit case holding competing, mutually exclusive explanations.

A :class:`ReasoningCase` persists the full reasoning state: evidence items and
their withdrawal status, candidate explanations with their own rationales,
declared exclusion relations, findings and (optionally) the final explanation
an auditor committed to once more evidence arrived.
"""
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple

from .models import Evidence
from .models import Exclusion
from .models import Explanation
from .models import Finding
from .models import FindingEvaluation
from .models import FindingStatus
from .models import InvalidReasoningError
from .models import ReasoningSchemaVersion


class ReasoningCase:
    """Coordinates the records of one multi-explanation audit."""

    def __init__(
        self,
        case_id: str,
        evidence: Optional[Sequence[Evidence]] = None,
        explanations: Optional[Sequence[Explanation]] = None,
        exclusions: Optional[Sequence[Exclusion]] = None,
        findings: Optional[Sequence[Finding]] = None,
        selected_explanation_id: Optional[str] = None,
    ) -> None:
        self.case_id = case_id
        self._evidence: Dict[str, Evidence] = {item.id: item for item in (evidence or [])}
        self._explanations: Dict[str, Explanation] = {
            item.id: item
            for item in (explanations or [])
        }
        self._exclusions: Dict[Tuple[str, str], Exclusion] = {
            item.pair(): item
            for item in (exclusions or [])
        }
        self._findings: Dict[str, Finding] = {item.id: item for item in (findings or [])}
        self.selected_explanation_id = selected_explanation_id
        self.validate()

    # -- record management -------------------------------------------------

    @property
    def evidence(self) -> Dict[str, Evidence]:
        return dict(self._evidence)

    @property
    def explanations(self) -> Dict[str, Explanation]:
        return dict(self._explanations)

    @property
    def exclusions(self) -> List[Exclusion]:
        return list(self._exclusions.values())

    @property
    def findings(self) -> Dict[str, Finding]:
        return dict(self._findings)

    def add_evidence(self, evidence: Evidence) -> None:
        self._evidence[evidence.id] = evidence

    def add_explanation(self, explanation: Explanation) -> None:
        self.validate_explanation(explanation)
        self._explanations[explanation.id] = explanation

    def add_exclusion(self, exclusion: Exclusion) -> None:
        if exclusion.left_id not in self._explanations:
            raise InvalidReasoningError(
                f'Unknown explanation in exclusion: {exclusion.left_id!r}.',
            )
        if exclusion.right_id not in self._explanations:
            raise InvalidReasoningError(
                f'Unknown explanation in exclusion: {exclusion.right_id!r}.',
            )
        if exclusion.left_id == exclusion.right_id:
            raise InvalidReasoningError('An explanation cannot exclude itself.')

        self._exclusions[exclusion.pair()] = exclusion

    def add_finding(self, finding: Finding) -> None:
        for explanation_id in finding.supporting_explanation_ids:
            if explanation_id not in self._explanations:
                raise InvalidReasoningError(
                    f'Unknown explanation supporting finding {finding.id!r}: '
                    f'{explanation_id!r}.',
                )
        self._findings[finding.id] = finding

    # -- evidence lifecycle ------------------------------------------------

    def withdraw_evidence(self, evidence_id: str) -> None:
        """Marks evidence as withdrawn and restores unknown state as needed.

        Explanations that relied solely on withdrawn evidence stop being
        viable. If the auditor's chosen explanation loses viability, the final
        commitment is cleared so the case is genuinely unknown again.
        """
        if evidence_id not in self._evidence:
            raise InvalidReasoningError(f'Unknown evidence: {evidence_id!r}.')

        current = self._evidence[evidence_id]
        if current.active:
            self._evidence[evidence_id] = Evidence(
                id=current.id,
                reason=current.reason,
                active=False,
            )

        if (
            self.selected_explanation_id is not None
            and self.selected_explanation_id not in self.viable_explanation_ids()
        ):
            self.selected_explanation_id = None

    def restore_evidence(self, evidence_id: str) -> None:
        """Re-activates previously withdrawn evidence."""
        if evidence_id not in self._evidence:
            raise InvalidReasoningError(f'Unknown evidence: {evidence_id!r}.')

        current = self._evidence[evidence_id]
        if not current.active:
            self._evidence[evidence_id] = Evidence(
                id=current.id,
                reason=current.reason,
                active=True,
            )

    # -- final commitment --------------------------------------------------

    def select_explanation(self, explanation_id: str) -> None:
        """Commits to a final interpretation once enough evidence exists."""
        if explanation_id not in self._explanations:
            raise InvalidReasoningError(f'Unknown explanation: {explanation_id!r}.')
        if explanation_id not in self.viable_explanation_ids():
            raise InvalidReasoningError(
                f'Explanation {explanation_id!r} is not viable with the active evidence.',
            )
        self.selected_explanation_id = explanation_id

    def clear_selection(self) -> None:
        self.selected_explanation_id = None

    # -- consistency analysis ----------------------------------------------

    def validate_explanation(self, explanation: Explanation) -> None:
        for evidence_id in explanation.evidence_ids:
            if evidence_id not in self._evidence:
                raise InvalidReasoningError(
                    f'Unknown evidence backing explanation {explanation.id!r}: {evidence_id!r}.',
                )

    def validate(self) -> None:
        """Verifies that every stored reference points at a known record."""
        for explanation in self._explanations.values():
            self.validate_explanation(explanation)

        for exclusion in self._exclusions.values():
            if exclusion.left_id == exclusion.right_id:
                raise InvalidReasoningError('An explanation cannot exclude itself.')
            for explanation_id in (exclusion.left_id, exclusion.right_id):
                if explanation_id not in self._explanations:
                    raise InvalidReasoningError(
                        f'Unknown explanation in exclusion: {explanation_id!r}.',
                    )

        for finding in self._findings.values():
            for explanation_id in finding.supporting_explanation_ids:
                if explanation_id not in self._explanations:
                    raise InvalidReasoningError(
                        f'Unknown explanation supporting finding {finding.id!r}: '
                        f'{explanation_id!r}.',
                    )

        if (
            self.selected_explanation_id is not None
            and self.selected_explanation_id not in self._explanations
        ):
            raise InvalidReasoningError(
                f'Unknown selected explanation: {self.selected_explanation_id!r}.',
            )

    def active_evidence_ids(self) -> Set[str]:
        return {item.id for item in self._evidence.values() if item.active}

    def viable_explanation_ids(self) -> Set[str]:
        """Explanations whose supporting evidence has not been withdrawn."""
        active_evidence = self.active_evidence_ids()
        return {
            explanation.id
            for explanation in self._explanations.values()
            if set(explanation.evidence_ids).issubset(active_evidence)
        }

    def exclusion_graph(self) -> Dict[str, Set[str]]:
        """Adjacency map of mutually exclusive, currently viable explanations."""
        viable = self.viable_explanation_ids()
        graph: Dict[str, Set[str]] = {
            explanation_id: set()
            for explanation_id in viable
        }
        for exclusion in self._exclusions.values():
            if exclusion.left_id in viable and exclusion.right_id in viable:
                graph[exclusion.left_id].add(exclusion.right_id)
                graph[exclusion.right_id].add(exclusion.left_id)
        return graph

    def consistent_worlds(self) -> List[frozenset]:
        """All maximal sets of viable explanations containing no exclusion.

        Each returned world is one self-consistent interpretation that the
        currently active evidence still permits. The worlds are maximal: any
        viable explanation left out is excluded by one that was kept.
        """
        graph = self.exclusion_graph()
        nodes = set(graph)
        if not nodes:
            # No viable explanation means no self-consistent interpretation
            # remains available; an empty case (no explanations at all) still
            # has a single, trivially consistent empty world.
            return [] if self._explanations else [frozenset()]
        worlds: List[frozenset] = []

        def enumerate_worlds(
            candidates: Set[str],
            forbidden: Set[str],
            chosen: Set[str],
        ) -> None:
            if not candidates and not forbidden:
                worlds.append(frozenset(chosen))
                return

            remaining = set(candidates)
            excluded = set(forbidden)
            for node in sorted(remaining):
                neighbors = graph[node]
                enumerate_worlds(
                    remaining - ({node} | neighbors),
                    excluded - neighbors,
                    chosen | {node},
                )
                remaining = remaining - {node}
                excluded = excluded | {node}

        enumerate_worlds(nodes, set(), set())
        return worlds

    def evaluate_findings(self) -> List[FindingEvaluation]:
        """Registers only findings with common support across every world.

        A finding registered here must hold no matter which self-consistent
        interpretation is eventually adopted. When two explanations each allow
        the finding but no single explanation survives every world, the finding
        stays pending. With no viable world, every finding is pending as well.
        """
        worlds = self.consistent_worlds()
        evaluations: List[FindingEvaluation] = []

        for finding in self._findings.values():
            supporting_worlds = tuple(
                world
                for world in worlds
                if finding.support & world
            )
            common_support = (
                set.intersection(*(
                    finding.support & world
                    for world in supporting_worlds
                ))
                if supporting_worlds
                else set()
            )
            is_registered = bool(worlds) and len(supporting_worlds) == len(worlds) and \
                bool(common_support)
            evaluations.append(
                FindingEvaluation(
                    finding=finding,
                    status=FindingStatus.REGISTERED if is_registered else FindingStatus.PENDING,
                    supporting_worlds=supporting_worlds,
                    world_count=len(worlds),
                ),
            )

        return evaluations

    def registered_findings(self) -> List[Finding]:
        return [
            evaluation.finding
            for evaluation in self.evaluate_findings()
            if evaluation.status == FindingStatus.REGISTERED
        ]

    def export(self) -> Dict[str, Any]:
        """Machine-readable export, keeping non-robust findings pending."""
        return {
            'case_id': self.case_id,
            'selected_explanation_id': self.selected_explanation_id,
            'findings': [
                evaluation.json()
                for evaluation in self.evaluate_findings()
            ],
        }

    # -- serialization -----------------------------------------------------

    def json(self) -> Dict[str, Any]:
        return {
            'version': ReasoningSchemaVersion.v1.value,
            'case_id': self.case_id,
            'evidence': [item.json() for item in self._evidence.values()],
            'explanations': [item.json() for item in self._explanations.values()],
            'exclusions': [item.json() for item in self._exclusions.values()],
            'findings': [item.json() for item in self._findings.values()],
            'selected_explanation_id': self.selected_explanation_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReasoningCase':
        try:
            case = cls(
                case_id=str(data['case_id']),
                evidence=[Evidence.from_dict(item) for item in data.get('evidence', [])],
                explanations=[
                    Explanation.from_dict(item)
                    for item in data.get('explanations', [])
                ],
                exclusions=[
                    Exclusion.from_dict(item)
                    for item in data.get('exclusions', [])
                ],
                findings=[Finding.from_dict(item) for item in data.get('findings', [])],
                selected_explanation_id=(
                    str(data['selected_explanation_id'])
                    if data.get('selected_explanation_id') is not None
                    else None
                ),
            )
        except KeyError as e:
            raise InvalidReasoningError(f'Missing required field: {e.args[0]!r}.') from e
        return case
