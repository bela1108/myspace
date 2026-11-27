"""Value types used to keep competing explanations of a synthetic sample.

An audit may gather more than one plausible explanation for the same sample.
Each explanation keeps the evidence it relies on and its own rationale. Two
explanations can be declared mutually exclusive (they cannot both hold at the
same time). A :class:`Finding` is registered only when it survives every set of
self-consistent explanations; otherwise its export stays pending.
"""
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from typing import Any
from typing import Dict
from typing import Set
from typing import Tuple


class InvalidReasoningError(ValueError):
    """Raised when a reasoning baseline references unknown records."""


class ReasoningSchemaVersion(Enum):
    """Supported on-disk versions of the reasoning baseline."""

    v1 = '1.0'


class FindingStatus(Enum):
    """Export disposition of a finding."""

    REGISTERED = 'registered'
    PENDING = 'pending'


@dataclass(frozen=True)
class Evidence:
    """A single piece of evidence backing one or more explanations.

    Withdrawing evidence flips ``active`` to ``False`` without deleting the
    record, so the audit trail (and any later restoration) is preserved.
    """

    id: str
    reason: str
    active: bool = True

    def json(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'reason': self.reason,
            'active': self.active,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Evidence':
        return cls(
            id=str(data['id']),
            reason=str(data['reason']),
            active=bool(data.get('active', True)),
        )


@dataclass(frozen=True)
class Explanation:
    """One plausible interpretation of the sample.

    :param evidence_ids: the evidence that would need to hold for this
        explanation. An explanation with no supporting evidence is always
        viable until it is excluded by another viable explanation.
    """

    id: str
    reason: str
    evidence_ids: Tuple[str, ...] = ()

    def json(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'reason': self.reason,
            'evidence_ids': list(self.evidence_ids),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Explanation':
        return cls(
            id=str(data['id']),
            reason=str(data['reason']),
            evidence_ids=tuple(str(item) for item in data.get('evidence_ids', [])),
        )


@dataclass(frozen=True)
class Exclusion:
    """Declares that two explanations cannot hold together.

    The exclusion is symmetric: storing either ordering means the pair cannot
    coexist. ``reason`` records why an auditor judged them incompatible.
    """

    left_id: str
    right_id: str
    reason: str

    def pair(self) -> Tuple[str, str]:
        return tuple(sorted((self.left_id, self.right_id)))  # type: ignore[return-value]

    def json(self) -> Dict[str, Any]:
        return {
            'left_id': self.left_id,
            'right_id': self.right_id,
            'reason': self.reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Exclusion':
        return cls(
            left_id=str(data['left_id']),
            right_id=str(data['right_id']),
            reason=str(data['reason']),
        )


@dataclass(frozen=True)
class Finding:
    """An audit finding and the explanations that independently support it.

    Each supporting explanation is an independent route to the same finding.
    The finding is only registered when at least one of these explanations is
    present in every self-consistent set of explanations.
    """

    id: str
    reason: str
    supporting_explanation_ids: Tuple[str, ...] = ()

    @property
    def support(self) -> Set[str]:
        return set(self.supporting_explanation_ids)

    def json(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'reason': self.reason,
            'supporting_explanation_ids': list(self.supporting_explanation_ids),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        return cls(
            id=str(data['id']),
            reason=str(data['reason']),
            supporting_explanation_ids=tuple(
                str(item)
                for item in data.get('supporting_explanation_ids', [])
            ),
        )


@dataclass(frozen=True)
class FindingEvaluation:
    """Result of evaluating a finding across all self-consistent worlds."""

    finding: Finding
    status: FindingStatus
    supporting_worlds: Tuple[frozenset, ...]
    world_count: int = field(default=0)

    def json(self) -> Dict[str, Any]:
        return {
            'id': self.finding.id,
            'reason': self.finding.reason,
            'status': self.status.value,
            'supporting_explanation_ids': list(self.finding.supporting_explanation_ids),
            'supporting_worlds': [sorted(world) for world in self.supporting_worlds],
            'world_count': self.world_count,
        }
