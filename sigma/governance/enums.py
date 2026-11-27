from __future__ import annotations

from enum import Enum, auto

from sigma.rule.attributes import EnumLowercaseStringMixin


class EvidenceKind(EnumLowercaseStringMixin, Enum):
    """Category of governance-controlled evidence.

    Each kind carries its own independent purpose allowlist inside the
    :class:`~sigma.governance.gate.PurposeGate`.
    """

    SAMPLE_SOURCE = auto()
    MATCH_RESULT = auto()
    DUAL_CONFIRMATION = auto()


class SamplePurpose(EnumLowercaseStringMixin, Enum):
    """Intended usage of a sample or derived evidence.

    Training samples may only back training/development work. Formal coverage
    sign-off (rule release evidence) requires an explicit formal-purpose grant.
    """

    TRAINING = auto()
    FORMAL = auto()
