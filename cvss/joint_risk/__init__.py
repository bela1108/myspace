"""
Joint risk statement support.

Two response teams keep their own, separately approved stop-ship policies while
owing the customer one unified risk statement. This package builds a
compatibility grid over a small, mutually agreed CVSS vector domain:

* every cell is scored with the real CVSS implementation shipped in this
  library (no hand-entered scores are trusted);
* a cell is a joint commitment only when both approved policies take the same
  action on the recomputed score, otherwise each team's individually valid
  position is retained and the lack of joint evidence is shown explicitly;
* internal responsibility labels never reach the customer-facing view;
* the agreed joint scope is order-independent: loading the two teams in
  reverse order must not widen, shrink, or relabel a single cell.
"""

from .compatibility import (
    JointCompatibility,
    JointRiskError,
    PolicyValidationError,
    StopShipPolicy,
    VectorDomainError,
    find_recomputable_disagreement,
    verify_reverse_loading,
)

__all__ = [
    "JointCompatibility",
    "JointRiskError",
    "PolicyValidationError",
    "StopShipPolicy",
    "VectorDomainError",
    "find_recomputable_disagreement",
    "verify_reverse_loading",
]
