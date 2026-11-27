"""Partial-signature driven correction notices over a local STIX history.

The scenario modelled here:

* An original notice (a STIX ``report``) published two sections about one
  object: section A (the part that later changes) and section B (a part that
  stays restricted and must never be disclosed to some recipients).
* Each recipient only signed for the sections it actually received.  The
  signatures are *local* ``x-delivery-receipt`` SDOs - synthetic data, never
  imported from a real feed.
* An explanatory note carrying a validity deadline expires.  When processing
  the correction, recipients that signed for section A must receive a
  correction notice; recipients that did not must not, and the reason has to
  be derivable from the same partial-signature list.
* The non-disclosure restriction on section B and the explanation's extension
  state must be preserved on the resulting objects.
"""

from .custom_types import DeliveryReceipt, RecipientDecision
from .processor import (
    CorrectionResult,
    determine_recipient_scope,
    process_correction,
)

__all__ = [
    "CorrectionResult",
    "DeliveryReceipt",
    "RecipientDecision",
    "determine_recipient_scope",
    "process_correction",
]
