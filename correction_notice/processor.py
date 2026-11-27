"""Determine correction-notice recipients from local partial signatures.

The processor reads only STIX objects handed to it (the local history) and
the local ``x-delivery-receipt`` objects.  It never reaches out to a feed:
the receipts are synthetic local data.
"""

from dataclasses import dataclass, field

import stix2
from stix2 import MemoryStore, new_version, parse

from .custom_types import RecipientDecision
from .fixtures import (
    CHANGED_SECTION,
    DECISION_IDS,
    EXPLANATION_ID,
    INDICATOR_ID,
    MARKING_ID,
    NO_SECTION_SIGNED,
    NOTICE_ID,
    T_CORRECTION,
)

REASON_INCLUDED = "signed-changed-section"
REASON_MISSING_SECTION = "missing-changed-section-signature"
REASON_NOT_SIGNED = "no-signature-on-file"


@dataclass
class RecipientScope:
    """Result of evaluating the partial-signature list."""

    included: list  # recipients that must receive the correction
    excluded: list  # recipients that must not, each with a reason

    @property
    def included_refs(self):
        return [item["recipient_ref"] for item in self.included]

    @property
    def excluded_refs(self):
        return [item["recipient_ref"] for item in self.excluded]


@dataclass
class CorrectionResult:
    """Everything produced when the correction is processed."""

    scope: RecipientScope
    corrected_indicator: object
    correction_notice: object
    extended_explanation: object
    restriction_marking: object
    decisions: list = field(default_factory=list)

    def as_bundle(self):
        """Bundle the new objects plus the retained restriction marking."""
        objects = [
            self.corrected_indicator,
            self.correction_notice,
            self.extended_explanation,
            self.restriction_marking,
            *self.decisions,
        ]
        return stix2.v21.Bundle(
            id="bundle--01234567-0000-4000-8000-0000000000f1",
            objects=objects,
            allow_custom=True,
        )


def load_history(bundle_data):
    """Parse a history bundle (dict or JSON string) into a MemoryStore.

    Custom types are registered by importing :mod:`correction_notice` first,
    so the local receipt SDOs parse into typed objects rather than dicts.
    """
    bundle = parse(bundle_data, allow_custom=True)

    store = MemoryStore()
    for obj in bundle.objects:
        store.add(obj)
    return store


def determine_recipient_scope(store, changed_section=CHANGED_SECTION):
    """Decide who must receive the correction using receipts only.

    Rule: a recipient is included only when its local receipt shows it
    signed for the section that changed.  Every other recipient is excluded
    with an explicit reason derived from the same receipt list.
    """
    receipts = [
        obj for obj in store.query()
        if obj.type == "x-delivery-receipt"
    ]

    included = []
    excluded = []
    for receipt in sorted(receipts, key=lambda obj: obj.id):
        recipient_ref = receipt.x_recipient_ref
        signed_sections = list(receipt.get("x_signed_sections", []) or [])
        effective_sections = [
            section for section in signed_sections
            if section != NO_SECTION_SIGNED
        ]
        base = {
            "recipient_ref": recipient_ref,
            "receipt_ref": receipt.id,
            # The sentinel is kept verbatim so the same receipt list drives
            # both the decision and the "why not" explanation.
            "signed_sections": signed_sections,
        }
        if not receipt.x_signed:
            excluded.append({
                **base,
                "reason": REASON_NOT_SIGNED,
                "explanation": (
                    "No signed receipt is on file, so no notice of any "
                    "section was delivered; a correction cannot be sent."
                ),
            })
        elif changed_section not in signed_sections:
            excluded.append({
                **base,
                "reason": REASON_MISSING_SECTION,
                "explanation": (
                    f"Only signed for {effective_sections or 'no sections'}; "
                    f"the corrected part ({changed_section}) was never "
                    "received, so no correction notice is required."
                ),
            })
        else:
            included.append({
                **base,
                "reason": REASON_INCLUDED,
                "explanation": (
                    f"Signed for {changed_section}, the part being "
                    "corrected; the correction notice must be delivered."
                ),
            })

    return RecipientScope(included=included, excluded=excluded)


def process_correction(store, correction_timestamp=T_CORRECTION):
    """Build the correction objects and preserve restriction/extension state.

    The explanation note is treated as expired at ``correction_timestamp``:
    a new version records the extension while keeping the original deadline
    and restriction context.  The section-B granular marking is carried over
    verbatim onto the corrected indicator.
    """
    scope = determine_recipient_scope(store)

    indicator = store.get(INDICATOR_ID)
    notice = store.get(NOTICE_ID)
    explanation = store.get(EXPLANATION_ID)
    restriction = store.get(MARKING_ID)

    corrected_indicator = new_version(
        indicator,
        modified=correction_timestamp,
        name="Corrected indicator (sections A and B)",
        description="Section A content after correction.",
        pattern="[file:hashes.MD5 = '0cc175b9c0f1b6a831c399e269772661']",
        valid_from=correction_timestamp,
        x_section_a_content="section-a: corrected indicator value",
        # x_section_b_content and its granular marking are untouched so the
        # non-disclosure restriction survives the correction.
        granular_markings=list(indicator.get("granular_markings", [])),
        allow_custom=True,
    )

    correction_notice = new_version(
        notice,
        modified=correction_timestamp,
        name="Correction notice for section A",
        description=(
            "Corrects section-a of the original indicator. Delivered only "
            "to recipients whose local receipt shows they signed for "
            "section-a. Section-b remains under non-disclosure."
        ),
        published=correction_timestamp,
        object_refs=[INDICATOR_ID],
        x_corrects_section=CHANGED_SECTION,
        x_target_recipient_refs=scope.included_refs,
        x_restricted_section_refs=[MARKING_ID],
        allow_custom=True,
    )

    extended_explanation = new_version(
        explanation,
        modified=correction_timestamp,
        abstract="Section B non-disclosure explanation (extended)",
        content=(
            "The previous explanation reached its x_valid_until deadline. "
            "It is extended pending review; the section-b non-disclosure "
            "restriction remains in force."
        ),
        object_refs=[INDICATOR_ID],
        x_valid_until=explanation.x_valid_until,
        x_explanation_state="extended",
        x_extended_at=correction_timestamp,
        object_marking_refs=[MARKING_ID],
        allow_custom=True,
    )

    decisions = [
        _decision(scope_item, "included", correction_timestamp, notice.id)
        for scope_item in scope.included
    ] + [
        _decision(scope_item, "excluded", correction_timestamp, notice.id)
        for scope_item in scope.excluded
    ]

    result = CorrectionResult(
        scope=scope,
        corrected_indicator=corrected_indicator,
        correction_notice=correction_notice,
        extended_explanation=extended_explanation,
        restriction_marking=restriction,
        decisions=decisions,
    )
    return result


def _decision(scope_item, decision, timestamp, notice_ref):
    return RecipientDecision(
        id=DECISION_IDS[scope_item["recipient_ref"]],
        created=timestamp,
        modified=timestamp,
        x_recipient_ref=scope_item["recipient_ref"],
        x_notice_ref=notice_ref,
        x_decision=decision,
        x_reason=scope_item["reason"],
        x_explanation=scope_item["explanation"],
        x_signed_sections=scope_item["signed_sections"],
    )
