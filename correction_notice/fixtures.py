"""Deterministic local STIX history used as the only input to the workflow.

Everything in this module is synthetic.  The receipt SDOs
(``x-delivery-receipt``) in particular are local fake acknowledgements; no
external feed or network source is consulted.
"""

import stix2

# Fixed timestamps so the generated bundle is byte-stable across runs.
T_ORIGINAL = "2026-10-01T08:00:00.000Z"
T_EXPLANATION_EXPIRY = "2026-11-27T00:00:00.000Z"
T_CORRECTION = "2026-11-28T09:00:00.000Z"

# Section identifiers shared by the notice and the local receipts.
SECTION_A = "section-a"  # the part that is corrected
SECTION_B = "section-b"  # the part that stays restricted
CHANGED_SECTION = SECTION_A
# Sentinel used because STIX forbids empty list-valued properties: it makes
# "signed for nothing" explicit and stable in the serialized receipts.
NO_SECTION_SIGNED = "section:none"

ISSUER_ID = "identity--01234567-0000-4000-8000-000000000001"
RECIPIENT_A_ID = "identity--01234567-0000-4000-8000-000000000010"
RECIPIENT_B_ID = "identity--01234567-0000-4000-8000-000000000011"
RECIPIENT_C_ID = "identity--01234567-0000-4000-8000-000000000012"
INDICATOR_ID = "indicator--01234567-0000-4000-8000-000000000020"
NOTICE_ID = "report--01234567-0000-4000-8000-000000000030"
MARKING_ID = "marking-definition--01234567-0000-4000-8000-000000000040"
EXPLANATION_ID = "note--01234567-0000-4000-8000-000000000050"
RECEIPT_A_ID = "x-delivery-receipt--01234567-0000-4000-8000-000000000060"
RECEIPT_B_ID = "x-delivery-receipt--01234567-0000-4000-8000-000000000061"
RECEIPT_C_ID = "x-delivery-receipt--01234567-0000-4000-8000-000000000062"
HISTORY_BUNDLE_ID = "bundle--01234567-0000-4000-8000-0000000000f0"
DECISION_IDS = {
    RECIPIENT_A_ID: "x-recipient-decision--01234567-0000-4000-8000-000000000070",
    RECIPIENT_B_ID: "x-recipient-decision--01234567-0000-4000-8000-000000000071",
    RECIPIENT_C_ID: "x-recipient-decision--01234567-0000-4000-8000-000000000072",
}


def build_history_bundle():
    """Build the pre-correction STIX bundle (history + local fake receipts)."""
    issuer = stix2.v21.Identity(
        id=ISSUER_ID,
        created=T_ORIGINAL,
        modified=T_ORIGINAL,
        name="Original Notice Issuer",
        identity_class="organization",
    )

    recipient_a = stix2.v21.Identity(
        id=RECIPIENT_A_ID,
        created=T_ORIGINAL,
        modified=T_ORIGINAL,
        name="Recipient Alpha",
        identity_class="organization",
    )
    recipient_b = stix2.v21.Identity(
        id=RECIPIENT_B_ID,
        created=T_ORIGINAL,
        modified=T_ORIGINAL,
        name="Recipient Bravo",
        identity_class="organization",
    )
    recipient_c = stix2.v21.Identity(
        id=RECIPIENT_C_ID,
        created=T_ORIGINAL,
        modified=T_ORIGINAL,
        name="Recipient Charlie",
        identity_class="organization",
    )

    # Restriction that must keep section B from being disclosed further.
    restriction = stix2.v21.MarkingDefinition(
        id=MARKING_ID,
        created=T_ORIGINAL,
        name="Section B non-disclosure",
        definition_type="statement",
        definition=stix2.v21.StatementMarking(
            "Disclosure of section-b content is prohibited; "
            "do not redistribute this part.",
        ),
    )

    # One object carrying two sections.  Section B lives in a custom property
    # and is pinned by a granular marking so the restriction is attached
    # directly to the field that must not be disclosed.
    indicator = stix2.v21.Indicator(
        id=INDICATOR_ID,
        created=T_ORIGINAL,
        modified=T_ORIGINAL,
        created_by_ref=ISSUER_ID,
        name="Original indicator (sections A and B)",
        description="Section A content of the original notice.",
        indicator_types=["malicious-activity"],
        pattern_type="stix",
        pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        valid_from=T_ORIGINAL,
        x_section_a_content="section-a: original indicator value",
        x_section_b_content="section-b: restricted handling detail",
        granular_markings=[
            stix2.v21.GranularMarking(
                marking_ref=MARKING_ID,
                selectors=["x_section_b_content"],
            ),
        ],
        allow_custom=True,
    )

    notice = stix2.v21.Report(
        id=NOTICE_ID,
        created=T_ORIGINAL,
        modified=T_ORIGINAL,
        created_by_ref=ISSUER_ID,
        name="Original two-section notice",
        description=(
            "Publishes section-a and section-b of one indicator. "
            "Section B carries a non-disclosure restriction."
        ),
        report_types=["other"],
        published=T_ORIGINAL,
        object_refs=[INDICATOR_ID],
        x_notice_sections=[SECTION_A, SECTION_B],
        allow_custom=True,
    )

    # Explanation with an explicit deadline.  It is expired by the time the
    # correction is processed.
    explanation = stix2.v21.Note(
        id=EXPLANATION_ID,
        created=T_ORIGINAL,
        modified=T_ORIGINAL,
        created_by_ref=ISSUER_ID,
        abstract="Why section B is withheld from some recipients",
        content=(
            "Section B is under a non-disclosure restriction. This "
            "explanation is valid only until its x_valid_until deadline."
        ),
        object_refs=[INDICATOR_ID],
        x_valid_until=T_EXPLANATION_EXPIRY,
        allow_custom=True,
    )

    # Local fake receipts: who actually signed for which section.
    receipt_a = _receipt(
        RECEIPT_A_ID, RECIPIENT_A_ID, [SECTION_A], True,
    )
    receipt_b = _receipt(
        RECEIPT_B_ID, RECIPIENT_B_ID, [SECTION_B], True,
    )
    receipt_c = _receipt(
        RECEIPT_C_ID, RECIPIENT_C_ID, [NO_SECTION_SIGNED], False,
    )

    return stix2.v21.Bundle(
        id=HISTORY_BUNDLE_ID,
        objects=[
            issuer,
            recipient_a,
            recipient_b,
            recipient_c,
            restriction,
            indicator,
            notice,
            explanation,
            receipt_a,
            receipt_b,
            receipt_c,
        ],
        allow_custom=True,
    )


def _receipt(receipt_id, recipient_id, signed_sections, signed):
    # Imported here so importing the fixtures module registers the custom
    # types before any STIX object is constructed.
    from .custom_types import DeliveryReceipt

    return DeliveryReceipt(
        id=receipt_id,
        created=T_ORIGINAL,
        modified=T_ORIGINAL,
        x_recipient_ref=recipient_id,
        x_notice_ref=NOTICE_ID,
        x_signed_sections=signed_sections,
        x_signed=signed,
    )
