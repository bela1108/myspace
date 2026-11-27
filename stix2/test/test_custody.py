import pytest

from stix2.custody import (
    SharedOccupancy,
    reconcile_custody,
)
from stix2.v21 import Relationship


OBJECT_ID = "report--84023ef7-5f96-4920-978f-0ec406c75162"
TEAM_A_ID = "identity--11111111-1111-4111-8111-111111111111"


def borrow(loan_id, team, selectors):
    return {
        "type": "relationship",
        "id": "relationship--%s" % loan_id,
        "relationship_type": "x-borrows",
        "source_ref": "identity--%s" % team,
        "target_ref": OBJECT_ID,
        "x_loan_id": loan_id,
        "x_team": team,
        "x_selectors": selectors,
    }


def receipt(receipt_id, loan_id, team, selectors=None, whole_object=False):
    record = {
        "type": "relationship",
        "id": "relationship--receipt-%s" % receipt_id,
        "relationship_type": "x-return-receipt",
        "source_ref": "identity--%s" % team,
        "target_ref": OBJECT_ID,
        "x_receipt_id": receipt_id,
        "x_loan_id": loan_id,
        "x_team": team,
        "x_whole_object": whole_object,
    }
    if selectors is not None:
        record["x_selectors"] = selectors
    return record


def test_overlapping_loans_settle_against_each_loan_scope():
    report = reconcile_custody([
        borrow("loan-a", "team-a", ["summary", "contacts", "attachments[0]"]),
        borrow("loan-b", "team-b", ["contacts", "attachments[0]", "attachments[1]"]),
        borrow("loan-c", "team-c", ["summary", "attachments[1]"]),
        receipt("receipt-a", "loan-a", "team-a", whole_object=True),
        receipt("receipt-b", "loan-b", "team-b", ["contacts", "attachments[0]"]),
    ])

    assert report.loans["loan-a"].returned is True
    assert report.loans["loan-b"].outstanding_selectors == frozenset(["attachments[1]"])
    assert report.loans["loan-c"].outstanding_selectors == frozenset([
        "summary", "attachments[1]",
    ])
    assert report.outstanding[OBJECT_ID] == frozenset(["summary", "attachments[1]"])
    assert report.shared_occupancy == [
        SharedOccupancy(OBJECT_ID, "attachments[1]", frozenset(["loan-b", "loan-c"])),
    ]


def test_whole_object_receipt_cannot_expand_approved_scope():
    report = reconcile_custody([
        borrow("loan-a", "team-a", ["summary"]),
        receipt("receipt-a", "loan-a", "team-a", ["summary", "contacts"]),
    ])

    settlement = report.loans["loan-a"]
    assert settlement.returned_selectors == frozenset(["summary"])
    assert settlement.outstanding_selectors == frozenset()
    assert settlement.out_of_scope_selectors == frozenset(["contacts"])
    assert report.out_of_scope_returns == [{
        "receipt_id": "receipt-a",
        "relationship_id": "relationship--receipt-receipt-a",
        "loan_id": "loan-a",
        "object_ref": OBJECT_ID,
        "selectors": frozenset(["contacts"]),
    }]


def test_whole_object_receipt_only_returns_approved_selectors():
    report = reconcile_custody([
        borrow("loan-a", "team-a", ["summary"]),
        receipt("receipt-a", "loan-a", "team-a", whole_object=True),
    ])

    assert report.loans["loan-a"].returned_selectors == frozenset(["summary"])
    assert report.loans["loan-a"].returned is True
    assert report.outstanding == {}


def test_duplicate_receipt_is_idempotent_for_other_teams():
    first_acknowledgement = receipt(
        "receipt-a", "loan-a", "team-a", ["summary", "contacts"],
    )
    report = reconcile_custody([
        borrow("loan-a", "team-a", ["summary", "contacts"]),
        borrow("loan-b", "team-b", ["contacts", "attachments[0]"]),
        first_acknowledgement,
        dict(first_acknowledgement),
    ])

    assert report.duplicate_receipt_ids == frozenset(["receipt-a"])
    assert report.loans["loan-a"].returned is True
    assert report.loans["loan-b"].outstanding_selectors == frozenset([
        "contacts", "attachments[0]",
    ])
    assert report.outstanding[OBJECT_ID] == frozenset(["contacts", "attachments[0]"])


def test_bundle_input_is_processed_offline():
    report = reconcile_custody({
        "type": "bundle",
        "id": "bundle--1322d67a-c4f0-4d17-9f88-37c9bd9f3409",
        "objects": [
            borrow("loan-a", "team-a", ["summary"]),
            receipt("receipt-a", "loan-a", "team-a", ["summary"]),
        ],
    })

    assert report.loans["loan-a"].processed_receipt_ids == frozenset(["receipt-a"])
    assert report.receipts == {"receipt-a": "loan-a"}
    serialized = report.as_dict()
    assert serialized["loans"]["loan-a"]["processed_receipt_ids"] == frozenset([
        "receipt-a",
    ])


def test_stix_relationship_objects_are_accepted():
    loan = Relationship(
        relationship_type="x-borrows",
        source_ref=TEAM_A_ID,
        target_ref=OBJECT_ID,
        x_loan_id="loan-a",
        x_team="team-a",
        x_selectors=["summary", "contacts"],
        allow_custom=True,
    )
    signed_return = Relationship(
        relationship_type="x-return-receipt",
        source_ref=TEAM_A_ID,
        target_ref=OBJECT_ID,
        x_receipt_id="receipt-a",
        x_loan_id="loan-a",
        x_team="team-a",
        x_whole_object=True,
        allow_custom=True,
    )

    report = reconcile_custody([loan, signed_return])

    assert report.loans["loan-a"].returned is True
    assert report.loans["loan-a"].returned_selectors == frozenset([
        "summary", "contacts",
    ])


def test_strict_mode_rejects_return_outside_approved_scope():
    with pytest.raises(ValueError, match="outside loan"):
        reconcile_custody([
            borrow("loan-a", "team-a", ["summary"]),
            receipt("receipt-a", "loan-a", "team-a", ["contacts"]),
        ], strict=True)


def test_hyphenated_custom_properties_are_accepted():
    report = reconcile_custody([
        {
            "type": "relationship",
            "id": "relationship--loan-a",
            "relationship_type": "x-borrows",
            "source_ref": "identity--11111111-1111-4111-8111-111111111111",
            "target_ref": OBJECT_ID,
            "x-loan-id": "loan-a",
            "x-team": "team-a",
            "x-fragments": ["summary"],
        },
        {
            "type": "relationship",
            "id": "relationship--receipt-a",
            "relationship_type": "x-return-receipt",
            "source_ref": "identity--11111111-1111-4111-8111-111111111111",
            "target_ref": OBJECT_ID,
            "x-receipt-id": "receipt-a",
            "x-loan-id": "loan-a",
            "x-team": "team-a",
            "x-fragments": ["summary"],
        },
    ])

    assert report.loans["loan-a"].returned is True


def test_custom_receipt_object_type_is_accepted():
    report = reconcile_custody([
        {
            "type": "x-borrows",
            "id": "x-borrows--11111111-1111-4111-8111-111111111111",
            "target_ref": OBJECT_ID,
            "x_loan_id": "loan-a",
            "x_team": "team-a",
            "x_selectors": ["summary"],
        },
        {
            "type": "x-return-receipt",
            "id": "x-return-receipt--11111111-1111-4111-8111-111111111111",
            "target_ref": OBJECT_ID,
            "x_receipt_id": "receipt-a",
            "x_loan_id": "loan-a",
            "x_team": "team-a",
            "x_selectors": ["summary"],
        },
    ])

    assert report.loans["loan-a"].returned is True
