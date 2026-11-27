"""Offline reconciliation for fragment-level STIX object custody."""

from dataclasses import dataclass, field


BORROW_RELATIONSHIP_TYPES = frozenset((
    "x-borrows", "x-loan", "x-loan-of",
))
RETURN_RELATIONSHIP_TYPES = frozenset((
    "x-returns", "x-return-receipt", "x-signed-return",
))
WHOLE_OBJECT_MARKERS = frozenset(("*", "[*]", "$"))

_BORROW_KEYS = (
    "x_loan_id", "x_borrow_id", "x_borrow_request_id", "x_request_id",
    "x-loan-id", "x-borrow-id", "x-borrow-request-id", "x-request-id",
    "loan_id", "borrow_id", "loan-id", "borrow-id",
)
_SELECTOR_KEYS = (
    "x_selectors", "x_fragments", "x_parts", "x_selector", "x_fragment",
    "x-selectors", "x-fragments", "x-parts", "x-selector", "x-fragment",
    "selectors", "fragments", "parts",
)
_RECEIPT_KEYS = (
    "x_receipt_id", "x_return_receipt_id", "x_receipt", "receipt_id",
    "x-receipt-id", "x-return-receipt-id", "receipt-id", "return-receipt-id",
)


@dataclass(frozen=True)
class LoanSettlement:
    """Return status for the scope approved by one borrow relationship."""

    loan_id: str
    relationship_id: str
    object_ref: str
    team: str
    approved_selectors: frozenset
    returned_selectors: frozenset
    outstanding_selectors: frozenset
    returned: bool
    processed_receipt_ids: frozenset = field(default_factory=frozenset)
    duplicate_receipt_ids: frozenset = field(default_factory=frozenset)
    out_of_scope_selectors: frozenset = field(default_factory=frozenset)


@dataclass(frozen=True)
class SharedOccupancy:
    """Approved fragments currently occupied by more than one loan."""

    object_ref: str
    selector: str
    loan_ids: frozenset


@dataclass(frozen=True)
class CustodyRiskReport:
    """Loan-level and object-level views produced without network access."""

    loans: dict
    outstanding: dict
    shared_occupancy: list
    receipts: dict
    duplicate_receipt_ids: frozenset
    out_of_scope_returns: list
    unprocessed_receipt_ids: frozenset

    def as_dict(self):
        """Return the report as a dictionary of native STIX-like values."""
        return {
            "loans": {
                loan_id: settlement.__dict__.copy()
                for loan_id, settlement in self.loans.items()
            },
            "outstanding": self.outstanding,
            "shared_occupancy": [
                occupancy.__dict__.copy()
                for occupancy in self.shared_occupancy
            ],
            "receipts": self.receipts,
            "duplicate_receipt_ids": self.duplicate_receipt_ids,
            "out_of_scope_returns": self.out_of_scope_returns,
            "unprocessed_receipt_ids": self.unprocessed_receipt_ids,
        }


@dataclass(frozen=True)
class _Receipt:
    receipt_id: str
    relationship_id: str
    loan_id: str
    object_ref: str
    team: str
    selectors: frozenset
    whole_object: bool


def reconcile_custody(stix_data, strict=False):
    """Reconcile borrow approvals against signed return receipts.

    A receipt may claim a whole STIX object, but only selectors intersecting
    that receipt's approved loan can settle that loan. Returning a selector
    never enlarges the approved scope.

    Args:
        stix_data: A STIX bundle/relationship, equivalent mappings, or an
            iterable of those values.
        strict: If True, raise ValueError when a receipt cannot be matched to
            a loan or claims selectors outside that loan. Otherwise record the
            condition in the returned risk report.

    Returns:
        CustodyRiskReport containing per-loan settlements, outstanding object
        fragments, shared outstanding fragments, and receipt risks.
    """
    relationships = list(_iter_relationships(stix_data))
    loans = _build_loans(relationships)
    raw_receipts = [_receipt_from_relationship(item) for item in relationships]
    receipts = [item for item in raw_receipts if item is not None]

    processed_receipts = {}
    duplicate_receipt_ids = set()
    out_of_scope_returns = []
    unprocessed_receipt_ids = set()
    returned_by_loan = {loan_id: set() for loan_id in loans}
    processed_by_loan = {loan_id: set() for loan_id in loans}

    for receipt in receipts:
        if receipt.receipt_id and receipt.receipt_id in processed_receipts:
            duplicate_receipt_ids.add(receipt.receipt_id)
            continue

        loan = _match_loan(receipt, loans)
        if loan is None:
            unprocessed_receipt_ids.add(receipt.receipt_id or receipt.relationship_id)
            if strict:
                raise ValueError(
                    "Return receipt does not match an approved loan: %s"
                    % (receipt.receipt_id or receipt.relationship_id),
                )
            continue

        approved = loan["selectors"]
        if receipt.whole_object or not receipt.selectors:
            effective_selectors = set(approved)
            rejected_selectors = frozenset()
        else:
            effective_selectors = set(receipt.selectors) & approved
            rejected_selectors = frozenset(receipt.selectors - approved)

        if rejected_selectors:
            out_of_scope_returns.append({
                "receipt_id": receipt.receipt_id,
                "relationship_id": receipt.relationship_id,
                "loan_id": loan["loan_id"],
                "object_ref": loan["object_ref"],
                "selectors": rejected_selectors,
            })
            if strict:
                raise ValueError(
                    "Return receipt %s includes selectors outside loan %s"
                    % (receipt.receipt_id or receipt.relationship_id, loan["loan_id"]),
                )

        returned_by_loan[loan["loan_id"]].update(effective_selectors)
        processed_by_loan[loan["loan_id"]].add(
            receipt.receipt_id or receipt.relationship_id,
        )
        if receipt.receipt_id:
            processed_receipts[receipt.receipt_id] = loan["loan_id"]

    settlements = {}
    outstanding = {}
    for loan_id, loan in loans.items():
        approved = frozenset(loan["selectors"])
        returned = frozenset(returned_by_loan[loan_id])
        outstanding_selectors = approved - returned
        settlement = LoanSettlement(
            loan_id=loan_id,
            relationship_id=loan["relationship_id"],
            object_ref=loan["object_ref"],
            team=loan["team"],
            approved_selectors=approved,
            returned_selectors=returned,
            outstanding_selectors=outstanding_selectors,
            returned=not outstanding_selectors,
            processed_receipt_ids=frozenset(processed_by_loan[loan_id]),
            duplicate_receipt_ids=frozenset(
                receipt_id
                for receipt_id in duplicate_receipt_ids
                if processed_receipts.get(receipt_id) == loan_id
            ),
            out_of_scope_selectors=frozenset(
                selector
                for item in out_of_scope_returns
                if item["loan_id"] == loan_id
                for selector in item["selectors"]
            ),
        )
        settlements[loan_id] = settlement
        outstanding.setdefault(loan["object_ref"], set()).update(outstanding_selectors)

    return CustodyRiskReport(
        loans=settlements,
        outstanding={
            object_ref: frozenset(selectors)
            for object_ref, selectors in sorted(outstanding.items())
            if selectors
        },
        shared_occupancy=_shared_occupancy(settlements.values()),
        receipts=processed_receipts,
        duplicate_receipt_ids=frozenset(duplicate_receipt_ids),
        out_of_scope_returns=out_of_scope_returns,
        unprocessed_receipt_ids=frozenset(unprocessed_receipt_ids),
    )


reconcile_loans = reconcile_custody
settle_loans = reconcile_custody

def _iter_relationships(value):
    if value is None:
        return
    if hasattr(value, "get"):
        value_type = value.get("type")
        if value_type == "bundle":
            for item in value.get("objects", []):
                yield from _iter_relationships(item)
        elif (
            value_type == "relationship"
            or value_type in BORROW_RELATIONSHIP_TYPES | RETURN_RELATIONSHIP_TYPES
            or value.get("relationship_type")
        ):
            yield value
        return
    if isinstance(value, str) or not hasattr(value, "__iter__"):
        return
    for item in value:
        yield from _iter_relationships(item)


def _build_loans(relationships):
    loans = {}
    for relationship in relationships:
        relationship_type = relationship.get("relationship_type") or relationship.get("type")
        if relationship_type not in BORROW_RELATIONSHIP_TYPES:
            continue

        object_ref = _object_ref(relationship)
        selectors = _selector_set(relationship)
        if not object_ref or not selectors:
            continue

        relationship_id = relationship.get("id")
        loan_id = _first_value(relationship, _BORROW_KEYS) or relationship_id
        if not loan_id:
            continue
        if loan_id in loans:
            raise ValueError("Duplicate borrow identifier: %s" % loan_id)

        loans[loan_id] = {
            "loan_id": loan_id,
            "relationship_id": relationship_id,
            "object_ref": object_ref,
            "team": _team(relationship),
            "selectors": selectors,
        }
    return loans


def _receipt_from_relationship(relationship):
    relationship_type = relationship.get("relationship_type") or relationship.get("type")
    if relationship_type not in RETURN_RELATIONSHIP_TYPES:
        return None

    receipt_id = _first_value(relationship, _RECEIPT_KEYS) or relationship.get("id")
    selectors, whole_object = _receipt_selectors(relationship)
    return _Receipt(
        receipt_id=receipt_id,
        relationship_id=relationship.get("id"),
        loan_id=_first_value(relationship, _BORROW_KEYS),
        object_ref=_object_ref(relationship),
        team=_team(relationship),
        selectors=selectors,
        whole_object=whole_object,
    )


def _match_loan(receipt, loans):
    if receipt.loan_id and receipt.loan_id in loans:
        loan = loans[receipt.loan_id]
        if receipt.object_ref and loan["object_ref"] != receipt.object_ref:
            return None
        if receipt.team and loan["team"] != receipt.team:
            return None
        return loan

    candidates = [
        loan for loan in loans.values()
        if loan["object_ref"] == receipt.object_ref
        and (not receipt.team or loan["team"] == receipt.team)
    ]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _shared_occupancy(settlements):
    occupancy = {}
    for settlement in settlements:
        for selector in settlement.outstanding_selectors:
            key = (settlement.object_ref, selector)
            occupancy.setdefault(key, set()).add(settlement.loan_id)

    return [
        SharedOccupancy(
            object_ref=object_ref,
            selector=selector,
            loan_ids=frozenset(loan_ids),
        )
        for (object_ref, selector), loan_ids in sorted(occupancy.items())
        if len(loan_ids) > 1
    ]


def _selector_set(relationship):
    values = []
    for key in _SELECTOR_KEYS:
        values.extend(_as_list(_value(relationship, key)))
    return frozenset(
        str(value) for value in values
        if value is not None and str(value) not in WHOLE_OBJECT_MARKERS
    )


def _receipt_selectors(relationship):
    whole_object = bool(
        _value(relationship, "x_whole_object")
        or _value(relationship, "x-whole-object")
        or _value(relationship, "whole_object"),
    )
    values = []
    for key in _SELECTOR_KEYS:
        values.extend(_as_list(_value(relationship, key)))

    selectors = set()
    for value in values:
        text_value = str(value)
        if text_value in WHOLE_OBJECT_MARKERS:
            whole_object = True
        else:
            selectors.add(text_value)
    return frozenset(selectors), whole_object


def _first_value(mapping, keys):
    for key in keys:
        value = _value(mapping, key)
        if value not in (None, "", []):
            return value
    return None


def _value(mapping, key):
    if key in mapping:
        return mapping[key]
    return mapping.get(key.replace("_", "-"))


def _object_ref(relationship):
    explicit_ref = _first_value(relationship, (
        "object_ref", "x_object_ref", "x_object_id",
    ))
    if explicit_ref:
        return explicit_ref

    refs = ("target_ref", "source_ref")
    for key in refs:
        value = _value(relationship, key)
        if value and not str(value).startswith("identity--"):
            return value
    for key in refs:
        value = _value(relationship, key)
        if value:
            return value
    return None


def _team(relationship):
    return (
        _value(relationship, "x_team")
        or _value(relationship, "x_borrower")
        or _value(relationship, "x_holder")
        or next(
            (
                _value(relationship, key)
                for key in ("source_ref", "target_ref")
                if str(_value(relationship, key) or "").startswith("identity--")
            ),
            None,
        )
        or _value(relationship, "created_by_ref")
    )


def _as_list(value):
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(value)
    return (value,)
