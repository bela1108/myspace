from detect_secrets.closure.model import ReceiptStatus
from detect_secrets.closure.proof import BlockedReason
from detect_secrets.closure.proof import resolve_grounded
from tests.closure.conftest import make_receipt


def always_valid(receipt):
    return True


def never_valid(receipt):
    return False


def test_standalone_approved_receipt_is_grounded():
    resolution = resolve_grounded([make_receipt('RT-1')], always_valid)
    assert resolution.grounded == frozenset({'RT-1'})
    assert resolution.blocked == {}


def test_citation_chain_grounds_from_the_root():
    receipts = [
        make_receipt('RT-1'),
        make_receipt('RT-2', based_on='RT-1'),
        make_receipt('RT-3', based_on='RT-2'),
    ]
    resolution = resolve_grounded(receipts, always_valid)
    assert resolution.grounded == frozenset({'RT-1', 'RT-2', 'RT-3'})


def test_revoked_receipt_is_blocked_and_blocks_its_dependents():
    receipts = [
        make_receipt('RT-1', status=ReceiptStatus.REVOKED),
        make_receipt('RT-2', based_on='RT-1'),
    ]
    resolution = resolve_grounded(receipts, always_valid)
    assert resolution.grounded == frozenset()
    assert resolution.blocked['RT-1'] is BlockedReason.NOT_APPROVED
    assert resolution.blocked['RT-2'] is BlockedReason.UNPROVEN_REFERENCE


def test_receipt_failing_validation_is_blocked():
    resolution = resolve_grounded([make_receipt('RT-1')], never_valid)
    assert resolution.grounded == frozenset()
    assert resolution.blocked['RT-1'] is BlockedReason.FAILED_VALIDATION


def test_unknown_reference_is_blocked():
    resolution = resolve_grounded([make_receipt('RT-1', based_on='RT-404')], always_valid)
    assert resolution.grounded == frozenset()
    assert resolution.blocked['RT-1'] is BlockedReason.UNKNOWN_REFERENCE


def test_cycle_produces_no_proof():
    receipts = [
        make_receipt('RT-1', based_on='RT-2'),
        make_receipt('RT-2', based_on='RT-1'),
    ]
    resolution = resolve_grounded(receipts, always_valid)
    assert resolution.grounded == frozenset()
    assert resolution.blocked['RT-1'] is BlockedReason.CYCLIC_REFERENCE
    assert resolution.blocked['RT-2'] is BlockedReason.CYCLIC_REFERENCE


def test_cycle_gains_nothing_from_extra_citations():
    # RT-3 cites into a cycle: the cycle cannot vouch for it either.
    receipts = [
        make_receipt('RT-1', based_on='RT-2'),
        make_receipt('RT-2', based_on='RT-1'),
        make_receipt('RT-3', based_on='RT-1'),
    ]
    resolution = resolve_grounded(receipts, always_valid)
    assert resolution.grounded == frozenset()
    assert resolution.blocked['RT-3'] is BlockedReason.CYCLIC_REFERENCE


def test_cycle_next_to_grounded_chain_does_not_leak_proof():
    receipts = [
        make_receipt('RT-1'),
        make_receipt('RT-2', based_on='RT-1'),
        make_receipt('RT-3', based_on='RT-4'),
        make_receipt('RT-4', based_on='RT-3'),
    ]
    resolution = resolve_grounded(receipts, always_valid)
    assert resolution.grounded == frozenset({'RT-1', 'RT-2'})
    assert resolution.blocked['RT-3'] is BlockedReason.CYCLIC_REFERENCE
    assert resolution.blocked['RT-4'] is BlockedReason.CYCLIC_REFERENCE
