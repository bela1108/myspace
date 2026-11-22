import copy

import pytest

import stix2.v21
from stix2.canonicalization.Canonicalize import canonicalize
from stix2.retraction import (
    GAP_MISSING_PAYLOAD, NOTICE_RETRACT_DELIVERED, NOTICE_RETRACT_SUPERSEDED,
    DeliveryLedger, DeliveryRecord, RecipientGroup, RetractionError,
    build_retraction_receipts, verify_receipt,
)

REPORT_ID = 'report--2c2b1c1e-4e6a-4f0a-9a1a-0d1f0e2a3b4c'
OBS_GREEN_ID = 'observed-data--11111111-1111-4111-8111-111111111111'
OBS_RED_ID = 'observed-data--22222222-2222-4222-8222-222222222222'

T1 = '2026-01-01T00:00:00.000Z'
T2 = '2026-02-01T00:00:00.000Z'

ALL_TLP = [
    stix2.v21.TLP_WHITE.id,
    stix2.v21.TLP_GREEN.id,
    stix2.v21.TLP_AMBER.id,
    stix2.v21.TLP_RED.id,
]
EXTERNAL_TLP = ALL_TLP[:-1]


def _report(modified):
    return stix2.v21.Report(
        id=REPORT_ID,
        created=T1,
        modified=modified,
        published=T1,
        name='Externally shared assessment',
        report_types=['threat-report'],
        object_refs=[OBS_GREEN_ID, OBS_RED_ID],
        object_marking_refs=[stix2.v21.TLP_GREEN],
    )


def _observation(obs_id, marking):
    return stix2.v21.ObservedData(
        id=obs_id,
        created=T1,
        modified=T1,
        first_observed=T1,
        last_observed=T1,
        number_observed=1,
        object_refs=['ipv4-addr--33333333-3333-4333-8333-333333333333'],
        object_marking_refs=[marking],
    )


@pytest.fixture
def report_v1():
    return _report(T1)


@pytest.fixture
def report_v2():
    return _report(T2)


@pytest.fixture
def obs_green():
    return _observation(OBS_GREEN_ID, stix2.v21.TLP_GREEN)


@pytest.fixture
def obs_red():
    return _observation(OBS_RED_ID, stix2.v21.TLP_RED)


@pytest.fixture
def groups():
    return [
        RecipientGroup('internal', ALL_TLP),
        RecipientGroup('external', EXTERNAL_TLP),
        RecipientGroup('archive-partner', EXTERNAL_TLP),
    ]


@pytest.fixture
def ledger(groups, report_v1, report_v2, obs_green):
    return DeliveryLedger(
        groups,
        [
            DeliveryRecord.from_object('internal', report_v1),
            DeliveryRecord.from_object('internal', report_v2),
            DeliveryRecord.from_object('internal', obs_green),
            DeliveryRecord.from_object('external', report_v1),
            DeliveryRecord.from_object('external', report_v2),
            DeliveryRecord.from_object('external', obs_green),
            DeliveryRecord.from_object('archive-partner', report_v1),
        ],
    )


def _entry_ids(receipt, section):
    return {entry['object_id'] for entry in receipt[section]}


def test_receipts_only_for_groups_that_received_revoked_object(ledger):
    receipts = build_retraction_receipts(ledger, REPORT_ID, T2)
    assert set(receipts) == {'internal', 'external', 'archive-partner'}

    receipts = build_retraction_receipts(ledger, OBS_GREEN_ID, T1)
    assert set(receipts) == {'internal', 'external'}


def test_notice_kind_depends_on_delivered_version(ledger):
    receipts = build_retraction_receipts(ledger, REPORT_ID, T2)
    assert receipts['internal']['notice'] == NOTICE_RETRACT_DELIVERED
    assert receipts['external']['notice'] == NOTICE_RETRACT_DELIVERED
    # archive-partner only ever received the superseded v1
    assert receipts['archive-partner']['notice'] == NOTICE_RETRACT_SUPERSEDED
    versions = receipts['archive-partner']['delivered_versions']
    assert [v['modified'] for v in versions] == [T1]


def test_receipt_scoped_to_own_deliveries(ledger):
    receipts = build_retraction_receipts(ledger, REPORT_ID, T2)
    external = receipts['external']
    assert _entry_ids(external, 'delivered_versions') == {REPORT_ID}
    assert _entry_ids(external, 'context') == {OBS_GREEN_ID}
    # no trace of other groups or of undelivered objects
    canonical = canonicalize(external, utf8=False)
    assert 'internal' not in canonical
    assert OBS_RED_ID not in canonical
    assert OBS_RED_ID not in _entry_ids(external, 'context')


def test_marking_visibility_filters_misdelivered_records(
    ledger, groups, obs_red,
):
    before = build_retraction_receipts(ledger, REPORT_ID, T2)['external']
    # a TLP:RED object lands in the external batch's records by mistake
    ledger.add(DeliveryRecord.from_object('external', obs_red))
    after = build_retraction_receipts(ledger, REPORT_ID, T2)['external']
    assert _entry_ids(after, 'context') == _entry_ids(before, 'context')
    assert after['receipt_sha256'] == before['receipt_sha256']


def test_legacy_records_surface_forensic_gaps(ledger):
    ledger.add(
        DeliveryRecord(
            'external', REPORT_ID, '2025-12-01T00:00:00.000Z',
            markings=[stix2.v21.TLP_GREEN.id], payload=None,
        ),
    )
    gaps = ledger.forensic_gaps(group='external', object_id=REPORT_ID)
    assert len(gaps) == 1

    receipt = build_retraction_receipts(ledger, REPORT_ID, T2)['external']
    assert len(receipt['forensic_gaps']) == 1
    gap = receipt['forensic_gaps'][0]
    assert gap['object_id'] == REPORT_ID
    assert gap['reason'] == GAP_MISSING_PAYLOAD
    # the gap does not appear as a deliverable version
    assert len(receipt['delivered_versions']) == 2


def test_group_with_only_gap_records_still_gets_receipt(groups, report_v2):
    ledger = DeliveryLedger(groups)
    ledger.add(DeliveryRecord.from_object('external', report_v2))
    ledger.add(
        DeliveryRecord(
            'archive-partner', REPORT_ID, T1,
            markings=[stix2.v21.TLP_GREEN.id], payload=None,
        ),
    )
    receipts = build_retraction_receipts(ledger, REPORT_ID, T2)
    partner = receipts['archive-partner']
    assert partner['delivered_versions'] == []
    assert len(partner['forensic_gaps']) == 1
    assert partner['notice'] == NOTICE_RETRACT_SUPERSEDED


def test_verify_receipt_roundtrip(ledger):
    receipts = build_retraction_receipts(ledger, REPORT_ID, T2)
    for receipt in receipts.values():
        result = verify_receipt(receipt, ledger)
        assert result.ok, result.problems


def test_verify_receipt_detects_tampering(ledger):
    receipts = build_retraction_receipts(ledger, REPORT_ID, T2)
    tampered = copy.deepcopy(receipts['external'])
    tampered['notice'] = NOTICE_RETRACT_SUPERSEDED
    result = verify_receipt(tampered, ledger)
    assert not result.ok
    assert 'receipt-self-digest-invalid' in result.problems


def test_verify_receipt_rejects_cross_batch_leakage(ledger, obs_red):
    ledger.add(DeliveryRecord.from_object('internal', obs_red))
    receipts = build_retraction_receipts(ledger, REPORT_ID, T2)

    # an entry only ever delivered to the internal batch
    leaked = copy.deepcopy(receipts['external'])
    leaked['context'].append(
        copy.deepcopy(
            next(
                e for e in receipts['internal']['context']
                if e['object_id'] == OBS_RED_ID
            ),
        ),
    )
    result = verify_receipt(leaked, ledger)
    assert not result.ok
    assert any(
        p.startswith('entry-not-delivered-to-group') for p in result.problems
    )


def test_verify_receipt_rejects_non_visible_entries(ledger, obs_red):
    # misdelivered to external, but external may not see TLP:RED
    ledger.add(DeliveryRecord.from_object('external', obs_red))
    receipts = build_retraction_receipts(ledger, REPORT_ID, T2)
    forged = copy.deepcopy(receipts['external'])
    forged['context'].append({
        'object_id': OBS_RED_ID,
        'modified': T1,
        'payload_sha256': ledger.find('external', OBS_RED_ID, T1)
            .payload_digest(),
    })
    result = verify_receipt(forged, ledger)
    assert not result.ok
    assert any(
        p.startswith('entry-not-visible-to-group') for p in result.problems
    )


def test_verify_receipt_unknown_group(ledger):
    receipts = build_retraction_receipts(ledger, REPORT_ID, T2)
    forged = copy.deepcopy(receipts['external'])
    forged['group'] = 'no-such-group'
    result = verify_receipt(forged, ledger)
    assert not result.ok


def test_unknown_group_record_rejected(groups):
    ledger = DeliveryLedger(groups)
    with pytest.raises(RetractionError):
        ledger.add(
            DeliveryRecord('outsider', REPORT_ID, T1),
        )


def test_internal_only_observation_does_not_change_external_receipt(
    ledger, obs_red,
):
    """Regression: adding an internal-only observation to the ledger must
    not change anything visible in the external batch's retraction receipt.
    """
    before = build_retraction_receipts(ledger, REPORT_ID, T2)

    ledger.add(DeliveryRecord.from_object('internal', obs_red))

    after = build_retraction_receipts(ledger, REPORT_ID, T2)

    # the internal receipt now reflects the new observation
    assert OBS_RED_ID in _entry_ids(after['internal'], 'context')
    assert after['internal']['receipt_sha256'] != \
        before['internal']['receipt_sha256']

    # the external receipt is byte-for-byte unchanged
    assert canonicalize(after['external']) == canonicalize(before['external'])
    assert after['external']['receipt_sha256'] == \
        before['external']['receipt_sha256']
    assert OBS_RED_ID not in _entry_ids(after['external'], 'context')
    # and the archive-partner receipt is equally unaffected
    assert canonicalize(after['archive-partner']) == \
        canonicalize(before['archive-partner'])
