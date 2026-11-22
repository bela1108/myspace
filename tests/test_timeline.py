import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from Evtx.Timeline import (
    Discontinuity,
    RecordObservation,
    analyze_observations,
    diagnose_timeline,
    load_collection,
    parse_numbering_rules,
    scan_evtx,
    main,
)

DATA = Path(__file__).parent / "data"


def _time(seconds=0):
    return datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)


def _record(
    index,
    record_number,
    event_time,
    event_id=4624,
    sequences=None,
    offset=None,
):
    return RecordObservation(
        index=index,
        chunk_index=0,
        chunk_offset=0x1000,
        offset=0x200 + index * 0x100 if offset is None else offset,
        length=0x100,
        record_number=record_number,
        event_record_id=record_number,
        event_id=event_id,
        record_time=event_time,
        event_time=event_time,
        xml_ok=True,
        sequences=sequences or {},
    )


def test_bad_record_is_retained_and_scan_resynchronizes():
    path = DATA / "dns_log_malformed.evtx"
    original = path.read_bytes()
    baseline = scan_evtx(original)
    assert len(baseline.records) >= 4

    damaged = bytearray(original)
    target = baseline.records[1]
    damaged[target.offset : target.offset + 4] = b"XXXX"
    result = diagnose_timeline(bytes(damaged))

    assert any(item.kind == "bad-record" for item in result.discontinuities)
    assert any(item.basis == "original-record" for item in result.discontinuities)
    assert result.records[-1].record_number == baseline.records[-1].record_number
    assert target.record_number not in {record.record_number for record in result.records}


def test_clock_rollback_is_kept_in_file_order_and_collection_can_corroborate():
    records = [
        _record(0, 100, _time(0)),
        _record(1, 101, _time(60)),
        _record(2, 102, _time(60 - 420)),
    ]
    receipts = [
        {"record_number": 100, "receipt_sequence": 1, "receipt_time": _time(70)},
        {"record_number": 102, "receipt_sequence": 4, "receipt_time": _time(90)},
        {"record_number": 101, "receipt_sequence": 3, "receipt_time": _time(80), "status": "missing"},
    ]

    result = analyze_observations(records, receipts=receipts)

    assert result.clock_rollbacks
    rollback = result.clock_rollbacks[0]
    assert rollback.rollback_seconds == 420.0
    assert rollback.before_record_index == 1
    assert rollback.after_record_index == 2
    assert "original-record" in rollback.bases
    assert "collection" in rollback.bases
    assert rollback.corroborated_by_collection is True

    record_order = [entry.file_index for entry in result.timeline if entry.kind == "record"]
    assert record_order == [0, 1, 2]
    assert {entry.kind for entry in result.timeline} >= {
        "record",
        "clock-rollback",
        "discontinuity",
        "collection-receipt",
        "collection-receipt-missing",
    }


def test_collection_gap_has_collection_basis_and_stays_in_timeline():
    records = [
        _record(0, 10, _time(0)),
        _record(1, 11, _time(10)),
        _record(2, 12, _time(20)),
    ]
    receipts = [
        {"record_number": 10, "receipt_sequence": 1},
        {"record_number": 11, "receipt_sequence": 2, "status": "missing"},
        {"record_number": 12, "receipt_sequence": 5},
    ]

    result = analyze_observations(records, receipts=receipts)

    collection_gaps = [item for item in result.discontinuities if item.basis == "collection"]
    assert any(item.kind == "collection-receipt-gap" for item in collection_gaps)
    assert any(item.kind == "collection-record-missing" for item in collection_gaps)
    assert any(item.kind == "discontinuity" and item.basis == "collection" for item in result.timeline)


def test_numbering_rules_are_explicit_and_scoped_per_event_id():
    rule = parse_numbering_rules([{"event_id": 4624, "field": "EventData/SequenceNumber", "scope": "event-id"}])[0]
    key = rule.key

    records = [
        _record(0, 1, _time(0), 4624, {key: 1}),
        _record(1, 2, _time(1), 4688, {"4688:EventData/SequenceNumber": 100}),
        _record(2, 3, _time(2), 4624, {key: 2}),
        _record(3, 4, _time(3), 4624, {key: 4}),
    ]

    result = analyze_observations(records, numbering_rules=[rule])

    assert len(result.constraints["eid_sequence"]) == 1
    assert result.constraints["eid_sequence"][0]["event_id"] == 4624
    sequence_gaps = [item for item in result.discontinuities if item.kind == "missing-event-sequence"]
    assert len(sequence_gaps) == 1
    assert sequence_gaps[0].missing == 1
    assert sequence_gaps[0].event_id == 4624


def test_no_numbering_rule_means_no_per_eid_inference():
    records = [
        _record(0, 1, _time(0), 4624),
        _record(1, 2, _time(1), 4688),
        _record(2, 3, _time(2), 4624),
    ]
    result = analyze_observations(records)
    assert result.discontinuities == []
    assert result.constraints["eid_sequence"] == []
    assert any("numbering rules" in warning for warning in result.warnings)


def test_manifest_can_be_metadata_only_and_json_serializable():
    manifest = load_collection({"missing_blocks": [3, 4], "block_size": 4096})
    assert len(manifest.receipts) == 2
    assert all(receipt.is_missing for receipt in manifest.receipts)
    assert all(receipt.kind == "block" for receipt in manifest.receipts)

    result = diagnose_timeline(DATA / "issue_38.evtx")
    payload = json.dumps(result.to_dict())
    assert "summary" in json.loads(payload)
    assert "timeline" in json.loads(payload)


def test_cli_accepts_collection_and_numbering_rule_files(tmp_path, capsys):
    manifest = tmp_path / "receipts.json"
    manifest.write_text(
        json.dumps({"receipts": [{"record_number": 1, "receipt_sequence": 1}]}),
        encoding="utf-8",
    )
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps({"rules": [{"event_id": "*", "field": "EventRecordID", "scope": "file"}]}),
        encoding="utf-8",
    )

    rc = main(
        [
            str(DATA / "issue_38.evtx"),
            "--collection",
            str(manifest),
            "--numbering-rules",
            str(rules),
            "--summary-only",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["record_count"] == 1
    assert output["receipt_count"] == 1


def test_combined_timeline_holds_original_gap_collection_gap_and_rollback():
    records = [
        _record(0, 100, _time(0)),
        _record(1, 101, _time(60)),
        _record(2, 102, _time(60 - 420)),
    ]
    original_gap = Discontinuity(
        kind="bad-record",
        basis="original-record",
        evidence="chunk-structure",
        detail="test bad record",
        start_offset=records[0].offset + records[0].length,
        end_offset=records[1].offset,
        before_record_index=0,
        after_record_index=1,
        missing=1,
    )
    receipts = [
        {"block_index": 5, "status": "missing", "receipt_sequence": 1},
        {"record_number": 102, "receipt_sequence": 2},
    ]

    result = analyze_observations(records, discontinuities=[original_gap], receipts=receipts)

    assert any(entry.kind == "clock-rollback" and "original-record" in entry.bases for entry in result.timeline)
    assert any(
        entry.kind == "discontinuity" and entry.basis == "original-record" and entry.payload.get("kind") == "bad-record"
        for entry in result.timeline
    )
    assert any(
        entry.kind == "discontinuity"
        and entry.basis == "collection"
        and entry.payload.get("kind") == "missing-file-block"
        for entry in result.timeline
    )
    assert result.original_record_timeline
    assert result.collection_timeline
