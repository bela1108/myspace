import os

from custody_audit.evtx_records import (
    RecordRange,
    RecordSummary,
    file_sha256,
    summarize_evtx,
)

from conftest import EVTX_DIR


def test_range_contains_open_ended():
    rng = RecordRange(first=2)
    assert not rng.contains(1)
    assert rng.contains(2)
    assert rng.contains(999)
    assert rng.describe() == "2-END"


def test_range_contains_bounded():
    rng = RecordRange(first=2, last=4)
    assert [rng.contains(n) for n in range(1, 6)] == [False, True, True, True, False]


def test_summarize_security_short():
    summaries = summarize_evtx(os.path.join(EVTX_DIR, "security_short.evtx"), RecordRange(1, 1))
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.record_num == 1
    assert summary.event_id == 4672
    assert summary.channel == "Security"
    assert summary.xml_ok is True
    assert len(summary.sha256) == 64


def test_summarize_keeps_unreadable_records():
    summaries = summarize_evtx(os.path.join(EVTX_DIR, "dns_short.evtx"), RecordRange(1, 5))
    assert [s.record_num for s in summaries] == [1, 2, 3, 4, 5]
    assert summaries[0].xml_ok is True
    assert summaries[0].event_id == 260
    assert all(s.xml_ok is False for s in summaries[1:])
    assert all(s.parse_error for s in summaries[1:])
    assert all(isinstance(s, RecordSummary) for s in summaries)


def test_manifest_row_has_no_sensitive_fields():
    summaries = summarize_evtx(os.path.join(EVTX_DIR, "security_short.evtx"), RecordRange(1, 1))
    row = summaries[0].as_manifest_row()
    assert set(row.keys()) == {"record_num", "timestamp", "event_id", "channel", "sha256", "xml_ok"}
    forbidden = ("event_xml", "user_data", "subject", "logon", "process", "command", "binary", "payload", "raw", "computer")
    assert not any(key.lower() == token or token in key.lower() for key in row for token in forbidden)


def test_file_sha256_stable():
    path = os.path.join(EVTX_DIR, "security_short.evtx")
    assert file_sha256(path) == file_sha256(path)
