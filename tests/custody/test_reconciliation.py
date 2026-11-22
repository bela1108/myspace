import copy

from custody_audit.audit import (
    CustodyState,
    HandoverMode,
    Severity,
    reconcile,
)

from conftest import run_reconcile


def _dispositions(result, evtx_file):
    file_result = next(fr for fr in result.file_results if fr.evtx_file == evtx_file)
    return {d.record_num: d for d in file_result.dispositions}


def test_sample_three_way_classification(sample_result):
    dns = _dispositions(sample_result, "dns_short.evtx")
    assert dns[1].state == CustodyState.SUMMARY_ONLY
    assert dns[1].signer_id == "C003"
    assert dns[1].effective_receipt_id == "R-02"
    assert dns[4].state == CustodyState.REVIEWABLE
    assert dns[5].state == CustodyState.REVIEWABLE
    assert dns[4].signer_id == "C002"
    assert dns[2].state == CustodyState.NOT_ACCEPTED
    assert dns[3].state == CustodyState.NOT_ACCEPTED
    assert dns[2].signer_id is None

    security = _dispositions(sample_result, "security_short.evtx")
    assert security[1].state == CustodyState.REVIEWABLE
    assert security[1].signer_id == "C002"
    assert security[1].effective_receipt_id == "R-01"


def test_retroactive_receipt_valid_after_guard_change(loaded):
    result = run_reconcile(loaded)
    effective = result.effective_receipts[("dns_short.evtx", 4, 5)]
    assert effective.receipt_id == "R-04"
    assert effective.receipt_type == "retroactive"
    assert effective.signer_id == "C002"


def test_retroactive_receipt_by_predecessor_is_rejected(loaded):
    result = run_reconcile(loaded)
    rejected_codes = {f.reference for f in result.rejected_receipts}
    assert "receipts.R-03" in rejected_codes
    assert ("dns_short.evtx", 2, 3) not in result.effective_receipts
    assert result.has_blocking_errors is True


def test_copy_holding_is_not_a_handover(loaded):
    receipts = copy.deepcopy(loaded["receipts"])
    receipts["receipts"] = [r for r in receipts["receipts"] if r["receipt_id"] != "R-01"]
    result = run_reconcile(loaded, receipts_override=receipts)
    security = _dispositions(result, "security_short.evtx")
    assert security[1].state == CustodyState.NOT_ACCEPTED
    assert any("副本持有不等于移交" in reason for reason in security[1].reasons)
    codes = {f.code for f in result.findings}
    assert "NO_EFFECTIVE_SIGNATURE" in codes

def test_summary_custodian_cannot_accept_full_handover(loaded):
    receipts = copy.deepcopy(loaded["receipts"])
    for receipt in receipts["receipts"]:
        if receipt["receipt_id"] == "R-01":
            receipt["signer_id"] = "C003"
    result = run_reconcile(loaded, receipts_override=receipts)
    security = _dispositions(result, "security_short.evtx")
    assert security[1].state == CustodyState.NOT_ACCEPTED
    rejection = next(f for f in result.rejected_receipts if f.reference == "receipts.R-01")
    assert "evtx.full_review" in rejection.message


def test_receipt_after_cutoff_is_rejected(loaded):
    receipts = copy.deepcopy(loaded["receipts"])
    for receipt in receipts["receipts"]:
        if receipt["receipt_id"] == "R-01":
            receipt["signed_at"] = "2018-01-02T00:00:00+08:00"
    result = run_reconcile(loaded, receipts_override=receipts)
    rejection = next(f for f in result.rejected_receipts if f.reference == "receipts.R-01")
    assert "销档日期" in rejection.message


def test_receipt_without_manifest_entry_is_rejected(loaded):
    manifest = copy.deepcopy(loaded["manifest"])
    manifest["entries"] = [e for e in manifest["entries"] if not (e["evtx_file"] == "security_short.evtx")]
    result = run_reconcile(loaded, manifest_override=manifest)
    rejection = next(f for f in result.rejected_receipts if f.reference == "receipts.R-01")
    assert "外部交接清单" in rejection.message


def test_unknown_signer_is_rejected(loaded):
    receipts = copy.deepcopy(loaded["receipts"])
    for receipt in receipts["receipts"]:
        if receipt["receipt_id"] == "R-02":
            receipt["signer_id"] = "C999"
    result = run_reconcile(loaded, receipts_override=receipts)
    rejection = next(f for f in result.rejected_receipts if f.reference == "receipts.R-02")
    assert "责任表" in rejection.message


def test_manifest_sensitive_field_is_blocked(loaded):
    manifest = copy.deepcopy(loaded["manifest"])
    manifest["entries"][0]["event_xml"] = "<Event>secret</Event>"
    result = run_reconcile(loaded, manifest_override=manifest)
    redaction = next(f for f in result.findings if f.code == "MANIFEST_SENSITIVE_KEY")
    assert redaction.severity == Severity.ERROR
    assert result.has_blocking_errors is True


def test_clean_manifest_has_no_redaction_finding(sample_result):
    assert not any(f.code == "MANIFEST_SENSITIVE_KEY" for f in sample_result.findings)


def test_unreadable_records_still_reconciled(sample_result):
    dns = _dispositions(sample_result, "dns_short.evtx")
    assert set(dns.keys()) == {1, 2, 3, 4, 5}
    warnings = [f for f in sample_result.findings if f.code == "RECORD_UNREADABLE"]
    assert {int(f.reference.split("#")[1]) for f in warnings} == {2, 3, 4, 5}


def test_latest_effective_receipt_wins(loaded):
    receipts = copy.deepcopy(loaded["receipts"])
    later = copy.deepcopy(next(r for r in receipts["receipts"] if r["receipt_id"] == "R-01"))
    later["receipt_id"] = "R-05"
    later["signed_at"] = "2017-07-10T09:00:00+08:00"
    receipts["receipts"].append(later)
    result = run_reconcile(loaded, receipts_override=receipts)
    chosen = result.effective_receipts[("security_short.evtx", 1, 1)]
    assert chosen.receipt_id == "R-05"


def test_summary_mode_on_full_receipt_mismatch(loaded):
    manifest = copy.deepcopy(loaded["manifest"])
    for entry in manifest["entries"]:
        if entry["evtx_file"] == "security_short.evtx":
            entry["mode"] = "summary"
    result = run_reconcile(loaded, manifest_override=manifest)
    rejection = next(f for f in result.rejected_receipts if f.reference == "receipts.R-01")
    assert "不一致" in rejection.message
