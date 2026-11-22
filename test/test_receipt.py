import pytest
from pathlib import Path

from pip_audit._receipt import (
    HandoffStage,
    ReceiptDocument,
    ReceiptReconciler,
    ReceiptSourceError,
    ReconciliationStatus,
    render_pending_report,
    report_to_dict,
)

_ASSETS = Path(__file__).parent / "assets" / "receipt"


def _load_sample():
    plan = ReceiptDocument.from_file(_ASSETS / "local-plan.json", HandoffStage.LOCAL_PLAN)
    manifest = ReceiptDocument.from_file(
        _ASSETS / "warehouse-manifest.json", HandoffStage.WAREHOUSE
    )
    receipt = ReceiptDocument.from_file(
        _ASSETS / "transit-receipt.json", HandoffStage.TRANSIT
    )
    return plan, manifest, receipt


def _rows_by_filename(report):
    return {row.filename: row for row in report.rows}


def test_documents_load_and_keep_provenance():
    plan, manifest, receipt = _load_sample()
    assert len(plan.records) == 7
    assert len(manifest.records) == 5
    assert len(receipt.records) == 5
    first = manifest.records[0]
    assert first.provided_by == "warehouse-bot"
    assert first.stage is HandoffStage.WAREHOUSE
    assert first.has_identity is True
    assert first.digest == (
        "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff66660000111122223333aa"
    )


def test_legacy_report_without_identity_opens_but_stays_pending():
    plan, _manifest, _receipt = _load_sample()
    legacy = next(record for record in plan.records if record.name == "urllib3")
    assert legacy.has_identity is False
    assert legacy.filename is None
    assert legacy.digest is None
    report = ReceiptReconciler(*_load_sample()).reconcile()
    legacy_row = next(
        row for row in report.rows if row.name == "urllib3" and row.filename is None
    )
    assert legacy_row.status is ReconciliationStatus.PENDING
    assert {material.material for material in legacy_row.missing_materials} == {
        "filename",
        "digest",
    }


def test_same_version_two_local_files_get_independent_rows():
    report = ReceiptReconciler(*_load_sample()).reconcile()
    numpy_rows = [row for row in report.rows if row.name == "numpy"]
    assert len(numpy_rows) == 2
    filenames = {row.filename for row in numpy_rows}
    assert filenames == {
        "numpy-1.26.0-cp312-cp312-macosx_11_0_arm64.whl",
        "numpy-1.26.0-cp312-cp312-manylinux_2_17_x86_64.whl",
    }
    by_name = _rows_by_filename(report)
    linux = by_name["numpy-1.26.0-cp312-cp312-manylinux_2_17_x86_64.whl"]
    macos = by_name["numpy-1.26.0-cp312-cp312-macosx_11_0_arm64.whl"]
    assert linux.status is ReconciliationStatus.MATCHED
    assert macos.status is ReconciliationStatus.CONFLICT
    assert linux.missing_materials == ()
    assert macos.missing_materials == ()


def test_transit_conflict_is_traced_to_transit_stage():
    report = ReceiptReconciler(*_load_sample()).reconcile()
    macos = _rows_by_filename(report)[
        "numpy-1.26.0-cp312-cp312-macosx_11_0_arm64.whl"
    ]
    assert len(macos.conflicts) == 1
    conflict = macos.conflicts[0]
    assert conflict.stage is HandoffStage.TRANSIT
    assert conflict.expected_digest == (
        "bbbb2222cccc3333dddd4444eeee5555ffff6666000011112222333344445555bb"
    )
    assert conflict.observed_digest == "0f" * 32
    assert "warehouse-manifest.json" in conflict.expected_source
    assert "transit-receipt.json" in conflict.observed_source
    assert macos.providers[HandoffStage.WAREHOUSE] == "warehouse-bot"
    assert macos.providers[HandoffStage.TRANSIT] == "transit-scanner-1"


def test_warehouse_conflict_is_traced_to_warehouse_stage():
    report = ReceiptReconciler(*_load_sample()).reconcile()
    flask = _rows_by_filename(report)["flask-3.0.0-py3-none-any.whl"]
    assert flask.status is ReconciliationStatus.CONFLICT
    warehouse_conflict = next(
        conflict for conflict in flask.conflicts if conflict.stage is HandoffStage.WAREHOUSE
    )
    assert warehouse_conflict.expected_digest == (
        "9999000011112222333344445555666677778888999900001111222233334444ff"
    )
    assert warehouse_conflict.observed_digest == (
        "cccc3333dddd4444eeee5555ffff666600001111222233334444555566667777cc"
    )
    assert {material.material for material in flask.missing_materials} == {"received_artifact"}


def test_missing_downstream_artifacts_are_independent_materials():
    report = ReceiptReconciler(*_load_sample()).reconcile()
    certifi = _rows_by_filename(report)["certifi-2024.2.2-py3-none-any.whl"]
    assert certifi.status is ReconciliationStatus.PENDING
    assert {material.material for material in certifi.missing_materials} == {
        "shipped_artifact",
        "received_artifact",
    }
    stages = {material.stage for material in certifi.missing_materials}
    assert stages == {HandoffStage.WAREHOUSE, HandoffStage.TRANSIT}


def test_orphan_artifacts_become_pending_rows():
    report = ReceiptReconciler(*_load_sample()).reconcile()
    by_name = _rows_by_filename(report)
    packaging = by_name["packaging-23.2-py3-none-any.whl"]
    idna = by_name["idna-3.6-py3-none-any.whl"]
    assert packaging.status is ReconciliationStatus.PENDING
    assert idna.status is ReconciliationStatus.PENDING
    assert packaging.evidence[0].stage is HandoffStage.WAREHOUSE
    assert idna.evidence[0].stage is HandoffStage.TRANSIT
    assert packaging.missing_materials[0].material == "planned_artifact"


def test_pending_report_lists_each_distribution_file_separately():
    report = ReceiptReconciler(*_load_sample()).reconcile()
    text = render_pending_report(report)
    assert "numpy-1.26.0-cp312-cp312-macosx_11_0_arm64.whl" in text
    assert "numpy-1.26.0-cp312-cp312-manylinux_2_17_x86_64.whl" not in text
    assert "<no distribution file>" in text
    assert "Total pending items: 8" in text
    serialized = report_to_dict(report)
    assert len(serialized["rows"]) == len(report.rows)
    assert None in serialized["pending_filenames"]


def test_digest_forms_are_equivalent():
    payload = {
        "entries": [
            {
                "name": "demo",
                "version": "1.0.0",
                "filename": "demo-1.0.0-py3-none-any.whl",
                "digest": "SHA256:ABCDEF",
            }
        ]
    }
    document = ReceiptDocument.from_dict(payload, HandoffStage.WAREHOUSE)
    assert document.records[0].digest == "abcdef"


def test_missing_name_is_rejected_but_legacy_identity_is_allowed():
    bad = {"entries": [{"version": "1.0.0"}]}
    with pytest.raises(ReceiptSourceError):
        ReceiptDocument.from_dict(bad, HandoffStage.LOCAL_PLAN)
    legacy = {"entries": [{"name": "oldpkg", "version": "0.9.0"}]}
    document = ReceiptDocument.from_dict(legacy, HandoffStage.LOCAL_PLAN)
    assert document.records[0].has_identity is False
