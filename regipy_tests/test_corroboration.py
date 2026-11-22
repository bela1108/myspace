"""Tests for offline registry identity corroboration."""

from __future__ import annotations

import json
from pathlib import Path

from regipy.corroboration import (
    CorroborationCase,
    ExportRecord,
    NameAssociation,
    Origin,
    PluginObservation,
    SamplingSource,
    Verdict,
    VolumeIdentity,
    corroborate,
    replace_identity_record,
)


def _association(
    profile: str = r"C:\Users\alice",
    name: str = "alice",
    verified: bool | None = True,
    independently_verifiable: bool = True,
    origin: Origin = Origin.HIVE,
) -> NameAssociation:
    return NameAssociation(
        identifier_type="profile_path",
        identifier=profile,
        name_type="account_name",
        name=name,
        method="fixture",
        origin=origin,
        independently_verifiable=independently_verifiable,
        verified=verified,
    )


def _export(
    export_id: str,
    source_id: str,
    profile: str = r"C:\Users\alice",
    name: str = "alice",
    derived_from: str | None = None,
    volume_serial: str = "VOL-1",
    verified: bool | None = True,
    independently_verifiable: bool = True,
    origin: Origin = Origin.HIVE,
) -> ExportRecord:
    return ExportRecord(
        export_id=export_id,
        sampling_source=SamplingSource(
            source_id=source_id,
            acquisition_id=source_id,
            derived_from=derived_from,
        ),
        volume_identity=VolumeIdentity(volume_serial=volume_serial, disk_signature=f"SIG-{volume_serial}"),
        name_associations=[
            _association(
                profile=profile,
                name=name,
                verified=verified,
                independently_verifiable=independently_verifiable,
                origin=origin,
            )
        ],
        auto_extract=False,
    )


def test_independent_verified_names_support_same_subject():
    case = CorroborationCase(
        case_id="same-subject",
        exports=[
            _export("EXP-A", "SRC-A", volume_serial="VOL-A"),
            _export("EXP-B", "SRC-B", volume_serial="VOL-B"),
        ],
    )
    result = corroborate(case)
    assert result.verdict is Verdict.SAME_SUBJECT
    assert result.pairwise[0]["verdict"] == "same_subject"
    assert result.pairwise[0]["independent"] is True


def test_clone_content_is_not_independent_corroboration():
    case = CorroborationCase(
        case_id="clone",
        exports=[
            _export("EXP-A", "SRC-A"),
            _export("EXP-B", "SRC-B", derived_from="EXP-A"),
        ],
    )
    result = corroborate(case)
    assert result.verdict is Verdict.MISSING_EVIDENCE
    pair = result.pairwise[0]
    assert pair["verdict"] == "missing_evidence"
    assert pair["clone_related"] is True
    assert pair["independent"] is False
    assert "link:source:EXP-A:EXP-B" in {item.association_id for item in result.associations}
    assert "link:clone:EXP-A:EXP-B" in {item.association_id for item in result.associations}


def test_different_names_produce_conflict():
    case = CorroborationCase(
        case_id="conflict",
        exports=[
            _export("EXP-A", "SRC-A", profile=r"C:\Users\alice", name="alice"),
            _export("EXP-C", "SRC-C", profile=r"C:\Users\bob", name="bob", volume_serial="VOL-B"),
        ],
    )
    result = corroborate(case)
    assert result.verdict is Verdict.CONFLICT
    assert result.pairwise[0]["verdict"] == "conflict"
    assert "account_name" in result.pairwise[0]["different_name_values"]


def test_missing_source_or_volume_downgrades_to_missing_evidence():
    case = CorroborationCase(
        case_id="missing-provenance",
        exports=[
            ExportRecord(
                export_id="EXP-A",
                name_associations=[_association()],
                auto_extract=False,
            ),
            ExportRecord(
                export_id="EXP-C",
                name_associations=[_association()],
                auto_extract=False,
            ),
        ],
    )
    result = corroborate(case)
    assert result.pairwise[0]["verdict"] == "same_subject"
    assert result.verdict is Verdict.MISSING_EVIDENCE
    association_ids = {item.association_id for item in result.associations}
    assert "missing:source:EXP-A" in association_ids
    assert "missing:volume:EXP-C" in association_ids


def test_contradictory_volume_fields_are_conflict():
    case = CorroborationCase(
        case_id="volume-conflict",
        exports=[
            ExportRecord(
                export_id="EXP-A",
                sampling_source=SamplingSource(source_id="SRC-A", acquisition_id="ACQ-A"),
                volume_identity=VolumeIdentity(volume_serial="VOL-1", disk_signature="SIG-X"),
                name_associations=[_association()],
                auto_extract=False,
            ),
            ExportRecord(
                export_id="EXP-C",
                sampling_source=SamplingSource(source_id="SRC-C", acquisition_id="ACQ-C"),
                volume_identity=VolumeIdentity(volume_serial="VOL-1", disk_signature="SIG-Y"),
                name_associations=[_association()],
                auto_extract=False,
            ),
        ],
    )
    result = corroborate(case)
    assert result.verdict is Verdict.CONFLICT
    assert result.pairwise[0]["volume_conflict"] is True
    assert result.pairwise[0]["verdict"] == "conflict"


def test_not_applicable_metadata_can_explain_missing_provenance():
    case = CorroborationCase(
        case_id="not-applicable-provenance",
        exports=[
            ExportRecord(
                export_id="EXP-A",
                name_associations=[_association()],
                metadata={"source_not_applicable": True, "volume_not_applicable": True},
                auto_extract=False,
            ),
            ExportRecord(
                export_id="EXP-C",
                name_associations=[_association()],
                metadata={"source_not_applicable": True, "volume_not_applicable": True},
                auto_extract=False,
            ),
        ],
    )
    result = corroborate(case)
    assert result.verdict is Verdict.SAME_SUBJECT


def test_unverified_name_association_is_missing_evidence():
    case = CorroborationCase(
        case_id="missing",
        exports=[
            _export("EXP-A", "SRC-A", verified=None, independently_verifiable=False),
            _export("EXP-C", "SRC-C", verified=None, independently_verifiable=False, volume_serial="VOL-B"),
        ],
    )
    result = corroborate(case)
    assert result.verdict is Verdict.MISSING_EVIDENCE
    assert result.pairwise[0]["verdict"] == "missing_evidence"
    assert any(item.kind == "missing_name_association" for item in result.associations)


def test_caller_evidence_path_without_verification_is_not_primary():
    association = _association(verified=None, independently_verifiable=True)
    association.evidence_path = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    case = CorroborationCase(
        case_id="unverified-claim",
        exports=[
            _export("EXP-A", "SRC-A", verified=None, volume_serial="VOL-A"),
            _export("EXP-C", "SRC-C", verified=None, volume_serial="VOL-B"),
        ],
    )
    for export in case.exports:
        export.name_associations = [association]
    result = corroborate(case)
    assert result.pairwise[0]["verdict"] == "missing_evidence"
    assert result.verdict is Verdict.MISSING_EVIDENCE


def test_failed_verification_is_a_conflict():
    case = CorroborationCase(
        case_id="failed-verification",
        exports=[
            _export("EXP-A", "SRC-A"),
            _export("EXP-C", "SRC-C", verified=False, volume_serial="VOL-B"),
        ],
    )
    result = corroborate(case)
    assert result.verdict is Verdict.CONFLICT
    assert any(item.kind == "name_verification_failure" for item in result.associations)


def test_plugin_values_remain_supplemental():
    plugin_association = _association(origin="plugin")
    case = CorroborationCase(
        case_id="plugin-only",
        exports=[
            ExportRecord(
                export_id="EXP-A",
                sampling_source=SamplingSource(source_id="SRC-A", acquisition_id="ACQ-A"),
                volume_identity=VolumeIdentity(volume_serial="VOL-A"),
                name_associations=[plugin_association],
                plugin_observations=[PluginObservation(plugin_name="typed_urls", digest="same-digest")],
                auto_extract=False,
            ),
            ExportRecord(
                export_id="EXP-B",
                sampling_source=SamplingSource(source_id="SRC-B", acquisition_id="ACQ-B"),
                volume_identity=VolumeIdentity(volume_serial="VOL-B"),
                name_associations=[_association(origin="plugin")],
                plugin_observations=[PluginObservation(plugin_name="typed_urls", digest="same-digest")],
                auto_extract=False,
            ),
        ],
    )
    result = corroborate(case)
    assert result.verdict is Verdict.MISSING_EVIDENCE
    assert result.provenance["plugin_values_are_supplemental"] is True
    assert result.provenance["plugin_values_used_as_original_source"] is False
    assert result.provenance["plugin_values_can_establish_identity"] is False
    assert all(item["origin"] == "plugin" for item in result.plugin_evidence)
    assert all(item["role"] == "supplemental" for item in result.plugin_evidence)
    assert all(item["used_as_source"] is False for item in result.plugin_evidence)
    assert not any(item.kind == "shared_name_node" for item in result.associations)


def test_replacement_invalidates_only_dependent_associations():
    case = CorroborationCase(
        case_id="replacement",
        exports=[
            _export("EXP-A", "SRC-A"),
            _export("EXP-B", "SRC-B", derived_from="EXP-A"),
        ],
    )
    result = replace_identity_record(
        case,
        "EXP-B",
        "volume",
        {"volume_serial": "VOL-OTHER", "disk_signature": "SIG-OTHER"},
        note="counterfactual",
    )
    invalidated = set(result.replacement["invalidated_association_ids"])
    surviving = set(result.replacement["surviving_association_ids"])
    assert "link:volume:EXP-A:EXP-B" in invalidated
    assert "link:source:EXP-A:EXP-B" in surviving
    assert "link:clone:EXP-A:EXP-B" in surviving
    assert any(item.startswith("link:name:EXP-A:EXP-B:") for item in surviving)
    assert result.replacement["verdict_before"] == "missing_evidence"
    assert result.replacement["verdict_after"] == "missing_evidence"


def test_replacing_name_record_invalidates_name_links_only():
    case = CorroborationCase(
        case_id="replacement-name",
        exports=[
            _export("EXP-A", "SRC-A"),
            _export("EXP-B", "SRC-B", derived_from="EXP-A"),
        ],
    )
    result = replace_identity_record(
        case,
        "EXP-B",
        "name:0",
        {"identifier": r"C:\Users\mallory", "name": "mallory"},
    )
    invalidated = set(result.replacement["invalidated_association_ids"])
    surviving = set(result.replacement["surviving_association_ids"])
    assert any(item.startswith("link:name:EXP-A:EXP-B:") for item in invalidated)
    assert "link:volume:EXP-A:EXP-B" in surviving
    assert "link:source:EXP-A:EXP-B" in surviving


def test_three_ntuser_exports_clone_and_conflict():
    data_dir = Path(__file__).parent / "data"
    case = CorroborationCase(
        case_id="three-ntuser",
        claim="The three exports were left by one user.",
        exports=[
            ExportRecord(
                export_id="EXP-A",
                hive_path=str(data_dir / "NTUSER.DAT.xz"),
                hive_type="ntuser",
                sampling_source=SamplingSource(source_id="SRC-A", acquisition_id="ACQ-1"),
                volume_identity=VolumeIdentity(volume_serial="1A2B3C4D", disk_signature="0xA1B2C3D4"),
            ),
            ExportRecord(
                export_id="EXP-B",
                hive_path=str(data_dir / "NTUSER_modified.DAT.xz"),
                hive_type="ntuser",
                sampling_source=SamplingSource(
                    source_id="SRC-B",
                    acquisition_id="ACQ-2",
                    derived_from="EXP-A",
                ),
                volume_identity=VolumeIdentity(volume_serial="1A2B3C4D", disk_signature="0xA1B2C3D4"),
            ),
            ExportRecord(
                export_id="EXP-C",
                hive_path=str(data_dir / "NTUSER_with_winscp.DAT.xz"),
                hive_type="ntuser",
                sampling_source=SamplingSource(source_id="SRC-C", acquisition_id="ACQ-3"),
                volume_identity=VolumeIdentity(volume_serial="5E6F7A8B", disk_signature="0xB2C3D4E5"),
            ),
        ],
    )
    result = corroborate(case)
    assert result.verdict is Verdict.CONFLICT
    pairs = {tuple(pair["exports"]): pair for pair in result.pairwise}

    clone_pair = pairs[("EXP-A", "EXP-B")]
    assert clone_pair["verdict"] == "missing_evidence"
    assert clone_pair["clone_related"] is True
    assert clone_pair["shared_hive_identity"] is True
    assert clone_pair["identical_anchor_count"] >= 2
    example_paths = {item["path"] for item in clone_pair["identical_anchor_examples"]}
    assert r"\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" in example_paths
    assert r"\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" in example_paths

    conflict_pair = pairs[("EXP-A", "EXP-C")]
    assert conflict_pair["verdict"] == "conflict"
    assert conflict_pair["different_name_values"]["account_name"]["first"] == ["vibranium"]
    assert conflict_pair["different_name_values"]["account_name"]["second"] == ["tony"]

    typed_urls = [
        item for item in result.plugin_evidence if item["export_id"] == "EXP-A" and item["plugin_name"] == "typed_urls"
    ]
    assert typed_urls
    assert typed_urls[0]["origin"] == "plugin"
    assert typed_urls[0]["role"] == "supplemental"
    assert typed_urls[0]["used_as_source"] is False

    markdown = result.to_markdown()
    assert "missing_evidence" in markdown
    assert "conflict" in markdown
    assert "Plugin evidence (supplemental only)" in markdown


def test_sam_and_software_extract_verifiable_names():
    data_dir = Path(__file__).parent / "data"
    cases = [
        ("SAM.xz", "sam", "Administrator"),
        ("SOFTWARE.xz", "software", "Pepper"),
    ]
    for file_name, hive_type, expected_name in cases:
        export = ExportRecord(
            export_id=hive_type.upper(),
            hive_path=str(data_dir / file_name),
            hive_type=hive_type,
            sampling_source=SamplingSource(source_id="SRC", acquisition_id="ACQ"),
            volume_identity=VolumeIdentity(volume_serial="VOL"),
            plugins=[],
        )
        corroborate(CorroborationCase(case_id=hive_type, exports=[export]))
        names = {record.value["name"] for record in export.records if record.kind == "name_association"}
        assert expected_name in names


def test_cli_review_and_replacement(tmp_path):
    from click.testing import CliRunner

    from regipy.corroboration_cli import main

    data_dir = Path(__file__).parent / "data"
    case = CorroborationCase(
        case_id="cli",
        exports=[
            ExportRecord(
                export_id="EXP-A",
                hive_path=str(data_dir / "NTUSER.DAT.xz"),
                hive_type="ntuser",
                sampling_source=SamplingSource(source_id="SRC-A", acquisition_id="ACQ-1"),
                volume_identity=VolumeIdentity(volume_serial="VOL-A"),
            ),
            ExportRecord(
                export_id="EXP-B",
                hive_path=str(data_dir / "NTUSER_modified.DAT.xz"),
                hive_type="ntuser",
                sampling_source=SamplingSource(
                    source_id="SRC-B",
                    acquisition_id="ACQ-2",
                    derived_from="EXP-A",
                ),
                volume_identity=VolumeIdentity(volume_serial="VOL-A"),
            ),
        ],
    )
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(case.to_dict()), encoding="utf-8")

    review_path = tmp_path / "review.json"
    runner = CliRunner()
    result = runner.invoke(main, [str(case_path), "-o", str(review_path), "--quiet"])
    assert result.exit_code == 0, result.output
    review = json.loads(review_path.read_text(encoding="utf-8"))
    assert review["verdict"] == "missing_evidence"

    replacement_path = tmp_path / "replacement.json"
    result = runner.invoke(
        main,
        [
            str(case_path),
            "--replace-export",
            "EXP-B",
            "--replace-record",
            "volume",
            "--replace-value",
            json.dumps({"volume_serial": "VOL-X", "disk_signature": "SIG-X"}),
            "-o",
            str(replacement_path),
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output
    replacement = json.loads(replacement_path.read_text(encoding="utf-8"))
    assert "link:volume:EXP-A:EXP-B" in replacement["replacement"]["invalidated_association_ids"]
