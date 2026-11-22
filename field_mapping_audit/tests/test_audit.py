"""Tests for the merged-log-source field mapping audit."""

from pathlib import Path

from field_mapping_audit.auditor import (
    build_collision_evidence,
    build_static_index,
    conditional_paths,
    load_rules_yaml,
    run_review,
)
from field_mapping_audit.fake_backend import run_audit_backend
from field_mapping_audit.pipeline import merged_logsource_pipeline


RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _run():
    pipeline = merged_logsource_pipeline()
    rules_yaml = load_rules_yaml(RULES_DIR)
    backend, queries = run_audit_backend(rules_yaml, pipeline)
    classification = build_static_index(pipeline)
    evidence = build_collision_evidence(backend.traces, classification)
    paths = conditional_paths(backend.traces, classification)
    return backend, queries, classification, evidence, paths


def test_static_index_detects_many_to_one_collisions():
    classification = build_static_index(merged_logsource_pipeline())
    assert set(classification.many_to_one["newlog.ip"]) == {
        "ClientIp",
        "DestinationIp",
        "SourceIp",
    }
    assert set(classification.many_to_one["newlog.path"]) == {
        "Image",
        "TargetFilename",
    }


def test_static_index_marks_reversible_one_to_one_mappings():
    classification = build_static_index(merged_logsource_pipeline())
    assert classification.reversible["newlog.user"] == "UserName"
    assert classification.reversible["newlog.host"] == "ComputerName"


def test_static_index_records_fan_out():
    classification = build_static_index(merged_logsource_pipeline())
    assert classification.fan_out["CommandLine"] == [
        "newlog.cmd",
        "newlog.cmd_raw",
    ]


def test_static_index_builds_reverse_lookup():
    classification = build_static_index(merged_logsource_pipeline())
    assert classification.reverse_index["newlog.ip"] == {
        "ClientIp",
        "DestinationIp",
        "SourceIp",
    }
    assert classification.reverse_index["newlog.user"] == {"UserName"}


def test_backend_traces_every_source_to_target_pair():
    backend, _, _, _, _ = _run()
    pairs = {(trace.original_field, trace.converted_field) for trace in backend.traces}
    assert ("SourceIp", "newlog.ip") in pairs
    assert ("DestinationIp", "newlog.ip") in pairs
    assert ("ClientIp", "newlog.ip") in pairs
    assert ("Image", "newlog.path") in pairs
    assert ("TargetFilename", "newlog.path") in pairs
    assert ("UserName", "newlog.user") in pairs


def test_fanout_emits_one_leaf_per_target():
    backend, _, _, _, _ = _run()
    commandline_targets = {
        trace.converted_field
        for trace in backend.traces
        if trace.original_field == "CommandLine"
    }
    assert commandline_targets == {"newlog.cmd", "newlog.cmd_raw"}


def test_collision_evidence_is_minimal_one_witness_per_source():
    _, _, classification, evidence, _ = _run()
    by_target = {item.target_field: item for item in evidence}
    ip_collision = by_target["newlog.ip"]
    assert set(ip_collision.source_fields) == {
        "ClientIp",
        "DestinationIp",
        "SourceIp",
    }
    witness_sources = {trace.original_field for trace in ip_collision.witness_traces}
    assert witness_sources == set(ip_collision.source_fields)
    assert len(ip_collision.witness_traces) == len(ip_collision.source_fields)
    assert ip_collision.reversible is False
    path_collision = by_target["newlog.path"]
    assert {trace.original_field for trace in path_collision.witness_traces} == {
        "Image",
        "TargetFilename",
    }


def test_conditional_transformation_fires_only_on_wildcard_path():
    backend, _, _, _, paths = _run()
    entry = paths["conditional-computername-tag"]
    fired = [
        trace
        for trace in backend.traces
        if "conditional-computername-tag" in trace.applied_processing_item_ids
    ]
    assert len(fired) == 1
    assert fired[0].selector == "host_pattern"
    assert fired[0].converted_field == "newlog.host"
    skipped_sources = {trace.original_field for trace in entry["skipped"]}
    assert "ComputerName" in skipped_sources
    skipped_kept = {trace.converted_field for trace in entry["skipped"]}
    assert skipped_kept == {"ComputerName"}


def test_unmapped_field_keeps_its_name():
    backend, _, _, _, _ = _run()
    port_traces = [
        trace for trace in backend.traces if trace.original_field == "DestinationPort"
    ]
    assert port_traces
    assert all(trace.converted_field == "DestinationPort" for trace in port_traces)
    assert all(not trace.applied_processing_item_ids for trace in port_traces)


def test_review_report_covers_all_sections():
    report, classification, traces, evidence = run_review(RULES_DIR)
    assert "## Static mapping classification" in report
    assert "## Backend trace" in report
    assert "## Minimal collision evidence" in report
    assert "## Conditional transformation firing paths" in report
    assert "newlog.ip" in report
    assert "conditional-computername-tag" in report
    assert classification.many_to_one
    assert traces
    assert evidence
