import hashlib
import lzma
from pathlib import Path

import pytest

from regipy.plugins.amcache.amcache import AmCachePlugin
from regipy.plugins.amcache.evidence import (
    STATUS_MATCH,
    STATUS_MISMATCH,
    STATUS_MISSING_EVIDENCE,
    STATUS_MISSING_RULE,
    STATUS_NO_DIGEST,
    STATUS_TRUNCATED,
    AmcacheEvidenceFile,
    AmcacheHashRule,
    verify_amcache_evidence,
)
from regipy.registry import RegistryHive

AMCACHE_HIVE_PATH = Path(__file__).parent / "data" / "amcache.hve.xz"


def write_evidence(tmp_path, evidence_id, content, registered_size=None):
    path = tmp_path / evidence_id
    path.write_bytes(content)
    return AmcacheEvidenceFile(
        evidence_id=evidence_id,
        local_path=path,
        registered_size=registered_size,
    )


def test_partial_hash_matches_two_prefixed_files_but_full_files_remain_distinct(tmp_path):
    shared_prefix = b"shared-prefix"
    boundary = len(shared_prefix)
    first_tail = b"-first"
    second_tail = b"-second"
    first_file = write_evidence(tmp_path, "E-1", shared_prefix + first_tail)
    second_file = write_evidence(tmp_path, "E-2", shared_prefix + second_tail)
    partial_digest = hashlib.sha1(shared_prefix).hexdigest()
    entries = [
        {
            "sha1": partial_digest,
            "full_path": r"C:\Registered\program.exe",
            "file_size": len(shared_prefix + first_tail),
            "windows_generation": "win7",
        },
        {
            "sha1": partial_digest,
            "full_path": r"C:\Registered\copy.exe",
            "file_size": len(shared_prefix + second_tail),
            "windows_generation": "win7",
        },
    ]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-1": first_file, "E-2": second_file},
        hash_rules={"win7": AmcacheHashRule(max_bytes=boundary)},
        entry_evidence_ids={0: "E-1", 1: "E-2"},
    )

    assert len(results) == 2
    assert all(result.status == STATUS_MATCH for result in results)
    assert {result.evidence_id for result in results} == {"E-1", "E-2"}
    assert {result.hashed_length for result in results} == {boundary}
    assert {result.local_size for result in results} == {len(shared_prefix + first_tail), len(shared_prefix + second_tail)}
    assert all(result.digest_scope == f"bytes_0_to_{boundary}" for result in results)
    assert all("proves only bytes 0 through" in result.digest_proof for result in results)
    assert all("does not prove bytes outside" in result.digest_proof for result in results)
    assert results[0].complete_file_sha1 != results[1].complete_file_sha1
    assert results[0].complete_file_sha1 == hashlib.sha1(shared_prefix + first_tail).hexdigest()
    assert results[1].complete_file_sha1 == hashlib.sha1(shared_prefix + second_tail).hexdigest()


def test_reports_size_conflict_and_missing_generation_rule(tmp_path):
    content = b"0123456789"
    evidence = write_evidence(tmp_path, "E-size", content, registered_size=99)
    entries = [
        {
            "sha1": hashlib.sha1(content).hexdigest(),
            "file_size": 99,
            "windows_generation": "known",
        },
        {
            "sha1": hashlib.sha1(content).hexdigest(),
            "file_size": len(content),
            "windows_generation": "unknown",
        },
    ]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-size": evidence},
        hash_rules={"known": AmcacheHashRule()},
        entry_evidence_ids={0: "E-size", 1: "E-size"},
    )

    assert results[0].status == STATUS_MATCH
    assert "Registered size 99 conflicts with local size 10" in results[0].findings
    assert results[1].status == STATUS_MISSING_RULE
    assert results[1].recomputed_digest is None


def test_truncated_collection_retains_original_digest_basis_without_claiming_match(tmp_path):
    boundary = 16
    registered_content = b"0123456789abcdef-tail"
    truncated_content = registered_content[:10]
    evidence = write_evidence(
        tmp_path,
        "E-truncated",
        truncated_content,
        registered_size=len(registered_content),
    )
    original_digest = hashlib.sha1(registered_content[:boundary]).hexdigest()
    entries = [
        {
            "sha1": original_digest,
            "file_size": len(registered_content),
            "windows_generation": "win10",
        }
    ]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-truncated": evidence},
        hash_rules={"win10": AmcacheHashRule(max_bytes=boundary)},
        entry_evidence_ids={0: "E-truncated"},
    )

    result = results[0]
    assert result.status == STATUS_TRUNCATED
    assert result.original_digest == original_digest
    assert result.recomputed_digest is None
    assert result.registered_size == len(registered_content)
    assert result.local_size == len(truncated_content)
    assert result.digest_scope == f"bytes_0_to_{boundary}"
    assert "truncation prevents even that segment from being verified" in result.digest_proof
    assert any("truncated" in finding for finding in result.findings)


def test_offset_beyond_file_is_reported_as_truncation(tmp_path):
    evidence = write_evidence(tmp_path, "E-offset-oob", b"short")
    entries = [{"sha1": hashlib.sha1(b"short").hexdigest(), "windows_generation": "offset-oob"}]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-offset-oob": evidence},
        hash_rules={"offset-oob": AmcacheHashRule(offset=10, max_bytes=4)},
        entry_evidence_ids={0: "E-offset-oob"},
    )

    assert results[0].status == STATUS_TRUNCATED
    assert results[0].digest_scope == "offset_out_of_bounds"
    assert results[0].hashed_length == 0
    assert "starts at offset 10" in results[0].digest_proof


def test_exact_segment_boundary_at_offset_matches(tmp_path):
    content = b"0123456789abcdef"
    evidence = write_evidence(tmp_path, "E-exact-boundary", content)
    rule = AmcacheHashRule(offset=10, max_bytes=6)
    entries = [
        {
            "sha1": hashlib.sha1(content[10:16]).hexdigest(),
            "windows_generation": "exact-boundary",
        }
    ]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-exact-boundary": evidence},
        hash_rules={"exact-boundary": rule},
        entry_evidence_ids={0: "E-exact-boundary"},
    )

    assert results[0].status == STATUS_MATCH
    assert results[0].hashed_offset == 10
    assert results[0].hashed_length == 6
    assert results[0].digest_scope == "bytes_10_to_16"


def test_configurable_offset_and_boundary_detect_tail_difference(tmp_path):
    first = b"ignored-prefix-match"
    second = b"ignored-DIFFERENT"
    first_evidence = write_evidence(tmp_path, "E-offset-1", first)
    second_evidence = write_evidence(tmp_path, "E-offset-2", second)
    rule = AmcacheHashRule(offset=7, max_bytes=6)
    entries = [
        {
            "sha1": hashlib.sha1(first[7:13]).hexdigest(),
            "windows_generation": "custom",
        },
        {
            "sha1": hashlib.sha1(first[7:13]).hexdigest(),
            "windows_generation": "custom",
        },
    ]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-offset-1": first_evidence, "E-offset-2": second_evidence},
        hash_rules={"custom": rule},
        entry_evidence_ids={0: "E-offset-1", 1: "E-offset-2"},
    )

    assert results[0].status == STATUS_MATCH
    assert results[1].status == STATUS_MISMATCH
    assert results[1].hashed_offset == 7
    assert results[1].hashed_length == 6
    assert results[1].digest_scope == "bytes_7_to_13"


def test_rule_resolver_can_use_caller_supplied_entry_metadata(tmp_path):
    content = b"custom-rule-content"
    evidence = write_evidence(tmp_path, "E-resolver", content)
    entries = [{"sha1": hashlib.sha1(content[:5]).hexdigest(), "collection_profile": "segment"}]

    def resolver(entry):
        if entry.get("collection_profile") == "segment":
            return AmcacheHashRule(max_bytes=5)
        return None

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-resolver": evidence},
        hash_rules={},
        entry_evidence_ids={0: "E-resolver"},
        rule_resolver=resolver,
    )

    assert results[0].status == STATUS_MATCH
    assert results[0].hashed_length == 5


def test_rule_can_strip_caller_declared_digest_prefix(tmp_path):
    content = b"prefix-rule"
    evidence = write_evidence(tmp_path, "E-prefix", content)
    entries = [{"sha1": "0000" + hashlib.sha1(content).hexdigest(), "windows_generation": "prefixed"}]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-prefix": evidence},
        hash_rules={"prefixed": AmcacheHashRule(strip_hex_prefix_chars=4)},
        entry_evidence_ids={0: "E-prefix"},
    )

    assert results[0].status == STATUS_MATCH
    assert results[0].original_digest.startswith("0000")


def test_invalid_rule_boundary_is_rejected():
    with pytest.raises(ValueError):
        AmcacheHashRule(max_bytes=0)


def test_rule_prefix_longer_than_digest_is_rejected(tmp_path):
    evidence = write_evidence(tmp_path, "E-bad-prefix", b"bad-prefix")
    entries = [{"sha1": "abcd", "windows_generation": "bad-prefix"}]

    with pytest.raises(ValueError):
        verify_amcache_evidence(
            entries=entries,
            evidence_files={"E-bad-prefix": evidence},
            hash_rules={"bad-prefix": AmcacheHashRule(strip_hex_prefix_chars=4)},
            entry_evidence_ids={0: "E-bad-prefix"},
        )


def test_missing_evidence_and_missing_digest_are_reported_per_entry(tmp_path):
    content = b"available"
    evidence = write_evidence(tmp_path, "E-available", content)
    entries = [
        {"sha1": hashlib.sha1(content).hexdigest(), "windows_generation": "known"},
        {"sha1": hashlib.sha1(content).hexdigest(), "windows_generation": "known"},
        {"file_size": 3, "windows_generation": "known"},
    ]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-available": evidence},
        hash_rules={"known": AmcacheHashRule()},
        entry_evidence_ids={0: "E-available", 1: "E-missing"},
    )

    assert results[0].status == STATUS_MATCH
    assert results[1].status == STATUS_MISSING_EVIDENCE
    assert results[1].local_path is None
    assert results[2].status == STATUS_NO_DIGEST
    assert results[2].findings == ["Amcache entry does not contain a digest"]


def test_registry_windows_path_is_not_used_as_local_path(tmp_path):
    content = b"evidence-only"
    evidence = write_evidence(tmp_path, "E-safe", content)
    entries = [
        {
            "sha1": hashlib.sha1(content).hexdigest(),
            "full_path": r"C:\Windows\System32\does-not-exist.exe",
            "windows_generation": "safe",
        }
    ]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-safe": evidence},
        hash_rules={"safe": AmcacheHashRule()},
        entry_evidence_ids={0: "E-safe"},
    )

    assert results[0].status == STATUS_MATCH
    assert Path(results[0].local_path) == tmp_path / "E-safe"


def test_amcache_plugin_preserves_numeric_and_file_id_source_without_changing_default_output(tmp_path):
    hive_path = tmp_path / "amcache.hve"
    hive_path.write_bytes(lzma.open(AMCACHE_HIVE_PATH).read())

    default_plugin = AmCachePlugin(RegistryHive(hive_path), as_json=True)
    source_plugin = AmCachePlugin(RegistryHive(hive_path), as_json=True, include_evidence_source=True)
    default_plugin.run()
    source_plugin.run()

    assert default_plugin.entries == [
        {key: value for key, value in entry.items() if key != "amcache_source"} for entry in source_plugin.entries
    ]

    sourced_entries = [entry for entry in source_plugin.entries if entry["amcache_source"]["hash_sources"]]
    numeric_entries = [
        entry
        for entry in sourced_entries
        if any(source["source_format"] == "numeric" for source in entry["amcache_source"]["hash_sources"])
    ]
    file_id_entries = [
        entry
        for entry in sourced_entries
        if any(source["source_format"] == "file_id" for source in entry["amcache_source"]["hash_sources"])
    ]

    assert len(sourced_entries) == 1367
    assert len(numeric_entries) == 1120
    assert len(file_id_entries) == 247
    assert all(entry["amcache_source"]["registry_key_path"].startswith("\\Root\\") for entry in sourced_entries)
    assert all(entry["amcache_source"]["numeric_value_sources"] for entry in numeric_entries)
    assert all(
        source["raw_value"].startswith("0000")
        for entry in numeric_entries
        for source in entry["amcache_source"]["hash_sources"]
        if source["source_format"] == "numeric"
    )
    assert all(
        source["raw_value"].startswith("0000") and source["strip_prefix_chars"] == 4
        for entry in file_id_entries
        for source in entry["amcache_source"]["hash_sources"]
        if source["source_format"] == "file_id"
    )


def test_duplicate_amcache_declarations_remain_separate_evidence_records(tmp_path):
    content = b"duplicate-declaration"
    digest = hashlib.sha1(content).hexdigest()
    first_evidence = write_evidence(tmp_path, "E-dup-1", content)
    second_evidence = write_evidence(tmp_path, "E-dup-2", content)
    shared_source = {
        "registry_key_path": r"\Root\File\volume\record",
        "windows_generations": ["root_file"],
        "numeric_value_sources": [],
        "hash_sources": [
            {
                "source_format": "file_id",
                "registry_value_name": "FileId",
                "output_field": "file_id",
                "raw_value": "0000" + digest,
                "normalized_value": digest,
            },
            {
                "source_format": "file_id",
                "registry_value_name": "FileId",
                "output_field": "sha1",
                "raw_value": "0000" + digest,
                "normalized_value": digest,
                "copied_from_file_id": True,
            },
        ],
    }
    entries = [
        {"sha1": digest, "amcache_source": shared_source},
        {"sha1": digest, "amcache_source": dict(shared_source)},
    ]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-dup-1": first_evidence, "E-dup-2": second_evidence},
        hash_rules={"root_file": AmcacheHashRule()},
        entry_evidence_ids={0: "E-dup-1", 1: "E-dup-2"},
    )

    assert [result.entry_index for result in results] == [0, 1]
    assert [result.evidence_id for result in results] == ["E-dup-1", "E-dup-2"]
    assert all(result.status == STATUS_MATCH for result in results)
    assert all(len(result.source["hash_sources"]) == 2 for result in results)


def test_plugin_generation_source_selects_caller_hash_rule(tmp_path):
    content = b"generation-selected"
    evidence = write_evidence(tmp_path, "E-generation", content)
    entries = [
        {
            "sha1": hashlib.sha1(content[:9]).hexdigest(),
            "amcache_source": {
                "registry_key_path": r"\Root\File\volume\record",
                "windows_generations": ["root_file"],
                "hash_sources": [
                    {
                        "source_format": "numeric",
                        "registry_value_name": "101",
                        "output_field": "sha1",
                        "raw_value": "0000" + hashlib.sha1(content[:9]).hexdigest(),
                        "normalized_value": hashlib.sha1(content[:9]).hexdigest(),
                    }
                ],
            },
        }
    ]

    results = verify_amcache_evidence(
        entries=entries,
        evidence_files={"E-generation": evidence},
        hash_rules={"root_file": AmcacheHashRule(max_bytes=9)},
        entry_evidence_ids={0: "E-generation"},
    )

    assert results[0].status == STATUS_MATCH
    assert results[0].windows_generation == "root_file"
    assert results[0].original_digest_source == "sha1"
    assert results[0].original_digest_raw.startswith("0000")


def test_plugin_exposes_callable_evidence_verification(tmp_path):
    hive_path = tmp_path / "amcache.hve"
    hive_path.write_bytes(lzma.open(AMCACHE_HIVE_PATH).read())
    plugin = AmCachePlugin(RegistryHive(hive_path), as_json=True, include_evidence_source=True)
    plugin.run()

    content = b"plugin-method"
    evidence_path = tmp_path / "E-plugin-method"
    evidence_path.write_bytes(content)
    first_entry = plugin.entries[0]
    first_entry["sha1"] = hashlib.sha1(content).hexdigest()
    generation = first_entry["amcache_source"]["windows_generations"][0]

    results = plugin.verify_evidence(
        evidence_files={"E-plugin-method": AmcacheEvidenceFile("E-plugin-method", evidence_path)},
        hash_rules={generation: AmcacheHashRule()},
        entry_evidence_ids={0: "E-plugin-method"},
    )

    assert results[0].status == STATUS_MATCH
    assert results[0].entry_index == 0
