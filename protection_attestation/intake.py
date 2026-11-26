"""Batch intake and reconciliation for protection parameter attestations."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .inspect import inspect_package
from .rules import RULE_PACKS, normalize_claim
from .sources import iter_tool_claims, load_json, sha256_file


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def resolve_project_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def _stable_id(*parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:10]
    return "CLM-" + digest


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _source_with_hash(source: dict[str, Any]) -> dict[str, Any]:
    artifact = source.get("artifact")
    if artifact and Path(artifact).exists() and "artifact_sha256" not in source:
        source["artifact_sha256"] = sha256_file(Path(artifact))
    return source


def make_claim(
    package_id: str,
    field: str,
    recorded_value: Any,
    source: dict[str, Any],
    ruleset_id: str,
    *,
    historical: bool = False,
) -> dict[str, Any]:
    source = _source_with_hash(dict(source))
    artifact = source.get("artifact")
    if artifact and Path(artifact).is_absolute():
        try:
            source["artifact"] = str(Path(artifact).resolve().relative_to(PROJECT_ROOT))
        except (ValueError, OSError):
            pass
    normalization = normalize_claim(
        field,
        recorded_value,
        ruleset_id,
        historical=historical,
    ).to_dict()
    locator = str(source.get("locator", ""))
    claim_id = _stable_id(package_id, field, str(source.get("source_id", "")), locator)
    return {
        "claim_id": claim_id,
        "package_id": package_id,
        "field": field,
        "recorded_value": recorded_value,
        "source": source,
        "normalization": normalization,
    }


def _approval_claims(
    package_id: str,
    approval: dict[str, Any],
    approvals_path: Path,
    ruleset_id: str,
) -> list[dict[str, Any]]:
    approval_ruleset = approval.get("ruleset_id", ruleset_id)
    historical = approval_ruleset != ruleset_id
    source_base = {
        "source_id": approval["approval_id"],
        "source_kind": "approval",
        "source_name": "Office protection parameter approval",
        "artifact": str(approvals_path),
        "artifact_sha256": sha256_file(approvals_path),
        "approval_id": approval["approval_id"],
        "approval_status": approval.get("status", "unknown"),
        "signed_at": approval.get("signed_at"),
        "adopted_ruleset_id": approval_ruleset,
    }
    claims = []
    for field, value in approval.get("accepted_parameters", {}).items():
        source = {
            **source_base,
            "locator": f"approvals[{approval['approval_id']}].accepted_parameters.{field}",
        }
        claims.append(
            make_claim(
                package_id,
                field,
                value,
                source,
                ruleset_id,
                historical=historical,
            )
        )
    return claims


def _live_claims(
    package: dict[str, Any], ruleset_id: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    inspection = inspect_package(resolve_project_path(package["path"]))
    source = {
        "source_id": f"msoffcrypto-live-{inspection['tool_version']}",
        "source_kind": "live_inspection",
        "source_name": "msoffcrypto.OfficeFile",
        "source_version": inspection["tool_version"],
        "artifact": package["path"],
        "artifact_sha256": inspection["sha256"],
        "locator": inspection["source_locator"],
        "plaintext_accessed": False,
    }
    claims = [
        make_claim(package["package_id"], field, value, source, ruleset_id)
        for field, value in inspection["parameters"].items()
    ]
    return claims, inspection


def _reconcile(package_id: str, claims: list[dict[str, Any]], actual_sha256: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for claim in claims:
        groups[claim["field"]].append(claim)

    field_rows = []
    transcription_notes = []
    protection_differences = []

    for field in sorted(groups):
        group = groups[field]
        accepted = [claim for claim in group if claim["normalization"]["accepted"]]
        rejected = [claim for claim in group if not claim["normalization"]["accepted"]]
        canonical_values = []
        for claim in accepted:
            value = claim["normalization"]["canonical_value"]
            if _json_text(value) not in {_json_text(item) for item in canonical_values}:
                canonical_values.append(value)

        raw_forms = []
        for claim in group:
            raw_form = {
                "recorded_value": claim["recorded_value"],
                "source_id": claim["source"]["source_id"],
                "source_kind": claim["source"]["source_kind"],
                "locator": claim["source"]["locator"],
                "rule_id": claim["normalization"].get("rule_id"),
                "notation_transform": claim["normalization"].get("notation_transform", False),
                "historical_compatibility": claim["normalization"].get(
                    "historical_compatibility", False
                ),
            }
            if _json_text(raw_form) not in {_json_text(item) for item in raw_forms}:
                raw_forms.append(raw_form)

        observed = [
            claim
            for claim in accepted
            if claim["source"]["source_kind"] in {"live_inspection", "tool_output"}
        ]
        live = [claim for claim in accepted if claim["source"]["source_kind"] == "live_inspection"]
        all_approval_claims = [claim for claim in group if claim["source"]["source_kind"] == "approval"]
        rejected_approvals = [
            claim for claim in all_approval_claims if not claim["normalization"]["accepted"]
        ]
        approval_claims = [claim for claim in accepted if claim["source"]["source_kind"] == "approval"]
        observed_reference = live[0] if live else (observed[0] if observed else None)
        approval = approval_claims[0] if approval_claims else None

        approval_status = "approval_missing"
        difference = None
        if rejected_approvals:
            approval_status = "normalization_rejected"
        elif approval is None:
            approval_status = "approval_missing"
        elif observed_reference is None:
            approval_status = "observed_value_missing"
        else:
            approved_value = approval["normalization"]["canonical_value"]
            observed_value = observed_reference["normalization"]["canonical_value"]
            if _json_text(approved_value) == _json_text(observed_value):
                transformed = (
                    approval["normalization"].get("notation_transform")
                    or approval["normalization"].get("historical_compatibility")
                    or _json_text(approval["recorded_value"]) != _json_text(approved_value)
                )
                approval_status = "approved_equivalent_notation" if transformed else "approved_exact"
            else:
                approval_status = "actual_difference"
                difference = {
                    "package_id": package_id,
                    "field": field,
                    "status": "needs_signed_approval",
                    "approved_value": approved_value,
                    "observed_value": observed_value,
                    "approval_id": approval["source"].get("approval_id"),
                    "approval_source": approval["source"].get("artifact"),
                    "observed_source_id": observed_reference["source"]["source_id"],
                    "observed_locator": observed_reference["source"]["locator"],
                    "rule_ids": sorted(
                        {
                            approval["normalization"].get("rule_id"),
                            observed_reference["normalization"].get("rule_id"),
                        }
                        - {None}
                    ),
                    "required_action": "Freeze prior use and obtain a newly signed approval for the changed protection parameter.",
                }
                protection_differences.append(difference)

        observed_canonical_values = []
        for claim in observed:
            observed_value = claim["normalization"]["canonical_value"]
            if _json_text(observed_value) not in {
                _json_text(item) for item in observed_canonical_values
            }:
                observed_canonical_values.append(observed_value)

        same_canonical = len(canonical_values) <= 1
        raw_distinct = len({_json_text(claim["recorded_value"]) for claim in group}) > 1
        if same_canonical and raw_distinct:
            transcription_notes.append(
                {
                    "package_id": package_id,
                    "field": field,
                    "disposition": "notation_only",
                    "canonical_value": canonical_values[0] if canonical_values else None,
                    "raw_forms": raw_forms,
                    "rule_ids": sorted(
                        {
                            claim["normalization"].get("rule_id")
                            for claim in group
                            if claim["normalization"].get("rule_id")
                        }
                    ),
                    "conclusion": "Recorded notation differs, but normalized protection value is identical; transcription note only.",
                }
            )

        if len(observed_canonical_values) > 1:
            protection_differences.append(
                {
                    "package_id": package_id,
                    "field": field,
                    "status": "source_canonical_conflict",
                    "canonical_values": observed_canonical_values,
                    "conclusion": "Sources remain inconsistent after normalization; intake must not choose silently.",
                }
            )

        field_rows.append(
            {
                "package_id": package_id,
                "field": field,
                "canonical_values": canonical_values,
                "canonical_consistent": len(canonical_values) <= 1,
                "raw_distinct": raw_distinct,
                "approval_status": approval_status,
                "approval_id": approval["source"].get("approval_id") if approval else None,
                "difference": difference,
                "rejected_claim_ids": [claim["claim_id"] for claim in rejected],
                "claim_ids": [claim["claim_id"] for claim in group],
            }
        )

    return {
        "package_id": package_id,
        "actual_sha256": actual_sha256,
        "fields": field_rows,
        "transcription_notes": transcription_notes,
        "protection_differences": [
            item for item in protection_differences if item.get("status") == "needs_signed_approval"
        ],
        "source_conflicts": [
            item for item in protection_differences if item.get("status") == "source_canonical_conflict"
        ],
    }


def evaluate_review_cases(config: dict[str, Any], reconciliations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_package = {item["package_id"]: item for item in reconciliations}
    results = []
    for case in config.get("review_cases", []):
        package_id = case["package_id"]
        package_result = by_package[package_id]
        focus_fields = set(case.get("focus_fields", []))
        notes = [
            note
            for note in package_result["transcription_notes"]
            if not focus_fields or note["field"] in focus_fields
        ]
        differences = [
            diff
            for diff in package_result["protection_differences"]
            if not focus_fields or diff["field"] in focus_fields
        ]
        if case["expected_disposition"] == "notation_only":
            actual = "notation_only" if notes and not differences else "unexpected_actual_difference"
            verified = actual == "notation_only"
        elif case["expected_disposition"] == "actual_update":
            actual = (
                "actual_update_requires_reapproval"
                if differences
                and all(diff["status"] == "needs_signed_approval" for diff in differences)
                else "not_detected"
            )
            verified = actual == "actual_update_requires_reapproval"
        else:
            actual = "unknown_case_type"
            verified = False
        results.append(
            {
                **case,
                "actual_disposition": actual,
                "verified": verified,
                "matching_transcription_note_count": len(notes),
                "matching_difference_count": len(differences),
            }
        )
    return results


def run_batch(config_path: str | Path) -> dict[str, Any]:
    config_path = Path(config_path)
    config = load_json(config_path)
    ruleset_id = config["ruleset_id"]
    if ruleset_id not in RULE_PACKS:
        raise ValueError(f"Unknown ruleset: {ruleset_id}")

    approvals_path = resolve_project_path(config["approvals"])
    approvals_document = load_json(approvals_path)
    approvals = {item["package_id"]: item for item in approvals_document["approvals"]}

    claims: list[dict[str, Any]] = []
    artifact_checks: list[dict[str, Any]] = []
    reconciliations: list[dict[str, Any]] = []

    for package in config["packages"]:
        package_id = package["package_id"]
        live_claims, inspection = _live_claims(package, ruleset_id)
        actual_sha256 = inspection["sha256"]
        claims.extend(live_claims)
        claims.extend(_approval_claims(package_id, approvals[package_id], approvals_path, ruleset_id))

        seen_artifact_checks = set()
        for output_ref in config.get("tool_outputs", []):
            output_path = resolve_project_path(output_ref)
            for raw_claim in iter_tool_claims(output_path):
                if raw_claim["package_id"] != package_id:
                    continue
                claims.append(
                    make_claim(
                        raw_claim["package_id"],
                        raw_claim["field"],
                        raw_claim["recorded_value"],
                        raw_claim["source"],
                        ruleset_id,
                    )
                )
                recorded_sha256 = raw_claim.get("recorded_file_sha256")
                check_key = (raw_claim["source"]["source_id"], package_id)
                if recorded_sha256 and check_key not in seen_artifact_checks:
                    seen_artifact_checks.add(check_key)
                    artifact_checks.append(
                        {
                            "package_id": package_id,
                            "source_id": raw_claim["source"]["source_id"],
                            "recorded_sha256": recorded_sha256,
                            "actual_sha256": actual_sha256,
                            "status": "verified" if recorded_sha256 == actual_sha256 else "hash_mismatch",
                            "rule": {
                                "rule_id": "integrity.sha256_exact",
                                "rule_version": "1.0",
                                "accepted_form": "64 lowercase hexadecimal SHA-256 digest",
                            },
                        }
                    )

        package_claims = [claim for claim in claims if claim["package_id"] == package_id]
        reconciliation = _reconcile(package_id, package_claims, actual_sha256)
        reconciliation["approval_id"] = approvals[package_id]["approval_id"]
        reconciliation["package_path"] = package["path"]
        reconciliations.append(reconciliation)

    review_cases = evaluate_review_cases(config, reconciliations)
    all_notes = [note for item in reconciliations for note in item["transcription_notes"]]
    all_differences = [diff for item in reconciliations for diff in item["protection_differences"]]
    reapproval_queue = [diff for diff in all_differences if diff.get("status") == "needs_signed_approval"]
    source_conflicts = [conflict for item in reconciliations for conflict in item["source_conflicts"]]
    rejected_claims = [claim for claim in claims if not claim["normalization"]["accepted"]]

    return {
        "batch_id": config["batch_id"],
        "title": config.get("title", config["batch_id"]),
        "ruleset_id": ruleset_id,
        "ruleset": RULE_PACKS[ruleset_id],
        "config_path": str(config_path),
        "plaintext_accessed": False,
        "summary": {
            "package_count": len(config["packages"]),
            "claim_count": len(claims),
            "artifact_check_count": len(artifact_checks),
            "transcription_note_count": len(all_notes),
            "protection_difference_count": len(all_differences),
            "reapproval_required_count": len(reapproval_queue),
            "source_conflict_count": len(source_conflicts),
            "rejected_claim_count": len(rejected_claims),
            "review_case_count": len(review_cases),
            "review_cases_verified": all(case["verified"] for case in review_cases),
        },
        "artifact_checks": artifact_checks,
        "review_cases": review_cases,
        "transcription_notes": all_notes,
        "protection_differences": all_differences,
        "reapproval_queue": reapproval_queue,
        "source_conflicts": source_conflicts,
        "rejected_claims": rejected_claims,
        "reconciliations": reconciliations,
        "claims": claims,
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + chr(10),
        encoding="utf-8",
    )


def write_ledger_csv(path: Path, claims: list[dict[str, Any]]) -> None:
    fieldnames = [
        "claim_id",
        "package_id",
        "field",
        "recorded_value_json",
        "accepted",
        "canonical_value_json",
        "ruleset_id",
        "rule_id",
        "rule_version",
        "notation_transform",
        "historical_compatibility",
        "source_kind",
        "source_id",
        "source_name",
        "artifact",
        "locator",
        "approval_id",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for claim in claims:
            norm = claim["normalization"]
            source = claim["source"]
            writer.writerow(
                {
                    "claim_id": claim["claim_id"],
                    "package_id": claim["package_id"],
                    "field": claim["field"],
                    "recorded_value_json": _json_text(claim["recorded_value"]),
                    "accepted": norm["accepted"],
                    "canonical_value_json": _json_text(norm.get("canonical_value")),
                    "ruleset_id": norm["ruleset_id"],
                    "rule_id": norm.get("rule_id"),
                    "rule_version": norm.get("rule_version"),
                    "notation_transform": norm.get("notation_transform"),
                    "historical_compatibility": norm.get("historical_compatibility"),
                    "source_kind": source.get("source_kind"),
                    "source_id": source.get("source_id"),
                    "source_name": source.get("source_name"),
                    "artifact": source.get("artifact"),
                    "locator": source.get("locator"),
                    "approval_id": source.get("approval_id", ""),
                }
            )
