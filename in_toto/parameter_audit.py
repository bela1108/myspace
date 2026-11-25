# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Read-only comparison helpers for parameterized in-toto links.

The helpers in this module support forensic comparison of two signed links
that may record the same command template with different parameter or option
names.  They deliberately never execute a link command and never mutate loaded
metadata.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Optional, Union

import securesystemslib.exceptions

from in_toto.exceptions import SignatureVerificationError
from in_toto.models.link import Link
from in_toto.models.metadata import Metadata

SCHEMA_VERSION = "in-toto/parameter-audit/v1"

PROVEN_EQUIVALENT = "proven_equivalent"
NOT_EQUIVALENT = "not_equivalent"

SIGNATURES_VERIFIED = "verified"
SIGNATURES_INVALID = "invalid"
SIGNATURES_NOT_VERIFIED = "not_verified"

_PLACEHOLDER_RE = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")

MetadataSource = Union[str, os.PathLike[str], Metadata]
VerificationKeys = Optional[Union[Mapping[str, Any], list[Mapping[str, Any]]]]


def _key_list(verification_keys: VerificationKeys) -> list[dict[str, Any]]:
    """Normalize either one key, a key mapping, or a list of keys."""
    if verification_keys is None:
        return []

    if isinstance(verification_keys, Mapping):
        if "keyid" in verification_keys and "keytype" in verification_keys:
            return [dict(verification_keys)]
        return [dict(key) for key in verification_keys.values()]

    return [dict(key) for key in verification_keys]


def _signature_keyids(metadata: Metadata) -> list[str]:
    """Return signature key ids for both traditional and DSSE metadata."""
    signatures = getattr(metadata, "signatures", [])

    if isinstance(signatures, Mapping):
        return sorted(str(keyid) for keyid in signatures)

    keyids = []
    for signature in signatures:
        if isinstance(signature, Mapping):
            keyid = signature.get("keyid")
        else:
            keyid = getattr(signature, "keyid", None)
        if keyid is not None:
            keyids.append(str(keyid))
    return sorted(set(keyids))


def verify_link_signatures(
    metadata: Metadata,
    verification_keys: VerificationKeys = None,
) -> dict[str, Any]:
    """Verify a loaded link without modifying it.

    When no verification keys are supplied, signatures are reported but marked
    as not verified.  A forensic equivalence verdict can therefore never be
    *proven* equivalent based on signature key ids alone.
    """
    claimed_keyids = _signature_keyids(metadata)
    keys = _key_list(verification_keys)

    if not keys:
        return {
            "status": SIGNATURES_NOT_VERIFIED,
            "verified": None,
            "claimed_keyids": claimed_keyids,
            "verified_keyids": [],
            "errors": [],
        }

    verified_keyids: list[str] = []
    errors: list[dict[str, str]] = []

    for key in keys:
        keyid = str(key.get("keyid", ""))
        try:
            metadata.verify_signature(key)
        except (
            SignatureVerificationError,
            securesystemslib.exceptions.Error,
            KeyError,
            ValueError,
        ) as exc:
            errors.append({"keyid": keyid, "error": str(exc)})
        else:
            verified_keyids.append(keyid)

    return {
        "status": (
            SIGNATURES_VERIFIED if verified_keyids else SIGNATURES_INVALID
        ),
        "verified": bool(verified_keyids),
        "claimed_keyids": claimed_keyids,
        "verified_keyids": sorted(set(verified_keyids)),
        "errors": errors,
    }


def load_signed_link(
    source: MetadataSource,
    verification_keys: VerificationKeys = None,
) -> dict[str, Any]:
    """Load a link from disk or metadata object and verify its signatures."""
    if isinstance(source, Metadata):
        metadata = source
        source_path: Optional[str] = None
    else:
        source_path = os.fspath(source)
        metadata = Metadata.load(source_path)

    link = metadata.get_payload()
    if not isinstance(link, Link):
        raise TypeError(f"{source_path or '<metadata>'} does not contain a link")

    signatures = verify_link_signatures(metadata, verification_keys)
    return {
        "path": source_path,
        "metadata": metadata,
        "link": link,
        "signatures": signatures,
    }


def _rename_placeholder(token: str, parameter_aliases: Mapping[str, str]) -> str:
    """Rename simple ``{parameter}`` placeholders without substituting them."""

    def replace(match: re.Match[str]) -> str:
        name = match.group(0)[1:-1]
        canonical_name = parameter_aliases.get(name, name)
        return "{" + canonical_name + "}"

    return _PLACEHOLDER_RE.sub(replace, token)


def _reverse_substitute(
    token: str,
    template_values: Mapping[str, str],
) -> str:
    """Replace concrete values with stable template placeholders."""
    for value in sorted(template_values, key=len, reverse=True):
        placeholder = template_values[value]
        if token == value:
            return placeholder

        key, separator, raw_value = token.partition("=")
        if separator and raw_value == value:
            return f"{key}={placeholder}"

    return token


def normalize_command(
    command: list[str],
    *,
    parameters: Optional[Mapping[str, str]] = None,
    parameter_aliases: Optional[Mapping[str, str]] = None,
    command_aliases: Optional[Mapping[str, str]] = None,
    template_values: Optional[Mapping[str, str]] = None,
    canonicalize_placeholders: bool = False,
) -> list[str]:
    """Return a normalized copy of a link command.

    Normalization is intentionally explicit: aliases and reverse substitutions
    must be supplied by the forensic analyst.  This avoids silently treating
    unrelated options as equivalent.
    """
    if not isinstance(command, list):
        raise TypeError("command must be a list of strings")

    normalized: list[str] = []
    for original_token in command:
        if not isinstance(original_token, str):
            raise TypeError("command tokens must be strings")

        token = original_token

        if parameter_aliases:
            token = _rename_placeholder(token, parameter_aliases)

        if parameters is not None:
            token = token.format(**dict(parameters))

        if command_aliases:
            if token in command_aliases:
                token = command_aliases[token]
            else:
                key, separator, value = token.partition("=")
                if separator and key in command_aliases:
                    token = f"{command_aliases[key]}={value}"

        if template_values:
            token = _reverse_substitute(token, template_values)

        if canonicalize_placeholders:
            token = _PLACEHOLDER_RE.sub("{}", token)

        normalized.append(token)

    return normalized


def _canonical_artifacts(
    artifacts: Mapping[str, Mapping[str, str]],
    path_aliases: Optional[Mapping[str, str]] = None,
) -> dict[str, dict[str, str]]:
    """Canonicalize artifact paths and hash algorithm ordering."""
    canonical: dict[str, dict[str, str]] = {}
    aliases = path_aliases or {}

    for path, hashes in artifacts.items():
        canonical_path = aliases.get(path, path)
        canonical_hashes = {name: hashes[name] for name in sorted(hashes)}

        existing = canonical.get(canonical_path)
        if existing is not None and existing != canonical_hashes:
            raise ValueError(
                f"path alias collision for '{canonical_path}' has conflicting hashes"
            )
        canonical[canonical_path] = canonical_hashes

    return {path: canonical[path] for path in sorted(canonical)}


def digest_fingerprints(
    artifacts: Mapping[str, Mapping[str, str]],
) -> list[str]:
    """Return algorithm-qualified digests independent of artifact paths."""
    fingerprints = set()
    for hashes in artifacts.values():
        for algorithm, digest in hashes.items():
            fingerprints.add(f"{algorithm}:{digest}")
    return sorted(fingerprints)


def compare_artifacts(
    left: Mapping[str, Mapping[str, str]],
    right: Mapping[str, Mapping[str, str]],
    *,
    path_aliases: Optional[Mapping[str, str]] = None,
) -> dict[str, Any]:
    """Compare artifact records, paths, and content digests."""
    left_canonical = _canonical_artifacts(left, path_aliases)
    right_canonical = _canonical_artifacts(right, path_aliases)

    left_paths = set(left_canonical)
    right_paths = set(right_canonical)
    missing_on_left = sorted(right_paths - left_paths)
    missing_on_right = sorted(left_paths - right_paths)

    hash_mismatches = []
    for path in sorted(left_paths & right_paths):
        if left_canonical[path] != right_canonical[path]:
            hash_mismatches.append(
                {
                    "path": path,
                    "left": left_canonical[path],
                    "right": right_canonical[path],
                }
            )

    left_digests = digest_fingerprints(left_canonical)
    right_digests = digest_fingerprints(right_canonical)
    records_equal = left_canonical == right_canonical
    complete = bool(left_canonical) and bool(right_canonical)

    return {
        "match": records_equal and complete,
        "records_equal": records_equal,
        "complete": complete,
        "path_aliases": dict(path_aliases or {}),
        "left": left_canonical,
        "right": right_canonical,
        "left_digests": left_digests,
        "right_digests": right_digests,
        "digest_sets_match": left_digests == right_digests,
        "missing_on_left": missing_on_left,
        "missing_on_right": missing_on_right,
        "hash_mismatches": hash_mismatches,
    }


def compare_step_identity(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    require_signer_overlap: bool = False,
) -> dict[str, Any]:
    """Compare link type, step name, and signing identities."""
    left_link: Link = left["link"]
    right_link: Link = right["link"]
    name_match = left_link.name == right_link.name

    left_keyids = set(left["signatures"]["verified_keyids"])
    right_keyids = set(right["signatures"]["verified_keyids"])
    if not left_keyids:
        left_keyids = set(left["signatures"]["claimed_keyids"])
    if not right_keyids:
        right_keyids = set(right["signatures"]["claimed_keyids"])

    signer_overlap = bool(left_keyids & right_keyids)
    match = name_match and (not require_signer_overlap or signer_overlap)

    return {
        "match": match,
        "type": "link",
        "left_name": left_link.name,
        "right_name": right_link.name,
        "name_match": name_match,
        "require_signer_overlap": require_signer_overlap,
        "signer_overlap": signer_overlap,
        "left_signer_keyids": sorted(left_keyids),
        "right_signer_keyids": sorted(right_keyids),
    }


def _command_check(
    left_link: Link,
    right_link: Link,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    common_parameters = policy.get("parameters")
    left_parameters = policy.get("left_parameters", common_parameters)
    right_parameters = policy.get("right_parameters", common_parameters)
    common_template_values = policy.get("template_values")
    left_template_values = policy.get(
        "left_template_values", common_template_values
    )
    right_template_values = policy.get(
        "right_template_values", common_template_values
    )

    normalize_kwargs = {
        "parameter_aliases": policy.get("parameter_aliases"),
        "command_aliases": policy.get("command_aliases"),
        "canonicalize_placeholders": policy.get(
            "canonicalize_placeholders", False
        ),
    }

    left_normalized = normalize_command(
        left_link.command,
        parameters=left_parameters,
        template_values=None,
        **normalize_kwargs,
    )
    right_normalized = normalize_command(
        right_link.command,
        parameters=right_parameters,
        template_values=None,
        **normalize_kwargs,
    )

    left_template = normalize_command(
        left_link.command,
        parameters=left_parameters,
        template_values=left_template_values,
        **normalize_kwargs,
    )
    right_template = normalize_command(
        right_link.command,
        parameters=right_parameters,
        template_values=right_template_values,
        **normalize_kwargs,
    )

    return {
        "match": left_normalized == right_normalized,
        "template_match": left_template == right_template,
        "left_raw": list(left_link.command),
        "right_raw": list(right_link.command),
        "left_normalized": left_normalized,
        "right_normalized": right_normalized,
        "left_template": left_template,
        "right_template": right_template,
    }


def _signature_check(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_status = left["signatures"]
    right_status = right["signatures"]
    keys_supplied = (
        left_status["status"] != SIGNATURES_NOT_VERIFIED
        or right_status["status"] != SIGNATURES_NOT_VERIFIED
    )
    verified = (
        left_status["status"] == SIGNATURES_VERIFIED
        and right_status["status"] == SIGNATURES_VERIFIED
    )
    return {
        "match": verified if keys_supplied else False,
        "proven": verified,
        "keys_supplied": keys_supplied,
        "left": left_status,
        "right": right_status,
    }


def _build_findings(checks: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if not checks["signatures"]["proven"]:
        code = (
            "SIGNATURE_UNVERIFIED"
            if checks["signatures"]["keys_supplied"]
            else "SIGNATURE_KEYS_NOT_PROVIDED"
        )
        findings.append(
            {
                "code": code,
                "message": "Both signed links must verify against trusted keys for provenance to be proven.",
            }
        )

    if not checks["step_identity"]["match"]:
        findings.append(
            {
                "code": "STEP_IDENTITY_MISMATCH",
                "message": "Links do not identify the same in-toto step/signer identity.",
            }
        )

    command = checks["normalized_command"]
    if not command["match"]:
        findings.append(
            {
                "code": "COMMAND_MISMATCH",
                "message": "Normalized commands differ; aliases/substitutions do not prove one template.",
            }
        )
    elif not command["template_match"]:
        findings.append(
            {
                "code": "COMMAND_TEMPLATE_MISMATCH",
                "message": "Normalized commands match but reverse-substituted templates differ.",
            }
        )

    materials = checks["materials"]
    if not materials["complete"] or materials["missing_on_left"] or materials["missing_on_right"]:
        findings.append(
            {
                "code": "MATERIAL_PROVENANCE_MISSING",
                "message": "At least one input material digest is absent; equal products do not prove provenance.",
            }
        )
    if materials["hash_mismatches"]:
        findings.append(
            {
                "code": "MATERIAL_DIGEST_MISMATCH",
                "message": "Material paths have different content digests.",
            }
        )
    elif not materials["match"] and materials["records_equal"] is False:
        findings.append(
            {
                "code": "MATERIAL_RECORD_MISMATCH",
                "message": "Material records differ after path normalization.",
            }
        )

    if not checks["products"]["match"]:
        findings.append(
            {
                "code": "PRODUCT_MISMATCH",
                "message": "Output product records or digests do not match.",
            }
        )

    if not findings:
        findings.append(
            {"code": "PROVEN_EQUIVALENT", "message": "Links are provably equivalent."}
        )

    return findings


def _primary_reason(findings: list[dict[str, str]]) -> str:
    codes = {finding["code"] for finding in findings}
    if "STEP_IDENTITY_MISMATCH" in codes:
        return "step_identity_mismatch"
    if "COMMAND_MISMATCH" in codes or "COMMAND_TEMPLATE_MISMATCH" in codes:
        return "command_mismatch"
    if "MATERIAL_PROVENANCE_MISSING" in codes:
        return "missing_materials"
    if codes & {"MATERIAL_DIGEST_MISMATCH", "MATERIAL_RECORD_MISMATCH"}:
        return "different_materials"
    if "PRODUCT_MISMATCH" in codes:
        return "different_products"
    if codes & {"SIGNATURE_UNVERIFIED", "SIGNATURE_KEYS_NOT_PROVIDED"}:
        return "signature_unverified"
    return "equivalent"


def audit_links(
    left: MetadataSource,
    right: MetadataSource,
    *,
    verification_keys: VerificationKeys = None,
    policy: Optional[Mapping[str, Any]] = None,
    require_signer_overlap: bool = False,
) -> dict[str, Any]:
    """Compare two signed links and return a JSON-serializable audit report.

    The audit is read-only.  ``policy`` may contain ``parameters``,
    ``parameter_aliases``, ``command_aliases``, ``template_values``,
    side-specific substitution/reverse-substitution mappings, and
    ``material_path_aliases``.
    """
    policy = policy or {}
    left_record = load_signed_link(left, verification_keys)
    right_record = load_signed_link(right, verification_keys)

    checks = {
        "signatures": _signature_check(left_record, right_record),
        "step_identity": compare_step_identity(
            left_record,
            right_record,
            require_signer_overlap=require_signer_overlap
            or bool(policy.get("require_signer_overlap", False)),
        ),
        "normalized_command": _command_check(
            left_record["link"], right_record["link"], policy
        ),
        "materials": compare_artifacts(
            left_record["link"].materials,
            right_record["link"].materials,
            path_aliases=policy.get("material_path_aliases"),
        ),
        "products": compare_artifacts(
            left_record["link"].products,
            right_record["link"].products,
            path_aliases=policy.get("product_path_aliases"),
        ),
    }

    findings = _build_findings(checks)
    checks_passing = (
        checks["signatures"]["proven"]
        and checks["step_identity"]["match"]
        and checks["normalized_command"]["match"]
        and checks["normalized_command"]["template_match"]
        and checks["materials"]["match"]
        and checks["products"]["match"]
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "verdict": PROVEN_EQUIVALENT if checks_passing else NOT_EQUIVALENT,
        "equivalent": checks_passing,
        "primary_reason": (
            "equivalent" if checks_passing else _primary_reason(findings)
        ),
        "findings": findings,
        "left": {
            "path": left_record["path"],
            "step_name": left_record["link"].name,
        },
        "right": {
            "path": right_record["path"],
            "step_name": right_record["link"].name,
        },
        "checks": checks,
    }


def audit_links_to_file(
    left: MetadataSource,
    right: MetadataSource,
    report_path: Union[str, os.PathLike[str]],
    *,
    verification_keys: VerificationKeys = None,
    policy: Optional[Mapping[str, Any]] = None,
    require_signer_overlap: bool = False,
) -> dict[str, Any]:
    """Run :func:`audit_links` and atomically-ish write its JSON report."""
    report = audit_links(
        left,
        right,
        verification_keys=verification_keys,
        policy=policy,
        require_signer_overlap=require_signer_overlap,
    )
    path = Path(report_path)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def load_audit_policy(path: Union[str, os.PathLike[str]]) -> dict[str, Any]:
    """Load an explicit JSON normalization policy."""
    with open(path, encoding="utf-8") as handle:
        policy = json.load(handle)
    if not isinstance(policy, dict):
        raise ValueError("audit policy must be a JSON object")
    return policy
