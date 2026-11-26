#!/usr/bin/env python3
"""Read-only AssemblyRef to sealed deliverable reconciliation.

The tool only parses PE/CLR metadata with dnfile.  It never loads or executes
an assembly.  Complete assembly identities constrain candidates first; an
independent sealing manifest is then used to attach custody records and verify
artifact digests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if SRC_DIR.is_dir() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import dnfile  # noqa: E402


HEX = "0123456789abcdef"


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _heap_native(value: Any) -> Any:
    """Unwrap dnfile HeapItem wrappers into str/bytes when available."""
    if hasattr(value, "value"):
        native = getattr(value, "value")
        if native is not None:
            return native
        value_bytes = getattr(value, "value_bytes", None)
        if callable(value_bytes):
            try:
                return value_bytes()
            except Exception:
                return None
    return value


def _hex(data: Optional[bytes]) -> Optional[str]:
    if not data:
        return None
    return bytes(data).hex()


def parse_hex_bytes(value: Any) -> Tuple[Optional[bytes], Optional[str]]:
    """Parse bytes or a hexadecimal string.

    Returns ``(value, issue)``.  A missing value is distinct from an invalid
    value so reports can distinguish evidence gaps from malformed evidence.
    """
    if value is None:
        return None, "missing"
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return (raw if raw else None), ("missing" if not raw else None)
    if not isinstance(value, str):
        return None, "invalid"
    text = value.strip().replace("0x", "").replace("-", "").replace(":", "").replace(" ", "")
    if not text or text.lower() == "null":
        return None, "missing"
    if len(text) % 2 or any(ch.lower() not in HEX for ch in text):
        return None, "invalid"
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None, "invalid"
    return raw, None


def public_key_token(public_key: Optional[bytes]) -> Optional[bytes]:
    """Return the ECMA-335 public key token (reversed low SHA-1 bytes)."""
    if not public_key:
        return None
    digest = hashlib.sha1(public_key).digest()
    return digest[-8:][::-1]


def normalize_version(value: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "raw": value,
        "parts": None,
        "canonical": None,
        "complete": False,
        "issues": [],
    }
    if value is None:
        result["issues"].append("version_missing")
        result["raw"] = None
        return result

    parts: List[Optional[int]] = []
    if isinstance(value, str):
        if not value.strip():
            result["issues"].append("version_missing")
            result["raw"] = ""
            return result
        raw_parts = value.split(".")
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        raw_parts = list(value)
    else:
        result["issues"].append("version_invalid")
        return result

    valid = True
    for item in raw_parts[:4]:
        if item is None:
            parts.append(None)
            continue
        try:
            number = int(item)
        except (TypeError, ValueError):
            valid = False
            continue
        if number < 0 or number > 0xFFFF:
            valid = False
        parts.append(number)

    while len(parts) < 4 and len(raw_parts) < 4:
        parts.append(None)

    if len(raw_parts) > 4 or not valid:
        result["issues"].append("version_invalid")
    if any(part is None for part in parts) or len(parts) != 4:
        result["issues"].append("version_incomplete")

    result["parts"] = parts[:4]
    if len(parts) == 4 and all(isinstance(part, int) for part in parts):
        result["canonical"] = ".".join(str(part) for part in parts)
        result["complete"] = "version_invalid" not in result["issues"] and all(
            0 <= part <= 0xFFFF for part in parts if isinstance(part, int)
        )
    return result


def normalize_culture(value: Any) -> Dict[str, Any]:
    if value is None:
        return {"raw": None, "canonical": None, "label": None, "present": False, "issue": "culture_missing"}
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return {"raw": _hex(bytes(value)), "canonical": None, "label": None, "present": False, "issue": "culture_invalid"}
    if not isinstance(value, str):
        return {"raw": repr(value), "canonical": None, "label": None, "present": False, "issue": "culture_invalid"}

    text = value.strip().replace("_", "-").casefold()
    if text in ("", "neutral"):
        return {"raw": value, "canonical": "", "label": "neutral", "present": True, "issue": None}
    return {"raw": value, "canonical": text, "label": text, "present": True, "issue": None}


def _flags_says_full_key(flags: Any, struct_flags: Any = None) -> bool:
    af_public = _get(flags, "afPublicKey")
    if isinstance(af_public, bool):
        return af_public
    if isinstance(flags, int):
        return bool(flags & 0x0001)
    struct_value = _get(struct_flags, "Flags")
    if isinstance(struct_value, int):
        return bool(struct_value & 0x0001)
    return False


def interpret_key(
    blob: Any,
    flags: Any = None,
    struct_flags: Any = None,
    force_full_public_key: bool = False,
) -> Dict[str, Any]:
    raw, issue = parse_hex_bytes(blob)
    if issue == "missing" or raw is None:
        return {"present": False, "token": None, "token_hex": None, "kind": None, "issues": ["public_key_identity_missing"]}
    if issue == "invalid":
        return {"present": False, "token": None, "token_hex": None, "kind": None, "issues": ["public_key_identity_invalid"]}

    is_full = force_full_public_key or _flags_says_full_key(flags, struct_flags)
    if is_full:
        token = public_key_token(raw)
        return {
            "present": True,
            "token": token,
            "token_hex": _hex(token),
            "kind": "full_public_key",
            "blob_sha256": hashlib.sha256(raw).hexdigest(),
            "issues": [],
        }

    if len(raw) == 8:
        return {
            "present": True,
            "token": raw,
            "token_hex": _hex(raw),
            "kind": "public_key_token",
            "issues": [],
        }

    return {
        "present": False,
        "token": None,
        "token_hex": None,
        "kind": "unrecognized_blob",
        "blob_sha256": hashlib.sha256(raw).hexdigest(),
        "issues": ["public_key_identity_not_legal_token"],
    }


def _row_file_offset(row: Any) -> Optional[int]:
    struct = _get(row, "struct")
    getter = _get(struct, "get_file_offset")
    if callable(getter):
        try:
            offset = getter()
            return int(offset) if offset is not None else None
        except Exception:
            return None
    return None


def table_evidence(row: Any, table_name: str, row_number: int) -> Dict[str, Any]:
    struct = _get(row, "struct")
    evidence: Dict[str, Any] = {
        "table": table_name,
        "row": row_number,
        "file_offset": _row_file_offset(row),
    }
    for key in (
        "MajorVersion",
        "MinorVersion",
        "BuildNumber",
        "RevisionNumber",
        "Flags",
        "PublicKey_BlobIndex",
        "Name_StringIndex",
        "Culture_StringIndex",
        "HashValue_BlobIndex",
    ):
        value = _get(struct, key)
        if isinstance(value, (int, str)) or value is None:
            evidence[_snake_case(key)] = value
    return evidence


def _snake_case(name: str) -> str:
    out: List[str] = []
    for ch in name:
        if ch.isupper() and out:
            out.append("_")
        out.append(ch.lower())
    return "".join(out).replace("__", "_")


def identity_from_row(row: Any, table_name: str, row_number: int) -> Dict[str, Any]:
    name = _heap_native(_get(row, "Name"))
    if isinstance(name, bytes):
        try:
            name = name.decode("utf-8")
        except UnicodeDecodeError:
            name = None
    name = name.strip() if isinstance(name, str) else None

    version = normalize_version(
        (
            _get(row, "MajorVersion"),
            _get(row, "MinorVersion"),
            _get(row, "BuildNumber"),
            _get(row, "RevisionNumber"),
        )
    )
    culture = normalize_culture(_heap_native(_get(row, "Culture")))
    key = interpret_key(
        _heap_native(_get(row, "PublicKey")),
        _get(row, "Flags"),
        _get(row, "struct"),
        force_full_public_key=(table_name == "Assembly"),
    )

    gaps: List[str] = []
    if not name:
        gaps.append("assembly_name_missing")
    gaps.extend(version["issues"])
    if not culture["present"]:
        gaps.append(culture["issue"] or "culture_missing")
    gaps.extend(key["issues"])

    complete = (
        bool(name)
        and version["complete"]
        and culture["present"]
        and key["present"]
        and not gaps
    )
    return {
        "name": name,
        "name_key": name.casefold() if name else None,
        "version": version["canonical"],
        "version_parts": version["parts"],
        "version_complete": version["complete"],
        "culture": culture["canonical"],
        "culture_label": culture["label"],
        "culture_present": culture["present"],
        "public_key_token": key["token_hex"],
        "public_key_kind": key["kind"],
        "complete_identity": complete,
        "evidence_gaps": gaps,
        "table_evidence": table_evidence(row, table_name, row_number),
    }


def identity_from_manifest(data: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(data, dict):
        return None
    name = _first_value(data, ("name", "Name", "assembly_name", "simple_name"))
    version = normalize_version(_first_value(data, ("version", "Version", "assembly_version")))
    culture = normalize_culture(_first_value(data, ("culture", "Culture", "culture_name")))
    token_raw = _first_value(data, ("public_key_token", "PublicKeyToken", "pkt", "token"))
    token, issue = parse_hex_bytes(token_raw)
    if issue == "missing":
        token_hex = None
        key_issue = "manifest.public_key_identity_missing"
    elif issue == "invalid":
        token_hex = None
        key_issue = "manifest.public_key_identity_invalid"
    else:
        token_hex = token.hex() if token else None
        key_issue = None
        if token and len(token) != 8:
            key_issue = "manifest.public_key_token_invalid_length"
            token_hex = None

    gaps: List[str] = []
    if not name:
        gaps.append("manifest.assembly_name_missing")
    if version["issues"]:
        gaps.extend("manifest." + item for item in version["issues"])
    if not culture["present"]:
        gaps.append("manifest." + (culture["issue"] or "culture_missing"))
    if key_issue:
        gaps.append(key_issue)

    return {
        "name": name if isinstance(name, str) else None,
        "name_key": name.strip().casefold() if isinstance(name, str) and name.strip() else None,
        "version": version["canonical"],
        "version_parts": version["parts"],
        "version_complete": version["complete"],
        "culture": culture["canonical"],
        "culture_label": culture["label"],
        "culture_present": culture["present"],
        "public_key_token": token_hex,
        "complete_identity": not gaps,
        "evidence_gaps": gaps,
    }


def _first_value(data: Dict[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def read_pe_metadata(path: Path) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "path": str(path),
        "file_name": path.name,
        "metadata_available": False,
        "assembly_identity": None,
        "assembly_identities": [],
        "references": [],
        "module_name": None,
        "parse_errors": [],
        "dnfile_warnings": [],
    }
    pe = None
    try:
        pe = dnfile.dnPE(str(path))
    except Exception as exc:  # forensic tool must report unreadable evidence
        record["parse_errors"].append(f"{type(exc).__name__}: {exc}")
        return record

    try:
        record["dnfile_warnings"] = list(_get(pe, "get_warnings", list)())[:10] if callable(_get(pe, "get_warnings")) else []
        net = _get(pe, "net")
        tables = _get(net, "mdtables")
        if tables is None:
            record["parse_errors"].append("no_clr_metadata")
            return record
        record["metadata_available"] = True

        module_table = _get(tables, "Module")
        module_rows = list(module_table) if module_table is not None else []
        if module_rows:
            module_name = _heap_native(_get(module_rows[0], "Name"))
            record["module_name"] = str(module_name) if module_name is not None else None

        assembly_table = _get(tables, "Assembly")
        assembly_rows = list(assembly_table) if assembly_table is not None else []
        for index, row in enumerate(assembly_rows, start=1):
            identity = identity_from_row(row, "Assembly", index)
            record["assembly_identities"].append(identity)
        if record["assembly_identities"]:
            record["assembly_identity"] = record["assembly_identities"][0]
        else:
            record["parse_errors"].append("assembly_table_missing")

        ref_table = _get(tables, "AssemblyRef")
        ref_rows = list(ref_table) if ref_table is not None else []
        for index, row in enumerate(ref_rows, start=1):
            identity = identity_from_row(row, "AssemblyRef", index)
            record["references"].append(
                {
                    "reference_id": f"{record['module_name'] or path.name}:AssemblyRef:{index}",
                    "source_path": str(path),
                    "source_module": record["module_name"],
                    "row": index,
                    "identity": identity,
                    "evidence_gaps": identity["evidence_gaps"],
                }
            )
    finally:
        close = _get(pe, "close")
        if callable(close):
            try:
                close()
            except Exception:
                pass
    return record


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        raw_entries = data
        case_id = None
    else:
        raw_entries = _first_value(data, ("artifacts", "items", "sealed_artifacts", "files", "entries")) or []
        case_id = _first_value(data, ("case_id", "case", "archive_id", "manifest_id"))
        note = _first_value(data, ("note", "description"))
    entries = []
    for index, raw in enumerate(raw_entries, start=1):
        if not isinstance(raw, dict):
            continue
        identity_data = _first_value(raw, ("identity", "assembly_identity", "assembly"))
        entry = {
            "record_index": index,
            "seal_id": _first_value(raw, ("seal_id", "seal", "id", "bag_id", "evidence_id")),
            "path_text": _first_value(raw, ("delivery_path", "archive_path", "path", "file", "filename", "artifact_path")),
            "sealed_artifact": _first_value(raw, ("sealed_artifact", "sealed_path", "sealed_file", "sealed_item", "artifact")),
            "sha256": (_first_value(raw, ("sha256", "sha256sum", "digest", "hash")) or "").lower() or None,
            "size": _first_value(raw, ("size", "length")),
            "manifest_identity": identity_from_manifest(identity_data),
            "manifest_identity_asserted": isinstance(identity_data, dict),
        }
        if isinstance(entry["sealed_artifact"], dict):
            sealed = entry["sealed_artifact"]
            entry["sealed_artifact"] = _first_value(sealed, ("path", "file", "label", "id")) or json.dumps(sealed, ensure_ascii=False, sort_keys=True)
        entries.append(entry)
    return {"path": str(path), "case_id": case_id, "note": note, "entries": entries}


def _manifest_path_candidates(entry: Dict[str, Any], manifest_path: Path, archive_dirs: Sequence[Path]) -> List[Path]:
    text = entry.get("path_text")
    if not text:
        return []
    raw = Path(str(text))
    candidates: List[Path] = []
    if raw.is_absolute():
        candidates.append(raw)
    base_dirs = [manifest_path.parent, *archive_dirs, Path.cwd()]
    for base in base_dirs:
        candidates.append(base / raw)
        if not raw.is_absolute():
            candidates.append(base / raw.name)
    unique: List[Path] = []
    seen = set()
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved not in seen:
            seen.add(resolved)
            unique.append(candidate)
    return unique


def attach_manifest_records(
    artifacts: List[Dict[str, Any]],
    manifest: Optional[Dict[str, Any]],
    archive_dirs: Sequence[Path],
) -> None:
    if manifest is None:
        for artifact in artifacts:
            artifact["manifest"] = None
            artifact["evidence_gaps"] = sorted(set(artifact.get("evidence_gaps", []) + ["manifest_missing"]))
        return

    manifest_path = Path(manifest["path"])
    by_resolved_path: Dict[Path, Dict[str, Any]] = {}
    by_basename: Dict[str, List[Dict[str, Any]]] = {}
    for entry in manifest["entries"]:
        for candidate in _manifest_path_candidates(entry, manifest_path, archive_dirs):
            try:
                by_resolved_path[candidate.resolve()] = entry
            except OSError:
                continue
        if entry.get("path_text"):
            by_basename.setdefault(Path(str(entry["path_text"])).name.casefold(), []).append(entry)

    for artifact in artifacts:
        artifact_path = Path(artifact["path"]).resolve()
        entry = by_resolved_path.get(artifact_path)
        if entry is None:
            name_matches = by_basename.get(artifact_path.name.casefold(), [])
            if len(name_matches) == 1:
                entry = name_matches[0]

        gaps = list(artifact.get("assembly_identity", {}).get("evidence_gaps", [])) if artifact.get("assembly_identity") else []
        if entry is None:
            artifact["manifest"] = {"found": False}
            gaps.append("manifest_entry_missing")
            artifact["evidence_gaps"] = sorted(set(gaps))
            continue

        sha_status = "missing"
        actual_sha = None
        try:
            actual_sha = sha256_file(Path(artifact["path"]))
        except OSError as exc:
            sha_status = f"unreadable:{type(exc).__name__}"
        if not entry.get("sha256"):
            sha_status = "manifest_digest_missing"
            gaps.append("manifest.sha256_missing")
        elif actual_sha is None:
            sha_status = "artifact_unreadable"
            gaps.append("artifact_unreadable")
        elif entry["sha256"] == actual_sha:
            sha_status = "verified"
        else:
            sha_status = "mismatch"
            gaps.append("manifest.sha256_mismatch")

        size_status = "not_asserted"
        if entry.get("size") is not None:
            try:
                size_status = "verified" if int(entry["size"]) == Path(artifact["path"]).stat().st_size else "mismatch"
                if size_status == "mismatch":
                    gaps.append("manifest.size_mismatch")
            except (OSError, TypeError, ValueError):
                size_status = "invalid"
                gaps.append("manifest.size_invalid")

        manifest_identity = entry.get("manifest_identity")
        identity_checks = compare_identities(artifact.get("assembly_identity"), manifest_identity) if manifest_identity else None
        if not entry.get("manifest_identity_asserted"):
            gaps.append("manifest.identity_not_asserted")
        elif manifest_identity:
            gaps.extend(manifest_identity.get("evidence_gaps", []))
            if identity_checks and identity_checks.get("mismatches"):
                gaps.extend("manifest_identity_mismatch:" + item for item in identity_checks["mismatches"])

        artifact["manifest"] = {
            "found": True,
            "seal_id": entry.get("seal_id"),
            "sealed_artifact": entry.get("sealed_artifact"),
            "record_index": entry.get("record_index"),
            "sha256": entry.get("sha256"),
            "actual_sha256": actual_sha,
            "sha256_status": sha_status,
            "size_status": size_status,
            "identity_checks": identity_checks,
        }
        artifact["evidence_gaps"] = sorted(set(gaps))


def compare_identities(reference: Optional[Dict[str, Any]], candidate: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    checks: Dict[str, Any] = {"name": "absent", "version": "absent", "culture": "absent", "public_key_token": "absent", "mismatches": []}
    if not reference or not candidate:
        return checks

    if reference.get("name_key") and candidate.get("name_key"):
        checks["name"] = "match" if reference["name_key"] == candidate["name_key"] else "mismatch"
        if checks["name"] == "mismatch":
            checks["mismatches"].append("name")
    elif not reference.get("name_key") or not candidate.get("name_key"):
        checks["name"] = "evidence_missing"

    ref_version = reference.get("version")
    cand_version = candidate.get("version")
    ref_parts = reference.get("version_parts")
    cand_parts = candidate.get("version_parts")
    version_mismatch = False
    if ref_parts and cand_parts:
        for ref_part, cand_part in zip(ref_parts, cand_parts):
            if ref_part is not None and cand_part is not None and ref_part != cand_part:
                version_mismatch = True
                break
    if version_mismatch or (ref_version and cand_version and ref_version != cand_version):
        checks["version"] = "mismatch"
        checks["mismatches"].append("version")
    elif ref_version and cand_version and ref_version == cand_version:
        checks["version"] = "match"
    else:
        checks["version"] = "evidence_missing"

    ref_culture = reference.get("culture") if reference.get("culture_present") else None
    cand_culture = candidate.get("culture") if candidate.get("culture_present") else None
    if reference.get("culture_present") and candidate.get("culture_present"):
        checks["culture"] = "match" if ref_culture == cand_culture else "mismatch"
        if checks["culture"] == "mismatch":
            checks["mismatches"].append("culture")
    else:
        checks["culture"] = "evidence_missing"

    ref_token = reference.get("public_key_token")
    cand_token = candidate.get("public_key_token")
    if ref_token and cand_token:
        checks["public_key_token"] = "match" if ref_token == cand_token else "mismatch"
        if checks["public_key_token"] == "mismatch":
            checks["mismatches"].append("public_key_token")
    else:
        checks["public_key_token"] = "evidence_missing"
    return checks


def _candidate_passes_available_constraints(ref_identity: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
    cand_identity = candidate.get("assembly_identity")
    if not cand_identity:
        return False
    checks = compare_identities(ref_identity, cand_identity)
    if checks["mismatches"]:
        return False
    return True


def reconcile(reference_records: List[Dict[str, Any]], artifacts: List[Dict[str, Any]], manifest: Optional[Dict[str, Any]] = None, archive_dirs: Optional[Sequence[Path]] = None) -> Dict[str, Any]:
    if manifest is not None and not any("manifest" in artifact for artifact in artifacts):
        attach_manifest_records(artifacts, manifest, archive_dirs or [])

    entries: List[Dict[str, Any]] = []
    for reference in reference_records:
        ref_identity = reference["identity"]
        candidates = [artifact for artifact in artifacts if _candidate_passes_available_constraints(ref_identity, artifact)]
        pairings = []
        for artifact in candidates:
            cand_identity = artifact["assembly_identity"]
            checks = compare_identities(ref_identity, cand_identity)
            gaps = sorted(set(ref_identity.get("evidence_gaps", []) + cand_identity.get("evidence_gaps", []) + artifact.get("evidence_gaps", [])))
            manifest_record = artifact.get("manifest") or {"found": False}
            if not manifest_record.get("found"):
                gaps = sorted(set(gaps + ["manifest_entry_missing"]))
            elif manifest_record.get("sha256_status") != "verified":
                gaps = sorted(set(gaps + ["manifest_digest_not_verified:" + str(manifest_record.get("sha256_status"))]))
            if not ref_identity.get("complete_identity"):
                gaps = sorted(set(gaps + ["reference_identity_incomplete"]))
            if not cand_identity.get("complete_identity"):
                gaps = sorted(set(gaps + ["candidate_identity_incomplete"]))

            identity_exact = (
                ref_identity.get("complete_identity")
                and cand_identity.get("complete_identity")
                and not checks["mismatches"]
                and all(checks[key] == "match" for key in ("name", "version", "culture", "public_key_token"))
            )
            seal_verified = bool(manifest_record.get("found")) and manifest_record.get("sha256_status") == "verified"
            pairings.append(
                {
                    "classification": "deterministic" if identity_exact and seal_verified and len(candidates) == 1 else "candidate",
                    "identity_exact_match": identity_exact,
                    "seal_verified": seal_verified,
                    "identity_comparison": checks,
                    "evidence_gaps": gaps,
                    "artifact_path": artifact["path"],
                    "file_name": artifact["file_name"],
                    "seal_id": manifest_record.get("seal_id"),
                    "sealed_artifact": manifest_record.get("sealed_artifact"),
                    "manifest": manifest_record,
                    "candidate_identity": cand_identity,
                }
            )

        deterministic = [pair for pair in pairings if pair["classification"] == "deterministic"]
        if len(deterministic) == 1 and len(pairings) == 1:
            status = "confirmed_pair"
        elif pairings:
            status = "candidate_only"
        else:
            status = "unmatched"

        all_gaps = sorted(set(gap for pair in pairings for gap in pair["evidence_gaps"]))
        if not pairings:
            all_gaps = sorted(set(all_gaps + ref_identity.get("evidence_gaps", []) + ["no_candidate_artifact"]))
        entries.append(
            {
                "reference_id": reference["reference_id"],
                "source_path": reference["source_path"],
                "row": reference["row"],
                "status": status,
                "reference_identity": ref_identity,
                "evidence_gaps": all_gaps,
                "confirmed_pair": deterministic[0] if status == "confirmed_pair" else None,
                "candidates": pairings if status != "confirmed_pair" else [],
                "all_pairings": pairings,
            }
        )

    summary = {
        "reference_rows": len(entries),
        "confirmed_pairs": sum(entry["status"] == "confirmed_pair" for entry in entries),
        "candidate_only_groups": sum(entry["status"] == "candidate_only" for entry in entries),
        "unmatched": sum(entry["status"] == "unmatched" for entry in entries),
        "candidate_sealed_artifacts": sum(len(entry["all_pairings"]) for entry in entries),
        "evidence_gap_items": sum(len(entry["evidence_gaps"]) for entry in entries),
    }
    return {
        "schema": "dnfile.assemblyref-inventory/v1",
        "case_id": manifest.get("case_id") if manifest else None,
        "summary": summary,
        "entries": entries,
        "artifacts": artifacts,
        "manifest": {k: v for k, v in (manifest or {}).items() if k != "entries"} | {"entry_count": len((manifest or {}).get("entries", []))},
    }


def scan_archive(archive_dirs: Sequence[Path]) -> List[Dict[str, Any]]:
    artifacts: List[Dict[str, Any]] = []
    seen = set()
    for directory in archive_dirs:
        if not directory.exists():
            continue
        paths = sorted(directory.rglob("*")) if directory.is_dir() else [directory]
        for path in paths:
            if not path.is_file() or path.suffix.lower() not in (".dll", ".exe", ".winmd"):
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            artifacts.append(read_pe_metadata(path))
    return artifacts


def collect_references(reference_paths: Sequence[Path]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    records: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    for path in reference_paths:
        record = read_pe_metadata(path)
        files.append({key: record[key] for key in ("path", "metadata_available", "module_name", "parse_errors", "dnfile_warnings")})
        records.extend(record["references"])
    return records, files


def build_inventory(
    reference_paths: Sequence[Path],
    archive_dirs: Sequence[Path],
    manifest_path: Optional[Path] = None,
) -> Dict[str, Any]:
    references, reference_files = collect_references(reference_paths)
    artifacts = scan_archive(archive_dirs)
    manifest = load_manifest(manifest_path) if manifest_path else None
    attach_manifest_records(artifacts, manifest, archive_dirs)
    inventory = reconcile(references, artifacts, manifest, archive_dirs)
    inventory["reference_files"] = reference_files
    inventory["archive_dirs"] = [str(path) for path in archive_dirs]
    inventory["manifest_path"] = str(manifest_path) if manifest_path else None
    return inventory


GAP_LABELS = {
    "culture_missing": "引用文化字段缺失",
    "public_key_identity_missing": "公钥身份字段缺失",
    "version_missing": "版本字段缺失",
    "version_incomplete": "版本四段不完整",
    "assembly_name_missing": "程序集名称缺失",
    "manifest_entry_missing": "封存清单缺少对应记录",
    "manifest.sha256_missing": "封存清单缺少 SHA-256",
    "manifest.sha256_mismatch": "封存摘要不一致",
    "manifest.culture_missing": "封存清单文化字段缺失",
    "manifest.identity_not_asserted": "封存清单未独立登记程序集身份",
    "reference_identity_incomplete": "引用身份不完整，不能作唯一同一认定",
    "candidate_identity_incomplete": "候选件身份不完整",
    "no_candidate_artifact": "没有符合同名约束的候选封存件",
}


def gap_label(code: str) -> str:
    if code.startswith("manifest_identity_mismatch:"):
        return "封存清单身份字段不一致：" + code.split(":", 1)[1]
    if code.startswith("manifest_digest_not_verified:"):
        return "封存摘要未验证：" + code.split(":", 1)[1]
    if code.startswith("manifest."):
        return GAP_LABELS.get(code, "封存清单证据缺项：" + code)
    return GAP_LABELS.get(code, "证据缺项/异常：" + code)


def render_markdown(inventory: Dict[str, Any]) -> str:
    lines: List[str] = []
    case_id = inventory.get("case_id") or "未命名案卷"
    lines.append("# AssemblyRef 封存件配对清册")
    lines.append("")
    lines.append(f"- 案卷：`{case_id}`")
    lines.append("- 方式：dnfile 只读解析 `AssemblyRef`/`Assembly` 表及 `#Strings`/`#Blob` 堆；不加载、不执行程序集。")
    manifest_note = (inventory.get("manifest") or {}).get("note")
    if manifest_note:
        lines.append(f"- 清单说明：{manifest_note}")
    summary = inventory["summary"]
    lines.append(
        "- 汇总：引用 {reference_rows} 项；确定配对 {confirmed_pairs} 项；候选配对 {candidate_only_groups} 组；未匹配 {unmatched} 项；涉及候选封存件 {candidate_sealed_artifacts} 件。".format(**summary)
    )
    lines.append("")

    confirmed = [entry for entry in inventory["entries"] if entry["status"] == "confirmed_pair"]
    candidates = [entry for entry in inventory["entries"] if entry["status"] == "candidate_only"]
    unmatched = [entry for entry in inventory["entries"] if entry["status"] == "unmatched"]

    lines.append("## 一、确定配对")
    lines.append("")
    if not confirmed:
        lines.append("无。")
    for entry in confirmed:
        pair = entry["confirmed_pair"]
        ref = entry["reference_identity"]
        lines.append(f"### `{entry['reference_id']}` → `{pair['seal_id']}`")
        lines.append("")
        lines.append(f"- 引用身份：`{_identity_text(ref)}`")
        lines.append(f"- 确定封存件：`{pair['seal_id']}`；清单登记封存路径：`{pair.get('sealed_artifact') or pair['artifact_path']}`")
        lines.append(f"- 交付文件：`{pair['artifact_path']}`")
        lines.append(f"- SHA-256：`{pair['manifest'].get('actual_sha256')}`（清单状态：`{pair['manifest'].get('sha256_status')}`）")
        lines.append(f"- 表项证据：{_evidence_text(ref.get('table_evidence'))}")
        lines.append("")

    lines.append("## 二、只能提供候选的配对")
    lines.append("")
    if not candidates:
        lines.append("无。")
    for entry in candidates:
        ref = entry["reference_identity"]
        lines.append(f"### `{entry['reference_id']}`")
        lines.append("")
        lines.append(f"- 引用身份：`{_identity_text(ref)}`")
        lines.append("- 结论：现有证据不足以唯一同一认定；以下每件均具体对应独立封存记录。")
        if entry["evidence_gaps"]:
            lines.append("- 证据缺项：" + "；".join(gap_label(gap) for gap in entry["evidence_gaps"]))
        lines.append("- 候选封存件：")
        for pair in entry["all_pairings"]:
            candidate_identity = _identity_text(pair["candidate_identity"])
            actual_sha = pair["manifest"].get("actual_sha256")
            sha_status = pair["manifest"].get("sha256_status")
            sealed_location = pair.get("sealed_artifact") or pair["artifact_path"]
            lines.append(
                f"  - `{pair['seal_id']}` → `{sealed_location}`；"
                f"文件 `{pair['file_name']}`；SHA-256 `{actual_sha}`；"
                f"摘要状态 `{sha_status}`；候选身份 `{candidate_identity}`"
            )
        lines.append(f"- 引用表项：{_evidence_text(ref.get('table_evidence'))}")
        lines.append("")

    lines.append("## 三、未匹配引用")
    lines.append("")
    if not unmatched:
        lines.append("无。")
    for entry in unmatched:
        lines.append(f"- `{entry['reference_id']}`：{gap_label('no_candidate_artifact')}")
    lines.append("")

    lines.append("## 四、机读结果")
    lines.append("")
    lines.append("完整表项偏移、堆索引、哈希和结构化缺项见同批输出的 JSON 清册。")
    return "\n".join(lines) + "\n"


def _identity_text(identity: Optional[Dict[str, Any]]) -> str:
    if not identity:
        return "<身份不可读>"
    culture = identity.get("culture_label")
    if culture is None:
        culture = "<缺失>"
    token = identity.get("public_key_token") or "<缺失>"
    version = identity.get("version") or "<缺失/不完整>"
    name = identity.get("name") or "<名称缺失>"
    return f"{name}, Version={version}, Culture={culture}, PublicKeyToken={token}"


def _evidence_text(evidence: Optional[Dict[str, Any]]) -> str:
    if not evidence:
        return "不可用"
    parts = [f"`{evidence.get('table')}` 第 {evidence.get('row')} 行"]
    if evidence.get("file_offset") is not None:
        parts.append(f"文件偏移 `{evidence['file_offset']}`")
    if evidence.get("name_string_index") is not None:
        parts.append(f"Name 堆索引 `{evidence['name_string_index']}`")
    if evidence.get("culture_string_index") is not None:
        parts.append(f"Culture 堆索引 `{evidence['culture_string_index']}`")
    if evidence.get("public_key_blob_index") is not None:
        parts.append(f"PublicKey Blob 索引 `{evidence['public_key_blob_index']}`")
    return "，".join(parts)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Reconcile .NET AssemblyRef rows with sealed artifacts.")
    parser.add_argument("references", nargs="*", type=Path, help="PE files containing AssemblyRef rows")
    parser.add_argument("--reference", action="append", type=Path, default=[], help="additional reference PE path")
    parser.add_argument("--archive-dir", action="append", type=Path, default=[], help="directory containing delivered candidate assemblies")
    parser.add_argument("--case-dir", type=Path, help="case directory with references/, delivery/, and sealing-manifest.json")
    parser.add_argument("--manifest", type=Path, help="independent sealing manifest JSON")
    parser.add_argument("--json", type=Path, help="write machine-readable inventory JSON here")
    parser.add_argument("--markdown", type=Path, help="write Markdown inventory here")
    args = parser.parse_args(argv)

    case_dir = args.case_dir
    reference_paths = list(args.references) + list(args.reference)
    archive_dirs = list(args.archive_dir)
    manifest_path = args.manifest
    if case_dir:
        reference_dir = case_dir / "references"
        delivery_dir = case_dir / "delivery"
        if reference_dir.is_dir():
            reference_paths.extend(sorted(p for p in reference_dir.iterdir() if p.suffix.lower() in (".dll", ".exe")))
        if delivery_dir.is_dir():
            archive_dirs.append(delivery_dir)
        default_manifest = case_dir / "sealing-manifest.json"
        if manifest_path is None and default_manifest.exists():
            manifest_path = default_manifest
        if args.json is None:
            args.json = case_dir / "inventory.json"
        if args.markdown is None:
            args.markdown = case_dir / "inventory.md"

    if not reference_paths:
        parser.error("at least one reference PE or --case-dir containing references/ is required")
    if not archive_dirs:
        parser.error("at least one --archive-dir or --case-dir with delivery/ is required")

    inventory = build_inventory(reference_paths, archive_dirs, manifest_path)
    rendered = json.dumps(inventory, ensure_ascii=False, indent=2, default=str)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    markdown = render_markdown(inventory)
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown, encoding="utf-8")
    if not args.json and not args.markdown:
        print(markdown)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
