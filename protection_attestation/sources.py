"""Adapters for the two divergent handoff tool-output dialects."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterator


PROTECTION_FIELDS = (
    "protection_kind",
    "encryption_suite",
    "cipher_algorithm",
    "cipher_chaining",
    "key_length_bits",
    "hash_algorithm",
    "spin_count",
    "salt_length_bytes",
    "block_size_bytes",
    "hash_size_bytes",
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _iter_msoffcrypto_output(
    document: dict[str, Any], source_path: Path
) -> Iterator[dict[str, Any]]:
    artifact_sha256 = sha256_file(source_path)
    tool = document.get("tool", "msoffcrypto-tool")
    version = document.get("tool_version", "unknown")
    for index, item in enumerate(document.get("outputs", [])):
        package_id = item["package_id"]
        claims = item.get("recorded_claims", item.get("parameters", {}))
        for field, value in claims.items():
            if field not in PROTECTION_FIELDS:
                continue
            yield {
                "package_id": package_id,
                "field": field,
                "recorded_value": value,
                "source": {
                    "source_id": f"{tool}-{version}",
                    "source_kind": "tool_output",
                    "source_name": tool,
                    "source_version": version,
                    "artifact": str(source_path),
                    "artifact_sha256": artifact_sha256,
                    "locator": f"outputs[{index}].recorded_claims.{field}",
                },
                "recorded_file_sha256": item.get("sha256"),
            }


def _iter_archive_desk_output(
    document: dict[str, Any], source_path: Path
) -> Iterator[dict[str, Any]]:
    artifact_sha256 = sha256_file(source_path)
    tool = document.get("tool", "archive-desk-export")
    version = document.get("tool_version", "unknown")
    for index, item in enumerate(document.get("outputs", [])):
        package_id = item["package_id"]
        summary = item.get("summary", {})
        mapped = (
            ("protection_kind", "protection", summary.get("protection")),
            ("encryption_suite", "cipher_description", summary.get("cipher_description")),
            ("key_length_bits", "secret_key_length", summary.get("secret_key_length")),
            ("hash_algorithm", "digest_description", summary.get("digest_description")),
            ("spin_count", "key_iterations", summary.get("key_iterations")),
            ("salt_length_bytes", "salt_length", summary.get("salt_length")),
            ("block_size_bytes", "block_length", summary.get("block_length")),
            ("hash_size_bytes", "digest_length", summary.get("digest_length")),
        )
        for field, source_key, value in mapped:
            if value is None or field not in PROTECTION_FIELDS:
                continue
            yield {
                "package_id": package_id,
                "field": field,
                "recorded_value": value,
                "source": {
                    "source_id": f"{tool}-{version}",
                    "source_kind": "tool_output",
                    "source_name": tool,
                    "source_version": version,
                    "artifact": str(source_path),
                    "artifact_sha256": artifact_sha256,
                    "locator": f"outputs[{index}].summary.{source_key}",
                    "dialect": "archive-desk-display",
                },
                "recorded_file_sha256": item.get("sha256"),
            }


def iter_tool_claims(path: str | Path) -> Iterator[dict[str, Any]]:
    source_path = Path(path)
    document = load_json(source_path)
    schema = document.get("schema", "")
    if schema == "office-protection-tool-output":
        yield from _iter_msoffcrypto_output(document, source_path)
    elif schema == "archive-desk-protection-export":
        yield from _iter_archive_desk_output(document, source_path)
    else:
        raise ValueError(f"未知工具输出 schema: {schema!r} in {source_path}")
