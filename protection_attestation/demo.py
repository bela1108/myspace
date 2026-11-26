"""Generate the two divergent handoff tool outputs from real test packages."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .inspect import inspect_package
from .intake import PROJECT_ROOT


DEMO_PACKAGES = [
    {
        "package_id": "ARCH-001",
        "path": "tests/inputs/ecma376agile_sha1_password.xlsx",
        "approval_id": "AP-2024-018",
    },
    {
        "package_id": "ARCH-002",
        "path": "tests/inputs/example_password.docx",
        "approval_id": "AP-2024-019",
    },
    {
        "package_id": "ARCH-003",
        "path": "tests/inputs/example_password.xlsx",
        "approval_id": "AP-2024-020",
    },
]

_HASH_DISPLAY = {
    "SHA1": "SHA-1 摘要算法",
    "SHA256": "SHA-256 摘要算法",
    "SHA512": "SHA-512 摘要算法",
}


def _write_json(path: Path, document: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + chr(10),
        encoding="utf-8",
    )
    return path


def _legacy_summary(parameters: dict[str, Any]) -> dict[str, Any]:
    bits = parameters["key_length_bits"]
    hash_token = parameters["hash_algorithm"]
    chaining = str(parameters["cipher_chaining"]).removeprefix("ChainingMode")
    return {
        "protection": "Agile 密码加密",
        "cipher_description": parameters["encryption_suite"]["cipher_algorithm"]
        + "-"
        + str(bits)
        + "-"
        + chaining,
        "digest_description": _HASH_DISPLAY.get(hash_token, hash_token + " 摘要算法"),
        "secret_key_length": {"value": bits // 8, "unit": "字节"},
        "key_iterations": str(parameters["spin_count"]) + " 轮 PBKDF2",
        "salt_length": str(parameters["salt_length_bytes"]) + " 字节",
        "block_length": str(parameters["block_size_bytes"]) + " 字节",
        "digest_length": str(parameters["hash_size_bytes"]) + " 字节",
    }


def build_handoff_outputs(handoff_dir: str | Path) -> list[Path]:
    handoff = Path(handoff_dir)
    if not handoff.is_absolute():
        handoff = PROJECT_ROOT / handoff

    msoff_outputs = []
    legacy_outputs = []
    tool_version = "6.1.0"

    for package in DEMO_PACKAGES:
        inspection = inspect_package(PROJECT_ROOT / package["path"])
        tool_version = inspection["tool_version"]
        msoff_outputs.append(
            {
                "package_id": package["package_id"],
                "approval_id": package["approval_id"],
                "path": package["path"],
                "sha256": inspection["sha256"],
                "plaintext_accessed": False,
                "recorded_claims": inspection["parameters"],
            }
        )
        legacy_outputs.append(
            {
                "package_id": package["package_id"],
                "approval_id": package["approval_id"],
                "path": package["path"],
                "sha256": inspection["sha256"],
                "scanner": "archive-desk offline profile",
                "summary": _legacy_summary(inspection["parameters"]),
            }
        )

    first = _write_json(
        handoff / "tool-output-1-msoffcrypto.json",
        {
            "schema": "office-protection-tool-output",
            "tool": "msoffcrypto-tool",
            "tool_version": tool_version,
            "batch_purpose": "Handoff output using Office attribute names and bit lengths",
            "outputs": msoff_outputs,
        },
    )
    second = _write_json(
        handoff / "tool-output-2-archive-desk.json",
        {
            "schema": "archive-desk-protection-export",
            "tool": "archive-desk-scanner",
            "tool_version": "3.4-historical",
            "batch_purpose": "Handoff output using Chinese descriptive names and byte lengths",
            "outputs": legacy_outputs,
        },
    )
    return [first, second]
