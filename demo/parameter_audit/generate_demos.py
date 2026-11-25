#!/usr/bin/env python3
"""Generate three local signed parameter-audit demonstrations."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from securesystemslib.signer import CryptoSigner

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from in_toto.models._signer import load_public_key_from_file  # noqa: E402
from in_toto.models.link import Link  # noqa: E402
from in_toto.models.metadata import Metablock  # noqa: E402
from in_toto.parameter_audit import audit_links  # noqa: E402

DEMO_ROOT = ROOT / "demo" / "parameter_audit"
INPUT_BYTES = b"shared forensic input material\n"
OUTPUT_BYTES = b"equivalent signed output\n"

COMMAND_ALIASES = {
    "--source": "--input",
    "--target": "--output",
    "--input": "--input",
    "--output": "--output",
}
TEMPLATE_VALUES = {
    "materials/input.txt": "{input}",
    "products/output.bin": "{output}",
}
EQUIVALENT_POLICY = {
    "command_aliases": COMMAND_ALIASES,
    "template_values": TEMPLATE_VALUES,
}


def digest(data: bytes) -> dict[str, str]:
    return {"sha256": hashlib.sha256(data).hexdigest()}


def write_signed_link(
    path: Path,
    signer: CryptoSigner,
    *,
    step_name: str,
    command: list[str],
    materials: dict[str, dict[str, str]],
    products: dict[str, dict[str, str]],
) -> None:
    link = Link(
        name=step_name,
        command=command,
        materials=materials,
        products=products,
        byproducts={"return-value": 0, "stdout": "", "stderr": ""},
        environment={},
    )
    metadata = Metablock(signed=link)
    metadata.create_signature(signer)
    metadata.dump(str(path))


def build_case(
    slug: str,
    title: str,
    signer: CryptoSigner,
    public_key: dict,
    *,
    left_command: list[str],
    right_command: list[str],
    right_has_materials: bool,
    policy: dict,
) -> dict:
    case_dir = DEMO_ROOT / slug
    if case_dir.exists():
        shutil.rmtree(case_dir)
    (case_dir / "materials").mkdir(parents=True)
    (case_dir / "products").mkdir()

    (case_dir / "materials" / "input.txt").write_bytes(INPUT_BYTES)
    (case_dir / "products" / "output.bin").write_bytes(OUTPUT_BYTES)
    shutil.copy2(DEMO_ROOT / "public-key.pem", case_dir / "public-key.pem")

    materials = {"materials/input.txt": digest(INPUT_BYTES)}
    products = {"products/output.bin": digest(OUTPUT_BYTES)}
    step_name = "build-package"

    write_signed_link(
        case_dir / "left.link",
        signer,
        step_name=step_name,
        command=left_command,
        materials=materials,
        products=products,
    )
    write_signed_link(
        case_dir / "right.link",
        signer,
        step_name=step_name,
        command=right_command,
        materials=materials if right_has_materials else {},
        products=products,
    )

    policy_path = case_dir / "audit-policy.json"
    policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")

    os.chdir(DEMO_ROOT)
    report = audit_links(
        f"{slug}/left.link",
        f"{slug}/right.link",
        verification_keys=[public_key],
        policy=policy,
    )
    report["demo_title"] = title
    (case_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    return report


def write_markdown_summary(reports: list[tuple[str, dict]]) -> None:
    lines = [
        "# Parameter substitution audit demo",
        "",
        "All links are signed locally and verified with each case public key.",
        "",
        "| Case | Verdict | Primary reason | Normalized command | Materials | Products |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for title, report in reports:
        command_ok = report["checks"]["normalized_command"]["match"]
        materials_ok = report["checks"]["materials"]["match"]
        products_ok = report["checks"]["products"]["match"]
        lines.append(
            "| {} | `{}` | `{}` | {} | {} | {} |".format(
                title,
                report["verdict"],
                report["primary_reason"],
                "match" if command_ok else "differ",
                "complete/match" if materials_ok else "missing/differ",
                "match" if products_ok else "differ",
            )
        )
    lines.append("")
    (DEMO_ROOT / "forensic-report.md").write_text("\n".join(lines))


def main() -> int:
    DEMO_ROOT.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    signer = CryptoSigner(private_key)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_path = DEMO_ROOT / "public-key.pem"
    key_path.write_bytes(public_pem)
    public_key = load_public_key_from_file(key_path)

    equivalent_left = [
        "python3", "build.py", "--source", "materials/input.txt",
        "--target", "products/output.bin",
    ]
    equivalent_right = [
        "python3", "build.py", "--input", "materials/input.txt",
        "--output", "products/output.bin",
    ]
    cases = [
        (
            "equivalent",
            "Provable equivalence",
            equivalent_left,
            equivalent_right,
            True,
            EQUIVALENT_POLICY,
        ),
        (
            "different-command",
            "Different command template",
            equivalent_left,
            [
                "python3", "build_debug.py", "--input",
                "materials/input.txt", "--output", "products/output.bin",
            ],
            True,
            EQUIVALENT_POLICY,
        ),
        (
            "missing-materials",
            "Missing input material record",
            equivalent_left,
            equivalent_right,
            False,
            EQUIVALENT_POLICY,
        ),
    ]

    reports = []
    for slug, title, left, right, has_materials, policy in cases:
        report = build_case(
            slug,
            title,
            signer,
            public_key,
            left_command=left,
            right_command=right,
            right_has_materials=has_materials,
            policy=policy,
        )
        reports.append((title, report))
        print(f"{slug}: {report['verdict']} ({report['primary_reason']})")

    write_markdown_summary(reports)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
