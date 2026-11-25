#!/usr/bin/env python3
"""Build the small TUF mirror used by the offline-export demonstration.

The tiny mirror has two target requests whose resolution chains share a
parent segment::

    root -> timestamp -> snapshot -> targets -> parent -> update-a -> target one
                                                  \\-> update-b -> target two

``root``, ``timestamp`` and ``snapshot`` are only part of the chain when the
caller asks for the ``full`` assurance level; the strict membership-minimal
set is ``root -> targets -> parent -> update-{a,b}``.

The mirror also contains:

* ``nightly.json`` - an unrelated role that must never be exported;
* ``root.alias`` - a planted *unsigned alias* temptation;
* ``root.json.sha256`` - the real digest of ``root.json``, planted to prove
  that even a correct standalone digest cannot replace missing signed material.

Every role is freshly generated and cryptographically signed with ed25519
keys.  Run ``python tiny_mirror_demo.py`` to (re)build the static example
under ``examples/offline_export/`` and execute both merge / deficiency
scenarios.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from securesystemslib.formats import encode_canonical
from securesystemslib.signer import CryptoSigner, Signer

from offline_export_plan import (
    TransferManifest,
    plan_export,
    render_markdown_report,
    write_bundle,
)

EXPIRY = "2031-01-01T00:00:00Z"
SPEC_VERSION = "1.0.0"

TARGET_ONE = "approved/repair-target-one.bin"
TARGET_TWO = "approved/repair-target-two.bin"

FULL_ROLE_ORDER = (
    "root",
    "timestamp",
    "snapshot",
    "targets",
    "parent",
    "update-a",
    "update-b",
)

MEMBERSHIP_ROLE_ORDER = (
    "root",
    "targets",
    "parent",
    "update-a",
    "update-b",
)


def _signed(payload_type: str, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "_type": payload_type,
        "spec_version": SPEC_VERSION,
        "version": 1,
        "expires": EXPIRY,
    }
    body.update(extra)
    return body


def _write_signed_role(
    metadata_dir: Path,
    role: str,
    signed: dict[str, Any],
    signers: list[Signer],
) -> bytes:
    canonical = encode_canonical(signed)
    assert canonical is not None
    canonical_bytes = canonical.encode("utf-8")
    signatures = []
    for signer in signers:
        signature = signer.sign(canonical_bytes)
        signatures.append(
            {"keyid": signature.keyid, "sig": signature.signature}
        )

    envelope = {"signatures": signatures, "signed": signed}
    path = metadata_dir / f"{role}.json"
    path.write_text(
        json.dumps(envelope, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path.read_bytes()


def _metafile(body: bytes) -> dict[str, Any]:
    import hashlib

    return {
        "version": 1,
        "length": len(body),
        "hashes": {"sha256": hashlib.sha256(body).hexdigest()},
    }


def _target_metafile(body: bytes) -> dict[str, Any]:
    import hashlib

    return {
        "length": len(body),
        "hashes": {
            "sha256": hashlib.sha256(body).hexdigest(),
            "sha512": hashlib.sha512(body).hexdigest(),
        },
    }


def generate_signers() -> dict[str, CryptoSigner]:
    """Generate one fresh ed25519 signer per role."""

    return {
        role: CryptoSigner.generate_ed25519()
        for role in (
            "root",
            "timestamp",
            "snapshot",
            "targets",
            "parent",
            "update-a",
            "update-b",
            "nightly",
        )
    }


def build_tiny_mirror(root: str | Path) -> Path:
    """Create the complete signed tiny mirror under ``root`` and return it."""

    mirror_root = Path(root)
    metadata_dir = mirror_root / "metadata"
    artifacts_dir = mirror_root / "targets" / "approved"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    signers = generate_signers()
    public = {
        role: signer.public_key.to_dict() for role, signer in signers.items()
    }
    keyids = {role: signer.public_key.keyid for role, signer in signers.items()}

    body_one = b"repair target one - pump controller bundle\n"
    body_two = b"repair target two - valve firmware bundle\n"
    (artifacts_dir / "repair-target-one.bin").write_bytes(body_one)
    (artifacts_dir / "repair-target-two.bin").write_bytes(body_two)

    written: dict[str, bytes] = {}

    update_a = _signed(
        "targets",
        targets={TARGET_ONE: _target_metafile(body_one)},
    )
    written["update-a"] = _write_signed_role(
        metadata_dir, "update-a", update_a, [signers["update-a"]]
    )

    update_b = _signed(
        "targets",
        targets={TARGET_TWO: _target_metafile(body_two)},
    )
    written["update-b"] = _write_signed_role(
        metadata_dir, "update-b", update_b, [signers["update-b"]]
    )

    parent = _signed(
        "targets",
        targets={},
        delegations={
            "keys": {
                keyids["update-a"]: public["update-a"],
                keyids["update-b"]: public["update-b"],
            },
            "roles": [
                {
                    "name": "update-a",
                    "keyids": [keyids["update-a"]],
                    "threshold": 1,
                    "paths": [TARGET_ONE],
                    "terminating": True,
                },
                {
                    "name": "update-b",
                    "keyids": [keyids["update-b"]],
                    "threshold": 1,
                    "paths": [TARGET_TWO],
                    "terminating": True,
                },
            ],
        },
    )
    written["parent"] = _write_signed_role(
        metadata_dir, "parent", parent, [signers["parent"]]
    )

    targets = _signed(
        "targets",
        targets={},
        delegations={
            "keys": {keyids["parent"]: public["parent"]},
            "roles": [
                {
                    "name": "parent",
                    "keyids": [keyids["parent"]],
                    "threshold": 1,
                    "paths": ["approved/*"],
                    "terminating": False,
                }
            ],
        },
    )
    written["targets"] = _write_signed_role(
        metadata_dir, "targets", targets, [signers["targets"]]
    )

    snapshot_meta = {
        f"{role}.json": _metafile(written[role])
        for role in ("targets", "parent", "update-a", "update-b")
    }
    snapshot = _signed("snapshot", meta=snapshot_meta)
    written["snapshot"] = _write_signed_role(
        metadata_dir, "snapshot", snapshot, [signers["snapshot"]]
    )

    timestamp = _signed(
        "timestamp",
        meta={"snapshot.json": _metafile(written["snapshot"])},
    )
    _write_signed_role(
        metadata_dir, "timestamp", timestamp, [signers["timestamp"]]
    )

    root_metadata = _signed(
        "root",
        consistent_snapshot=False,
        keys={
            keyids[role]: public[role]
            for role in ("root", "timestamp", "snapshot", "targets")
        },
        roles={
            role: {"keyids": [keyids[role]], "threshold": 1}
            for role in ("root", "timestamp", "snapshot", "targets")
        },
    )
    _write_signed_role(metadata_dir, "root", root_metadata, [signers["root"]])

    nightly = _signed(
        "targets",
        targets={
            "nightly/latest.bin": _target_metafile(b"unrelated nightly build")
        },
    )
    _write_signed_role(
        metadata_dir, "nightly", nightly, [signers["nightly"]]
    )

    # Temptation 1: an unsigned alias pointer for the root role.  It has no
    # signatures and must never be counted as root material.
    (metadata_dir / "root.alias").write_text(
        json.dumps(
            {
                "alias_for": "root",
                "role": "root",
                "signed": False,
                "note": "Unsigned delegation-style alias; not export proof.",
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )

    # Temptation 2: the *correct* digest of root.json, still useless as a
    # substitute for the signed root envelope and its signature material.
    import hashlib

    root_bytes = (metadata_dir / "root.json").read_bytes()
    root_digest = hashlib.sha256(root_bytes).hexdigest()
    (metadata_dir / "root.json.sha256").write_text(
        f"{root_digest}  root.json\n", encoding="utf-8"
    )

    return mirror_root


def standard_requests() -> list[dict[str, Any]]:
    """Two repair-contract target requests sharing the parent segment."""

    return [
        {
            "request_id": "repair-review-one",
            "target": TARGET_ONE,
            "approved_roles": ["update-a"],
        },
        {
            "request_id": "repair-review-two",
            "target": TARGET_TWO,
            "approved_roles": ["update-b"],
        },
    ]


def merge_manifest() -> dict[str, Any]:
    """Explicit caller allowlist for the full-verification minimal set."""

    return {
        "description": "Repair contract review material release list",
        "transferable_materials": [
            f"metadata/{role}.json" for role in FULL_ROLE_ORDER
        ],
    }


def allow_all_manifest() -> dict[str, Any]:
    return {"transferable_materials": ["*"]}


def missing_root_manifest() -> dict[str, Any]:
    """Everything is releasable except the signed root material."""

    return {
        "transferable_materials": ["*"],
        "denied_materials": ["metadata/root.json"],
        "substitutes": [
            {
                "role": "root",
                "unsigned_alias": "metadata/root.alias",
                "digests": [{"ref": "metadata/root.json.sha256"}],
            }
        ],
    }


def signature_blocked_manifest() -> dict[str, Any]:
    """Root payload allowed, but its signature material may not be delivered."""

    return {
        "transferable_materials": [
            "*",
            {"path": "metadata/root.json", "signatures": False},
        ]
    }


def run_demo(example_dir: str | Path) -> dict[str, Any]:
    """Build mirror/manifests, run both scenarios, write handoff bundles."""

    base = Path(example_dir)
    mirror_dir = build_tiny_mirror(base / "tiny-mirror")
    requests = standard_requests()

    (base / "requests.json").write_text(
        json.dumps(requests, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    manifests = {
        "manifest-merge.json": merge_manifest(),
        "manifest-allow-all.json": allow_all_manifest(),
        "manifest-missing-root.json": missing_root_manifest(),
        "manifest-signature-blocked.json": signature_blocked_manifest(),
    }
    for name, payload in manifests.items():
        (base / name).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    # Scenario 1a: merged full-verification export, explicit allowlist.
    merged_full = plan_export(
        mirror_dir,
        requests,
        TransferManifest.from_obj(merge_manifest()),
        assurance_level="full",
        verify_crypto=True,
    )
    assert merged_full.sufficient, [
        (m.role, m.code, m.reason) for m in merged_full.missing
    ]
    assert merged_full.mergeable is True
    assert merged_full.minimal_roles == list(FULL_ROLE_ORDER)
    assert merged_full.shared_roles == [
        "root",
        "timestamp",
        "snapshot",
        "targets",
        "parent",
    ]
    assert merged_full.excluded_roles == ["nightly"]
    assert len(merged_full.handoff_files) == 7
    write_bundle(merged_full, base / "handoff-merged-full")

    # Scenario 1b: strict membership-minimal merged export.
    merged_membership = plan_export(
        mirror_dir,
        requests,
        TransferManifest.from_obj(merge_manifest()),
        assurance_level="membership",
        verify_crypto=True,
    )
    # The merge manifest also lists snapshot/timestamp; that is an allowlist
    # superset, while the planner answer stays minimal at 5 roles.
    assert merged_membership.sufficient
    assert merged_membership.minimal_roles == list(MEMBERSHIP_ROLE_ORDER)
    assert merged_membership.shared_roles == ["root", "targets", "parent"]
    residual_causes = {
        claim.scope for claim in merged_membership.unattested_scope
    }
    assert {"snapshot_consistency", "freshness"} <= residual_causes
    write_bundle(merged_membership, base / "handoff-merged-membership")

    # Scenario 1c: allow-all manifest still yields the same minimal set.
    allow_all = plan_export(
        mirror_dir,
        requests,
        TransferManifest.from_obj(allow_all_manifest()),
        assurance_level="full",
        verify_crypto=True,
    )
    assert allow_all.sufficient
    assert allow_all.minimal_roles == list(FULL_ROLE_ORDER)
    assert "nightly" in allow_all.excluded_roles

    # Scenario 2a: signed root material not transferable -> deficiency only.
    missing_root = plan_export(
        mirror_dir,
        requests,
        TransferManifest.from_obj(missing_root_manifest()),
        assurance_level="full",
        verify_crypto=True,
    )
    assert missing_root.sufficient is False
    assert missing_root.mergeable is False
    assert missing_root.certified_handoff_files == []
    root_missing = [m for m in missing_root.missing if m.role == "root"]
    assert root_missing and root_missing[0].code == "not_transferable"
    rejected_codes = {item.code for item in missing_root.rejected_substitutes}
    assert "rejected_unsigned_alias" in rejected_codes
    assert "rejected_arbitrary_digest" in rejected_codes
    e2e_targets = {
        claim.target
        for claim in missing_root.unattested_scope
        if claim.scope == "end_to_end_attestation"
    }
    assert e2e_targets == {TARGET_ONE, TARGET_TWO}
    write_bundle(missing_root, base / "report-missing-root")

    # Scenario 2b: root payload allowed but signature material blocked.
    sig_blocked = plan_export(
        mirror_dir,
        requests,
        TransferManifest.from_obj(signature_blocked_manifest()),
        assurance_level="full",
        verify_crypto=True,
    )
    assert sig_blocked.sufficient is False
    root_block = [m for m in sig_blocked.missing if m.role == "root"]
    assert root_block
    assert root_block[0].code == "signature_material_blocked"

    (base / "report-missing-root" / "REPORT.zh.md").write_text(
        render_markdown_report(missing_root), encoding="utf-8"
    )

    return {
        "mirror": str(mirror_dir),
        "merged_full": merged_full,
        "merged_membership": merged_membership,
        "allow_all": allow_all,
        "missing_root": missing_root,
        "signature_blocked": sig_blocked,
    }


def _print_summary(results: dict[str, Any]) -> None:
    merged = results["merged_full"]
    missing = results["missing_root"]
    print("== Scenario 1: mergeable ==")
    print("minimal roles:", " -> ".join(merged.minimal_roles))
    print("shared segment:", " -> ".join(merged.shared_roles))
    print("handoff files:")
    for ref in merged.handoff_files:
        print("  +", ref)
    print("excluded mirror roles:", ", ".join(merged.excluded_roles))
    membership = results["merged_membership"]
    print(
        "membership-minimal roles:",
        " -> ".join(membership.minimal_roles),
    )
    print()
    print("== Scenario 2: missing upper-role material ==")
    print("status:", missing.status, "mergeable:", missing.mergeable)
    print("certified handoff:", missing.certified_handoff_files)
    for item in missing.missing:
        print(f"  ! missing {item.code}: {item.ref} ({item.role})")
    for sub in missing.rejected_substitutes:
        print(f"  x rejected {sub.code}: {sub.ref}")
    print("unattested end-to-end targets:")
    for claim in missing.unattested_scope:
        if claim.scope == "end_to_end_attestation":
            print("  ?", claim.target, "<- blocked by", claim.blocked_by)


def main() -> int:
    example_dir = Path(__file__).resolve().parent / "examples" / "offline_export"
    results = run_demo(example_dir)
    _print_summary(results)
    print(f"\nArtifacts written under {example_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
