#!/usr/bin/env python3
# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Small-image demo of the offline export planner.

Two review requests share one top-level parent chain (root -> timestamp ->
snapshot -> targets) but reach different delegated leaf roles:

* request A looks up ``pkg/foo/app-1.tar`` (delegated role ``role-foo``);
* request B looks up ``pkg/bar/app-2.tar`` (delegated role ``role-bar``).

The demo runs three transferable manifests against the same signed repository
to show when role chains can be merged and when the planner can only report a
gap instead of weakening the hand-off with an unsigned alias or a digest:

1. every role is transferable  -> the shared parent chain is merged, each
   leaf appears once and both targets are proven;
2. the ``role-bar`` signed file is withheld -> request A still proves, request
   B lands in the no-proof range;
3. ``role-bar`` is delivered under-signed -> the missing threshold is reported,
   never papered over.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    MetaFile,
    Metadata,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,

)
from tuf.api.serialization.json import JSONSerializer

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from offline_export_planner import (  # noqa: E402
    DictMetadataSource,
    OfflineExportPlanner,
    TransferManifest,
)

REQUEST_A = "pkg/foo/app-1.tar"
REQUEST_B = "pkg/bar/app-2.tar"
ROLE_FOO = "role-foo"
ROLE_BAR = "role-bar"


def _expiry(days: int) -> datetime:
    return datetime.now(UTC).replace(microsecond=0) + timedelta(days=days)


def _target(path: str, content: bytes) -> TargetFile:
    return TargetFile.from_data(path, content, ["sha256"])

def build_signed_repository(
) -> tuple[DictMetadataSource, dict[str, CryptoSigner]]:
    """Create a small, fully signed repository and return its role bytes.

    The top-level targets role delegates ``pkg/foo/*`` to ``role-foo`` and
    ``pkg/bar/*`` to ``role-bar`` (non-terminating, ordered). Each leaf
    carries one target. All metadata is signed and the snapshot pins every
    targets-type role by version, exactly as a real repository would.
    """
    signer_store: dict[str, CryptoSigner] = {}
    serializer = JSONSerializer(compact=False)

    def signer_for(role: str) -> CryptoSigner:
        signer = CryptoSigner.generate_ed25519()
        signer_store[role] = signer
        return signer

    root_md = Metadata(Root(expires=_expiry(365)))
    timestamp_md = Metadata(Timestamp(expires=_expiry(1)))
    snapshot_md = Metadata(Snapshot(expires=_expiry(30)))
    targets_md = Metadata(Targets(expires=_expiry(365)))

    top_signers = {}
    for name in ("root", "timestamp", "snapshot", "targets"):
        role_signer = signer_for(name)
        top_signers[name] = role_signer
        root_md.signed.add_key(role_signer.public_key, name)

    foo_signer = signer_for(ROLE_FOO)
    bar_signer = signer_for(ROLE_BAR)
    foo_md = Metadata(Targets(expires=_expiry(30), targets={
        REQUEST_A: _target(REQUEST_A, b"artifact-a"),
    }))
    bar_md = Metadata(Targets(expires=_expiry(30), targets={
        REQUEST_B: _target(REQUEST_B, b"artifact-b"),
    }))

    targets_md.signed.delegations = Delegations(
        keys={
            foo_signer.public_key.keyid: foo_signer.public_key,
            bar_signer.public_key.keyid: bar_signer.public_key,
        },
        roles={
            ROLE_FOO: DelegatedRole(
                ROLE_FOO, [foo_signer.public_key.keyid], 1, False,
                paths=["pkg/foo/*"],
            ),
            ROLE_BAR: DelegatedRole(
                ROLE_BAR, [bar_signer.public_key.keyid], 1, False,
                paths=["pkg/bar/*"],
            ),
        },
    )

    for role_name, role_md, role_signer in (
        (ROLE_FOO, foo_md, foo_signer),
        (ROLE_BAR, bar_md, bar_signer),
        ("targets", targets_md, top_signers["targets"]),
    ):
        role_md.sign(role_signer)
        snapshot_md.signed.meta[f"{role_name}.json"] = MetaFile(
            role_md.signed.version
        )

    snapshot_md.sign(top_signers["snapshot"])
    timestamp_md.signed.snapshot_meta = MetaFile(snapshot_md.signed.version)
    timestamp_md.sign(top_signers["timestamp"])
    root_md.sign(top_signers["root"])

    source = DictMetadataSource()
    for role_name, role_md in (
        ("root", root_md),
        ("timestamp", timestamp_md),
        ("snapshot", snapshot_md),
        ("targets", targets_md),
        (ROLE_FOO, foo_md),
        (ROLE_BAR, bar_md),
    ):
        source.add(role_name, role_md.to_bytes(serializer))
    return source, signer_store

ALL_ROLES = ("root", "timestamp", "snapshot", "targets", ROLE_FOO, ROLE_BAR)


def _print_plan(title: str, plan) -> None:
    print("=" * 72)
    print(title)
    print("-" * 72)
    print("hand-off role files (minimal, de-duplicated):")
    for requirement in plan.roles:
        print(
            f"  - {requirement.filename:<18} delegated by "
            f"{requirement.delegator:<8} proves "
            f"{sorted(requirement.proves_targets)}"
        )
    if not plan.roles:
        print("  (none)")
    print(f"proven targets  : {sorted(plan.proven_targets)}")
    print(f"unproven targets: {sorted(plan.unproven_targets)}")
    if plan.gaps:
        print("no-proof range:")
        for gap in plan.gaps:
            print(
            f"  ! {gap.target_path} <- {gap.role} "
            f"[{gap.reason.value}]: {gap.detail}"
        )
    else:
        print("no-proof range: (empty)")
    print()


def main() -> None:
    """Run the merge and the gap scenarios against one small image."""
    source, _signers = build_signed_repository()
    requests = [REQUEST_A, REQUEST_B]

    full_manifest = TransferManifest(ALL_ROLES)
    merge_plan = OfflineExportPlanner(source, full_manifest).plan(requests)
    _print_plan(
        "Scenario 1: all roles transferable - shared parent chain merges",
        merge_plan,
    )

    withheld = TransferManifest(r for r in ALL_ROLES if r != ROLE_BAR)
    gap_plan = OfflineExportPlanner(source, withheld).plan(requests)
    _print_plan(
        "Scenario 2: role-bar signed file withheld - report the gap",
        gap_plan,
    )

    undersigned = DictMetadataSource(
        {role: source.role_bytes(role) for role in ALL_ROLES}
    )
    bar_bytes = undersigned.role_bytes(ROLE_BAR)
    bar_md = Metadata.from_bytes(bar_bytes)
    bar_md.signatures.clear()
    undersigned.add(ROLE_BAR, bar_md.to_bytes(JSONSerializer(compact=False)))
    threshold_plan = OfflineExportPlanner(
        undersigned, full_manifest
    ).plan(requests)
    _print_plan(
        "Scenario 3: role-bar delivered under-signed - threshold gap",
        threshold_plan,
    )

    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(tmp) / "review-bundle"
        written = OfflineExportPlanner(source, full_manifest).materialize(
            merge_plan, str(bundle)
        )
        print("=" * 72)
        print(f"Materialized hand-off bundle at {bundle}")
        for role_name, path in sorted(written.items()):
            print(f"  - {role_name}: {Path(path).name}")
        print(f"  - plan.json: role list + no-proof range")


if __name__ == "__main__":
    main()
