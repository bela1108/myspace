# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for the offline export planner minimal-role selection."""

from __future__ import annotations

import sys
import tempfile
import unittest
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

_EXAMPLE_DIR = (
    Path(__file__).resolve().parents[1] / "examples" / "offline_export"
)
sys.path.insert(0, str(_EXAMPLE_DIR))

from offline_export_planner import (  # noqa: E402
    DictMetadataSource,
    GapReason,
    OfflineExportPlanner,
    TransferManifest,
)

FOO = "pkg/foo/app-1.tar"
BAR = "pkg/bar/app-2.tar"
ROLE_FOO = "role-foo"
ROLE_BAR = "role-bar"
TOP_LEVEL = ("root", "timestamp", "snapshot", "targets")
ALL_ROLES = TOP_LEVEL + (ROLE_FOO, ROLE_BAR)


def _expiry(days: int) -> datetime:
    return datetime.now(UTC).replace(microsecond=0) + timedelta(days=days)


class SignedRepoBuilder:
    """Build a small signed repository in memory for planner tests."""

    def __init__(self) -> None:
        self.serializer = JSONSerializer(compact=False)
        self.signers: dict[str, CryptoSigner] = {}
        self.root = Metadata(Root(expires=_expiry(365)))
        self.timestamp = Metadata(Timestamp(expires=_expiry(1)))
        self.snapshot = Metadata(Snapshot(expires=_expiry(30)))
        self.targets = Metadata(Targets(expires=_expiry(365)))
        self.leaves: dict[str, Metadata[Targets]] = {}
        for name in TOP_LEVEL:
            signer = self._signer(name)
            self.root.signed.add_key(signer.public_key, name)

    def _signer(self, role: str) -> CryptoSigner:
        signer = CryptoSigner.generate_ed25519()
        self.signers[role] = signer
        return signer

    def add_leaf(
        self,
        name: str,
        target_path: str | None,
        paths: list[str],
        *,
        terminating: bool = False,
    ) -> None:
        signer = self._signer(name)
        targets = {}
        if target_path is not None:
            targets[target_path] = TargetFile.from_data(
                target_path, b"data", ["sha256"]
            )
        leaf = Metadata(Targets(expires=_expiry(30), targets=targets))
        leaf.sign(signer)
        self.leaves[name] = leaf
        if self.targets.signed.delegations is None:
            self.targets.signed.delegations = Delegations(
                keys={}, roles={}
            )
        delegations = self.targets.signed.delegations
        delegations.keys[signer.public_key.keyid] = signer.public_key
        delegations.roles[name] = DelegatedRole(
            name, [signer.public_key.keyid], 1, terminating, paths=paths
        )

    def build(self) -> DictMetadataSource:
        self.targets.sign(self.signers["targets"])
        for name, leaf in self.leaves.items():
            self.snapshot.signed.meta[f"{name}.json"] = MetaFile(
                leaf.signed.version
            )
        self.snapshot.signed.meta["targets.json"] = MetaFile(
            self.targets.signed.version
        )
        self.snapshot.sign(self.signers["snapshot"])
        self.timestamp.signed.snapshot_meta = MetaFile(
            self.snapshot.signed.version
        )
        self.timestamp.sign(self.signers["timestamp"])
        self.root.sign(self.signers["root"])
        source = DictMetadataSource()
        for name, metadata in (
            *[("root", self.root), ("timestamp", self.timestamp),
              ("snapshot", self.snapshot), ("targets", self.targets)],
            *list(self.leaves.items()),
        ):
            source.add(name, metadata.to_bytes(self.serializer))
        return source

class OfflineExportPlannerTest(unittest.TestCase):
    """Cover minimal-set merge, target hit conditions and gap reporting."""

    def _builder(self) -> SignedRepoBuilder:
        builder = SignedRepoBuilder()
        builder.add_leaf(ROLE_FOO, FOO, ["pkg/foo/*"])
        builder.add_leaf(ROLE_BAR, BAR, ["pkg/bar/*"])
        return builder

    def test_minimal_set_and_shared_parent_merge(self) -> None:
        source = self._builder().build()
        plan = OfflineExportPlanner(
            source, TransferManifest(ALL_ROLES)
        ).plan([FOO, BAR])

        self.assertEqual(set(plan.proven_targets), {FOO, BAR})
        self.assertEqual(plan.unproven_targets, frozenset())
        names = plan.role_names()
        self.assertEqual(names, list(TOP_LEVEL) + [ROLE_FOO, ROLE_BAR])
        self.assertEqual(len(plan.roles), len(set(names)))
        targets_req = next(r for r in plan.roles if r.role == "targets")
        self.assertEqual(targets_req.proves_targets, {FOO, BAR})
        foo_req = next(r for r in plan.roles if r.role == ROLE_FOO)
        self.assertEqual(foo_req.proves_targets, {FOO})

    def test_single_request_excludes_unrelated_leaf(self) -> None:
        source = self._builder().build()
        plan = OfflineExportPlanner(
            source, TransferManifest(ALL_ROLES)
        ).plan([FOO])

        self.assertIn(ROLE_FOO, plan.role_names())
        self.assertNotIn(ROLE_BAR, plan.role_names())
        self.assertEqual(set(plan.proven_targets), {FOO})

    def test_withheld_role_is_gap_not_alias(self) -> None:
        source = self._builder().build()
        manifest = TransferManifest(r for r in ALL_ROLES if r != ROLE_BAR)
        plan = OfflineExportPlanner(source, manifest).plan([FOO, BAR])

        self.assertEqual(set(plan.proven_targets), {FOO})
        self.assertEqual(plan.unproven_targets, frozenset({BAR}))
        self.assertNotIn(ROLE_BAR, plan.role_names())
        gap = next(g for g in plan.gaps if g.target_path == BAR)
        self.assertEqual(gap.reason, GapReason.ROLE_NOT_TRANSFERABLE)
        self.assertEqual(gap.role, ROLE_BAR)

    def test_undersigned_role_reports_threshold_gap(self) -> None:
        builder = self._builder()
        source = builder.build()
        bar = Metadata.from_bytes(source.role_bytes(ROLE_BAR))
        bar.signatures.clear()
        source.add(ROLE_BAR, bar.to_bytes(builder.serializer))

        plan = OfflineExportPlanner(
            source, TransferManifest(ALL_ROLES)
        ).plan([FOO, BAR])
        gap = next(g for g in plan.gaps if g.target_path == BAR)
        self.assertEqual(gap.reason, GapReason.THRESHOLD_UNMET)
        self.assertNotIn(ROLE_BAR, plan.role_names())
        self.assertEqual(set(plan.proven_targets), {FOO})

    def test_missing_snapshot_entry_is_gap(self) -> None:
        builder = self._builder()
        source = builder.build()
        snapshot = Metadata.from_bytes(source.role_bytes("snapshot"))
        del snapshot.signed.meta[f"{ROLE_FOO}.json"]
        snapshot.signatures.clear()
        snapshot.sign(builder.signers["snapshot"])
        source.add("snapshot", snapshot.to_bytes(builder.serializer))

        plan = OfflineExportPlanner(
            source, TransferManifest(ALL_ROLES)
        ).plan([FOO])
        gap = next(g for g in plan.gaps if g.target_path == FOO)
        self.assertEqual(gap.reason, GapReason.NOT_IN_SNAPSHOT)
        self.assertNotIn(ROLE_FOO, plan.role_names())

    def test_terminating_delegation_stops_backtracking(self) -> None:
        builder = SignedRepoBuilder()
        builder.add_leaf(ROLE_FOO, None, ["pkg/foo/*"], terminating=True)
        builder.add_leaf(ROLE_BAR, FOO, ["pkg/foo/*"])
        source = builder.build()

        plan = OfflineExportPlanner(
            source, TransferManifest(ALL_ROLES)
        ).plan([FOO])
        # terminating role-foo ends the walk: sibling role-bar is never visited
        self.assertNotIn(ROLE_BAR, plan.role_names())
        self.assertNotIn(ROLE_FOO, plan.role_names())
        self.assertEqual(plan.proven_targets, frozenset())
        gap = next(iter(plan.gaps))
        self.assertEqual(gap.reason, GapReason.TARGET_NOT_FOUND)
        self.assertEqual(gap.role, "targets")

    def test_unclaimed_target_is_not_found_gap(self) -> None:
        builder = SignedRepoBuilder()
        builder.add_leaf(ROLE_FOO, FOO, ["pkg/foo/*"])
        source = builder.build()

        plan = OfflineExportPlanner(
            source, TransferManifest(ALL_ROLES)
        ).plan(["pkg/other/missing.tar"])
        gap = next(iter(plan.gaps))
        self.assertEqual(gap.reason, GapReason.TARGET_NOT_FOUND)
        self.assertEqual(plan.proven_targets, frozenset())

    def test_withheld_anchor_blocks_every_request(self) -> None:
        source = self._builder().build()
        manifest = TransferManifest(r for r in ALL_ROLES if r != "snapshot")
        plan = OfflineExportPlanner(source, manifest).plan([FOO, BAR])

        self.assertEqual(plan.proven_targets, frozenset())
        self.assertEqual(plan.unproven_targets, frozenset({FOO, BAR}))
        self.assertTrue(all(
            g.role == "snapshot"
            and g.reason is GapReason.ROLE_NOT_TRANSFERABLE
            for g in plan.gaps
        ))
        self.assertEqual(plan.role_names(), [])

    def test_materialize_writes_only_gated_roles(self) -> None:
        source = self._builder().build()
        planner = OfflineExportPlanner(source, TransferManifest(ALL_ROLES))
        plan = planner.plan([FOO, BAR])
        with tempfile.TemporaryDirectory() as tmp:
            written = planner.materialize(plan, tmp)
            names = {Path(path).name for path in written.values()}
            self.assertEqual(names, {r.filename for r in plan.roles})
            self.assertTrue((Path(tmp) / "plan.json").exists())
            for requirement in plan.roles:
                path = Path(tmp) / requirement.filename
                self.assertEqual(path.read_bytes(),
                                 source.role_bytes(requirement.role))


if __name__ == "__main__":
    unittest.main()
