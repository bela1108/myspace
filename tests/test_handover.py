# Copyright 2026 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for tuf.repository handover precheck"""

from __future__ import annotations

import copy
import logging
import unittest
from datetime import UTC, datetime, timedelta

from securesystemslib.signer import CryptoSigner, Signer

from tuf.api.metadata import (
    Metadata,
    Root,
    Signed,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.repository import handover_precheck

logger = logging.getLogger(__name__)

ONLINE_ROLES = ["timestamp", "snapshot", "targets"]
ALL_ROLES = ["root", *ONLINE_ROLES]


def _signed_md(signed: Signed, signers: list[Signer]) -> Metadata:
    md = Metadata(signed)
    for signer in signers:
        md.sign(signer, append=True)
    return md


class TestHandoverPrecheck(unittest.TestCase):
    """Test the read-only handover precheck with test keys"""

    def setUp(self) -> None:
        self.expires = datetime.now(UTC) + timedelta(days=30)
        # team A (handing over) and team B (taking over) test keys
        self.a = {r: CryptoSigner.generate_ed25519() for r in ALL_ROLES}
        self.b = {r: CryptoSigner.generate_ed25519() for r in ALL_ROLES}

    def _root_v1(self) -> Root:
        """Initial root: team A serves every role"""
        root = Root(expires=self.expires)
        for role in ALL_ROLES:
            root.add_key(self.a[role].public_key, role)
        return root

    def _final_root(self) -> Root:
        """Handover root: both teams sign root, team B serves the rest"""
        root = Root(version=2, expires=self.expires)
        root.add_key(self.a["root"].public_key, "root")
        root.add_key(self.b["root"].public_key, "root")
        root.roles["root"].threshold = 2
        for role in ONLINE_ROLES:
            root.add_key(self.b[role].public_key, role)
        return root

    def _role_metadata(self, signers: dict[str, Signer]) -> dict[str, Metadata]:
        """Fresh pending-release metadata for the online roles"""
        return {
            "timestamp": _signed_md(
                Timestamp(expires=self.expires), [signers["timestamp"]]
            ),
            "snapshot": _signed_md(
                Snapshot(expires=self.expires), [signers["snapshot"]]
            ),
            "targets": _signed_md(
                Targets(expires=self.expires), [signers["targets"]]
            ),
        }

    def _make_plans(
        self,
    ) -> tuple[dict[str, dict[str, Metadata]], dict[str, dict[str, Metadata]]]:
        """Two handover plans that must end with the same final root"""

        def current_stage() -> dict[str, Metadata]:
            return {
                "root": _signed_md(self._root_v1(), [self.a["root"]]),
                **self._role_metadata(self.a),
            }

        def handover_stage() -> dict[str, Metadata]:
            return {
                "root": _signed_md(
                    self._final_root(), [self.a["root"], self.b["root"]]
                ),
                **self._role_metadata(self.b),
            }

        # plan 1: rotate root and hand over all roles in one step
        plan1 = {
            "current": current_stage(),
            "handover": handover_stage(),
        }
        # plan 2: team B first shadow-signs alongside team A, then handover
        shadow = current_stage()
        for role in ONLINE_ROLES:
            shadow[role].sign(self.b[role], append=True)
        plan2 = {
            "current": current_stage(),
            "shadow": shadow,
            "handover": handover_stage(),
        }
        return plan1, plan2

    def _available(self, team: dict[str, Signer]) -> dict[str, set[str]]:
        return {role: {s.public_key.keyid} for role, s in team.items()}

    def test_two_handovers_pass_and_share_final_root(self) -> None:
        plan1, plan2 = self._make_plans()
        # both teams are still available during the whole handover
        available = {
            role: keyids | self._available(self.b)[role]
            for role, keyids in self._available(self.a).items()
        }

        report1 = handover_precheck(plan1, available)
        report2 = handover_precheck(plan2, available)

        self.assertTrue(report1.ok, report1.first_gap)
        self.assertTrue(report2.ok, report2.first_gap)
        self.assertIsNone(report1.first_gap)
        self.assertIsNone(report2.first_gap)
        self.assertEqual([s.stage for s in report1.stages], list(plan1))
        self.assertEqual([s.stage for s in report2.stages], list(plan2))

        # the two handovers must agree on the final root
        final1 = plan1["handover"]["root"].signed
        final2 = plan2["handover"]["root"].signed
        self.assertEqual(final1, final2)

    def test_first_uncovered_stage_role_and_evidence(self) -> None:
        plan1, _ = self._make_plans()
        # team B's snapshot key holder is not available to take over
        available = {
            role: keyids | self._available(self.b)[role]
            for role, keyids in self._available(self.a).items()
        }
        available["snapshot"].discard(self.b["snapshot"].public_key.keyid)

        report = handover_precheck(plan1, available)

        self.assertFalse(report.ok)
        self.assertTrue(report.stages[0].ok)
        gap = report.first_gap
        assert gap is not None
        self.assertEqual(gap.stage, "handover")
        self.assertEqual(gap.role, "snapshot")
        self.assertEqual(gap.reason, "coverage")
        self.assertIn("requires 1 key(s) but only 0 of 1", gap.evidence)
        self.assertIn(self.b["snapshot"].public_key.keyid, gap.evidence)

    def test_root_chain_gap(self) -> None:
        plan1, _ = self._make_plans()
        # team A never signs the handover root: chain of trust is broken
        handover = plan1["handover"]
        handover["root"] = _signed_md(self._final_root(), [self.b["root"]])
        available = {
            role: keyids | self._available(self.b)[role]
            for role, keyids in self._available(self.a).items()
        }

        report = handover_precheck(plan1, available)

        self.assertFalse(report.ok)
        gap = report.first_gap
        assert gap is not None
        self.assertEqual(gap.stage, "handover")
        self.assertEqual(gap.role, "root")
        self.assertEqual(gap.reason, "trust")
        self.assertIn("0/1 keys of the previous root", gap.evidence)
        self.assertIn("1/2 keys of the current root", gap.evidence)
        self.assertIn(self.a["root"].public_key.keyid, gap.evidence)

    def test_role_trust_gap(self) -> None:
        plan1, _ = self._make_plans()
        # handover targets is signed by team A, but root already requires B
        handover = plan1["handover"]
        handover["targets"] = _signed_md(
            Targets(expires=self.expires), [self.a["targets"]]
        )
        available = {
            role: keyids | self._available(self.b)[role]
            for role, keyids in self._available(self.a).items()
        }

        report = handover_precheck(plan1, available)

        self.assertFalse(report.ok)
        gap = report.first_gap
        assert gap is not None
        self.assertEqual(gap.stage, "handover")
        self.assertEqual(gap.role, "targets")
        self.assertEqual(gap.reason, "trust")
        self.assertIn("0/1 required keys", gap.evidence)
        self.assertIn(self.b["targets"].public_key.keyid, gap.evidence)

    def test_precheck_is_read_only(self) -> None:
        plan1, _ = self._make_plans()
        available = {
            role: keyids | self._available(self.b)[role]
            for role, keyids in self._available(self.a).items()
        }
        available["snapshot"].discard(self.b["snapshot"].public_key.keyid)
        before = copy.deepcopy(plan1)

        handover_precheck(plan1, available)

        self.assertEqual(plan1, before)


if __name__ == "__main__":
    unittest.main()
