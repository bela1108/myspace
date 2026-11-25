# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta

from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import TOP_LEVEL_ROLE_NAMES, Metadata, Role, Root
from tuf.api.root_transition import precheck_root_transition


class TestRootTransition(unittest.TestCase):
    def setUp(self) -> None:
        self.signers = [CryptoSigner.generate_ed25519() for _ in range(4)]
        self.base_time = datetime(2026, 1, 1, tzinfo=UTC)

    def make_root(
        self,
        version: int,
        expires_after_days: int,
        root_key_indexes: list[int],
        threshold: int = 1,
    ) -> Metadata[Root]:
        keys = {
            self.signers[index].public_key.keyid: self.signers[
                index
            ].public_key
            for index in root_key_indexes
        }
        keyids = [
            self.signers[index].public_key.keyid for index in root_key_indexes
        ]
        roles = {
            role_name: Role(keyids.copy(), threshold)
            for role_name in TOP_LEVEL_ROLE_NAMES
        }
        return Metadata(
            Root(
                version=version,
                expires=self.base_time + timedelta(days=expires_after_days),
                keys=keys,
                roles=roles,
            )
        )

    def test_valid_transition(self) -> None:
        plan = [
            self.make_root(1, 1, [0]),
            self.make_root(2, 2, [0, 1]),
            self.make_root(3, 3, [0, 1]),
        ]

        result = precheck_root_transition(plan)

        self.assertTrue(result.verified)
        self.assertIsNone(result.first_gap)
        self.assertEqual(result.stages_checked, 3)

    def test_same_final_root_can_have_different_conclusions(self) -> None:
        final_root = self.make_root(3, 3, [0, 1])
        continuous_plan = [
            self.make_root(1, 1, [0]),
            self.make_root(2, 2, [0, 1]),
            deepcopy(final_root),
        ]
        plan_with_gap = [
            self.make_root(1, 2, [0]),
            self.make_root(2, 1, [1]),
            deepcopy(final_root),
        ]

        continuous_result = precheck_root_transition(continuous_plan)
        gap_result = precheck_root_transition(plan_with_gap)

        self.assertEqual(
            continuous_plan[-1].to_bytes(),
            plan_with_gap[-1].to_bytes(),
        )
        self.assertTrue(continuous_result.verified)
        self.assertFalse(gap_result.verified)
        self.assertEqual(gap_result.stages_checked, 2)
        assert gap_result.first_gap is not None
        self.assertEqual(gap_result.first_gap.kind, "effective_time")
        self.assertEqual(gap_result.first_gap.stage_version, 2)

    def test_first_unreachable_threshold_is_returned(self) -> None:
        plan = [
            self.make_root(1, 1, [0]),
            self.make_root(2, 2, [1], threshold=2),
            self.make_root(3, 1, [1]),
        ]

        result = precheck_root_transition(plan)

        self.assertFalse(result.verified)
        self.assertEqual(result.stages_checked, 2)
        assert result.first_gap is not None
        self.assertEqual(result.first_gap.kind, "unreachable_threshold")
        self.assertEqual(result.first_gap.role, Root.type)
        self.assertEqual(result.first_gap.stage_version, 2)

    def test_missing_role_key_is_returned(self) -> None:
        root = self.make_root(1, 1, [0])
        root.signed.roles[Root.type].keyids.append("missing-key")

        result = precheck_root_transition([root])

        assert result.first_gap is not None
        self.assertEqual(result.first_gap.kind, "missing_role_key")
        self.assertEqual(result.first_gap.role, Root.type)

    def test_non_root_role_is_checked(self) -> None:
        root = self.make_root(1, 1, [0])
        root.signed.roles["timestamp"].threshold = 2

        result = precheck_root_transition([root])

        assert result.first_gap is not None
        self.assertEqual(result.first_gap.kind, "unreachable_threshold")
        self.assertEqual(result.first_gap.role, "timestamp")

    def test_nonsequential_version_is_returned(self) -> None:
        plan = [
            self.make_root(1, 1, [0]),
            self.make_root(3, 2, [0, 1]),
        ]

        result = precheck_root_transition(plan)

        assert result.first_gap is not None
        self.assertEqual(result.first_gap.kind, "version_sequence")
        self.assertEqual(result.first_gap.stage_version, 3)

    def test_equal_expiration_is_a_gap(self) -> None:
        plan = [
            self.make_root(1, 1, [0]),
            self.make_root(2, 1, [0, 1]),
        ]

        result = precheck_root_transition(plan)

        assert result.first_gap is not None
        self.assertEqual(result.first_gap.kind, "effective_time")

    def test_empty_plan_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            precheck_root_transition([])

    def test_metadata_is_not_modified(self) -> None:
        plan = [
            self.make_root(1, 1, [0]),
            self.make_root(2, 2, [0, 1]),
        ]
        before = [deepcopy(metadata).to_dict() for metadata in plan]

        precheck_root_transition(plan)

        after = [metadata.to_dict() for metadata in plan]
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
