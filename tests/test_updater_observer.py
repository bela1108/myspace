# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test offline observation next to the ngclient update workflow."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.metadata import Root, Snapshot, Targets, Timestamp
from tuf.ngclient import ObservationCancelledError, Updater


class RecordingSimulator(RepositorySimulator):
    """Simulator that records the order in which metadata is served."""

    def __init__(self) -> None:
        super().__init__()
        self.served: list[tuple[str, int | None]] = []

    def fetch_metadata(self, role: str, version: int | None = None) -> bytes:
        self.served.append((role, version))
        return super().fetch_metadata(role, version)


class TestObserver(unittest.TestCase):
    """Test Updater.observe() offline observations."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.makedirs(self.metadata_dir)
        os.makedirs(self.targets_dir)

        self.sim = RecordingSimulator()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _init_updater(self, bootstrap: bytes | None = None) -> Updater:
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            bootstrap=bootstrap
            if bootstrap is not None
            else self.sim.signed_roots[0],
        )

    def _metadata_cache_files(self) -> list[str]:
        files = []
        for root, _dirs, names in os.walk(self.metadata_dir):
            for name in names:
                files.append(
                    os.path.relpath(os.path.join(root, name), self.metadata_dir)
                )
        return sorted(files)

    def test_interleaved_observations_keep_own_views(self) -> None:
        # Use unversioned metadata URLs so a pre-refresh observation
        # (whose view only contains root) can address all roles
        self.sim.root.consistent_snapshot = False
        self.sim.publish_root()
        updater = self._init_updater(self.sim.signed_roots[-1])
        # keep a single published root v1 (re-signed without
        # consistent_snapshot) so the simulator serves it for v1 only
        self.sim.signed_roots = [self.sim.signed_roots[-1]]

        # First observation starts while the client is still waiting
        # for the update: its trusted view only contains root
        obs1 = updater.observe()
        self.assertEqual(obs1.reference, "obs-1")
        self.assertIsNone(obs1.view.version(Timestamp.type))

        # The update completes: trusted view now covers all top-level roles
        updater.refresh()
        obs2 = updater.observe()
        self.assertEqual(obs2.view.version(Timestamp.type), 1)

        # Repository publishes new versions while both observations pend
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        # The fake fetcher serves the later-issued observation first:
        # obs2's read-only checks complete before obs1's. Each
        # observation checks several roles so its report observes
        # multiple verified states at once.
        self.sim.served.clear()
        obs2_states = [
            obs2.check(role)
            for role in (Timestamp.type, Snapshot.type, Targets.type)
        ]
        obs1_states = [
            obs1.check(role)
            for role in (Targets.type, Snapshot.type, Timestamp.type)
        ]

        # Fetcher log proves the later observation was served first
        self.assertEqual(
            self.sim.served,
            [
                (Timestamp.type, None),
                (Snapshot.type, None),
                (Targets.type, None),
                (Targets.type, None),
                (Snapshot.type, None),
                (Timestamp.type, None),
            ],
        )

        # Both observations verified the same remote content (v2) ...
        for state in obs1_states + obs2_states:
            self.assertEqual(state.version, 2)

        # ... but each report explains the view it was based on
        report1 = obs1.report()
        report2 = obs2.report()
        self.assertEqual(report1.reference, "obs-1")
        self.assertEqual(report2.reference, "obs-2")

        # obs1 saw the pre-refresh view (root only), obs2 the refreshed one
        self.assertIsNone(report1.view.version(Timestamp.type))
        self.assertEqual(report1.view.version(Root.type), 1)
        self.assertEqual(report2.view.version(Timestamp.type), 1)
        self.assertEqual(report2.view.version(Targets.type), 1)
        self.assertEqual(report1.states[Timestamp.type].version, 2)
        self.assertEqual(report2.states[Timestamp.type].version, 2)

        explanation1 = report1.explain()
        explanation2 = report2.explain()
        self.assertIn("obs-1", explanation1)
        self.assertIn("root v1", explanation1)
        self.assertNotIn("timestamp v1", explanation1)
        self.assertIn("observed timestamp v2", explanation1)
        self.assertIn("obs-2", explanation2)
        self.assertIn("timestamp v1", explanation2)
        self.assertIn("observed timestamp v2", explanation2)

    def test_observation_does_not_pollute_cache_or_trust(self) -> None:
        updater = self._init_updater()
        updater.refresh()
        cache_before = self._metadata_cache_files()
        trusted_before = {
            role: signed.version
            for role, signed in updater._trusted_set.trusted_items()
        }

        # Remote has newer content that read-only checks will load
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        obs = updater.observe()
        # read-only checks load and verify the newer remote content
        for role in (Timestamp.type, Snapshot.type, Targets.type):
            self.assertEqual(obs.check(role).version, 2)

        # The formal update cache only contains content that passed the
        # original trust verification: observation downloads add nothing
        self.assertEqual(self._metadata_cache_files(), cache_before)

        # The updater's trusted set is untouched by read-only checks
        trusted_after = {
            role: signed.version
            for role, signed in updater._trusted_set.trusted_items()
        }
        self.assertEqual(trusted_after, trusted_before)

    def test_observation_view_is_detached_copy(self) -> None:
        updater = self._init_updater()
        obs = updater.observe()
        updater.refresh()

        # The captured view still describes the state at observation start
        self.assertIsNone(obs.view.version(Timestamp.type))
        self.assertEqual(obs.view.version(Root.type), 1)
        self.assertIsNot(obs.view.roles[Root.type], updater._trusted_set.root)

    def test_observation_checks_next_root(self) -> None:
        updater = self._init_updater()
        updater.refresh()
        obs = updater.observe()

        # Repository rotates root: the observation can verify the next
        # root against its captured view without trusting it
        self.sim.root.version += 1
        self.sim.publish_root()
        state = obs.check(Root.type)
        self.assertEqual(state.version, 2)

        # The updater itself still only trusts root v1
        self.assertEqual(updater._trusted_set.root.version, 1)

    def test_observation_cancellation(self) -> None:
        updater = self._init_updater()
        updater.refresh()
        obs = updater.observe()
        obs.cancel("awaiting-update")

        with self.assertRaises(ObservationCancelledError) as ctx:
            obs.check(Timestamp.type)
        self.assertIn("awaiting-update", str(ctx.exception))

        report = obs.report()
        self.assertEqual(report.cancelled_at, "awaiting-update")
        self.assertIn("cancelled at 'awaiting-update'", report.explain())
        self.assertEqual(report.states, {})

    def test_observation_rejects_bad_signature(self) -> None:
        updater = self._init_updater()
        updater.refresh()
        obs = updater.observe()

        # Remote metadata signed by an untrusted key must not verify,
        # and must certainly not become trusted
        self.sim.rotate_keys(Timestamp.type)
        self.sim.update_timestamp()
        with self.assertRaises(UnsignedMetadataError):
            obs.check(Timestamp.type)


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
