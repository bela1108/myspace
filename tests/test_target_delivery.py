# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for the resumable local target delivery state.

The acceptance focus is the two crash windows around target delivery:

* Boundary A: the candidate bytes are already on disk but the delivery state
  record describing them has not been persisted yet.
* Boundary B: the delivery state has been persisted but the candidate file is
  later lost before the upper layer picks the target up.

For both boundaries the tests assert the read/write ordering observed when
the target is picked up again and provide positive evidence (length and hash
against the trusted metadata) that the installed file is the advertised
version.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import unittest
from pathlib import Path
from typing import TYPE_CHECKING
from unittest import mock

from tests.repository_simulator import RepositorySimulator
from tuf.api.exceptions import LengthOrHashMismatchError
from tuf.ngclient import Updater
from tuf.ngclient._internal import target_delivery

if TYPE_CHECKING:
    from tuf.api.metadata import TargetFile

from tuf.ngclient._internal.target_delivery import (
    CANDIDATE_FILENAME,
    DELIVERY_RECORD_VERSION,
    STATE_FILENAME,
    DeliveryState,
    TargetDelivery,
)

TARGET_PATH = "targetpath"
TARGET_CONTENT = b"target content"


class TargetDeliveryTestBase(unittest.TestCase):
    """Common in-memory repository and updater setup."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        self.sim = RepositorySimulator()
        self.sim.targets.version += 1
        self.sim.add_target("targets", TARGET_CONTENT, TARGET_PATH)
        self.sim.update_snapshot()

        self.destination = os.path.join(self.targets_dir, TARGET_PATH)
        self.delivery_dir = f"{self.destination}.delivery"
        self.state_path = os.path.join(self.delivery_dir, STATE_FILENAME)
        self.candidate_path = os.path.join(
            self.delivery_dir, CANDIDATE_FILENAME
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _new_updater(self) -> Updater:
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            bootstrap=self.sim.signed_roots[0],
        )

    def _targetinfo(self, updater: Updater) -> TargetFile:
        info = updater.get_targetinfo(TARGET_PATH)
        self.assertIsNotNone(info)
        assert info is not None
        return info

    def _target_url(self, info: TargetFile) -> str:
        digest = next(iter(info.hashes.values()))
        return f"https://example.com/targets/{digest}.{TARGET_PATH}"

    def _read_state(self) -> dict:
        with open(self.state_path, encoding="utf-8") as state_file:
            return json.load(state_file)

    def _assert_state_is(self, state: DeliveryState) -> None:
        record = self._read_state()
        self.assertEqual(record["state"], state.value)
        self.assertEqual(record["record_version"], DELIVERY_RECORD_VERSION)

    def _assert_installed_matches_trusted_metadata(
        self, info: TargetFile, expected_content: bytes = TARGET_CONTENT
    ) -> None:
        """Positive version evidence against the current trusted view."""
        self.assertTrue(os.path.exists(self.destination))
        with open(self.destination, "rb") as installed:
            info.verify_length_and_hashes(installed)
        with open(self.destination, "rb") as installed:
            self.assertEqual(installed.read(), expected_content)
        record = self._read_state()
        self.assertEqual(record["target"]["path"], info.path)
        self.assertEqual(record["target"]["length"], info.length)
        self.assertEqual(record["target"]["hashes"], info.hashes)


class TestDeliveryStateMachine(TargetDeliveryTestBase):
    """Unit-level checks of the three delivery states and recovery."""

    def test_happy_path_moves_through_all_states(self) -> None:
        updater = self._new_updater()
        info = self._targetinfo(updater)

        path = updater.download_target(info)

        self.assertEqual(path, self.destination)
        self._assert_state_is(DeliveryState.READY)
        self.assertFalse(os.path.exists(self.candidate_path))
        self._assert_installed_matches_trusted_metadata(info)

    def test_resume_downloaded_without_refetching(self) -> None:
        """A DOWNLOADED candidate only needs verification, no fetch."""
        updater = self._new_updater()
        info = self._targetinfo(updater)

        delivery = TargetDelivery.open(self.destination, info)
        self.assertTrue(delivery.needs_download)
        with updater._fetcher.download_file(
            self._target_url(info), info.length
        ) as target_file:
            delivery.stage_candidate(target_file)
        self._assert_state_is(DeliveryState.DOWNLOADED)

        resumed = TargetDelivery.open(self.destination, info)
        self.assertFalse(resumed.needs_download)
        self.assertTrue(resumed.needs_verification)

        fetches_before = len(self.sim.fetch_tracker.targets)
        resumed.verify_candidate()
        resumed.promote()
        self.assertEqual(len(self.sim.fetch_tracker.targets), fetches_before)
        self._assert_installed_matches_trusted_metadata(info)

    def test_superseded_candidate_is_never_reused(self) -> None:
        """A new trusted version discards the old candidate and record."""
        updater = self._new_updater()
        old_info = self._targetinfo(updater)
        old_delivery = TargetDelivery.open(self.destination, old_info)
        with updater._fetcher.download_file(
            self._target_url(old_info), old_info.length
        ) as target_file:
            old_delivery.stage_candidate(target_file)
        self.assertTrue(os.path.exists(self.candidate_path))

        new_content = b"target content version 2"
        self.sim.targets.version += 1
        self.sim.add_target("targets", new_content, TARGET_PATH)
        self.sim.update_snapshot()

        updater = self._new_updater()
        new_info = self._targetinfo(updater)
        self.assertNotEqual(new_info.hashes, old_info.hashes)

        with self.assertLogs(
            target_delivery.logger, level=logging.DEBUG
        ) as logs:
            new_delivery = TargetDelivery.open(self.destination, new_info)

        self.assertTrue(
            any("target identity changed" in msg for msg in logs.output)
        )
        self.assertTrue(new_delivery.needs_download)
        self._assert_state_is(DeliveryState.PENDING)

        path = updater.download_target(new_info)
        self.assertEqual(path, self.destination)
        with open(self.destination, "rb") as installed:
            self.assertEqual(installed.read(), new_content)
        self._assert_installed_matches_trusted_metadata(new_info, new_content)

    def test_unreadable_state_record_restarts_delivery(self) -> None:
        updater = self._new_updater()
        info = self._targetinfo(updater)
        delivery = TargetDelivery.open(self.destination, info)
        delivery._write_state(DeliveryState.PENDING)
        Path(self.state_path).write_text("{not valid json", encoding="utf-8")

        restarted = TargetDelivery.open(self.destination, info)

        self.assertTrue(restarted.needs_download)
        self._assert_state_is(DeliveryState.PENDING)

    def test_unknown_state_value_restarts_delivery(self) -> None:
        updater = self._new_updater()
        info = self._targetinfo(updater)
        TargetDelivery.open(self.destination, info)
        record = self._read_state()
        record["state"] = "mysterious-future-state"
        Path(self.state_path).write_text(json.dumps(record), encoding="utf-8")

        restarted = TargetDelivery.open(self.destination, info)

        self.assertTrue(restarted.needs_download)
        self._assert_state_is(DeliveryState.PENDING)

    def test_corrupt_candidate_fails_verification_and_restarts(self) -> None:
        updater = self._new_updater()
        info = self._targetinfo(updater)
        delivery = TargetDelivery.open(self.destination, info)
        Path(self.delivery_dir).mkdir(parents=True, exist_ok=True)
        with open(self.candidate_path, "wb") as corrupt:
            corrupt.write(b"not the advertised content")
        delivery._write_state(DeliveryState.DOWNLOADED)

        with self.assertRaises(LengthOrHashMismatchError):
            delivery.verify_candidate()

        self._assert_state_is(DeliveryState.PENDING)
        self.assertFalse(os.path.exists(self.candidate_path))


class TestCrashBoundaries(TargetDeliveryTestBase):
    """Acceptance tests for the two crash windows.

    Every test rebuilds the Updater (and therefore re-reads all trusted
    metadata from disk) before the second pickup, mirroring a process restart
    after the power loss.
    """

    def test_boundary_a_data_on_disk_state_not_written(self) -> None:
        """Candidate flushed, DOWNLOADED state lost: re-fetch required."""
        updater = self._new_updater()
        info = self._targetinfo(updater)

        real_write_state = TargetDelivery._write_state

        def crash_before_downloaded_state(
            delivery: TargetDelivery, state: DeliveryState
        ) -> None:
            if state == DeliveryState.DOWNLOADED:
                raise OSError("simulated power loss before state write")
            real_write_state(delivery, state)

        with (
            mock.patch.object(
                TargetDelivery,
                "_write_state",
                autospec=True,
                side_effect=crash_before_downloaded_state,
            ),
            self.assertRaises(OSError),
        ):
            updater.download_target(info)

        # Boundary A on disk: PENDING record plus an orphaned candidate.
        self._assert_state_is(DeliveryState.PENDING)
        self.assertTrue(os.path.exists(self.candidate_path))

        # Restart and pick the target up again.
        fetches_before = len(self.sim.fetch_tracker.targets)
        updater = self._new_updater()
        info = self._targetinfo(updater)
        with self.assertLogs(
            target_delivery.logger, level=logging.DEBUG
        ) as logs:
            path = updater.download_target(info)

        # Read/write order: state is read first, the orphan is discarded and
        # the candidate is fetched and written again.
        messages = "\n".join(logs.output)
        self.assertIn("Resuming delivery", messages)
        self.assertIn("Candidate for targetpath staged", messages)
        self.assertGreater(len(self.sim.fetch_tracker.targets), fetches_before)
        self.assertEqual(path, self.destination)
        self._assert_installed_matches_trusted_metadata(info)

    def test_boundary_b_state_written_candidate_lost(self) -> None:
        """READY state persisted, candidate later deleted: re-fetch."""
        updater = self._new_updater()
        info = self._targetinfo(updater)

        def crash_after_verification(delivery: TargetDelivery) -> None:
            # State is READY on disk; remove the candidate to model the file
            # being lost before the upper layer picks it up.
            os.remove(delivery.candidate_path)
            raise OSError("simulated power loss after state write")

        with (
            mock.patch.object(
                TargetDelivery,
                "promote",
                autospec=True,
                side_effect=crash_after_verification,
            ),
            self.assertRaises(OSError),
        ):
            updater.download_target(info)

        # Boundary B on disk: persisted state without a candidate.
        self._assert_state_is(DeliveryState.READY)
        self.assertFalse(os.path.exists(self.candidate_path))

        # Restart and pick the target up again.
        fetches_before = len(self.sim.fetch_tracker.targets)
        updater = self._new_updater()
        info = self._targetinfo(updater)
        with self.assertLogs(
            target_delivery.logger, level=logging.DEBUG
        ) as logs:
            path = updater.download_target(info)

        # Read/write order: the state is read, the missing candidate is
        # detected, the material is discarded and a fresh fetch happens.
        messages = "\n".join(logs.output)
        self.assertIn("candidate is missing", messages)
        self.assertIn("Candidate for targetpath staged", messages)
        self.assertGreater(len(self.sim.fetch_tracker.targets), fetches_before)
        self.assertEqual(path, self.destination)
        self._assert_installed_matches_trusted_metadata(info)

    def test_boundary_b_downloaded_state_candidate_lost(self) -> None:
        """Same recovery when the loss happens while still DOWNLOADED."""
        updater = self._new_updater()
        info = self._targetinfo(updater)

        delivery = TargetDelivery.open(self.destination, info)
        with updater._fetcher.download_file(
            self._target_url(info), info.length
        ) as target_file:
            delivery.stage_candidate(target_file)
        self._assert_state_is(DeliveryState.DOWNLOADED)
        os.remove(self.candidate_path)

        updater = self._new_updater()
        info = self._targetinfo(updater)
        fetches_before = len(self.sim.fetch_tracker.targets)
        with self.assertLogs(
            target_delivery.logger, level=logging.DEBUG
        ) as logs:
            path = updater.download_target(info)

        self.assertIn("candidate is missing", "\n".join(logs.output))
        self.assertGreater(len(self.sim.fetch_tracker.targets), fetches_before)
        self._assert_installed_matches_trusted_metadata(info)
        self.assertEqual(path, self.destination)


if __name__ == "__main__":
    unittest.main()
