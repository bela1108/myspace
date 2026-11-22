# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Resumable local delivery state for target downloads.

The TUF client workflow in :mod:`tuf.ngclient.updater` downloads a target,
verifies it against signed metadata and only then exposes it to the
application. A process or power failure in the middle of that workflow used
to leave an installation directory with nothing but an orphaned, partially
written file: on the next run the client could not tell whether that file was
still worth fetching or had to be discarded.

:class:`TargetDelivery` adds a small, crash-safe delivery record that lives
next to the destination file and makes that distinction explicit. A delivery
moves through three states:

* ``PENDING``: the target identity claimed by the caller has been recorded but
  no candidate has been fully staged yet. The temporary candidate (if any) is
  still missing or incomplete and has to be fetched.
* ``DOWNLOADED``: a complete candidate has been flushed to disk and is waiting
  for the length/hash check against the trusted view.
* ``READY``: the candidate matched the claimed length and hashes and can be
  handed to the upper layer by atomically moving it into place.

Both the state record and the candidate are written atomically
(:func:`os.replace`) so that a crash can only expose the previous or the new
state, never a torn write. Every state transition also stores the target
path, length and hashes that the state is a claim about: a later request for
the same destination re-checks that claim against the currently trusted
metadata and starts over when the repository has published a different
version. A stale candidate can therefore never be used to fill in for a
newer target.
"""

from __future__ import annotations

import contextlib
import enum
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from tuf.api import exceptions

if TYPE_CHECKING:
    from tuf.api.metadata import TargetFile

logger = logging.getLogger(__name__)

#: Version of the on-disk delivery record format.
DELIVERY_RECORD_VERSION = 1

#: File name of the JSON delivery record inside the delivery directory.
STATE_FILENAME = "state.json"

#: File name of the staged candidate inside the delivery directory.
CANDIDATE_FILENAME = "candidate"


class DeliveryState(enum.StrEnum):
    """Lifecycle states of a resumable target delivery."""

    #: Target identity recorded, candidate still has to be fetched.
    PENDING = "pending"

    #: Candidate fully staged, length/hash verification still pending.
    DOWNLOADED = "downloaded"

    #: Candidate verified against trusted metadata, ready to be installed.
    READY = "ready"


class TargetDelivery:
    """Crash-safe delivery state for a single target destination.

    The delivery material is kept in a hidden directory that sits next to the
    destination file (``"<destination>.delivery/"``) so that different target
    paths cannot share state. Instances are normally created with
    :meth:`open`, which reconciles a possibly interrupted previous delivery
    with the currently trusted target information.

    Args:
        destination: Final path that the upper layer expects the target at.
        targetinfo: Trusted target information from the current metadata.
    """

    def __init__(self, destination: str, targetinfo: TargetFile) -> None:
        self.destination = destination
        self.targetinfo = targetinfo
        self.delivery_dir = f"{destination}.delivery"
        self.state_path = os.path.join(self.delivery_dir, STATE_FILENAME)
        self.candidate_path = os.path.join(
            self.delivery_dir, CANDIDATE_FILENAME
        )
        self.state: DeliveryState | None = None

    @classmethod
    def open(cls, destination: str, targetinfo: TargetFile) -> TargetDelivery:
        """Open a delivery, reconciling any interrupted previous attempt.

        If a persisted state record exists and still describes the same
        target identity as ``targetinfo`` (path, length and hashes), the
        recorded state is resumed. Otherwise the old candidate and record are
        discarded and a fresh ``PENDING`` delivery for the currently trusted
        target is started.

        Raises:
            OSError: Delivery state or candidate cannot be read or written.
        """

        delivery = cls(destination, targetinfo)
        previous_state = delivery._load_state()

        try:
            resume_state = (
                DeliveryState(previous_state["state"])
                if previous_state is not None
                else None
            )
        except ValueError:
            # An unknown state value cannot be trusted: restart the delivery.
            resume_state = None

        if (
            resume_state is not None
            and delivery._identity_matches(previous_state)
            and delivery._candidate_is_present(previous_state)
        ):
            delivery.state = resume_state
            logger.debug(
                "Resuming delivery of %s in state %s",
                targetinfo.path,
                delivery.state.value,
            )
            return delivery

        if previous_state is not None:
            reason = (
                "target identity changed"
                if not delivery._identity_matches(previous_state)
                else "candidate is missing"
            )
            logger.debug(
                "Discarding interrupted delivery of %s: %s",
                targetinfo.path,
                reason,
            )
        delivery.discard()
        delivery.begin()
        return delivery

    @property
    def needs_download(self) -> bool:
        """Return whether a candidate still has to be fetched."""
        return self.state == DeliveryState.PENDING

    @property
    def needs_verification(self) -> bool:
        """Return whether a staged candidate still has to be verified.

        A delivery resumed in ``DOWNLOADED`` reports ``True`` here even though
        no network fetch is required: the candidate on disk must still be
        re-checked against the currently trusted length and hashes before it
        may be promoted.
        """
        return self.state == DeliveryState.DOWNLOADED

    def begin(self) -> None:
        """Persist the ``PENDING`` state before any bytes are fetched."""
        Path(self.delivery_dir).mkdir(parents=True, exist_ok=True)
        self._write_state(DeliveryState.PENDING)
        logger.debug(
            "Delivery of %s is pending candidate download",
            self.targetinfo.path,
        )

    def stage_candidate(self, source: IO[bytes]) -> None:
        """Flush a fully downloaded candidate and mark it ``DOWNLOADED``.

        ``source`` is a binary file object positioned at the start of the
        target content. The candidate is written and fsynced first; only
        afterwards is the state atomically updated to ``DOWNLOADED``. A crash
        between the two operations therefore leaves a ``PENDING`` record with
        an orphaned candidate, which is safely re-fetched on resume.

        Raises:
            OSError: Candidate or state cannot be written to disk.
        """

        self._atomic_write(self.candidate_path, _read_all(source))
        self._write_state(DeliveryState.DOWNLOADED)
        logger.debug(
            "Candidate for %s staged, waiting for verification",
            self.targetinfo.path,
        )

    def verify_candidate(self) -> None:
        """Verify the staged candidate against the trusted target info.

        On success the delivery moves to ``READY``. On failure the unverifiable
        candidate and its record are discarded and the delivery returns to
        ``PENDING`` so that a fresh download can be attempted.

        Raises:
            OSError: Candidate cannot be read or state cannot be written.
            LengthOrHashMismatchError: Candidate does not match metadata.
        """

        try:
            with open(self.candidate_path, "rb") as candidate:
                self.targetinfo.verify_length_and_hashes(candidate)
        except exceptions.LengthOrHashMismatchError:
            self.discard()
            self.begin()
            raise

        self._write_state(DeliveryState.READY)
        logger.debug(
            "Candidate for %s verified, delivery is ready",
            self.targetinfo.path,
        )

    def promote(self) -> str:
        """Move the verified candidate to its final destination.

        Returns:
            The destination path handed to the upper layer.

        Raises:
            OSError: Candidate cannot be moved into place.
            LengthOrHashMismatchError: Candidate no longer matches metadata.
        """

        if self.state != DeliveryState.READY:
            raise exceptions.RepositoryError(
                f"Delivery of {self.targetinfo.path} is not ready: "
                f"state is {self.state.value if self.state else 'unknown'}"
            )

        # Re-verify before handoff: a READY record whose candidate was
        # replaced or truncated on disk must not be promoted.
        with open(self.candidate_path, "rb") as candidate:
            self.targetinfo.verify_length_and_hashes(candidate)

        Path(self.destination).parent.mkdir(parents=True, exist_ok=True)
        os.replace(self.candidate_path, self.destination)
        logger.debug(
            "Verified candidate for %s installed at %s",
            self.targetinfo.path,
            self.destination,
        )
        return self.destination

    def discard(self) -> None:
        """Remove all local delivery material for this destination."""
        if not Path(self.delivery_dir).exists():
            return
        for filename in (CANDIDATE_FILENAME, STATE_FILENAME):
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(self.delivery_dir, filename))
        with contextlib.suppress(OSError):
            os.rmdir(self.delivery_dir)
        self.state = None

    def _load_state(self) -> dict[str, Any] | None:
        """Read the persisted state record, tolerating a missing record."""
        try:
            with open(self.state_path, encoding="utf-8") as state_file:
                record = json.load(state_file)
        except FileNotFoundError:
            return None
        except (json.JSONDecodeError, OSError) as e:
            # A half-written or unreadable record cannot be trusted:
            # treat it as absent and re-deliver from scratch.
            logger.debug(
                "Delivery state for %s is unreadable (%s); restarting",
                self.destination,
                e,
            )
            return None

        if not isinstance(record, dict):
            return None
        return record

    def _identity_matches(self, record: dict[str, Any]) -> bool:
        """Check that a record still claims the currently trusted target."""
        try:
            return (
                record["record_version"] == DELIVERY_RECORD_VERSION
                and record["target"]["path"] == self.targetinfo.path
                and record["target"]["length"] == self.targetinfo.length
                and record["target"]["hashes"] == self.targetinfo.hashes
            )
        except (KeyError, TypeError):
            return False

    def _candidate_is_present(self, record: dict[str, Any]) -> bool:
        """Return whether the staged candidate required by a state exists."""
        if record.get("state") == DeliveryState.PENDING.value:
            return True
        return Path(self.candidate_path).is_file()

    def _write_state(self, state: DeliveryState) -> None:
        """Atomically persist a state transition and its target identity."""
        Path(self.delivery_dir).mkdir(parents=True, exist_ok=True)
        record = {
            "record_version": DELIVERY_RECORD_VERSION,
            "state": state.value,
            "target": {
                "path": self.targetinfo.path,
                "length": self.targetinfo.length,
                "hashes": self.targetinfo.hashes,
            },
        }
        data = json.dumps(record, sort_keys=True).encode("utf-8")
        self._atomic_write(self.state_path, data)
        self.state = state

    def _atomic_write(self, filename: str, data: bytes) -> None:
        """Write ``data`` to ``filename`` atomically and durably."""
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.delivery_dir, delete=False
            ) as temp_file:
                temp_name = temp_file.name
                temp_file.write(data)
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_name, filename)
        except OSError:
            if temp_name is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(temp_name)
            raise


def _read_all(source: IO[bytes]) -> bytes:
    """Read ``source`` from its current position without rewinding it."""
    chunks: list[bytes] = []
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
