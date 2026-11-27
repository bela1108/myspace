# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline observation of an Updater's trusted metadata view.

Applications sometimes want a side report of repository state while an
update is in progress. Observation provides this as a strictly
read-only session next to the client update workflow:

  * Updater.observe() captures the current trusted view: the
    observation and its report always reason about the view as of
    observation start, even if the updater refreshes afterwards.
  * Observation.check() performs read-only checks: downloaded
    metadata is verified against the captured view, but is never
    persisted to the local metadata cache and never promoted into the
    updater's trusted set.
  * Observation.cancel() records the cancellation location: a
    cancelled observation refuses further checks and its report shows
    where it was cancelled.
  * Observation.report() returns an ObservationReport that can
    explain which trusted view it is based on.

Multiple observations may be in flight at the same time and may
complete in any order: each one only sees its own captured view.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tuf.api.metadata import Root, Signed, Snapshot, Targets, Timestamp
from tuf.ngclient._internal.trusted_metadata_set import (
    _load_from_metadata,
    _load_from_simple_envelope,
)
from tuf.ngclient.config import EnvelopeType, UpdaterConfig

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

logger = logging.getLogger(__name__)

_ROLE_TYPES: dict[str, type[Signed]] = {
    Root.type: Root,
    Timestamp.type: Timestamp,
    Snapshot.type: Snapshot,
}


class ObservationCancelledError(RuntimeError):
    """Raised when a cancelled observation is used for further checks."""


@dataclass(frozen=True)
class RoleState:
    """A single verified role state observed by an Observation.

    Args:
        role: Name of the observed role.
        version: Version of the verified metadata.
        expires: Expiry of the verified metadata.
    """

    role: str
    version: int
    expires: datetime


@dataclass(frozen=True)
class TrustedView:
    """Immutable snapshot of an updater's trusted metadata.

    The view is captured when an observation starts: the observation
    reasons about this copy even if the updater's trusted set changes
    later.

    Args:
        roles: Deep-copied mapping of role name to trusted Signed.
        reference_time: Reference time of the trusted set at capture.
    """

    roles: dict[str, Signed]
    reference_time: datetime

    def version(self, role: str) -> int | None:
        """Return trusted version for role, or None if not in view."""
        signed = self.roles.get(role)
        return signed.version if signed is not None else None

    def explain(self) -> str:
        """Return a human-readable description of this view."""
        lines = [
            f"trusted view captured at {self.reference_time.isoformat()}:",
        ]
        for role, signed in sorted(self.roles.items()):
            lines.append(f"  {role} v{signed.version}")
        return "\n".join(lines)


@dataclass
class ObservationReport:
    """Result of a finished Observation.

    Args:
        reference: Observation reference assigned at observation start.
        view: The trusted view this report is based on.
        states: Verified role states gathered by read-only checks.
        cancelled_at: Cancellation location, or None if the observation
            was not cancelled.
    """

    reference: str
    view: TrustedView
    states: dict[str, RoleState] = field(default_factory=dict)
    cancelled_at: str | None = None

    def explain(self) -> str:
        """Explain which trusted view this report is based on."""
        lines = [
            f"observation '{self.reference}' based on {self.view.explain()}",
        ]
        for role, state in sorted(self.states.items()):
            lines.append(
                f"  observed {role} v{state.version}"
                " (verified against this view)"
            )
        if self.cancelled_at is not None:
            lines.append(f"  cancelled at '{self.cancelled_at}'")
        return "\n".join(lines)


class Observation:
    """A single offline observation session.

    Created with Updater.observe(): captures the observation
    reference, the current trusted view and (once cancelled) the
    cancellation location.

    Args:
        reference: Unique observation reference.
        view: Trusted view captured at observation start.
        download_metadata: Read-only metadata download callback, as
            provided by the updater. Downloaded content is not
            persisted by the observation.
        config: Updater configuration.
    """

    def __init__(
        self,
        reference: str,
        view: TrustedView,
        download_metadata: Callable[[str, int, int | None], bytes],
        config: UpdaterConfig,
    ):
        self.reference = reference
        self._view = view
        self._download_metadata = download_metadata
        self._config = config
        self._states: dict[str, RoleState] = {}
        self._cancelled_at: str | None = None

    @property
    def view(self) -> TrustedView:
        """The trusted view captured at observation start."""
        return self._view

    @property
    def cancelled_at(self) -> str | None:
        """Cancellation location, or None if not cancelled."""
        return self._cancelled_at

    def cancel(self, location: str) -> None:
        """Cancel this observation, recording the cancellation location.

        Args:
            location: Describes where in the application the observation
                was cancelled (e.g. "awaiting-update").
        """
        logger.debug(
            "Cancelling observation %s at %s", self.reference, location
        )
        self._cancelled_at = location

    def check(self, role: str, delegator: str = Root.type) -> RoleState:
        """Read-only check of remote metadata for a role.

        Downloads metadata for the role and verifies it against the
        trusted view captured at observation start. The downloaded
        content is never written to the updater's metadata cache and
        never promoted into the updater's trusted set.

        Args:
            role: Name of the role to observe.
            delegator: Name of the role delegating to the observed role
                in the captured view. Default is root (top-level roles).

        Raises:
            ObservationCancelledError: Observation was cancelled.
            ValueError: delegator is not part of the captured view.
            RepositoryError: Metadata failed to deserialize or verify.
            DownloadError: Download of the metadata failed in some way.

        Returns:
            The verified RoleState for the role.
        """
        if self._cancelled_at is not None:
            raise ObservationCancelledError(
                f"Observation '{self.reference}' was cancelled at "
                f"'{self._cancelled_at}'"
            )

        delegator_signed = self._view.roles.get(delegator)
        if not isinstance(delegator_signed, Root | Targets):
            raise ValueError(
                f"Delegator '{delegator}' is not part of the captured "
                f"trusted view of observation '{self.reference}'"
            )

        data = self._download_metadata(
            role, self._max_length(role), self._observed_version(role)
        )
        if self._config.envelope_type is EnvelopeType.SIMPLE:
            load = _load_from_simple_envelope
        else:
            load = _load_from_metadata
        signed, _, _ = load(
            _ROLE_TYPES.get(role, Targets), data, delegator_signed, role
        )

        state = RoleState(role, signed.version, signed.expires)
        self._states[role] = state
        logger.debug(
            "Observation %s verified %s v%d",
            self.reference,
            role,
            state.version,
        )
        return state

    def report(self) -> ObservationReport:
        """Return a report of this observation.

        The report always describes the trusted view captured at
        observation start, regardless of later updater refreshes.
        """
        return ObservationReport(
            reference=self.reference,
            view=self._view,
            states=dict(self._states),
            cancelled_at=self._cancelled_at,
        )

    def _max_length(self, role: str) -> int:
        if role == Root.type:
            return self._config.root_max_length
        if role == Timestamp.type:
            return self._config.timestamp_max_length
        if role == Snapshot.type:
            return self._config.snapshot_max_length
        return self._config.targets_max_length

    def _observed_version(self, role: str) -> int | None:
        """Version to request for role, mirroring the updater's URL
        logic: the captured view pins the versions the observation sees.
        """
        view_root = self._view.roles.get(Root.type)
        if role == Root.type:
            # ask for the root after the trusted one, like the updater
            return view_root.version + 1 if view_root is not None else None

        version = None
        if (
            role != Timestamp.type
            and isinstance(view_root, Root)
            and view_root.consistent_snapshot
        ):
            if role == Snapshot.type:
                timestamp = self._view.roles.get(Timestamp.type)
                if isinstance(timestamp, Timestamp):
                    version = timestamp.snapshot_meta.version
            else:
                snapshot = self._view.roles.get(Snapshot.type)
                if isinstance(snapshot, Snapshot):
                    metainfo = snapshot.meta.get(f"{role}.json")
                    if metainfo is not None:
                        version = metainfo.version
        return version
