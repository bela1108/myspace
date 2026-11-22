"""Offline reconciliation of managed root certificate inventories.

This module builds on truststore's backend interface to audit, offline,
which trust anchors each process configuration may actually claim. The
platform backends expose two verification entry points:

* ``_configure_context`` -- system trust is loaded into the SSL context.
* ``_verify_peercerts_impl`` -- peer certificates are verified after the
  handshake.

A system trust observation is only complete once both entry points have
been observed for a certificate; a partial observation is reported as
pending evidence.

Three independent inputs are reconciled per process configuration:

* system trust observations from a local stand-in for the backend,
* verify locations explicitly appended by the application via
  ``SSLContext.load_verify_locations``,
* an independent approval table for exception certificates that may only
  be used by specific processes, each with an expiry.

System trust and exception approvals are kept as separate lineages: an
expired approval is reported as a reference to revoke even when the same
certificate is still trusted by the system.
"""

from __future__ import annotations

import hashlib
import os
import ssl
import typing
from dataclasses import dataclass, field
from datetime import datetime, timezone

ENTRY_POINT_CONFIGURE_CONTEXT = "configure_context"
ENTRY_POINT_VERIFY_PEERCERTS = "verify_peercerts"
#: Verification entry points of the truststore backend interface. A system
#: trust observation must cover both to be considered complete.
ENTRY_POINTS: tuple[str, str] = (
    ENTRY_POINT_CONFIGURE_CONTEXT,
    ENTRY_POINT_VERIFY_PEERCERTS,
)

SOURCE_SYSTEM = "system"
SOURCE_EXPLICIT = "explicit"
SOURCE_APPROVAL = "approval"


def fingerprint_der(der_bytes: bytes, algorithm: str = "sha256") -> str:
    """Returns the colon-separated hex fingerprint of a DER certificate."""
    digest = hashlib.new(algorithm, der_bytes).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


@dataclass(frozen=True)
class CertRecord:
    """A managed certificate identified by its DER fingerprint."""

    fingerprint: str
    subject: str | None = None
    not_after: datetime | None = None


def load_pem_cert_record(path: str | os.PathLike[str]) -> CertRecord:
    """Loads a public certificate from a PEM file into a :class:`CertRecord`."""
    with open(path, "rb") as f:
        der_bytes = ssl.PEM_cert_to_DER_cert(f.read().decode("ascii"))
    subject: str | None = None
    not_after: datetime | None = None
    try:
        decoded = ssl._ssl._test_decode_cert(os.fspath(path))  # type: ignore[attr-defined]
        subject = ", ".join(
            "=".join(part for part in item)
            for group in decoded.get("subject", ())
            for item in group
        )
        if "notAfter" in decoded:
            not_after = datetime.strptime(
                decoded["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
    except Exception:  # pragma: no cover - decoding is best-effort
        pass
    return CertRecord(
        fingerprint=fingerprint_der(der_bytes), subject=subject, not_after=not_after
    )


class SystemTrustStandIn:
    """In-memory stand-in for a truststore backend's system trust.

    Records which verification entry points observed each certificate as
    trusted by the system, mirroring ``_configure_context`` and
    ``_verify_peercerts_impl``.
    """

    def __init__(self) -> None:
        self._observed: dict[str, set[str]] = {}

    def record(self, fingerprint: str, entry_point: str) -> None:
        if entry_point not in ENTRY_POINTS:
            raise ValueError(f"unknown verification entry point: {entry_point!r}")
        self._observed.setdefault(fingerprint, set()).add(entry_point)

    def fingerprints(self) -> frozenset[str]:
        return frozenset(self._observed)

    def entry_points_for(self, fingerprint: str) -> frozenset[str]:
        return frozenset(self._observed.get(fingerprint, ()))

    def missing_entry_points(self, fingerprint: str) -> tuple[str, ...]:
        observed = self._observed.get(fingerprint, set())
        return tuple(ep for ep in ENTRY_POINTS if ep not in observed)


@dataclass(frozen=True)
class ExplicitLocation:
    """A verify location appended via ``SSLContext.load_verify_locations``."""

    kind: str  # "cafile", "capath" or "cadata"
    location: str
    fingerprints: frozenset[str]


@dataclass(frozen=True)
class Approval:
    """An independent approval for an exception certificate."""

    reference: str
    fingerprint: str
    processes: frozenset[str]
    not_after: datetime

    def is_expired(self, as_of: datetime) -> bool:
        return self.not_after <= as_of


@dataclass(frozen=True)
class ProcessConfig:
    """A process configuration whose claimable trust scope is reconciled."""

    name: str
    explicit_locations: tuple[ExplicitLocation, ...] = ()
    exception_fingerprints: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Evidence:
    """One piece of evidence backing a claimable trust anchor."""

    fingerprint: str
    source: str  # SOURCE_SYSTEM, SOURCE_EXPLICIT or SOURCE_APPROVAL
    detail: str


@dataclass(frozen=True)
class Revocation:
    """An exception certificate reference that must be revoked."""

    reference: str
    fingerprint: str
    reason: str


@dataclass(frozen=True)
class PendingEvidence:
    """A certificate whose observation lacks a verification entry point."""

    fingerprint: str
    missing_entry_points: tuple[str, ...]


@dataclass
class ProcessReport:
    """Reconciled trust scope for one process configuration."""

    process: str
    as_of: datetime
    general_entry: dict[str, list[Evidence]] = field(default_factory=dict)
    approved_entry: dict[str, list[Evidence]] = field(default_factory=dict)
    revocations: list[Revocation] = field(default_factory=list)
    pending_evidence: list[PendingEvidence] = field(default_factory=list)

    def claimable(self) -> frozenset[str]:
        return frozenset(self.general_entry) | frozenset(self.approved_entry)


def reconcile_process(
    config: ProcessConfig,
    *,
    stand_in: SystemTrustStandIn,
    approvals: typing.Iterable[Approval],
    as_of: datetime | None = None,
) -> ProcessReport:
    """Reconciles one process configuration against the three inputs."""
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    approvals = list(approvals)
    report = ProcessReport(process=config.name, as_of=as_of)

    # General entry: system trust observations, kept as their own lineage.
    for fingerprint in sorted(stand_in.fingerprints()):
        observed = stand_in.entry_points_for(fingerprint)
        report.general_entry.setdefault(fingerprint, []).append(
            Evidence(
                fingerprint=fingerprint,
                source=SOURCE_SYSTEM,
                detail="entry-points:" + "+".join(sorted(observed)),
            )
        )
        missing = stand_in.missing_entry_points(fingerprint)
        if missing:
            report.pending_evidence.append(
                PendingEvidence(fingerprint=fingerprint, missing_entry_points=missing)
            )

    # General entry: locations explicitly appended by the application.
    for location in config.explicit_locations:
        for fingerprint in sorted(location.fingerprints):
            report.general_entry.setdefault(fingerprint, []).append(
                Evidence(
                    fingerprint=fingerprint,
                    source=SOURCE_EXPLICIT,
                    detail=f"{location.kind}:{location.location}",
                )
            )

    # Approved entry: exception certificates referenced by this process,
    # checked against the independent approval table.
    for fingerprint in sorted(config.exception_fingerprints):
        matching = [
            approval
            for approval in approvals
            if approval.fingerprint == fingerprint and config.name in approval.processes
        ]
        valid = [a for a in matching if not a.is_expired(as_of)]
        expired = [a for a in matching if a.is_expired(as_of)]
        for approval in valid:
            report.approved_entry.setdefault(fingerprint, []).append(
                Evidence(
                    fingerprint=fingerprint,
                    source=SOURCE_APPROVAL,
                    detail=f"approval:{approval.reference}",
                )
            )
        for approval in expired:
            report.revocations.append(
                Revocation(
                    reference=approval.reference,
                    fingerprint=fingerprint,
                    reason=(
                        f"approval expired on "
                        f"{approval.not_after.isoformat()}; revoke the reference "
                        f"even if the certificate is still system-trusted"
                    ),
                )
            )
        if not valid and not expired:
            report.revocations.append(
                Revocation(
                    reference="<none>",
                    fingerprint=fingerprint,
                    reason="no approval covers this process; revoke the reference",
                )
            )
    return report


def reconcile(
    configs: typing.Iterable[ProcessConfig],
    *,
    stand_in: SystemTrustStandIn,
    approvals: typing.Iterable[Approval],
    as_of: datetime | None = None,
) -> list[ProcessReport]:
    """Reconciles several process configurations at the same point in time."""
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    approvals = list(approvals)
    return [
        reconcile_process(config, stand_in=stand_in, approvals=approvals, as_of=as_of)
        for config in configs
    ]


@dataclass(frozen=True)
class ReportDiff:
    """Evidence changes for one process between two points in time."""

    process: str
    general_added: frozenset[Evidence]
    general_removed: frozenset[Evidence]
    approved_added: frozenset[Evidence]
    approved_removed: frozenset[Evidence]
    revocations_added: frozenset[Revocation]
    pending_added: frozenset[PendingEvidence]
    pending_resolved: frozenset[PendingEvidence]


def _evidence_set(entry: dict[str, list[Evidence]]) -> frozenset[Evidence]:
    return frozenset(
        evidence for evidences in entry.values() for evidence in evidences
    )


def diff_reports(before: ProcessReport, after: ProcessReport) -> ReportDiff:
    """Compares the evidence of two reports for the same process."""
    if before.process != after.process:
        raise ValueError("cannot diff reports for different processes")
    general_before = _evidence_set(before.general_entry)
    general_after = _evidence_set(after.general_entry)
    approved_before = _evidence_set(before.approved_entry)
    approved_after = _evidence_set(after.approved_entry)
    return ReportDiff(
        process=before.process,
        general_added=general_after - general_before,
        general_removed=general_before - general_after,
        approved_added=approved_after - approved_before,
        approved_removed=approved_before - approved_after,
        revocations_added=frozenset(after.revocations) - frozenset(before.revocations),
        pending_added=frozenset(after.pending_evidence)
        - frozenset(before.pending_evidence),
        pending_resolved=frozenset(before.pending_evidence)
        - frozenset(after.pending_evidence),
    )
