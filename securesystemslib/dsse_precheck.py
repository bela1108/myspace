"""Read-only migration precheck for DSSE envelopes.

When two generations of archive services consume the same signed
statements, a signature that *verifies* is not necessarily a statement
the receiving service can *use*: the receiver may not approve the
payload type encoding, may not recognize the key identifier or key
type, and may silently drop envelope or signature extension fields
that the customer's audit trail depends on.

This module checks existing DSSE envelopes, one by one, against
caller-provided receiver capability lists and reports, per receiver,
whether the envelope can be safely handed over. It never modifies the
envelopes, the keyring, or the capability lists it is given.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from enum import StrEnum, unique
from typing import Any

from securesystemslib import exceptions
from securesystemslib.dsse import Envelope
from securesystemslib.signer import Key

logger = logging.getLogger(__name__)

ENVELOPE_CORE_FIELDS = frozenset({"payload", "payloadType", "signatures"})
SIGNATURE_CORE_FIELDS = frozenset({"keyid", "sig"})


@unique
class Category(StrEnum):
    """Precheck finding categories."""

    SIGNATURE = "signature"
    PAYLOAD_TYPE = "payload_type"
    KEY_TYPE = "key_type"
    KEYID = "keyid"
    EXTENSION = "extension"


@dataclass(frozen=True)
class Finding:
    """A single precheck observation.

    Attributes:
        category: The aspect of the envelope that was checked.
        ok: Whether the check passed.
        detail: Human-readable explanation of the outcome.
    """

    category: Category
    ok: bool
    detail: str


@dataclass(frozen=True)
class ReceiverCapabilities:
    """What one archive service generation explicitly supports.

    Attributes:
        name: Identifier of the receiving service.
        payload_types: Approved payload type encodings.
        key_types: Approved key types (e.g. "rsa", "ecdsa", "ed25519").
        keyids: Key identifiers this receiver accepts on signatures.
        envelope_extensions: Envelope-level extension fields the
            receiver is known to preserve and interpret.
        signature_extensions: Signature-level extension fields the
            receiver is known to preserve and interpret.
    """

    name: str
    payload_types: frozenset[str]
    key_types: frozenset[str]
    keyids: frozenset[str]
    envelope_extensions: frozenset[str] = frozenset()
    signature_extensions: frozenset[str] = frozenset()


@dataclass
class ReceiverReport:
    """Precheck outcome for one envelope and one receiver.

    Attributes:
        receiver: Name of the receiver that was checked against.
        findings: Capability findings, in check order.
    """

    receiver: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def compatible(self) -> bool:
        """Whether every capability check passed for this receiver."""
        return all(finding.ok for finding in self.findings)

    def failures(self) -> list[Finding]:
        """Return only the failed capability findings."""
        return [finding for finding in self.findings if not finding.ok]


@dataclass
class EnvelopeReport:
    """Precheck outcome for one envelope across all receivers.

    Attributes:
        name: Caller-provided label for the envelope.
        signature_findings: Cryptographic verification results. These
            are receiver-independent: every receiver sees the same
            envelope and keyring.
        receivers: Per-receiver capability reports.
    """

    name: str
    signature_findings: list[Finding] = field(default_factory=list)
    receivers: list[ReceiverReport] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        """Whether all signatures verified against the keyring.

        Note:
            A ``True`` value does not imply any receiver can use the
            envelope's audit fields; check ``deliverable_to`` instead.
        """
        return bool(self.signature_findings) and all(
            finding.ok for finding in self.signature_findings
        )

    @property
    def deliverable_to(self) -> list[str]:
        """Names of receivers the envelope can be safely handed to.

        A receiver is listed only if the signatures verify *and* all
        of its capability checks pass.
        """
        if not self.verified:
            return []
        return [report.receiver for report in self.receivers if report.compatible]


def _verify_signatures(envelope: Envelope, keyring: dict[str, Key]) -> list[Finding]:
    """Verify each envelope signature against the keyring."""
    findings = []
    pae = envelope.pae()

    if not envelope.signatures:
        findings.append(
            Finding(Category.SIGNATURE, False, "envelope has no signatures")
        )

    for signature in envelope.signatures.values():
        key = keyring.get(signature.keyid)
        if key is None:
            findings.append(
                Finding(
                    Category.SIGNATURE,
                    False,
                    f"no key in keyring for keyid {signature.keyid}",
                )
            )
            continue

        try:
            key.verify_signature(signature, pae)
        except exceptions.UnverifiedSignatureError as e:
            findings.append(
                Finding(
                    Category.SIGNATURE,
                    False,
                    f"signature for keyid {signature.keyid} does not verify: {e}",
                )
            )
        else:
            findings.append(
                Finding(
                    Category.SIGNATURE,
                    True,
                    f"signature for keyid {signature.keyid} verifies",
                )
            )

    return findings


def _check_receiver(
    envelope_dict: dict[str, Any],
    envelope: Envelope,
    keyring: dict[str, Key],
    receiver: ReceiverCapabilities,
) -> ReceiverReport:
    """Check one parsed envelope against one receiver's capabilities."""
    report = ReceiverReport(receiver.name)

    # Payload type: does the receiver approve this encoding?
    if envelope.payload_type in receiver.payload_types:
        report.findings.append(
            Finding(
                Category.PAYLOAD_TYPE,
                True,
                f"payload type {envelope.payload_type!r} is approved",
            )
        )
    else:
        report.findings.append(
            Finding(
                Category.PAYLOAD_TYPE,
                False,
                f"payload type {envelope.payload_type!r} is not approved "
                f"by {receiver.name}",
            )
        )

    # Envelope-level unknown extensions.
    for field_name in sorted(set(envelope_dict) - ENVELOPE_CORE_FIELDS):
        ok = field_name in receiver.envelope_extensions
        report.findings.append(
            Finding(
                Category.EXTENSION,
                ok,
                f"envelope extension {field_name!r} is "
                + ("known" if ok else "unknown")
                + f" to {receiver.name}",
            )
        )

    # Per-signature keyid, key type and unknown extensions.
    for signature in envelope.signatures.values():
        keyid = signature.keyid

        ok = keyid in receiver.keyids
        report.findings.append(
            Finding(
                Category.KEYID,
                ok,
                f"keyid {keyid} is "
                + ("accepted" if ok else "not accepted")
                + f" by {receiver.name}",
            )
        )

        key = keyring.get(keyid)
        if key is None:
            report.findings.append(
                Finding(
                    Category.KEY_TYPE,
                    False,
                    f"key type for keyid {keyid} is unknown (key not in keyring)",
                )
            )
        else:
            ok = key.keytype in receiver.key_types
            report.findings.append(
                Finding(
                    Category.KEY_TYPE,
                    ok,
                    f"key type {key.keytype!r} of keyid {keyid} is "
                    + ("approved" if ok else "not approved")
                    + f" by {receiver.name}",
                )
            )

        for field_name in sorted(signature.unrecognized_fields):
            ok = field_name in receiver.signature_extensions
            report.findings.append(
                Finding(
                    Category.EXTENSION,
                    ok,
                    f"signature extension {field_name!r} on keyid {keyid} "
                    + ("is known" if ok else "is unknown")
                    + f" to {receiver.name}",
                )
            )

    return report


def precheck_envelope(
    envelope_dict: dict[str, Any],
    keyring: dict[str, Key],
    receivers: list[ReceiverCapabilities],
    name: str = "",
) -> EnvelopeReport:
    """Check one DSSE envelope against each receiver's capabilities.

    The check is read-only: ``envelope_dict`` and ``keyring`` are not
    modified.

    Arguments:
        envelope_dict: JSON-like dict representation of the envelope,
            as produced by ``Envelope.to_dict``.
        keyring: Public keys to verify signatures with, keyed by keyid.
        receivers: Capability lists of the candidate archive services.
        name: Optional label used in the report.

    Returns:
        An "EnvelopeReport" with cryptographic verification results
        and per-receiver capability findings.
    """
    # Work on a copy: Envelope.from_dict mutates the dict it is given.
    data = copy.deepcopy(envelope_dict)
    report = EnvelopeReport(name)

    try:
        envelope = Envelope.from_dict(data)
    except (KeyError, TypeError, ValueError) as e:
        report.signature_findings.append(
            Finding(Category.SIGNATURE, False, f"envelope cannot be parsed: {e}")
        )
        report.receivers = [ReceiverReport(receiver.name) for receiver in receivers]
        return report

    report.signature_findings = _verify_signatures(envelope, keyring)
    report.receivers = [
        _check_receiver(data, envelope, keyring, receiver) for receiver in receivers
    ]
    return report


def precheck_envelopes(
    envelope_dicts: dict[str, dict[str, Any]],
    keyring: dict[str, Key],
    receivers: list[ReceiverCapabilities],
) -> list[EnvelopeReport]:
    """Check multiple DSSE envelopes against each receiver's capabilities.

    Arguments:
        envelope_dicts: Envelope dicts to check, keyed by label.
        keyring: Public keys to verify signatures with, keyed by keyid.
        receivers: Capability lists of the candidate archive services.

    Returns:
        A list of "EnvelopeReport", one per envelope, in input order.
    """
    return [
        precheck_envelope(envelope_dict, keyring, receivers, name)
        for name, envelope_dict in envelope_dicts.items()
    ]
