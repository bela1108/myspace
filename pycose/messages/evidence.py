"""
Evidence projections for COSE messages.

Forensic handover requires disclosing only selected message fields (e.g. the
algorithm, the evidence timestamp and the payload digest) while other fields
(e.g. the key identifier and the raw external AAD) must be retained internally.

An evidence projection extracts a fixed set of fields from a signed COSE
message and applies a FieldPolicy deciding, per field, whether the value is
disclosed in the clear or redacted behind a salted commitment. The resulting
EvidenceView is bound to the message signature through a signature digest and
carries a root digest over all fields, so a receiving party can verify the
integrity of the disclosed fields without being able to derive the hidden
values. Projecting the same signature under two different policies yields two
different, independently verifiable views.
"""

import hmac
import os
from datetime import datetime, timezone
from hashlib import sha256
from typing import Dict, Iterable, Optional, Tuple

import cbor2

from pycose import headers
from pycose.exceptions import CoseException
from pycose.messages.sign1message import Sign1Message

EVIDENCE_FIELDS: Tuple[str, ...] = ("alg", "time", "payload_digest", "kid", "external_aad")

_ROOT_DOMAIN = b"pycose-evidence-root\x00"
_FIELD_DOMAIN = b"pycose-evidence-field\x00"

_SALT_LEN = 32


class FieldPolicy:
    """
    Decides which evidence fields are disclosed and which are redacted.

    The disclosed and redacted sets must partition EVIDENCE_FIELDS.
    """

    FORENSIC_HANDOVER: 'FieldPolicy' = None  # assigned below
    INTERNAL_ARCHIVE: 'FieldPolicy' = None  # assigned below

    def __init__(self, name: str, disclosed: Iterable[str], redacted: Iterable[str]):
        self.name = name
        self.disclosed = frozenset(disclosed)
        self.redacted = frozenset(redacted)

        if self.disclosed & self.redacted:
            raise CoseException(f"Field policy {name!r}: fields cannot be both disclosed and redacted")

        unknown = (self.disclosed | self.redacted) - set(EVIDENCE_FIELDS)
        if unknown:
            raise CoseException(f"Field policy {name!r}: unknown evidence fields {sorted(unknown)}")

        missing = set(EVIDENCE_FIELDS) - (self.disclosed | self.redacted)
        if missing:
            raise CoseException(f"Field policy {name!r}: fields without a disclosure decision {sorted(missing)}")

    def is_disclosed(self, field: str) -> bool:
        return field in self.disclosed

    def __repr__(self) -> str:
        return f"<FieldPolicy: {self.name}>"


FieldPolicy.FORENSIC_HANDOVER = FieldPolicy(
    "forensic-handover",
    disclosed=("alg", "time", "payload_digest"),
    redacted=("kid", "external_aad"),
)

FieldPolicy.INTERNAL_ARCHIVE = FieldPolicy(
    "internal-archive",
    disclosed=EVIDENCE_FIELDS,
    redacted=(),
)


def _field_commitment(salt: bytes, name: str, value) -> bytes:
    """ Salted commitment hiding a field value from the external view. """

    return sha256(
        _FIELD_DOMAIN
        + salt
        + cbor2.dumps(name, canonical=True)
        + cbor2.dumps(value, canonical=True)
    ).digest()


class EvidenceField:
    """ A single projected field: either a disclosed value or a commitment. """

    __slots__ = ("name", "disclosed", "value", "commitment")

    def __init__(self, name: str, disclosed: bool, value=None, commitment: Optional[bytes] = None):
        if disclosed and commitment is not None:
            raise CoseException("Disclosed evidence fields must not carry a commitment")
        if not disclosed and commitment is None:
            raise CoseException("Redacted evidence fields must carry a commitment")

        self.name = name
        self.disclosed = disclosed
        self.value = value if disclosed else None
        self.commitment = commitment

    def _root_entry(self):
        return [self.name, self.disclosed, self.value if self.disclosed else self.commitment]

    def _wire_entry(self):
        return [self.name, self.disclosed, self.value if self.disclosed else None, self.commitment]

    def __repr__(self) -> str:
        content = repr(self.value) if self.disclosed else f"commitment={self.commitment.hex()}"
        return f"<EvidenceField: {self.name} {content}>"


class EvidenceView:
    """
    The external, policy-filtered projection of a signed COSE message.

    Disclosed fields can be read directly; redacted fields appear only as
    salted commitments. The view is bound to the message signature via
    ``signature_digest`` and protected by ``root``, which ``verify``
    recomputes over the view content.
    """

    def __init__(self, policy_name: str, fields: Tuple[EvidenceField, ...], signature_digest: bytes):
        self.policy_name = policy_name
        self.fields = tuple(fields)
        self.signature_digest = signature_digest
        self.root = self._compute_root()

    def _compute_root(self) -> bytes:
        entries = [f._root_entry() for f in self.fields]
        return sha256(
            _ROOT_DOMAIN
            + cbor2.dumps([self.policy_name, entries, self.signature_digest], canonical=True)
        ).digest()

    def verify(self) -> bool:
        """ Recompute the root digest over the view content and compare it. """

        return hmac.compare_digest(self.root, self._compute_root())

    def public_fields(self) -> Dict[str, object]:
        """ Return the disclosed field values. """

        return {f.name: f.value for f in self.fields if f.disclosed}

    def hidden_fields(self) -> Tuple[str, ...]:
        """ Return the names of the redacted fields. """

        return tuple(f.name for f in self.fields if not f.disclosed)

    def get_field(self, name: str) -> EvidenceField:
        for f in self.fields:
            if f.name == name:
                return f
        raise KeyError(f"Unknown evidence field {name!r}")

    def open_commitment(self, name: str, value, salt: bytes) -> bool:
        """
        Internal audit hook: check that ``value`` and ``salt`` open the
        commitment of a redacted field. Never exposed in the external view.
        """

        field = self.get_field(name)
        if field.disclosed:
            raise CoseException(f"Field {name!r} is disclosed, nothing to open")

        return hmac.compare_digest(field.commitment, _field_commitment(salt, name, value))

    def encode(self) -> bytes:
        """ Encode the view as canonical CBOR for handover. """

        return cbor2.dumps(
            [self.policy_name, [f._wire_entry() for f in self.fields], self.signature_digest, self.root],
            canonical=True,
        )

    @classmethod
    def decode(cls, received: bytes) -> 'EvidenceView':
        """ Decode a view from its CBOR encoding. """

        policy_name, entries, signature_digest, root = cbor2.loads(received)
        fields = tuple(
            EvidenceField(name, disclosed, value=value, commitment=commitment)
            for name, disclosed, value, commitment in entries
        )
        view = cls(policy_name, fields, signature_digest)
        if not hmac.compare_digest(view.root, root):
            raise CoseException("Evidence view root digest mismatch")
        return view

    def __repr__(self) -> str:
        disclosed = ", ".join(f.name for f in self.fields if f.disclosed)
        hidden = ", ".join(f.name for f in self.fields if not f.disclosed)
        return f"<EvidenceView: {self.policy_name} disclosed=[{disclosed}] hidden=[{hidden}]>"


class EvidenceRecord:
    """
    Internal retention record: the external view plus the blinding material
    (salt and hidden values) required to later open the commitments.
    """

    def __init__(self, view: EvidenceView, salt: bytes, hidden_values: Dict[str, object]):
        self.view = view
        self.salt = salt
        self.hidden_values = dict(hidden_values)

    def handover(self) -> bytes:
        """ The encoded external view; contains no salt and no hidden values. """

        return self.view.encode()

    def reveal(self, name: str):
        """ Return an internally retained hidden value. """

        if name not in self.hidden_values:
            raise KeyError(f"Field {name!r} is not retained (disclosed or unknown)")
        return self.hidden_values[name]

    def prove(self, name: str) -> bool:
        """ Prove to a holder of the view that the retained value opens the commitment. """

        return self.view.open_commitment(name, self.reveal(name), self.salt)


class MessageEvidenceProjection:
    """ Projects a signed COSE message into a policy-filtered evidence view. """

    @staticmethod
    def _extract_fields(message: Sign1Message, evidence_time: Optional[str]) -> Dict[str, object]:
        alg = message.get_attr(headers.Algorithm)
        if alg is None:
            raise CoseException("Cannot project evidence: message has no algorithm header")

        if message.payload is None:
            raise CoseException("Cannot project evidence: message has no payload")

        if not message.signature:
            raise CoseException("Cannot project evidence: message is not signed")

        if evidence_time is None:
            evidence_time = datetime.now(timezone.utc).isoformat()
        if not isinstance(evidence_time, str):
            raise TypeError("evidence_time must be an ISO formatted string")

        return {
            "alg": alg.fullname,
            "time": evidence_time,
            "payload_digest": sha256(message.payload).digest(),
            "kid": message.get_attr(headers.KID),
            "external_aad": message.external_aad,
        }

    @classmethod
    def project(cls,
                message: Sign1Message,
                policy: FieldPolicy,
                evidence_time: Optional[str] = None,
                salt: Optional[bytes] = None) -> EvidenceRecord:
        """
        Project ``message`` under ``policy``.

        :param message: a signed Sign1Message
        :param policy: the FieldPolicy deciding per-field disclosure
        :param evidence_time: ISO formatted evidence timestamp, defaults to now (UTC)
        :param salt: commitment blinding salt, randomly generated when omitted
        :returns: an EvidenceRecord pairing the external view with the
            internally retained salt and hidden values
        """

        if not isinstance(message, Sign1Message):
            raise TypeError("Evidence projection requires a Sign1Message")

        values = cls._extract_fields(message, evidence_time)

        if salt is None:
            salt = os.urandom(_SALT_LEN)
        if not isinstance(salt, bytes) or not salt:
            raise TypeError("salt must be non-empty bytes")

        fields = []
        hidden_values = {}
        for name in EVIDENCE_FIELDS:
            value = values[name]
            if policy.is_disclosed(name):
                fields.append(EvidenceField(name, True, value=value))
            else:
                fields.append(EvidenceField(name, False, commitment=_field_commitment(salt, name, value)))
                hidden_values[name] = value

        signature_digest = sha256(message.signature).digest()
        view = EvidenceView(policy.name, tuple(fields), signature_digest)
        return EvidenceRecord(view, salt, hidden_values)
