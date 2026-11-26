"""Offline review of already signed delivery receipts.

The review keeps two questions deliberately separate:

* *historical evidence* -- was the COSE signature backed by a locally trusted
  certificate path at the receipt's confirmed signing time?  A certificate that
  expired or was revoked after that time does not rewrite history.
* *current dispatch* -- is there an independent, currently effective transfer
  authorization for this receiver and purpose?  This decision is intentionally
  not coupled to whether the old signing certificate is still valid today.

Only caller supplied identity material is used.  Certificates, CRLs and keys are
read locally; no fetch is attempted.
"""

from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import date, datetime, time, timezone
from enum import Enum
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from pycose.exceptions import CoseException
from pycose.extensions.x509 import (
    certificate_sha256,
    certificate_valid_at,
    load_certificate,
    public_key_matches as certificate_key_matches,
    validate_local_certificate_path,
)
from pycose.headers import KID, X5bag, X5chain
from pycose.keys import CoseKey
from pycose.messages import Sign1Message


CONFIRMED_SIGNING_TIME = 'confirmed_signing_time'
TIMESTAMP_BINDING = 'timestamp_binding'
TIME_EVIDENCE_VERIFICATION = 'time_evidence_verification'


def _utc(moment: Optional[datetime]) -> Optional[datetime]:
    if moment is None:
        return None
    if isinstance(moment, date) and not isinstance(moment, datetime):
        return datetime.combine(moment, time.min, tzinfo=timezone.utc)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _normalize_fingerprint(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return value.replace(':', '').replace(' ', '').lower()


def _message_bytes(receipt: 'DeliveryReceipt') -> Optional[bytes]:
    if receipt.encoded_receipt is not None:
        return receipt.encoded_receipt
    if isinstance(receipt.message, bytes):
        return receipt.message
    try:
        return receipt.message.encode(sign=False)
    except Exception:
        return None


def _message_object(message) -> Sign1Message:
    if isinstance(message, Sign1Message):
        return message
    if isinstance(message, bytes):
        return Sign1Message.decode(message)
    raise TypeError("receipt message must be a Sign1Message or encoded bytes")


class EvidenceStatus(str, Enum):
    HISTORICAL = 'historical_evidence'
    NOT_EVIDENCE = 'not_historical_evidence'
    NEEDS_TIME_EVIDENCE = 'needs_time_evidence'
    SIGNATURE_INVALID = 'signature_invalid'


class DispatchStatus(str, Enum):
    AUTHORIZED = 'authorized'
    SIGNATURE_INVALID = 'signature_invalid'
    NO_AUTHORIZATION = 'no_authorization'
    REVOKED = 'revoked'
    EXPIRED = 'expired'
    NOT_YET_VALID = 'not_yet_valid'


@dataclass(frozen=True)
class SigningTimeEvidence:
    """Confirmed time evidence for a receipt.

    ``source`` documents where the confirmed time came from (for example a
    local receipt log or a locally retained timestamp token).  ``message_digest``
    optionally binds the evidence to the exact receipt bytes; when supplied and
    mismatched, the time is not accepted as confirmation.
    """

    signing_time: datetime
    source: str = 'caller'
    message_digest: Optional[Union[bytes, str]] = None
    verified: bool = True

    def __post_init__(self):
        object.__setattr__(self, 'signing_time', _utc(self.signing_time))


@dataclass(frozen=True)
class DeliveryReceipt:
    """A signed receipt plus the metadata needed for a transfer review."""

    receipt_id: str
    message: Union[Sign1Message, bytes]
    recipient: str
    purpose: Optional[str] = None
    signer_certificate: Optional[Any] = None
    certificate_chain: Tuple[Any, ...] = ()
    verification_key: Optional[CoseKey] = None
    signing_time: Optional[Union[datetime, SigningTimeEvidence]] = None
    claimed_signing_time: Optional[datetime] = None
    encoded_receipt: Optional[bytes] = None
    detached_payload: Optional[bytes] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.encoded_receipt is None and isinstance(self.message, bytes):
            object.__setattr__(self, 'encoded_receipt', self.message)

        chain = self.certificate_chain
        if chain is None:
            chain = ()
        elif isinstance(chain, (bytes, str)) or not isinstance(chain, (list, tuple)):
            chain = (chain,)
        object.__setattr__(self, 'certificate_chain', tuple(chain))

        if isinstance(self.signing_time, date) and not isinstance(self.signing_time, datetime):
            object.__setattr__(self, 'signing_time', SigningTimeEvidence(_utc(self.signing_time)))
        elif isinstance(self.signing_time, datetime):
            object.__setattr__(self, 'signing_time', SigningTimeEvidence(self.signing_time))
        object.__setattr__(self, 'claimed_signing_time', _utc(self.claimed_signing_time))


@dataclass(frozen=True)
class TransferAuthorization:
    """A current authorization to dispatch for a recipient and purpose.

    Authorizations can target particular receipts with ``receipt_ids``; this is
    useful when two receipts were signed on the same day but only one transfer
    permit was withdrawn.  ``revoked_at`` and the validity interval are evaluated
    at the review moment, never at the historical signing time.
    """

    authorization_id: str
    recipient: Optional[str] = None
    purpose: Optional[str] = None
    signer_fingerprint: Optional[str] = None
    receipt_ids: frozenset = frozenset()
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    def __post_init__(self):
        object.__setattr__(self, 'receipt_ids', frozenset(self.receipt_ids or ()))
        object.__setattr__(self, 'valid_from', _utc(self.valid_from))
        object.__setattr__(self, 'valid_until', _utc(self.valid_until))
        object.__setattr__(self, 'revoked_at', _utc(self.revoked_at))
        object.__setattr__(self, 'signer_fingerprint',
                           _normalize_fingerprint(self.signer_fingerprint))

    def matches(self, receipt: DeliveryReceipt, signer_fingerprint: Optional[str]) -> bool:
        if self.receipt_ids and receipt.receipt_id not in self.receipt_ids:
            return False
        if self.recipient is not None and self.recipient != receipt.recipient:
            return False
        if self.purpose is not None and receipt.purpose is not None \
                and self.purpose != receipt.purpose:
            return False
        if self.signer_fingerprint is not None:
            if _normalize_fingerprint(signer_fingerprint) != self.signer_fingerprint:
                return False
        return True

    def status_at(self, moment: datetime) -> DispatchStatus:
        moment = _utc(moment)
        if self.revoked_at is not None and self.revoked_at <= moment:
            return DispatchStatus.REVOKED
        if self.valid_from is not None and moment < self.valid_from:
            return DispatchStatus.NOT_YET_VALID
        if self.valid_until is not None and moment > self.valid_until:
            return DispatchStatus.EXPIRED
        return DispatchStatus.AUTHORIZED

    def revoke(self, at: Optional[datetime] = None) -> 'TransferAuthorization':
        """Return a copy revoked at ``at`` (default: now)."""

        return replace(self, revoked_at=at or datetime.now(timezone.utc))


@dataclass(frozen=True)
class LocalIdentityStore:
    """Caller supplied trust anchors, revocation data and current permits."""

    trust_roots: Tuple[Any, ...] = ()
    intermediate_certificates: Tuple[Any, ...] = ()
    crls: Tuple[Any, ...] = ()
    authorizations: Tuple[TransferAuthorization, ...] = ()
    trusted_keys: Mapping[Any, CoseKey] = field(default_factory=dict)

    def __post_init__(self):
        for name in ('trust_roots', 'intermediate_certificates', 'crls', 'authorizations'):
            value = getattr(self, name)
            if value is None:
                value = ()
            elif not isinstance(value, (list, tuple)):
                value = (value,)
            object.__setattr__(self, name, tuple(value))

    def with_revoked_authorization(self, authorization_id: str,
                                   at: Optional[datetime] = None) -> 'LocalIdentityStore':
        """Return a store in which one transfer permit is withdrawn."""

        updated = []
        found = False
        for authorization in self.authorizations:
            if authorization.authorization_id == authorization_id:
                updated.append(authorization.revoke(at))
                found = True
            else:
                updated.append(authorization)
        if not found:
            raise KeyError(f'unknown authorization: {authorization_id}')
        return replace(self, authorizations=tuple(updated))


LocalIdentityMaterial = LocalIdentityStore


@dataclass(frozen=True)
class ReceiptReview:
    receipt_id: str
    signature_valid: bool
    historical_evidence: bool
    historical_status: EvidenceStatus
    confirmed_signing_time: Optional[datetime]
    historical_reasons: Tuple[str, ...]
    missing_time_evidence: Tuple[str, ...]
    dispatchable: bool
    dispatch_status: DispatchStatus
    authorization_id: Optional[str]
    dispatch_reasons: Tuple[str, ...]
    signer_certificate_sha256: Optional[str]
    signer_subject: Optional[str]
    certificate_valid_at_signing_time: Optional[bool]
    certificate_valid_now: Optional[bool]
    certificate_revoked_at_signing_time: Optional[bool]
    certificate_revoked_now: Optional[bool]
    certificate_matches_verification_key: Optional[bool]

    @property
    def is_historical_evidence(self) -> bool:
        return self.historical_evidence

    @property
    def can_dispatch(self) -> bool:
        return self.dispatchable

    def to_dict(self) -> Dict[str, Any]:
        return {
            'receipt_id': self.receipt_id,
            'signature_valid': self.signature_valid,
            'historical_evidence': self.historical_evidence,
            'historical_status': self.historical_status.value,
            'confirmed_signing_time': self.confirmed_signing_time,
            'historical_reasons': list(self.historical_reasons),
            'missing_time_evidence': list(self.missing_time_evidence),
            'dispatchable': self.dispatchable,
            'dispatch_status': self.dispatch_status.value,
            'authorization_id': self.authorization_id,
            'dispatch_reasons': list(self.dispatch_reasons),
            'signer_certificate_sha256': self.signer_certificate_sha256,
            'signer_subject': self.signer_subject,
            'certificate_valid_at_signing_time': self.certificate_valid_at_signing_time,
            'certificate_valid_now': self.certificate_valid_now,
            'certificate_revoked_at_signing_time': self.certificate_revoked_at_signing_time,
            'certificate_revoked_now': self.certificate_revoked_now,
            'certificate_matches_verification_key':
                self.certificate_matches_verification_key,
        }


@dataclass(frozen=True)
class TransferReviewReport:
    reviews: Tuple[ReceiptReview, ...]

    @property
    def receipts(self) -> Tuple[ReceiptReview, ...]:
        return self.reviews

    @property
    def historical_evidence_ids(self) -> Tuple[str, ...]:
        return tuple(review.receipt_id for review in self.reviews
                     if review.historical_evidence)

    @property
    def historical_ids(self) -> Tuple[str, ...]:
        return self.historical_evidence_ids

    @property
    def dispatchable_ids(self) -> Tuple[str, ...]:
        return tuple(review.receipt_id for review in self.reviews if review.dispatchable)

    @property
    def dispatch_ids(self) -> Tuple[str, ...]:
        return self.dispatchable_ids

    @property
    def missing_time_evidence(self) -> Dict[str, Tuple[str, ...]]:
        return {review.receipt_id: review.missing_time_evidence
                for review in self.reviews if review.missing_time_evidence}

    @property
    def pending_time_evidence_ids(self) -> Tuple[str, ...]:
        return tuple(self.missing_time_evidence)

    def by_id(self, receipt_id: str) -> ReceiptReview:
        for review in self.reviews:
            if review.receipt_id == receipt_id:
                return review
        raise KeyError(receipt_id)

    def __iter__(self):
        return iter(self.reviews)

    def __len__(self):
        return len(self.reviews)

    def __getitem__(self, index):
        return self.reviews[index]


ReceiptReviewReport = TransferReviewReport


def _header_certificates(message: Sign1Message) -> List[Any]:
    """Read an embedded X5chain/X5bag from a COSE message, if present."""

    for attribute in (X5chain, X5bag):
        try:
            value = message.get_attr(attribute)
        except CoseException:
            value = None
        if value is None:
            continue
        if hasattr(value, 'encode') and not isinstance(value, (bytes, list, tuple)):
            value = value.encode()
        if isinstance(value, (bytes, bytearray)):
            return [bytes(value)]
        if isinstance(value, (list, tuple)):
            return list(value)
    return []


def _evidence_digest(value: Union[bytes, str]) -> bytes:
    if isinstance(value, bytes):
        return value
    try:
        return bytes.fromhex(value)
    except ValueError:
        return value.encode()


class TransferReviewer:
    """Review signed receipts using only a :class:`LocalIdentityStore`."""

    def __init__(self, identity_store: Optional[LocalIdentityStore] = None,
                 *, now: Optional[datetime] = None,
                 trust_roots: Iterable = (),
                 intermediate_certificates: Iterable = (),
                 crls: Iterable = (),
                 authorizations: Iterable = (),
                 trusted_keys: Optional[Mapping[Any, CoseKey]] = None):
        if identity_store is None:
            identity_store = LocalIdentityStore(
                trust_roots=tuple(trust_roots),
                intermediate_certificates=tuple(intermediate_certificates),
                crls=tuple(crls),
                authorizations=tuple(authorizations),
                trusted_keys=trusted_keys or {},
            )
        self.identity_store = identity_store
        self.now = _utc(now) or datetime.now(timezone.utc)

    def review(self, receipts: Union[DeliveryReceipt, Iterable[DeliveryReceipt]],
               signing_times: Optional[Mapping[str, Union[datetime, SigningTimeEvidence]]] = None,
               now: Optional[datetime] = None) -> TransferReviewReport:
        """Review one or more receipts and return per-receipt conclusions."""

        if isinstance(receipts, DeliveryReceipt):
            receipts = [receipts]
        reviews = []
        for receipt in receipts:
            supplied_time = None
            if signing_times is not None:
                supplied_time = signing_times.get(receipt.receipt_id)
            reviews.append(self.review_one(receipt, signing_time=supplied_time, now=now))
        return TransferReviewReport(tuple(reviews))

    def review_one(self, receipt: DeliveryReceipt,
                   signing_time: Optional[Union[datetime, SigningTimeEvidence]] = None,
                   now: Optional[datetime] = None) -> ReceiptReview:
        now = _utc(now) or self.now
        message = _message_object(receipt.message)

        certificate_chain = list(receipt.certificate_chain)
        if receipt.signer_certificate is not None:
            certificate_chain = [receipt.signer_certificate] + certificate_chain
        if not certificate_chain:
            certificate_chain = _header_certificates(message)

        leaf_certificate = None
        if certificate_chain:
            try:
                leaf_certificate = load_certificate(certificate_chain[0])
            except Exception as error:
                leaf_certificate = None
                certificate_error = f'unreadable signer certificate: {error}'
            else:
                certificate_error = None
        else:
            certificate_error = None

        fingerprint = certificate_sha256(leaf_certificate) if leaf_certificate else None
        subject = leaf_certificate.subject.rfc4514_string() if leaf_certificate else None

        verification_key = receipt.verification_key
        key_is_trusted = verification_key is not None

        if verification_key is None and leaf_certificate is not None:
            try:
                verification_key = CoseKey._from_cryptography_key(leaf_certificate.public_key())
            except Exception:
                verification_key = None

        key_reason = None
        if verification_key is None:
            verification_key, key_is_trusted = self._trusted_key_for(
                receipt, message, fingerprint)
            if verification_key is None:
                key_reason = 'no local verification key or signer certificate available'
        elif fingerprint is not None:
            _, key_is_trusted = self._trusted_key_for(receipt, message, fingerprint)

        certificate_matches_verification_key = None
        if verification_key is not None and leaf_certificate is not None:
            try:
                certificate_matches_verification_key = certificate_key_matches(
                    verification_key, leaf_certificate)
            except Exception:
                certificate_matches_verification_key = False
            if not certificate_matches_verification_key:
                key_reason = 'the leaf certificate public key does not match the verification key'

        signature_valid = False
        signature_reason = None
        if verification_key is not None:
            candidate = deepcopy(message)
            candidate.key = verification_key
            try:
                signature_valid = bool(candidate.verify_signature(receipt.detached_payload))
            except Exception as error:
                signature_valid = False
                signature_reason = f'signature verification failed: {error}'
            if not signature_valid and signature_reason is None:
                signature_reason = 'COSE signature is invalid'

        evidence = signing_time
        if evidence is None:
            evidence = receipt.signing_time
        if isinstance(evidence, date) and not isinstance(evidence, datetime):
            evidence = SigningTimeEvidence(_utc(evidence))
        elif isinstance(evidence, datetime):
            evidence = SigningTimeEvidence(evidence)

        missing_time_evidence: List[str] = []
        if evidence is None:
            missing_time_evidence.append(CONFIRMED_SIGNING_TIME)
        else:
            if not evidence.verified:
                missing_time_evidence.append(TIME_EVIDENCE_VERIFICATION)
            if evidence.message_digest is not None:
                encoded = _message_bytes(receipt)
                if encoded is None or sha256(encoded).digest() != _evidence_digest(
                        evidence.message_digest):
                    missing_time_evidence.append(TIMESTAMP_BINDING)

        confirmed_signing_time = evidence.signing_time if not missing_time_evidence else None

        chain_result = None
        historical_reasons: List[str] = []
        if certificate_error:
            historical_reasons.append(certificate_error)

        if leaf_certificate is not None and confirmed_signing_time is not None \
                and self.identity_store.trust_roots \
                and certificate_matches_verification_key is not False:
            chain_result = validate_local_certificate_path(
                leaf_certificate,
                certificate_chain[1:] + list(self.identity_store.intermediate_certificates),
                self.identity_store.trust_roots,
                moment=confirmed_signing_time,
                key_usage={'digital_signature'},
                crls=self.identity_store.crls,
            )
            if not chain_result.valid:
                historical_reasons.extend(chain_result.reasons)

        certificate_valid_at_signing_time = None
        if leaf_certificate is not None and confirmed_signing_time is not None:
            certificate_valid_at_signing_time = certificate_valid_at(
                leaf_certificate, confirmed_signing_time)

        chain_was_checked = chain_result is not None
        chain_was_valid = chain_result.valid if chain_result is not None else None

        if not signature_valid:
            historical_status = EvidenceStatus.SIGNATURE_INVALID
            historical_evidence = False
            if signature_reason:
                historical_reasons.append(signature_reason)
            elif key_reason:
                historical_reasons.append(key_reason)
        elif missing_time_evidence:
            historical_status = EvidenceStatus.NEEDS_TIME_EVIDENCE
            historical_evidence = False
            if evidence is None:
                historical_reasons.append('no confirmed signing time was supplied')
            else:
                historical_reasons.append(
                    'the supplied time evidence is not usable: '
                    + ', '.join(missing_time_evidence))
            if receipt.claimed_signing_time is not None:
                historical_reasons.append(
                    'the receipt only has an unconfirmed signing-time claim')
        elif certificate_error:
            historical_status = EvidenceStatus.NOT_EVIDENCE
            historical_evidence = False
        elif chain_was_checked and not chain_was_valid:
            historical_status = EvidenceStatus.NOT_EVIDENCE
            historical_evidence = False
        elif certificate_matches_verification_key is False:
            historical_status = EvidenceStatus.NOT_EVIDENCE
            historical_evidence = False
            historical_reasons.append(key_reason)
        elif not chain_was_checked and not key_is_trusted:
            historical_status = EvidenceStatus.NOT_EVIDENCE
            historical_evidence = False
            historical_reasons.append('no local trust anchor was available for the signer')
        else:
            historical_status = EvidenceStatus.HISTORICAL
            historical_evidence = True

        current_chain_result = None
        if leaf_certificate is not None and self.identity_store.trust_roots:
            current_chain_result = validate_local_certificate_path(
                leaf_certificate,
                certificate_chain[1:] + list(self.identity_store.intermediate_certificates),
                self.identity_store.trust_roots,
                moment=now,
                key_usage={'digital_signature'},
                crls=self.identity_store.crls,
            )

        certificate_valid_now = certificate_valid_at(leaf_certificate, now) \
            if leaf_certificate is not None else None
        certificate_revoked_at_signing_time = chain_result.revoked if chain_result else None
        certificate_revoked_now = current_chain_result.revoked if current_chain_result else None

        dispatch_status, authorization_id, dispatch_reasons = self._dispatch_status(
            receipt, fingerprint, signature_valid, signature_reason, key_reason,
            certificate_revoked_now, now)

        return ReceiptReview(
            receipt_id=receipt.receipt_id,
            signature_valid=signature_valid,
            historical_evidence=historical_evidence,
            historical_status=historical_status,
            confirmed_signing_time=confirmed_signing_time,
            historical_reasons=tuple(historical_reasons),
            missing_time_evidence=tuple(missing_time_evidence),
            dispatchable=dispatch_status is DispatchStatus.AUTHORIZED,
            dispatch_status=dispatch_status,
            authorization_id=authorization_id,
            dispatch_reasons=tuple(dispatch_reasons),
            signer_certificate_sha256=fingerprint,
            signer_subject=subject,
            certificate_valid_at_signing_time=certificate_valid_at_signing_time,
            certificate_valid_now=certificate_valid_now,
            certificate_revoked_at_signing_time=certificate_revoked_at_signing_time,
            certificate_revoked_now=certificate_revoked_now,
            certificate_matches_verification_key=certificate_matches_verification_key,
        )

    def _trusted_key_for(self, receipt: DeliveryReceipt, message: Sign1Message,
                         fingerprint: Optional[str]):
        candidates: List[Any] = []
        if fingerprint is not None:
            candidates.extend([fingerprint, fingerprint.lower()])

        key_id = receipt.metadata.get('key_id') if receipt.metadata else None
        if key_id is None:
            try:
                key_id = message.get_attr(KID)
            except CoseException:
                key_id = None
        if key_id is not None:
            candidates.append(key_id)
            if isinstance(key_id, bytes):
                candidates.extend([key_id.hex(), key_id.decode('utf-8', errors='ignore')])
            elif isinstance(key_id, str):
                candidates.append(key_id.encode())

        for candidate in candidates:
            if candidate in self.identity_store.trusted_keys:
                return self.identity_store.trusted_keys[candidate], True
        return None, False

    def _dispatch_status(self, receipt: DeliveryReceipt, fingerprint: Optional[str],
                         signature_valid: bool, signature_reason: Optional[str],
                         key_reason: Optional[str], signer_revoked_now: Optional[bool],
                         now: datetime):
        if not signature_valid:
            return (DispatchStatus.SIGNATURE_INVALID, None,
                    [signature_reason or key_reason or 'signature is not valid'])

        matching = [authorization for authorization in self.identity_store.authorizations
                    if authorization.matches(receipt, fingerprint)]

        if signer_revoked_now:
            authorization_id = matching[0].authorization_id if matching else None
            return (DispatchStatus.REVOKED, authorization_id,
                    ['the signer certificate was revoked before the current review time'])

        if not matching:
            return (DispatchStatus.NO_AUTHORIZATION, None,
                    ['no current transfer authorization matches this receipt'])

        for authorization in matching:
            if authorization.status_at(now) is DispatchStatus.AUTHORIZED:
                return DispatchStatus.AUTHORIZED, authorization.authorization_id, []

        statuses = [(authorization.status_at(now), authorization)
                    for authorization in matching]
        priority = [DispatchStatus.REVOKED, DispatchStatus.EXPIRED, DispatchStatus.NOT_YET_VALID]
        selected_status, selected = next(
            (item for status in priority for item in statuses if item[0] is status),
            statuses[0],
        )
        return selected_status, selected.authorization_id, [
            f'current authorization {selected.authorization_id} is {selected_status.value}'
        ]


def review_delivery_receipts(
        receipts: Union[DeliveryReceipt, Iterable[DeliveryReceipt]],
        *,
        signing_times: Optional[Mapping[str, Union[datetime, SigningTimeEvidence]]] = None,
        trust_roots: Iterable = (),
        intermediate_certificates: Iterable = (),
        crls: Iterable = (),
        authorizations: Iterable = (),
        trusted_keys: Optional[Mapping[Any, CoseKey]] = None,
        now: Optional[datetime] = None) -> TransferReviewReport:
    """Convenience wrapper around :class:`TransferReviewer`."""

    store = LocalIdentityStore(
        trust_roots=tuple(trust_roots),
        intermediate_certificates=tuple(intermediate_certificates),
        crls=tuple(crls),
        authorizations=tuple(authorizations),
        trusted_keys=trusted_keys or {},
    )
    return TransferReviewer(store, now=now).review(receipts, signing_times=signing_times)


LocalTransferReviewer = TransferReviewer
review_transfer_receipts = review_delivery_receipts
review_receipts = review_delivery_receipts
SignedReceipt = DeliveryReceipt
Receipt = DeliveryReceipt
UsageAuthorization = TransferAuthorization
TransferPermit = TransferAuthorization
HistoricalEvidenceStatus = EvidenceStatus
