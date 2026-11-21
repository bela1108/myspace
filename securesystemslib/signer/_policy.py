"""Time-aware signature policy evaluation.

The signer module answers a cryptographic question: *did this key produce this
signature over this payload?*  This module answers the follow-up approval
question: *given the caller's trusted clocks and knowledge cut-off, what may
that verified signature be used for?*

Two uses are evaluated independently:

``archive``
    Historical evidence.  The signature is anchored at its proven (attested)
    time, or at the trusted receipt time when no attestation is available.

``release``
    A new publication.  The signature is anchored at the trusted evaluation
    time of the receipt view.

Revocation notices are never added to a view "because we know them now".  A
notice is visible only when its ``known_at`` time is at or before the view's
trusted time.  An effective revocation then blocks a use only if it was
effective at that use's anchor.  This makes it possible to replay a historical
receipt without retroactively injecting a later notice.

No wall clock is read anywhere in this module.  The caller must supply every
trusted time point, which keeps evaluations deterministic and auditable.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, cast

from securesystemslib.signer._key import Key
from securesystemslib.signer._signature import Signature

__all__ = [
    "ArchiveAnchor",
    "EvaluationView",
    "PolicyCheck",
    "PolicyDecision",
    "Decision",
    "PolicyUse",
    "Receipt",
    "ReplayReport",
    "Revocation",
    "RevocationNotice",
    "RevocationCheck",
    "SignatureEvidence",
    "SignaturePolicy",
    "TimeClaim",
    "TimeInterval",
    "TimeWindow",
    "TrustedTime",
    "Use",
    "UseDecision",
    "UseDifference",
    "evaluate_signature_policy",
    "evaluate",
    "replay_receipts",
    "replay",
    "replay_views",
    "verify_and_evaluate",
]


def _coerce_datetime(value: datetime | int | float | str, field_name: str) -> datetime:
    """Return an aware UTC datetime from a caller supplied time value."""
    if isinstance(value, bool):
        raise TypeError(f"{field_name} must be a datetime or timestamp, not bool")

    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, (int, float)):
        moment = datetime.fromtimestamp(value, tz=UTC)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = f"{text[:-1]}+00:00"
        moment = datetime.fromisoformat(text)
    else:
        raise TypeError(
            f"{field_name} must be datetime, ISO 8601 string, or epoch seconds"
        )

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _isoformat(value: datetime | None) -> str:
    if value is None:
        return "unbounded"
    return value.isoformat().replace("+00:00", "Z")


def _optional_datetime(
    value: datetime | int | float | str | None,
    field_name: str,
) -> datetime | None:
    """Parse an optional time value, accepting the 'unbounded' display token."""
    if value is None or value == "unbounded":
        return None
    return _coerce_datetime(value, field_name)


def _digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TrustedTime:
    """A time value whose provenance the caller explicitly trusts.

    ``source`` is free-form (for example ``"tsa"``, ``"offline-clock"`` or
    ``"receipt-log"``).  It is copied into decision traces.
    """

    value: datetime
    source: str = "caller"
    kind: str = "trusted"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _coerce_datetime(cast(Any, self.value), "TrustedTime.value"),
        )
        if not isinstance(self.source, str) or not self.source:
            raise ValueError("TrustedTime.source must be a non-empty string")
        if not isinstance(self.kind, str) or not self.kind:
            raise ValueError("TrustedTime.kind must be a non-empty string")

    @property
    def at(self) -> datetime:
        return self.value

    def to_dict(self) -> dict[str, str]:
        return {
            "value": _isoformat(self.value),
            "source": self.source,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class TimeClaim:
    """A time declaration together with its trust status.

    A declaration parsed from signature metadata starts as untrusted.  Only a
    caller supplied :class:`TrustedTime` (or an explicit trusted claim) can
    make it usable as proof.  Untrusted claims are retained in decision traces
    instead of being silently discarded.
    """

    value: datetime | None
    trusted: bool = False
    source: str | None = None
    declaration: str | None = None
    raw: Any = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.value is not None:
            object.__setattr__(
                self,
                "value",
                _coerce_datetime(cast(Any, self.value), "TimeClaim.value"),
            )

    @classmethod
    def from_trusted(
        cls,
        value: datetime | int | float | str | TrustedTime,
        source: str = "caller",
        declaration: str | None = None,
    ) -> TimeClaim:
        if isinstance(value, TrustedTime):
            return cls(value.value, True, value.source, declaration)
        return cls(
            _coerce_datetime(value, declaration or "trusted time"),
            True,
            source,
            declaration,
        )

    @classmethod
    def from_unverified(
        cls,
        value: datetime | int | float | str,
        source: str | None = None,
        declaration: str | None = None,
        raw: Any = None,
    ) -> TimeClaim:
        return cls(
            _coerce_datetime(value, declaration or "time claim"),
            False,
            source,
            declaration,
            raw,
        )

    @property
    def at(self) -> datetime | None:
        return self.value

    @property
    def is_trusted(self) -> bool:
        return self.trusted and self.value is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": _isoformat(self.value),
            "trusted": self.trusted,
            "source": self.source,
            "declaration": self.declaration,
        }


TimeLike = datetime | int | float | str | TrustedTime | TimeClaim


def _as_claim(
    value: TimeLike,
    *,
    trusted: bool,
    source: str | None,
    declaration: str | None,
) -> TimeClaim:
    if isinstance(value, TimeClaim):
        return value
    if isinstance(value, TrustedTime):
        return TimeClaim(value.value, True, value.source, declaration)
    return TimeClaim(
        _coerce_datetime(value, declaration or "time"),
        trusted,
        source,
        declaration,
    )


@dataclass(frozen=True)
class TimeInterval:
    """A possibly open time interval.

    The default is the half-open interval ``[start, end)``.  ``None`` means an
    open (unbounded) side.  The booleans allow all four boundary combinations,
    including finite closed and fully open intervals.
    """

    start: datetime | None = None
    end: datetime | None = None
    include_start: bool = True
    include_end: bool = False

    def __post_init__(self) -> None:
        if self.start is not None:
            object.__setattr__(
                self,
                "start",
                _coerce_datetime(cast(Any, self.start), "TimeInterval.start"),
            )
        if self.end is not None:
            object.__setattr__(
                self,
                "end",
                _coerce_datetime(cast(Any, self.end), "TimeInterval.end"),
            )

    @classmethod
    def closed(
        cls,
        start: datetime | int | float | str,
        end: datetime | int | float | str,
    ) -> TimeInterval:
        return cls(start, end, include_start=True, include_end=True)

    @classmethod
    def open(
        cls,
        start: datetime | int | float | str,
        end: datetime | int | float | str,
    ) -> TimeInterval:
        return cls(start, end, include_start=False, include_end=False)

    @classmethod
    def half_open(
        cls,
        start: datetime | int | float | str,
        end: datetime | int | float | str,
    ) -> TimeInterval:
        return cls(start, end, include_start=True, include_end=False)

    @classmethod
    def unbounded(cls) -> TimeInterval:
        return cls(None, None)

    @property
    def is_empty(self) -> bool:
        if self.start is None or self.end is None:
            return False
        if self.start < self.end:
            return False
        if self.start > self.end:
            return True
        return not (self.include_start and self.include_end)

    @property
    def start_inclusive(self) -> bool:
        return self.include_start

    @property
    def end_inclusive(self) -> bool:
        return self.include_end

    @property
    def left_closed(self) -> bool:
        return self.include_start

    @property
    def right_closed(self) -> bool:
        return self.include_end

    def contains(self, moment: TimeLike) -> bool:  # noqa: PLR0911, PLR0912
        if isinstance(moment, TimeClaim):
            if moment.value is None:
                return False
            value = moment.value
        elif isinstance(moment, TrustedTime):
            value = moment.value
        else:
            value = _coerce_datetime(cast(Any, moment), "moment")

        if self.is_empty:
            return False
        if self.start is not None:
            if self.include_start:
                if value < self.start:
                    return False
            elif value <= self.start:
                return False
        if self.end is not None:
            if self.include_end:
                if value > self.end:
                    return False
            elif value >= self.end:
                return False
        return True

    valid_at = contains

    def __contains__(self, moment: object) -> bool:
        if not isinstance(moment, (datetime, int, float, str, TrustedTime, TimeClaim)):
            return False
        return self.contains(moment)

    def describe(self) -> str:
        left = "[" if self.include_start else "("
        right = "]" if self.include_end else ")"
        return f"{left}{_isoformat(self.start)}, {_isoformat(self.end)}{right}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": _isoformat(self.start),
            "end": _isoformat(self.end),
            "include_start": self.include_start,
            "include_end": self.include_end,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TimeInterval:
        return cls(
            start=_optional_datetime(data.get("start"), "TimeInterval.start"),
            end=_optional_datetime(data.get("end"), "TimeInterval.end"),
            include_start=bool(data.get("include_start", True)),
            include_end=bool(data.get("include_end", False)),
        )


TimeWindow = TimeInterval


class PolicyUse(StrEnum):
    """The two approval purposes evaluated by this module."""

    ARCHIVE = "archive"
    RELEASE = "release"

    HISTORICAL_ARCHIVE = "archive"
    NEW_RELEASE = "release"
    PUBLISH = "release"


Use = PolicyUse


class ArchiveAnchor(StrEnum):
    """How historical archive time is selected."""

    ATTESTED_OR_RECEIPT = "attested-or-receipt"
    ATTESTED = "attested"
    RECEIPT = "receipt"

    AUTO = "attested-or-receipt"


def _coerce_use(value: str | PolicyUse) -> PolicyUse:
    if isinstance(value, PolicyUse):
        return value
    try:
        return PolicyUse(value)
    except ValueError as exc:
        valid = ", ".join(use.value for use in (PolicyUse.ARCHIVE, PolicyUse.RELEASE))
        raise ValueError(
            f"unknown policy use {value!r}; expected one of {valid}"
        ) from exc


def _coerce_uses(
    uses: str | PolicyUse | Iterable[str | PolicyUse] | None,
) -> tuple[PolicyUse, ...]:
    if uses is None:
        return (PolicyUse.ARCHIVE, PolicyUse.RELEASE)
    if isinstance(uses, (str, PolicyUse)):
        return (_coerce_use(uses),)

    result: list[PolicyUse] = []
    for use in uses:
        policy_use = _coerce_use(use)
        if policy_use not in result:
            result.append(policy_use)
    if not result:
        raise ValueError("at least one policy use is required")
    return tuple(result)


_INTERVAL_ENDS = 2


def _coerce_interval(value: Any) -> TimeInterval | None:
    if value is None or isinstance(value, TimeInterval):
        return value
    if isinstance(value, (tuple, list)) and len(value) == _INTERVAL_ENDS:
        return TimeInterval(value[0], value[1])
    raise TypeError("expected TimeInterval, a (start, end) pair, or None")


def _coerce_archive_anchor(value: str | ArchiveAnchor) -> ArchiveAnchor:
    if isinstance(value, ArchiveAnchor):
        return value
    normalized = value.strip().lower().replace("_", "-")
    aliases = {
        "auto": ArchiveAnchor.ATTESTED_OR_RECEIPT,
        "attested-else-receipt": ArchiveAnchor.ATTESTED_OR_RECEIPT,
    }
    if normalized in aliases:
        return aliases[normalized]
    try:
        return ArchiveAnchor(normalized)
    except ValueError as exc:
        raise ValueError(f"unknown archive anchor {value!r}") from exc


@dataclass(frozen=True)
class Revocation:
    """A withdrawal notice for a key, signature, or artifact.

    Args:
        effective_at: Instant from which the target is revoked.
        known_at: Instant at which the evaluating view learned about the
            notice.  If omitted, the notice is treated as known when it became
            effective.  A view never sees a notice with a later ``known_at``.
        keyid: Optional key identifier narrowed by the notice.
        signature_id: Optional signature identifier.  The raw signature hex and
            ``keyid:signature`` form are also accepted for convenience.
        artifact_id: Optional artifact identifier.
        uses: Optional restriction of the notice to specific uses.
    """

    effective_at: datetime
    known_at: datetime | None = None
    keyid: str | None = None
    signature_id: str | None = None
    artifact_id: str | None = None
    reason: str | None = None
    source: str | None = None
    uses: frozenset[PolicyUse] | None = None
    notice_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "effective_at",
            _coerce_datetime(
                cast(Any, self.effective_at),
                "Revocation.effective_at",
            ),
        )
        if self.known_at is None:
            object.__setattr__(self, "known_at", self.effective_at)
        else:
            object.__setattr__(
                self,
                "known_at",
                _coerce_datetime(cast(Any, self.known_at), "Revocation.known_at"),
            )

        raw_uses = cast(Any, self.uses)
        if raw_uses is not None:
            if isinstance(raw_uses, (str, PolicyUse)):
                uses: Iterable[str | PolicyUse] = (raw_uses,)
            else:
                uses = raw_uses
            object.__setattr__(
                self,
                "uses",
                frozenset(_coerce_use(use) for use in uses),
            )

        if self.notice_id is None:
            object.__setattr__(
                self,
                "notice_id",
                "rev-"
                + _digest(
                    self.keyid or "",
                    self.signature_id or "",
                    self.artifact_id or "",
                    self.effective_at.isoformat(),
                    cast(datetime, self.known_at).isoformat(),
                    self.reason or "",
                )[:16],
            )

    @property
    def revoked_at(self) -> datetime:
        return self.effective_at

    @property
    def announced_at(self) -> datetime:
        return cast(datetime, self.known_at)

    @property
    def received_at(self) -> datetime:
        return cast(datetime, self.known_at)

    def visible_at(self, view_time: TimeLike) -> bool:
        moment = (
            view_time.value
            if isinstance(view_time, (TrustedTime, TimeClaim))
            else _coerce_datetime(cast(Any, view_time), "view_time")
        )
        return moment is not None and cast(datetime, self.known_at) <= cast(
            datetime, moment
        )

    def effective_at_or_before(self, moment: TimeLike) -> bool:
        value = (
            moment.value
            if isinstance(moment, (TrustedTime, TimeClaim))
            else _coerce_datetime(cast(Any, moment), "moment")
        )
        return value is not None and self.effective_at <= cast(datetime, value)

    def is_about(self, use: str | PolicyUse) -> bool:
        return self.uses is None or _coerce_use(use) in self.uses

    def matches(self, evidence: SignatureEvidence) -> bool:
        if self.keyid is not None and self.keyid != evidence.key.keyid:
            return False

        if self.signature_id is not None:
            candidates = {
                evidence.signature_id,
                evidence.signature.signature,
                f"{evidence.signature.keyid}:{evidence.signature.signature}",
            }
            if self.signature_id not in candidates:
                return False

        if self.artifact_id is not None:
            if evidence.artifact_id != self.artifact_id:
                return False

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "notice_id": self.notice_id,
            "effective_at": _isoformat(self.effective_at),
            "known_at": _isoformat(cast(datetime, self.known_at)),
            "keyid": self.keyid,
            "signature_id": self.signature_id,
            "artifact_id": self.artifact_id,
            "reason": self.reason,
            "source": self.source,
            "uses": (
                None if self.uses is None else sorted(use.value for use in self.uses)
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Revocation:
        uses = data.get("uses")
        return cls(
            effective_at=data["effective_at"],
            known_at=data.get("known_at"),
            keyid=data.get("keyid"),
            signature_id=data.get("signature_id"),
            artifact_id=data.get("artifact_id"),
            reason=data.get("reason"),
            source=data.get("source"),
            uses=uses,
            notice_id=data.get("notice_id"),
        )


RevocationNotice = Revocation


_TIME_CLAIM_FIELDS = (
    "signed_at",
    "signing_time",
    "signature_time",
    "claimed_signed_at",
    "timestamp",
)


@dataclass(frozen=True)
class SignatureEvidence:
    """A securesystemslib signature plus the policy-relevant context.

    ``verified`` is the result of ``Key.verify_signature()`` (or an equivalent
    DSSE verification).  Use :meth:`verify` to obtain a result directly from
    securesystemslib, or :meth:`from_verification` when the verification
    already happened elsewhere.

    ``attested_at`` is trusted only because the caller supplied it.  Time-like
    fields found in `` Signature.unrecognized_fields`` are retained as
    untrusted :class:`TimeClaim` values.
    """

    key: Key
    signature: Signature
    payload: bytes
    artifact_id: str | None = None
    signature_id: str | None = None
    attested_at: TimeClaim | None = None
    claimed_signed_at: TimeClaim | None = None
    verified: bool = True
    verification_source: str = "securesystemslib.signer.Key.verify_signature"
    verification_detail: str | None = None
    unverified_time_claims: Mapping[str, TimeClaim] = field(
        default_factory=dict,
        compare=False,
        hash=False,
        repr=False,
    )
    metadata: Mapping[str, Any] = field(
        default_factory=dict,
        compare=False,
        hash=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", bytes(self.payload))

        if self.attested_at is not None:
            object.__setattr__(
                self,
                "attested_at",
                _as_claim(
                    self.attested_at,
                    trusted=True,
                    source="caller",
                    declaration="attested_at",
                ),
            )
        if self.claimed_signed_at is not None:
            object.__setattr__(
                self,
                "claimed_signed_at",
                _as_claim(
                    self.claimed_signed_at,
                    trusted=False,
                    source="signature",
                    declaration="claimed_signed_at",
                ),
            )

        claims = dict(self.unverified_time_claims)
        metadata = dict(self.metadata)
        unparsed: dict[str, Any] = dict(metadata.get("unparsed_time_claims", {}))

        for field_name in _TIME_CLAIM_FIELDS:
            if field_name not in self.signature.unrecognized_fields:
                continue
            raw = self.signature.unrecognized_fields[field_name]
            try:
                claims[field_name] = TimeClaim.from_unverified(
                    cast(Any, raw),
                    source=f"signature.unrecognized_fields[{field_name}]",
                    declaration=field_name,
                    raw=raw,
                )
            except (TypeError, ValueError, OverflowError):
                unparsed[field_name] = raw

        if self.claimed_signed_at is None:
            for field_name in _TIME_CLAIM_FIELDS:
                if field_name in claims:
                    object.__setattr__(
                        self,
                        "claimed_signed_at",
                        claims[field_name],
                    )
                    break

        if self.signature_id is None:
            derived = _digest(
                self.key.keyid,
                self.signature.keyid,
                self.signature.signature,
            )[:24]
            object.__setattr__(self, "signature_id", f"sha256:{derived}")

        if unparsed:
            metadata["unparsed_time_claims"] = unparsed
        object.__setattr__(self, "unverified_time_claims", claims)
        object.__setattr__(self, "metadata", metadata)

    @classmethod
    def from_verification(  # noqa: PLR0913
        cls,
        key: Key,
        signature: Signature,
        payload: bytes,
        *,
        verified: bool = True,
        verification_source: str = ("securesystemslib.signer.Key.verify_signature"),
        verification_detail: str | None = None,
        artifact_id: str | None = None,
        signature_id: str | None = None,
        attested_at: TimeLike | None = None,
        claimed_signed_at: TimeLike | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> SignatureEvidence:
        return cls(
            key=key,
            signature=signature,
            payload=payload,
            artifact_id=artifact_id,
            signature_id=signature_id,
            attested_at=(
                None
                if attested_at is None
                else _as_claim(
                    attested_at,
                    trusted=True,
                    source="caller",
                    declaration="attested_at",
                )
            ),
            claimed_signed_at=(
                None
                if claimed_signed_at is None
                else _as_claim(
                    claimed_signed_at,
                    trusted=False,
                    source="signature",
                    declaration="claimed_signed_at",
                )
            ),
            verified=verified,
            verification_source=verification_source,
            verification_detail=verification_detail,
            metadata={} if metadata is None else metadata,
        )

    @classmethod
    def verify(
        cls,
        key: Key,
        signature: Signature,
        payload: bytes,
        **kwargs: Any,
    ) -> SignatureEvidence:
        """Verify with securesystemslib and return policy evidence.

        Raises whatever ``Key.verify_signature()`` raises (normally
        ``UnverifiedSignatureError``).
        """
        key.verify_signature(signature, payload)
        kwargs.pop("verified", None)
        return cls.from_verification(key, signature, payload, verified=True, **kwargs)

    @property
    def keyid(self) -> str:
        return self.key.keyid

    @property
    def attested_time(self) -> datetime | None:
        return None if self.attested_at is None else self.attested_at.value

    @property
    def claimed_signed_time(self) -> datetime | None:
        return None if self.claimed_signed_at is None else self.claimed_signed_at.value

    def with_attestation(
        self,
        value: datetime | int | float | str | TrustedTime,
        *,
        source: str = "caller",
    ) -> SignatureEvidence:
        """Return a copy with a caller-trusted proven time."""
        return replace(
            self,
            attested_at=TimeClaim.from_trusted(
                value,
                source=source,
                declaration="attested_at",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "keyid": self.key.keyid,
            "signature_id": self.signature_id,
            "artifact_id": self.artifact_id,
            "verified": self.verified,
            "verification_source": self.verification_source,
            "verification_detail": self.verification_detail,
            "attested_at": (
                None if self.attested_at is None else self.attested_at.to_dict()
            ),
            "claimed_signed_at": (
                None
                if self.claimed_signed_at is None
                else self.claimed_signed_at.to_dict()
            ),
            "unverified_time_claims": {
                name: claim.to_dict()
                for name, claim in sorted(self.unverified_time_claims.items())
            },
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class EvaluationView:
    """A trusted replay point for a receipt.

    ``trusted_time`` is the receipt/evaluation time supplied by the caller.
    ``attested_at`` optionally overrides the evidence's proven time for this
    view (for example, when an attestation was established at receipt time).
    ``known_at`` is not a field on purpose: notice visibility is always
    computed from each notice and this view's trusted time.
    """

    name: str
    trusted_time: datetime
    attested_at: TimeClaim | None = None
    source: str = "caller"
    note: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("EvaluationView.name must be a non-empty string")

        raw_time = cast(Any, self.trusted_time)
        if isinstance(raw_time, TrustedTime):
            object.__setattr__(self, "trusted_time", raw_time.value)
            object.__setattr__(self, "source", raw_time.source)
        elif isinstance(raw_time, TimeClaim):
            if not raw_time.is_trusted:
                raise ValueError(
                    "EvaluationView.trusted_time must be a trusted TimeClaim"
                )
            object.__setattr__(
                self,
                "trusted_time",
                cast(datetime, raw_time.value),
            )
        else:
            object.__setattr__(
                self,
                "trusted_time",
                _coerce_datetime(raw_time, "EvaluationView.trusted_time"),
            )

        if self.attested_at is not None:
            object.__setattr__(
                self,
                "attested_at",
                _as_claim(
                    self.attested_at,
                    trusted=True,
                    source="caller",
                    declaration="view.attested_at",
                ),
            )

    @property
    def view_time(self) -> datetime:
        return self.trusted_time

    @property
    def receipt_time(self) -> datetime:
        return self.trusted_time

    @property
    def trusted_at(self) -> datetime:
        return self.trusted_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "trusted_time": _isoformat(self.trusted_time),
            "source": self.source,
            "attested_at": (
                None if self.attested_at is None else self.attested_at.to_dict()
            ),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvaluationView:
        attested = data.get("attested_at")
        return cls(
            name=data["name"],
            trusted_time=_optional_datetime(
                data["trusted_time"],
                "EvaluationView.trusted_time",
            ),
            attested_at=(
                None
                if attested is None
                else TimeClaim(
                    _optional_datetime(
                        attested.get("value"),
                        "EvaluationView.attested_at",
                    ),
                    bool(attested.get("trusted", False)),
                    attested.get("source"),
                    attested.get("declaration"),
                )
            ),
            source=data.get("source", "caller"),
            note=data.get("note"),
        )


Receipt = EvaluationView


@dataclass(frozen=True)
class PolicyCheck:
    """One auditable check in a use decision."""

    subject: str
    passed: bool
    code: str
    detail: str
    warning: bool = False
    data: Mapping[str, Any] = field(
        default_factory=dict,
        compare=False,
        hash=False,
        repr=False,
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "passed": self.passed,
            "code": self.code,
            "detail": self.detail,
            "warning": self.warning,
            "data": dict(self.data),
        }


@dataclass(frozen=True)
class RevocationCheck:
    """How one matching revocation notice affected a use decision."""

    notice: Revocation
    status: str
    applied: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "notice": self.notice.to_dict(),
            "status": self.status,
            "applied": self.applied,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class UseDecision:
    """The result of evaluating one use (archive or release)."""

    use: PolicyUse
    allowed: bool
    anchor: datetime | None
    anchor_source: str | None
    anchor_trusted: bool | None
    checks: tuple[PolicyCheck, ...]
    revocations: tuple[RevocationCheck, ...]

    @property
    def permitted(self) -> bool:
        return self.allowed

    @property
    def trace(self) -> tuple[PolicyCheck, ...]:
        return self.checks

    @property
    def reason_code(self) -> str:
        return self.checks[-1].code

    @property
    def reason(self) -> str:
        return self.checks[-1].detail

    @property
    def applied_revocations(self) -> tuple[Revocation, ...]:
        return tuple(check.notice for check in self.revocations if check.applied)

    @property
    def ignored_revocations(self) -> tuple[Revocation, ...]:
        return tuple(check.notice for check in self.revocations if not check.applied)

    def explain(self) -> str:
        state = "ALLOW" if self.allowed else "DENY"
        lines = [f"{self.use.value}: {state} [{self.reason_code}] {self.reason}"]
        for check in self.checks:
            if check.subject == "decision":
                continue
            marker = "ok" if check.passed else "FAIL"
            if check.warning:
                marker = "warn"
            lines.append(f"  - {marker} {check.code}: {check.detail}")
        for notice_check in self.revocations:
            marker = "applied" if notice_check.applied else "ignored"
            lines.append(
                f"  - {marker} notice {notice_check.notice.notice_id} "
                f"[{notice_check.status}]: {notice_check.detail}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "use": self.use.value,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "anchor": _isoformat(self.anchor),
            "anchor_source": self.anchor_source,
            "anchor_trusted": self.anchor_trusted,
            "checks": [check.to_dict() for check in self.checks],
            "revocations": [check.to_dict() for check in self.revocations],
        }


_USE_ORDER = (PolicyUse.ARCHIVE, PolicyUse.RELEASE)


@dataclass(frozen=True)
class PolicyDecision:
    """The approval decision for one signature in one receipt view."""

    signature_id: str
    keyid: str
    view_name: str
    view_time: datetime
    attested_at: datetime | None
    uses: Mapping[PolicyUse, UseDecision] = field(hash=False)

    @property
    def allowed_uses(self) -> frozenset[PolicyUse]:
        return frozenset(use for use, decision in self.uses.items() if decision.allowed)

    @property
    def permitted_uses(self) -> frozenset[PolicyUse]:
        return self.allowed_uses

    @property
    def valid_for_archive(self) -> bool:
        return self.allows(PolicyUse.ARCHIVE)

    @property
    def valid_for_release(self) -> bool:
        return self.allows(PolicyUse.RELEASE)

    @property
    def trace(self) -> dict[PolicyUse, tuple[PolicyCheck, ...]]:
        return {use: decision.checks for use, decision in self.uses.items()}

    @property
    def denied_uses(self) -> frozenset[PolicyUse]:
        return frozenset(
            use for use, decision in self.uses.items() if not decision.allowed
        )

    def allows(self, use: str | PolicyUse) -> bool:
        decision = self.uses.get(_coerce_use(use))
        return decision is not None and decision.allowed

    def explain(self, use: str | PolicyUse | None = None) -> str:
        lines = [
            (
                f"{self.view_name} at {_isoformat(self.view_time)}: "
                f"signature {self.signature_id} (key {self.keyid})"
            )
        ]
        if use is not None:
            selected = _coerce_use(use)
            lines.append(self.uses[selected].explain())
            return "\n".join(lines)

        for policy_use in _USE_ORDER:
            decision = self.uses.get(policy_use)
            if decision is not None:
                lines.append(decision.explain())
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "keyid": self.keyid,
            "view": self.view_name,
            "view_time": _isoformat(self.view_time),
            "attested_at": _isoformat(self.attested_at),
            "allowed_uses": sorted(use.value for use in self.allowed_uses),
            "uses": {
                use.value: decision.to_dict()
                for use, decision in sorted(
                    self.uses.items(),
                    key=lambda item: _USE_ORDER.index(item[0]),
                )
            },
        }


Decision = PolicyDecision


@dataclass(frozen=True)
class UseDifference:
    """An allowed/denied change for one use between two replayed views."""

    use: PolicyUse
    first: PolicyDecision
    second: PolicyDecision
    first_use: UseDecision
    second_use: UseDecision

    @property
    def before(self) -> PolicyDecision:
        return self.first

    @property
    def after(self) -> PolicyDecision:
        return self.second

    @property
    def explanation(self) -> str:
        return (
            f"{self.use.value}: "
            f"{self.first.view_name}="
            f"{'ALLOW' if self.first_use.allowed else 'DENY'} "
            f"[{self.first_use.reason_code}] {self.first_use.reason}; "
            f"{self.second.view_name}="
            f"{'ALLOW' if self.second_use.allowed else 'DENY'} "
            f"[{self.second_use.reason_code}] {self.second_use.reason}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "use": self.use.value,
            "first": {
                "view": self.first.view_name,
                "allowed": self.first_use.allowed,
                "reason_code": self.first_use.reason_code,
                "reason": self.first_use.reason,
            },
            "second": {
                "view": self.second.view_name,
                "allowed": self.second_use.allowed,
                "reason_code": self.second_use.reason_code,
                "reason": self.second_use.reason,
            },
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class ReplayReport:
    """Decisions for the same signature material replayed at several receipts."""

    evidence: SignatureEvidence
    policy: SignaturePolicy
    decisions: tuple[PolicyDecision, ...]

    @property
    def views(self) -> tuple[PolicyDecision, ...]:
        return self.decisions

    def for_receipt(self, name: str) -> PolicyDecision:
        for decision in self.decisions:
            if decision.view_name == name:
                return decision
        raise KeyError(f"no receipt named {name!r}")

    def differences(self) -> tuple[UseDifference, ...]:
        differences: list[UseDifference] = []
        for index, first in enumerate(self.decisions):
            for second in self.decisions[index + 1 :]:
                for use in _USE_ORDER:
                    first_use = first.uses.get(use)
                    second_use = second.uses.get(use)
                    if first_use is None or second_use is None:
                        continue
                    if first_use.allowed != second_use.allowed:
                        differences.append(
                            UseDifference(use, first, second, first_use, second_use)
                        )
        return tuple(differences)

    @property
    def changed_uses(self) -> frozenset[PolicyUse]:
        return frozenset(difference.use for difference in self.differences())

    def explain(self) -> str:
        validity = (
            self.policy.validity.describe() if self.policy.validity else "unbounded"
        )
        lines = [
            (f"signature {self.evidence.signature_id} (key {self.evidence.key.keyid})"),
            (f"policy: validity={validity}, notices={len(self.policy.revocations)}"),
        ]
        for decision in self.decisions:
            lines.append(decision.explain())

        differences = self.differences()
        lines.append("changed uses:")
        if not differences:
            lines.append("  none")
        else:
            for difference in differences:
                lines.append(f"  - {difference.explanation}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_id": self.evidence.signature_id,
            "keyid": self.evidence.key.keyid,
            "decisions": [decision.to_dict() for decision in self.decisions],
            "differences": [difference.to_dict() for difference in self.differences()],
        }


@dataclass(frozen=True)
class SignaturePolicy:
    """Time-aware policy applied to a verified signature.

    Args:
        validity: Interval in which the signing key/signature is valid.  It is
            checked at the archive anchor and at the release view time.
        revocations: Withdrawal notices.  Visibility is always computed per
            view from each notice's ``known_at`` value.
        archive_anchor: Select the proven time, the trusted receipt time, or
            the proven time with receipt fallback.
        archive_window: Optional interval restricting archive anchors.
        release_window: Optional interval restricting release view times.
        allow_unverified_claims_for_archive: Permit an untrusted signature time
            declaration as an archive anchor.  Such a decision is marked with
            the ``allowed_with_unverified_time`` reason code.  Release never
            uses an untrusted anchor.
        release_max_age: Optional maximum age between the proven time and the
            release view.  Requires a trusted attested time.
        require_verified_signature: When true (the default), a failed
            securesystemslib verification denies every use.
    """

    validity: TimeInterval | None = None
    revocations: tuple[Revocation, ...] = ()
    archive_anchor: ArchiveAnchor = ArchiveAnchor.ATTESTED_OR_RECEIPT
    archive_window: TimeInterval | None = None
    release_window: TimeInterval | None = None
    allow_unverified_claims_for_archive: bool = False
    release_max_age: timedelta | None = None
    require_verified_signature: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "archive_anchor",
            _coerce_archive_anchor(cast(Any, self.archive_anchor)),
        )
        object.__setattr__(self, "validity", _coerce_interval(self.validity))
        object.__setattr__(
            self, "archive_window", _coerce_interval(self.archive_window)
        )
        object.__setattr__(
            self, "release_window", _coerce_interval(self.release_window)
        )
        object.__setattr__(self, "revocations", tuple(self.revocations or ()))
        raw_max_age = cast(Any, self.release_max_age)
        if raw_max_age is not None and not isinstance(raw_max_age, timedelta):
            object.__setattr__(
                self,
                "release_max_age",
                timedelta(seconds=float(raw_max_age)),
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the policy for offline handover storage."""
        return {
            "validity": (None if self.validity is None else self.validity.to_dict()),
            "revocations": [notice.to_dict() for notice in self.revocations],
            "archive_anchor": self.archive_anchor.value,
            "archive_window": (
                None if self.archive_window is None else self.archive_window.to_dict()
            ),
            "release_window": (
                None if self.release_window is None else self.release_window.to_dict()
            ),
            "allow_unverified_claims_for_archive": (
                self.allow_unverified_claims_for_archive
            ),
            "release_max_age_seconds": (
                None
                if self.release_max_age is None
                else cast(timedelta, self.release_max_age).total_seconds()
            ),
            "require_verified_signature": self.require_verified_signature,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SignaturePolicy:
        """Deserialize a policy produced by :meth:`to_dict`."""
        validity = data.get("validity")
        archive_window = data.get("archive_window")
        release_window = data.get("release_window")
        release_max_age = data.get("release_max_age_seconds")
        return cls(
            validity=(None if validity is None else TimeInterval.from_dict(validity)),
            revocations=tuple(
                Revocation.from_dict(notice)
                for notice in (data.get("revocations") or ())
            ),
            archive_anchor=cast(
                Any,
                data.get("archive_anchor") or ArchiveAnchor.ATTESTED_OR_RECEIPT,
            ),
            archive_window=(
                None
                if archive_window is None
                else TimeInterval.from_dict(archive_window)
            ),
            release_window=(
                None
                if release_window is None
                else TimeInterval.from_dict(release_window)
            ),
            allow_unverified_claims_for_archive=bool(
                data.get("allow_unverified_claims_for_archive", False)
            ),
            release_max_age=(
                None
                if release_max_age is None
                else timedelta(seconds=float(release_max_age))
            ),
            require_verified_signature=bool(
                data.get("require_verified_signature", True)
            ),
        )

    def evaluate(
        self,
        evidence: SignatureEvidence,
        view: EvaluationView,
        uses: str | PolicyUse | Iterable[str | PolicyUse] | None = None,
    ) -> PolicyDecision:
        selected_uses = _coerce_uses(uses)
        decisions = {
            use: self._evaluate_use(evidence, view, use) for use in selected_uses
        }

        attested = view.attested_at or evidence.attested_at
        return PolicyDecision(
            signature_id=cast(str, evidence.signature_id),
            keyid=evidence.key.keyid,
            view_name=view.name,
            view_time=view.trusted_time,
            attested_at=None if attested is None else attested.value,
            uses=decisions,
        )

    def evaluate_at(
        self,
        evidence: SignatureEvidence,
        trusted_time: datetime | int | float | str | TrustedTime,
        *,
        name: str = "evaluation",
        attested_at: TimeLike | None = None,
        uses: str | PolicyUse | Iterable[str | PolicyUse] | None = None,
    ) -> PolicyDecision:
        view = EvaluationView(name, cast(Any, trusted_time), attested_at=attested_at)
        return self.evaluate(evidence, view, uses=uses)

    def allowed_uses(
        self,
        evidence: SignatureEvidence,
        view: EvaluationView,
        uses: str | PolicyUse | Iterable[str | PolicyUse] | None = None,
    ) -> frozenset[PolicyUse]:
        return self.evaluate(evidence, view, uses=uses).allowed_uses

    def is_allowed(
        self,
        evidence: SignatureEvidence,
        view: EvaluationView,
        use: str | PolicyUse = PolicyUse.RELEASE,
    ) -> bool:
        return self.evaluate(evidence, view, uses=use).allows(use)

    def _evaluate_use(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        evidence: SignatureEvidence,
        view: EvaluationView,
        use: PolicyUse,
    ) -> UseDecision:
        checks: list[PolicyCheck] = []
        revocation_checks: list[RevocationCheck] = []
        anchor: datetime | None = None
        anchor_source: str | None = None
        anchor_trusted: bool | None = None

        def finish(allowed: bool, code: str, detail: str) -> UseDecision:
            checks.append(PolicyCheck("decision", allowed, code, detail))
            return UseDecision(
                use=use,
                allowed=allowed,
                anchor=anchor,
                anchor_source=anchor_source,
                anchor_trusted=anchor_trusted,
                checks=tuple(checks),
                revocations=tuple(revocation_checks),
            )

        if self.require_verified_signature and not evidence.verified:
            detail = "securesystemslib did not report a successful verification"
            if evidence.verification_detail:
                detail = f"{detail}: {evidence.verification_detail}"
            checks.append(
                PolicyCheck(
                    "verification",
                    False,
                    "signature_not_verified",
                    detail,
                )
            )
            return finish(False, "signature_not_verified", detail)

        checks.append(
            PolicyCheck(
                "verification",
                True,
                "signature_verified",
                f"{evidence.verification_source} reported a valid signature",
            )
        )

        if use is PolicyUse.ARCHIVE:
            anchor, anchor_source, anchor_trusted = self._archive_anchor(
                evidence,
                view,
                checks,
            )
            if anchor is None:
                detail = self._archive_anchor_failure(evidence)
                checks.append(
                    PolicyCheck(
                        "time",
                        False,
                        "no_trusted_attested_time",
                        detail,
                    )
                )
                return finish(False, "no_trusted_attested_time", detail)
        else:
            anchor = view.trusted_time
            anchor_source = f"view:{view.name}"
            anchor_trusted = True
            checks.append(
                PolicyCheck(
                    "time",
                    True,
                    "evaluation_time",
                    (
                        f"release is anchored at caller trusted view time "
                        f"{_isoformat(anchor)}"
                    ),
                )
            )
            self._record_ignored_claims(evidence, checks, used_claim=None)

        if self.validity is not None:
            if not self.validity.contains(cast(datetime, anchor)):
                detail = (
                    f"anchor {_isoformat(anchor)} is outside validity interval "
                    f"{self.validity.describe()}"
                )
                checks.append(
                    PolicyCheck(
                        "validity",
                        False,
                        "outside_validity_interval",
                        detail,
                    )
                )
                return finish(False, "outside_validity_interval", detail)
            checks.append(
                PolicyCheck(
                    "validity",
                    True,
                    "within_validity_interval",
                    (
                        f"anchor {_isoformat(anchor)} is inside validity interval "
                        f"{self.validity.describe()}"
                    ),
                )
            )

        window = (
            self.archive_window if use is PolicyUse.ARCHIVE else self.release_window
        )
        if window is not None:
            if not window.contains(cast(datetime, anchor)):
                code = (
                    "outside_archive_window"
                    if use is PolicyUse.ARCHIVE
                    else "outside_release_window"
                )
                detail = (
                    f"anchor {_isoformat(anchor)} is outside "
                    f"{use.value} window {window.describe()}"
                )
                checks.append(PolicyCheck("window", False, code, detail))
                return finish(False, code, detail)
            checks.append(
                PolicyCheck(
                    "window",
                    True,
                    f"within_{use.value}_window",
                    (
                        f"anchor {_isoformat(anchor)} is inside "
                        f"{use.value} window {window.describe()}"
                    ),
                )
            )

        if use is PolicyUse.RELEASE and self.release_max_age is not None:
            trusted_attested = self._trusted_attested_claim(evidence, view)
            if trusted_attested is None:
                detail = "release_max_age requires a caller trusted attested time"
                checks.append(
                    PolicyCheck(
                        "freshness",
                        False,
                        "no_trusted_attested_time_for_freshness",
                        detail,
                    )
                )
                return finish(
                    False,
                    "no_trusted_attested_time_for_freshness",
                    detail,
                )
            attested_time = cast(datetime, trusted_attested.value)
            if attested_time > view.trusted_time:
                detail = (
                    f"attested time {_isoformat(attested_time)} is after view time "
                    f"{_isoformat(view.trusted_time)}"
                )
                checks.append(
                    PolicyCheck(
                        "freshness",
                        False,
                        "attestation_after_view",
                        detail,
                    )
                )
                return finish(False, "attestation_after_view", detail)

            age = view.trusted_time - attested_time
            if age > self.release_max_age:
                detail = (
                    f"signature age {age} exceeds release_max_age "
                    f"{self.release_max_age}"
                )
                checks.append(
                    PolicyCheck(
                        "freshness",
                        False,
                        "stale_signature",
                        detail,
                    )
                )
                return finish(False, "stale_signature", detail)
            checks.append(
                PolicyCheck(
                    "freshness",
                    True,
                    "fresh_signature",
                    (
                        f"signature age {age} is within release_max_age "
                        f"{self.release_max_age}"
                    ),
                )
            )

        related = [
            notice
            for notice in self.revocations
            if notice.matches(evidence) and notice.is_about(use)
        ]
        for notice in related:
            if not notice.visible_at(view.trusted_time):
                revocation_checks.append(
                    RevocationCheck(
                        notice,
                        "not_yet_known",
                        False,
                        (
                            f"notice {notice.notice_id} known at "
                            f"{_isoformat(cast(datetime, notice.known_at))} is not "
                            f"visible in view {view.name} at "
                            f"{_isoformat(view.trusted_time)}"
                        ),
                    )
                )
                continue

            if not notice.effective_at_or_before(cast(datetime, anchor)):
                status = (
                    "effective_after_anchor"
                    if use is PolicyUse.ARCHIVE
                    else "not_yet_effective"
                )
                revocation_checks.append(
                    RevocationCheck(
                        notice,
                        status,
                        False,
                        (
                            f"notice {notice.notice_id} is visible but effective "
                            f"at {_isoformat(notice.effective_at)}, after "
                            f"{use.value} anchor {_isoformat(anchor)}"
                        ),
                    )
                )
                continue

            revocation_checks.append(
                RevocationCheck(
                    notice,
                    "applied",
                    True,
                    (
                        f"notice {notice.notice_id} is visible and effective at "
                        f"{_isoformat(notice.effective_at)}, at or before "
                        f"{use.value} anchor {_isoformat(anchor)}"
                    ),
                )
            )

        applied = [check for check in revocation_checks if check.applied]
        if applied:
            detail = "; ".join(check.detail for check in applied)
            checks.append(
                PolicyCheck(
                    "revocation",
                    False,
                    "revoked",
                    detail,
                )
            )
            return finish(False, "revoked", detail)

        ignored = len(revocation_checks) - len(applied)
        detail = (
            f"no revocation is effective at {use.value} anchor {_isoformat(anchor)}"
        )
        if ignored:
            detail = f"{detail}; {ignored} matching notice(s) ignored in this view"
        checks.append(
            PolicyCheck(
                "revocation",
                True,
                "no_active_revocation",
                detail,
            )
        )

        if anchor_trusted is False:
            code = "allowed_with_unverified_time"
            detail = (
                f"{use.value} allowed using unverified time "
                f"{_isoformat(anchor)} from "
                f"{anchor_source or 'unverified declaration'}"
            )
            return finish(True, code, detail)

        code = "allowed"
        detail = (
            f"{use.value} allowed at {_isoformat(anchor)} "
            f"using {anchor_source or 'trusted time'}"
        )
        return finish(True, code, detail)

    def _archive_anchor(
        self,
        evidence: SignatureEvidence,
        view: EvaluationView,
        checks: list[PolicyCheck],
    ) -> tuple[datetime | None, str | None, bool | None]:
        if self.archive_anchor is ArchiveAnchor.RECEIPT:
            checks.append(
                PolicyCheck(
                    "time",
                    True,
                    "trusted_receipt_time",
                    (
                        "archive is anchored at caller trusted receipt time "
                        f"{_isoformat(view.trusted_time)}"
                    ),
                )
            )
            self._record_ignored_claims(evidence, checks, used_claim=None)
            return view.trusted_time, f"view:{view.name}", True

        claim = self._trusted_attested_claim(evidence, view)
        if claim is not None:
            checks.append(
                PolicyCheck(
                    "time",
                    True,
                    "trusted_attested_time",
                    (
                        f"archive is anchored at caller trusted attested time "
                        f"{_isoformat(claim.value)} from "
                        f"{claim.source or 'caller'}"
                    ),
                )
            )
            self._record_ignored_claims(evidence, checks, used_claim=claim)
            return (
                claim.value,
                claim.source or claim.declaration or "attested",
                True,
            )

        if self.archive_anchor is ArchiveAnchor.ATTESTED:
            if self.allow_unverified_claims_for_archive:
                unverified = self._unverified_claim(evidence)
                if unverified is not None:
                    checks.append(
                        PolicyCheck(
                            "time",
                            True,
                            "unverified_time_used",
                            (
                                f"archive is anchored at unverified time "
                                f"{_isoformat(unverified.value)} from "
                                f"{unverified.source or 'signature'} because "
                                "allow_unverified_claims_for_archive is enabled"
                            ),
                            warning=True,
                        )
                    )
                    return (
                        unverified.value,
                        unverified.source or unverified.declaration,
                        False,
                    )
            self._record_ignored_claims(evidence, checks, used_claim=None)
            return None, None, None

        # ATTESTED_OR_RECEIPT: a trusted receipt is a safe fallback.
        if self.allow_unverified_claims_for_archive:
            unverified = self._unverified_claim(evidence)
            if unverified is not None:
                checks.append(
                    PolicyCheck(
                        "time",
                        True,
                        "unverified_time_used",
                        (
                            f"archive is anchored at unverified time "
                            f"{_isoformat(unverified.value)} from "
                            f"{unverified.source or 'signature'} because "
                            "allow_unverified_claims_for_archive is enabled"
                        ),
                        warning=True,
                    )
                )
                return (
                    unverified.value,
                    unverified.source or unverified.declaration,
                    False,
                )

        checks.append(
            PolicyCheck(
                "time",
                True,
                "trusted_receipt_time",
                (
                    "no trusted attestation is available; archive is anchored "
                    f"at caller trusted receipt time "
                    f"{_isoformat(view.trusted_time)}"
                ),
            )
        )
        self._record_ignored_claims(evidence, checks, used_claim=None)
        return view.trusted_time, f"view:{view.name}", True

    @staticmethod
    def _trusted_attested_claim(
        evidence: SignatureEvidence,
        view: EvaluationView,
    ) -> TimeClaim | None:
        for claim in (view.attested_at, evidence.attested_at):
            if claim is not None and claim.is_trusted:
                return claim
        return None

    @staticmethod
    def _unverified_claim(evidence: SignatureEvidence) -> TimeClaim | None:
        for claim in (
            evidence.claimed_signed_at,
            *evidence.unverified_time_claims.values(),
        ):
            if claim is not None and claim.value is not None and not claim.trusted:
                return claim
        return None

    @staticmethod
    def _record_ignored_claims(
        evidence: SignatureEvidence,
        checks: list[PolicyCheck],
        used_claim: TimeClaim | None,
    ) -> None:
        claims = dict(evidence.unverified_time_claims)
        if (
            evidence.claimed_signed_at is not None
            and evidence.claimed_signed_at.declaration not in claims
        ):
            claims[evidence.claimed_signed_at.declaration or "claimed_signed_at"] = (
                evidence.claimed_signed_at
            )

        for name, claim in sorted(claims.items()):
            if claim is used_claim:
                continue
            checks.append(
                PolicyCheck(
                    "time",
                    True,
                    "unverified_time_claim_ignored",
                    (
                        f"unverified {name} declaration "
                        f"{_isoformat(claim.value)} was retained for audit but "
                        "not used as trusted evidence"
                    ),
                    warning=True,
                )
            )

    @staticmethod
    def _archive_anchor_failure(evidence: SignatureEvidence) -> str:
        untrusted = SignaturePolicy._unverified_claim(evidence)
        if untrusted is not None:
            return (
                "no caller trusted attested time is available; the signature "
                f"only declares {untrusted.declaration or 'a time'} at "
                f"{_isoformat(untrusted.value)}, and "
                "allow_unverified_claims_for_archive is disabled"
            )
        return (
            "no caller trusted attested time is available and the policy "
            "requires an attested archive anchor"
        )


def evaluate_signature_policy(
    evidence: SignatureEvidence,
    policy: SignaturePolicy,
    view: EvaluationView,
    uses: str | PolicyUse | Iterable[str | PolicyUse] | None = None,
) -> PolicyDecision:
    """Evaluate ``policy`` for one verified signature in one receipt view."""
    return policy.evaluate(evidence, view, uses=uses)


def replay_receipts(
    evidence: SignatureEvidence,
    policy: SignaturePolicy,
    receipts: Sequence[EvaluationView],
) -> ReplayReport:
    """Replay the same evidence at several caller-trusted receipt views."""
    if not receipts:
        raise ValueError("at least one receipt view is required")
    decisions = tuple(policy.evaluate(evidence, receipt) for receipt in receipts)
    return ReplayReport(evidence=evidence, policy=policy, decisions=decisions)


replay_views = replay_receipts
replay = replay_receipts
evaluate = evaluate_signature_policy


def verify_and_evaluate(  # noqa: PLR0913
    key: Key,
    signature: Signature,
    payload: bytes,
    policy: SignaturePolicy,
    view: EvaluationView | datetime | int | float | str | TrustedTime,
    *,
    uses: str | PolicyUse | Iterable[str | PolicyUse] | None = None,
    artifact_id: str | None = None,
    signature_id: str | None = None,
    attested_at: TimeLike | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> PolicyDecision:
    """Verify with securesystemslib, then apply the time-aware policy."""
    evidence = SignatureEvidence.verify(
        key,
        signature,
        payload,
        artifact_id=artifact_id,
        signature_id=signature_id,
        attested_at=attested_at,
        metadata=metadata,
    )
    if not isinstance(view, EvaluationView):
        view = EvaluationView("evaluation", cast(Any, view))
    return policy.evaluate(evidence, view, uses=uses)
