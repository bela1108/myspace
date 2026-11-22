"""
Delivery contract checks for XML that has already passed signature verification.

SignXML establishes that a signature is cryptographically valid. It does not establish that the
object inside the signature is the object a particular receiver expects, that every field the
receiver relies on has a known owner, or that fields which must be delivered together were signed
together. This module adds that second step without changing the result of
:meth:`signxml.XMLVerifier.verify`.

The check is receiver-specific. A failure for one receiver is reported in that receiver's
:class:`DeliveryDecision` and does not prevent other receivers from being accepted.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cryptography import x509
from lxml import etree

from .exceptions import InvalidInput
from .processor import XMLSignatureProcessor
from .util import namespaces as _ds_namespaces
from .verifier import VerifyResult


class DeliveryStatus(str, Enum):
    """
    The delivery decision for one receiver.

    ``DELIVER`` means every field the receiver declared can be explained from the verified object.
    ``REFUSE`` means the receiver must not receive the data automatically. ``MANUAL_REVIEW`` means
    the data should go to a manual reconciliation queue before delivery.
    """

    DELIVER = "deliver"
    ACCEPT = "deliver"
    ACCEPTED = "deliver"
    PASS = "deliver"
    DELIVERABLE = "deliver"
    REFUSE = "refuse"
    REJECT = "refuse"
    REJECTED = "refuse"
    REFUSED = "refuse"
    DENY = "refuse"
    MANUAL_REVIEW = "manual_review"
    REVIEW = "manual_review"
    NEEDS_REVIEW = "manual_review"
    MANUAL = "manual_review"
    REVIEW_REQUIRED = "manual_review"
    BLOCKED = "refuse"
    DENIED = "refuse"

    def __str__(self) -> str:
        return self.value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return _normalize_delivery_status(other) is self
        return str.__eq__(self, other)

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash(self.value)


class FieldStatus(str, Enum):
    """
    The explanation status of one field declared by a receiver.
    """

    DELIVERED = "delivered"
    OK = "delivered"
    RESOLVED = "delivered"
    MISSING = "missing"
    NOT_FOUND = "missing"
    AMBIGUOUS = "ambiguous"
    UNKNOWN_OWNER = "unknown_owner"
    OWNER_MISMATCH = "owner_mismatch"
    OWNERSHIP_MISMATCH = "owner_mismatch"
    UNKNOWN_IDENTITY = "unknown_identity"
    CONTEXT_MISSING = "context_missing"
    VALUE_MISMATCH = "value_mismatch"
    UNPARSEABLE = "unparseable"

    def __str__(self) -> str:
        return self.value


_STATUS_SYNONYMS = {
    "deliver": DeliveryStatus.DELIVER,
    "delivered": DeliveryStatus.DELIVER,
    "accept": DeliveryStatus.DELIVER,
    "accepted": DeliveryStatus.DELIVER,
    "pass": DeliveryStatus.DELIVER,
    "ok": DeliveryStatus.DELIVER,
    "deliverable": DeliveryStatus.DELIVER,
    "refuse": DeliveryStatus.REFUSE,
    "refused": DeliveryStatus.REFUSE,
    "reject": DeliveryStatus.REFUSE,
    "rejected": DeliveryStatus.REFUSE,
    "deny": DeliveryStatus.REFUSE,
    "denied": DeliveryStatus.REFUSE,
    "manual_review": DeliveryStatus.MANUAL_REVIEW,
    "manual": DeliveryStatus.MANUAL_REVIEW,
    "review": DeliveryStatus.MANUAL_REVIEW,
    "needs_review": DeliveryStatus.MANUAL_REVIEW,
    "needs_manual_review": DeliveryStatus.MANUAL_REVIEW,
}


def _normalize_delivery_status(value: Any) -> DeliveryStatus | None:
    if isinstance(value, DeliveryStatus):
        return value
    text = re.sub(r"[\s-]+", "_", str(value).strip().lower())
    return _STATUS_SYNONYMS.get(text)


_UNSET = object()


@dataclass(frozen=True)
class FieldSpec:
    """
    One field a receiver depends on.

    ``path`` is an XPath expression evaluated against the signed XML returned by SignXML. If the
    path cannot be evaluated directly (for example because the document uses a default namespace),
    a local-name fallback is attempted for simple element paths.
    """

    path: str
    required: bool = True
    owner: str | Sequence[str] | None = None
    expected: Any = _UNSET
    namespaces: Mapping[str, str] | None = None
    description: str | None = None
    type: Any = None
    parser: Any = None

    @property
    def name(self) -> str:
        """
        The field path used as the field identifier.
        """

        return self.path

    @property
    def xpath(self) -> str:
        """
        The XPath expression used to resolve the field.
        """

        return self.path


class Field(FieldSpec):
    """
    A field declaration with convenient aliases for the field path.

    path, name, and field are interchangeable. All other arguments have the same
    meaning as in FieldSpec.
    """

    def __init__(
        self,
        path: str | None = None,
        required: bool = True,
        owner: str | Sequence[str] | None = None,
        expected: Any = _UNSET,
        namespaces: Mapping[str, str] | None = None,
        description: str | None = None,
        type: Any = None,
        parser: Any = None,
        *,
        name: str | None = None,
        field: str | None = None,
        **kwargs: Any,
    ) -> None:
        field_path = path or name or field or kwargs.pop("field_path", None) or kwargs.pop("xpath", None)
        if field_path is None:
            raise InvalidInput("Field requires a path or name")
        super().__init__(
            path=str(field_path),
            required=required,
            owner=owner,
            expected=expected,
            namespaces=namespaces,
            description=description,
            type=type,
            parser=parser,
        )


FieldDeclaration = Field


@dataclass(frozen=True)
class FieldOwnership:
    """
    Ownership declaration for a field.

    ``owner`` is the identity that is allowed to define or sign the field. ``context`` optionally
    scopes the declaration to one contract context. ``required`` overrides the receiver's field
    requirement when set.
    """

    owner: str | Sequence[str] | None = None
    context: str | None = None
    required: bool | None = None
    namespaces: Mapping[str, str] | None = None

    @property
    def identity(self) -> str | Sequence[str] | None:
        """
        Alias for :attr:`owner`.
        """

        return self.owner


class Recipient:
    """
    A receiver's declaration of the fields it supports and the context in which it supports them.

    ``context`` can be a contract version name, a mapping containing ``version`` and optional
    ``field_paths``/``namespaces`` values, or any application-specific value. When a contract has
    multiple versions, the context selects the version used to explain the receiver's fields.
    """

    def __init__(
        self,
        name: str | None = None,
        supported_fields: Any = None,
        context: Any = None,
        *,
        fields: Any = None,
        required_fields: Iterable[str] | None = None,
        must_sign_together: Any = None,
        cosign_requirements: Any = None,
        on_unexplained: str | None = None,
        id: str | None = None,
        **kwargs: Any,
    ) -> None:
        if name is None:
            name = (
                id
                or kwargs.pop("recipient", None)
                or kwargs.pop("receiver", None)
                or kwargs.pop("recipient_id", None)
                or kwargs.pop("receiver_id", None)
            )
        if name is None:
            raise InvalidInput("Recipient requires a name")
        if fields is not None:
            if supported_fields is not None:
                raise InvalidInput("Specify either supported_fields or fields, not both")
            supported_fields = fields
        if supported_fields is None:
            supported_fields = (
                kwargs.pop("supported", None) or kwargs.pop("supports", None) or kwargs.pop("field_names", None) or ()
            )
        if context is None:
            context = kwargs.pop("contract_version", None) or kwargs.pop("version", None)
        requirements = (
            must_sign_together
            or cosign_requirements
            or kwargs.pop("co_sign", None)
            or kwargs.pop("cosign", None)
            or kwargs.pop("co_sign_requirements", None)
            or ()
        )
        self.name = str(name)
        self.fields = _normalize_supported_fields(supported_fields, required_fields)
        self.context = context
        self.must_sign_together = tuple(_normalize_cosign_requirements(requirements))
        self.on_unexplained = on_unexplained or kwargs.pop("unexplained_policy", None)
        self.metadata = dict(kwargs)

    @property
    def supported_fields(self) -> dict[str, FieldSpec]:
        """
        The fields declared by the receiver, keyed by path.
        """

        return self.fields

    @property
    def required(self) -> tuple[str, ...]:
        """
        Paths of fields the receiver marked as required.
        """

        return tuple(path for path, spec in self.fields.items() if spec.required)

    @property
    def cosign_requirements(self) -> tuple[frozenset[str], ...]:
        """
        Field groups that must be signed together for this receiver.
        """

        return self.must_sign_together

    def __repr__(self) -> str:
        return f"Recipient(name={self.name!r}, fields={tuple(self.fields)!r}, context={self.context!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Recipient):
            return NotImplemented
        return (
            self.name == other.name
            and self.fields == other.fields
            and self.context == other.context
            and self.must_sign_together == other.must_sign_together
        )

    def __hash__(self) -> int:
        return hash((self.name, self.context))


RecipientDeclaration = Recipient
Receiver = Recipient


@dataclass(frozen=True)
class ReviewTicket:
    """
    A manual reconciliation item for one receiver.
    """

    recipient: str
    fields: tuple[str, ...]
    reasons: tuple[str, ...]
    context: Any = None
    object_identity: str | Sequence[str] | None = None
    action: str = "manual_review"

    def to_dict(self) -> dict[str, Any]:
        """
        Return the ticket as a JSON-friendly dictionary.
        """

        return {
            "recipient": self.recipient,
            "status": "manual_review",
            "type": "manual_review",
            "fields": list(self.fields),
            "reasons": list(self.reasons),
            "context": self.context,
            "object_identity": list(self.object_identity)
            if isinstance(self.object_identity, (list, tuple))
            else self.object_identity,
            "action": self.action,
        }


@dataclass(frozen=True)
class DeliveryDecision:
    """
    The independent delivery decision for one receiver.
    """

    recipient: str
    status: DeliveryStatus
    delivered_fields: tuple[str, ...] = ()
    refused_fields: tuple[str, ...] = ()
    review_fields: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    context: Any = None
    object_identity: str | Sequence[str] | None = None
    field_results: tuple[dict[str, Any], ...] = ()
    review_ticket: ReviewTicket | None = None

    @property
    def name(self) -> str:
        """
        Alias for :attr:`recipient`.
        """

        return self.recipient

    @property
    def accepted(self) -> bool:
        """
        Whether the receiver can receive its declared fields.
        """

        return self.status == DeliveryStatus.DELIVER

    @property
    def deliverable(self) -> bool:
        """
        Alias for :attr:`accepted`.
        """

        return self.accepted

    @property
    def refused(self) -> bool:
        """
        Whether delivery is refused.
        """

        return self.status == DeliveryStatus.REFUSE

    @property
    def needs_review(self) -> bool:
        """
        Whether the decision requires manual review.
        """

        return self.status == DeliveryStatus.MANUAL_REVIEW

    @property
    def fields(self) -> tuple[str, ...]:
        """
        Fields delivered to the receiver.
        """

        return self.delivered_fields

    @property
    def delivered(self) -> tuple[str, ...]:
        """
        Alias for delivered_fields.
        """

        return self.delivered_fields

    @property
    def manual_review(self) -> bool:
        """
        Alias for needs_review.
        """

        return self.needs_review

    @property
    def reason(self) -> str:
        """
        All decision reasons joined into one string.
        """

        return "; ".join(self.reasons)

    @property
    def manual_review_sheet(self) -> dict[str, Any] | None:
        """
        The manual reconciliation sheet for this receiver, if one was produced.
        """

        return None if self.review_ticket is None else self.review_ticket.to_dict()

    def to_dict(self) -> dict[str, Any]:
        """
        Return the decision as a JSON-friendly dictionary.
        """

        return {
            "recipient": self.recipient,
            "status": self.status.value,
            "delivered_fields": list(self.delivered_fields),
            "refused_fields": list(self.refused_fields),
            "review_fields": list(self.review_fields),
            "reasons": list(self.reasons),
            "context": self.context,
            "object_identity": list(self.object_identity)
            if isinstance(self.object_identity, (list, tuple))
            else self.object_identity,
            "field_results": list(self.field_results),
            "manual_review_sheet": self.manual_review_sheet,
        }


DeliveryCheckResult = DeliveryDecision
DeliveryResult = DeliveryDecision


@dataclass(frozen=True)
class DeliveryReport:
    """
    The delivery decisions for all receivers in a contract check.
    """

    decisions: tuple[DeliveryDecision, ...]
    object_identity: str | Sequence[str] | None = None
    contract_version: str | None = None

    def __iter__(self):
        return iter(self.decisions)

    def __len__(self) -> int:
        return len(self.decisions)

    def __contains__(self, key: object) -> bool:
        return any(decision.recipient == key for decision in self.decisions)

    def __getitem__(self, key: int | str) -> DeliveryDecision:
        if isinstance(key, str):
            for decision in self.decisions:
                if decision.recipient == key:
                    return decision
            raise KeyError(key)
        return self.decisions[key]

    def keys(self) -> tuple[str, ...]:
        """
        Recipient names in report order.
        """

        return tuple(decision.recipient for decision in self.decisions)

    def values(self) -> tuple[DeliveryDecision, ...]:
        """
        Decisions in report order.
        """

        return self.decisions

    def items(self) -> tuple[tuple[str, DeliveryDecision], ...]:
        """
        Recipient names paired with their decisions.
        """

        return tuple((decision.recipient, decision) for decision in self.decisions)

    def get(self, key: str, default: Any = None) -> DeliveryDecision | Any:
        """
        Return the decision for a recipient name, or ``default``.
        """

        try:
            return self[key]
        except KeyError:
            return default

    @property
    def status(self) -> DeliveryStatus:
        """
        The aggregate status: refused if any receiver is refused, otherwise review if any receiver
        needs review, otherwise delivered.
        """

        statuses = {decision.status for decision in self.decisions}
        if DeliveryStatus.REFUSE in statuses:
            return DeliveryStatus.REFUSE
        if DeliveryStatus.MANUAL_REVIEW in statuses:
            return DeliveryStatus.MANUAL_REVIEW
        return DeliveryStatus.DELIVER

    @property
    def accepted(self) -> tuple[str, ...]:
        """
        Names of receivers whose delivery was accepted.
        """

        return tuple(decision.recipient for decision in self.decisions if decision.accepted)

    @property
    def delivered(self) -> tuple[str, ...]:
        """
        Alias for :attr:`accepted`.
        """

        return self.accepted

    @property
    def refused(self) -> tuple[str, ...]:
        """
        Names of receivers whose delivery was refused.
        """

        return tuple(decision.recipient for decision in self.decisions if decision.refused)

    @property
    def needs_review(self) -> tuple[str, ...]:
        """
        Names of receivers whose delivery needs manual review.
        """

        return tuple(decision.recipient for decision in self.decisions if decision.needs_review)

    @property
    def manual_review_sheet(self) -> tuple[dict[str, Any], ...]:
        """
        All manual reconciliation sheets produced by the check.
        """

        return tuple(
            decision.manual_review_sheet for decision in self.decisions if decision.manual_review_sheet is not None
        )

    @property
    def by_recipient(self) -> dict[str, DeliveryDecision]:
        """
        Decisions keyed by receiver name.
        """

        return {decision.recipient: decision for decision in self.decisions}

    @property
    def recipients(self) -> dict[str, DeliveryDecision]:
        """
        Alias for by_recipient.
        """

        return self.by_recipient

    @property
    def overall_status(self) -> DeliveryStatus:
        """
        Alias for status.
        """

        return self.status

    def status_for(self, recipient: str) -> DeliveryStatus | None:
        """
        Return the status for one receiver, or None.
        """

        decision = self.decision_for(recipient)
        return None if decision is None else decision.status

    @property
    def statuses(self) -> dict[str, DeliveryStatus]:
        """
        Statuses keyed by receiver name.
        """

        return {decision.recipient: decision.status for decision in self.decisions}

    @property
    def results(self) -> tuple[DeliveryDecision, ...]:
        """
        Alias for decisions.
        """

        return self.decisions

    @property
    def review_sheet(self) -> tuple[dict[str, Any], ...]:
        """
        Alias for manual_review_sheet.
        """

        return self.manual_review_sheet

    def decision_for(self, recipient: str) -> DeliveryDecision | None:
        """
        Return the decision for one receiver, or None.
        """

        return self.by_recipient.get(recipient)

    @property
    def manual_review_tickets(self) -> tuple[ReviewTicket, ...]:
        """
        All manual reconciliation tickets produced by the check.
        """

        return tuple(decision.review_ticket for decision in self.decisions if decision.review_ticket is not None)

    def to_dict(self) -> dict[str, Any]:
        """
        Return the report as a JSON-friendly dictionary.
        """

        return {
            "status": self.status.value,
            "object_identity": list(self.object_identity)
            if isinstance(self.object_identity, (list, tuple))
            else self.object_identity,
            "contract_version": self.contract_version,
            "recipients": {decision.recipient: decision.to_dict() for decision in self.decisions},
            "manual_review_sheet": list(self.manual_review_sheet),
        }


class AffectedRecipients(set[str]):
    """
    The set of receivers whose declared fields changed ownership.

    The value compares equal to a set, frozenset, list, or tuple containing the same receiver
    names.
    """

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (set, frozenset, list, tuple)):
            return set(self) == set(other)
        return super().__eq__(other)

    __hash__ = None


@dataclass(frozen=True)
class ContractVersion:
    """
    One version of a delivery contract.

    ``field_owners`` maps field paths to the object identity that owns the field. An ownership value
    may be a string, a sequence of acceptable identities, :class:`FieldOwnership`, or a mapping with
    an ``owner``, ``signer``, ``identity``, or ``object`` key.
    """

    version: str | None = None
    field_owners: Mapping[str, Any] = field(default_factory=dict)
    cosign_requirements: tuple[frozenset[str], ...] = ()
    namespaces: Mapping[str, str] = field(default_factory=dict)

    def __init__(
        self,
        version: str | None = None,
        field_owners: Mapping[str, Any] | None = None,
        cosign_requirements: Any = (),
        namespaces: Mapping[str, str] | None = None,
        *,
        ownership: Mapping[str, Any] | None = None,
        must_sign_together: Any = None,
        **kwargs: Any,
    ) -> None:
        if field_owners is None:
            field_owners = ownership or kwargs.pop("fields", None) or kwargs.pop("owners", None) or {}
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "field_owners", dict(field_owners))
        object.__setattr__(
            self,
            "cosign_requirements",
            tuple(_normalize_cosign_requirements(must_sign_together or cosign_requirements or ())),
        )
        object.__setattr__(self, "namespaces", dict(namespaces or {}))

    @property
    def ownership(self) -> Mapping[str, Any]:
        """
        Alias for :attr:`field_owners`.
        """

        return self.field_owners

    def with_field_owner(self, field_path: str, owner: str | Sequence[str] | None) -> ContractVersion:
        """
        Return a copy of this version with one field's owner changed.
        """

        owners = dict(self.field_owners)
        owners[field_path] = owner
        return ContractVersion(
            version=self.version,
            field_owners=owners,
            cosign_requirements=self.cosign_requirements,
            namespaces=self.namespaces,
        )


class DeliveryContract:
    """
    A versioned delivery contract.

    The contract records which object identity owns each field and which fields must be signed
    together. Receivers declare the fields they support; :meth:`check` evaluates each receiver
    independently against the verified object identity.

    A contract can be flat (one ownership map) or versioned (a mapping of version names to
    :class:`ContractVersion` objects). See :meth:`check` for the post-verification entry point.
    """

    def __init__(
        self,
        version: str | ContractVersion | None = None,
        field_owners: Mapping[str, Any] | None = None,
        recipients: Any = None,
        cosign_requirements: Any = (),
        *,
        versions: Mapping[str, Any] | None = None,
        ownership: Mapping[str, Any] | None = None,
        fields: Mapping[str, Any] | None = None,
        must_sign_together: Any = None,
        namespaces: Mapping[str, str] | None = None,
        unexplained_policy: str | None = None,
        **kwargs: Any,
    ) -> None:
        if isinstance(version, ContractVersion):
            contract_version = version
            version = version.version
        else:
            contract_version = None
        if version is None:
            version = kwargs.pop("contract_version", None)
        if versions is None:
            versions = kwargs.pop("contracts", None)
        if recipients is None:
            recipients = kwargs.pop("receiver_declarations", None) or kwargs.pop("recipient_declarations", None)
        if field_owners is None:
            field_owners = (
                ownership or fields or kwargs.pop("field_ownership", None) or kwargs.pop("owners", None) or {}
            )
        requirements = (
            must_sign_together or cosign_requirements or kwargs.pop("co_sign", None) or kwargs.pop("cosign", None) or ()
        )
        self.verified = kwargs.pop("verified", None) or kwargs.pop("verification", None) or kwargs.pop("result", None)
        self.object_identity = kwargs.pop("object_identity", None) or kwargs.pop("identity", None)
        self.version = version
        self.namespaces = dict(namespaces or {})
        self.unexplained_policy = unexplained_policy
        self.recipients = _normalize_recipients(recipients)
        self.cosign_requirements = tuple(_normalize_cosign_requirements(requirements))
        self.metadata = dict(kwargs)

        normalized_versions: dict[str, ContractVersion] = {}
        if versions is not None:
            for name, value in versions.items():
                normalized_versions[str(name)] = _coerce_contract_version(str(name), value)
        if contract_version is not None:
            name = str(contract_version.version or version or "default")
            normalized_versions[name] = contract_version
        self.versions = normalized_versions

        if not self.versions:
            self.field_owners = dict(field_owners)
        elif version is not None and version in self.versions:
            self.field_owners = dict(self.versions[version].field_owners)
        elif len(self.versions) == 1:
            self.field_owners = dict(next(iter(self.versions.values())).field_owners)
        elif version is None:
            self.field_owners = dict(next(iter(self.versions.values())).field_owners)
        else:
            self.field_owners = {}

        if not self.versions:
            self.versions = {
                str(version or "default"): ContractVersion(
                    version=str(version or "default"),
                    field_owners=self.field_owners,
                    cosign_requirements=self.cosign_requirements,
                    namespaces=self.namespaces,
                )
            }
        self.version = version or next(iter(self.versions))

    @property
    def ownership(self) -> Mapping[str, Any]:
        """
        The field ownership map of the default version.
        """

        return self.field_owners

    @property
    def fields(self) -> Mapping[str, Any]:
        """
        Alias for :attr:`ownership`.
        """

        return self.field_owners

    def view_for_context(self, context: Any) -> ContractVersion | None:
        """
        Resolve a receiver context to a contract version.

        Return ``None`` if the context names a version that is not present in this contract.
        """

        if isinstance(context, ContractVersion):
            return context
        context_version = _context_version(context)
        if context_version is not None:
            version_name = str(context_version)
            if version_name in self.versions:
                return self.versions[version_name]
            alias = _resolve_version_alias(version_name, self.versions)
            return None if alias is None else self.versions[alias]
        if isinstance(context, str):
            if context in self.versions:
                return self.versions[context]
            alias = _resolve_version_alias(context, self.versions)
            if alias is not None:
                return self.versions[alias]
        if context is not None and isinstance(context, str) and not self._is_flat_context(context):
            return None
        if self.version in self.versions:
            return self.versions[self.version]
        if len(self.versions) == 1:
            return next(iter(self.versions.values()))
        return None

    def _is_flat_context(self, context: str) -> bool:
        if len(self.versions) == 1 and self.version == context:
            return True
        return not _looks_like_version(context)

    def check(
        self,
        verification: VerifyResult | Sequence[VerifyResult] | None = None,
        *args: Any,
        object_identity: str | Sequence[str] | Mapping[str, Any] | None = None,
        identity: str | Sequence[str] | Mapping[str, Any] | None = None,
        recipients: Any = None,
        unexplained_policy: str | None = None,
        verified: VerifyResult | Sequence[VerifyResult] | None = None,
        result: VerifyResult | Sequence[VerifyResult] | None = None,
        verify_result: VerifyResult | Sequence[VerifyResult] | None = None,
        verification_result: VerifyResult | Sequence[VerifyResult] | None = None,
        verified_result: VerifyResult | Sequence[VerifyResult] | None = None,
        verified_identity: str | Sequence[str] | Mapping[str, Any] | None = None,
    ) -> DeliveryReport:
        """
        Check a successful SignXML verification result against this contract.

        :param verification: The result returned by :meth:`signxml.XMLVerifier.verify`, or a
            sequence of results when the signature contains multiple references.
        :param object_identity: The identity that was actually verified. If omitted, it is inferred
            from the signed object's Id attribute, then from the signing certificate subject, then
            from a SHA-256 fingerprint of the verification key. A mapping may be supplied to give
            field-specific identities.
        :param recipients: Optional replacement for the receivers stored in the contract.
        :param unexplained_policy: ``"refuse"`` or ``"manual_review"``. By default, missing or
            misowned required fields are refused, while ambiguous or optional unexplained fields
            produce manual review tickets.
        :raises: :class:`signxml.exceptions.InvalidInput` if the verification input is not a
            successful SignXML result.
        """

        if verification is None:
            verification = (
                verified or result or verify_result or verification_result or verified_result or self.verified
            )
        if object_identity is None:
            object_identity = identity or verified_identity or self.object_identity
        if args:
            first = args[0]
            if object_identity is None and isinstance(first, (str, bytes)):
                object_identity = first
            elif recipients is None:
                recipients = first
            args = args[1:]
        if args and recipients is None:
            recipients = args[0]
        verified_inputs = _coerce_verifications(verification)
        if recipients is None:
            selected_recipients = self.recipients
        else:
            selected_recipients = _normalize_recipients(recipients)
        policy = unexplained_policy or self.unexplained_policy
        decisions = tuple(
            _evaluate_recipient(
                recipient,
                self,
                verified_inputs,
                object_identity=object_identity,
                default_policy=policy,
            )
            for recipient in selected_recipients
        )
        return DeliveryReport(
            decisions=decisions,
            object_identity=object_identity,
            contract_version=self.version,
        )

    def check_delivery(self, verification: VerifyResult | Sequence[VerifyResult], **kwargs: Any) -> DeliveryReport:
        """
        Alias for :meth:`check`.
        """

        return self.check(verification, **kwargs)

    def evaluate(self, verification: VerifyResult | Sequence[VerifyResult], **kwargs: Any) -> DeliveryReport:
        """
        Alias for :meth:`check`.
        """

        return self.check(verification, **kwargs)

    def with_field_owner(
        self,
        field_path: str,
        owner: str | Sequence[str] | None,
        *,
        version: str | None = None,
    ) -> DeliveryContract:
        """
        Return a copy of this contract with one field's owner changed.

        Only receivers that declare the changed field are affected by the new contract version. The
        returned contract can be compared with the original using :meth:`affected_recipients`.
        """

        selected_version = version or self.version
        versions = dict(self.versions)
        current = versions.get(
            selected_version, ContractVersion(version=selected_version, field_owners=self.field_owners)
        )
        versions[selected_version] = current.with_field_owner(field_path, owner)
        return DeliveryContract(
            version=selected_version,
            versions=versions,
            recipients=self.recipients,
            namespaces=self.namespaces,
            unexplained_policy=self.unexplained_policy,
        )

    change_field_owner = with_field_owner

    def update_field_owner(
        self,
        field_path: str,
        owner: str | Sequence[str] | None,
        **kwargs: Any,
    ) -> DeliveryContract:
        """
        Alias for :meth:`with_field_owner`.
        """

        return self.with_field_owner(field_path, owner, **kwargs)

    def changed_field_ownership(
        self,
        other: DeliveryContract,
        *,
        version: str | None = None,
    ) -> dict[str, tuple[Any, Any]]:
        """
        Return fields whose owner differs between this contract and ``other``.

        Each value is a ``(previous_owner, new_owner)`` pair.
        """

        old_owners, new_owners = _ownership_maps(self, other, version=version)
        changed = {}
        for path in sorted(set(old_owners) | set(new_owners)):
            old_owner = _owner_value(old_owners.get(path, _UNSET))
            new_owner = _owner_value(new_owners.get(path, _UNSET))
            if old_owner != new_owner:
                changed[path] = (old_owner, new_owner)
        return changed

    def affected_recipients(
        self,
        other: DeliveryContract,
        *,
        version: str | None = None,
    ) -> AffectedRecipients:
        """
        Return receivers whose declared fields have changed ownership.

        These are the only receivers that need to re-accept or re-sign the delivery contract after
        moving from this contract to ``other``.
        """

        changed_fields = set(self.changed_field_ownership(other, version=version))
        changes_by_version: dict[str, set[str]] = {}
        if version is None and self.versions and other.versions:
            for version_name in set(self.versions).intersection(other.versions):
                changes_by_version[version_name] = set(self.changed_field_ownership(other, version=version_name))
        recipients: dict[str, Recipient] = {recipient.name: recipient for recipient in self.recipients}
        recipients.update({recipient.name: recipient for recipient in other.recipients})
        affected = set()
        for name, recipient in recipients.items():
            field_paths = _context_field_paths(recipient.context)
            declared_paths = {field_paths.get(path, path) for path in recipient.fields}
            recipient_changes = changed_fields
            if changes_by_version:
                contract_version = self.view_for_context(recipient.context) or other.view_for_context(recipient.context)
                if contract_version is not None and contract_version.version in changes_by_version:
                    recipient_changes = changes_by_version[contract_version.version]
            if recipient_changes.intersection(declared_paths):
                affected.add(name)
        return AffectedRecipients(affected)

    def recipients_requiring_resignature(
        self,
        other: DeliveryContract,
        **kwargs: Any,
    ) -> set[str]:
        """
        Alias for :meth:`affected_recipients`.
        """

        return self.affected_recipients(other, **kwargs)

    def requires_resignature(
        self,
        other: DeliveryContract,
        recipient: str | None = None,
        **kwargs: Any,
    ) -> bool | set[str]:
        """
        Whether one receiver must re-accept the contract after an ownership change.

        When recipient is omitted, return the set of all affected receivers.
        """

        affected = self.affected_recipients(other, **kwargs)
        return affected if recipient is None else recipient in affected

    def requires_resignation(
        self,
        other: DeliveryContract,
        recipient: str | None = None,
        **kwargs: Any,
    ) -> bool | set[str]:
        """
        Alias for requires_resignature.
        """

        return self.requires_resignature(other, recipient, **kwargs)

    def to_dict(self) -> dict[str, Any]:
        """
        Return the contract as a JSON-friendly dictionary.
        """

        return {
            "version": self.version,
            "versions": {
                name: {
                    "field_owners": {
                        path: list(owner) if isinstance(owner, (list, tuple, set, frozenset)) else owner
                        for path, owner in version.field_owners.items()
                    },
                    "cosign_requirements": [sorted(group) for group in version.cosign_requirements],
                }
                for name, version in self.versions.items()
            },
            "recipients": [
                {
                    "name": recipient.name,
                    "fields": sorted(recipient.fields),
                    "required_fields": list(recipient.required),
                    "context": recipient.context,
                    "must_sign_together": [sorted(group) for group in recipient.must_sign_together],
                    "on_unexplained": recipient.on_unexplained,
                }
                for recipient in self.recipients
            ],
        }

    verify = check
    audit = check
    reconcile = check
    check_verification = check
    check_contract = check


Contract = DeliveryContract
DeliveryContractChecker = DeliveryContract


def _normalize_supported_fields(
    supported_fields: Any,
    required_fields: Iterable[str] | None = None,
) -> dict[str, FieldSpec]:
    required_paths = set(required_fields or ())
    default_required = required_fields is None
    result: dict[str, FieldSpec] = {}
    if supported_fields is None:
        return result
    if isinstance(supported_fields, (str, bytes)):
        items: Any = [supported_fields]
    elif isinstance(supported_fields, Mapping):
        items = supported_fields.items()
    else:
        items = supported_fields
    for item in items:
        if isinstance(supported_fields, Mapping):
            path, value = item
            spec = _coerce_field_spec(path, value, required_paths, default_required)
        elif isinstance(item, FieldSpec):
            spec = item
            if item.path in required_paths:
                spec = FieldSpec(
                    path=item.path,
                    required=True,
                    owner=item.owner,
                    expected=item.expected,
                    namespaces=item.namespaces,
                    description=item.description,
                    type=item.type,
                    parser=item.parser,
                )
        elif isinstance(item, Mapping):
            path = item.get("path") or item.get("field") or item.get("name")
            if path is None:
                raise InvalidInput("Field mapping requires a path or name")
            spec = _coerce_field_spec(str(path), item, required_paths, default_required)
        elif isinstance(item, (tuple, list)) and len(item) >= 2 and isinstance(item[0], str):
            spec = _coerce_field_spec(item[0], item[1], required_paths, default_required)
        else:
            path = str(item)
            spec = FieldSpec(
                path=path,
                required=path in required_paths if required_fields is not None else True,
            )
        result[spec.path] = spec
    return result


def _coerce_field_spec(
    path: Any,
    value: Any,
    required_paths: set[str],
    default_required: bool,
) -> FieldSpec:
    path = str(path)
    if isinstance(value, FieldSpec):
        if value.path == path:
            return value
        return FieldSpec(
            path=path,
            required=value.required,
            owner=value.owner,
            expected=value.expected,
            namespaces=value.namespaces,
            description=value.description,
            type=value.type,
            parser=value.parser,
        )
    if isinstance(value, Mapping):
        required = value.get("required", path in required_paths if not default_required else True)
        return FieldSpec(
            path=path,
            required=bool(required),
            owner=value.get("owner") or value.get("signer") or value.get("identity"),
            expected=value.get("expected", value.get("value", _UNSET)),
            namespaces=value.get("namespaces"),
            description=value.get("description"),
            type=value.get("type") or value.get("value_type"),
            parser=value.get("parser"),
        )
    if value is None:
        return FieldSpec(path=path, required=path in required_paths if not default_required else True)
    if isinstance(value, bool):
        return FieldSpec(path=path, required=value)
    return FieldSpec(path=path, required=path in required_paths if not default_required else True, expected=value)


def _normalize_cosign_requirements(requirements: Any) -> list[frozenset[str]]:
    if not requirements:
        return []
    if isinstance(requirements, Mapping):
        if "fields" in requirements:
            requirements = [requirements]
        else:
            groups = []
            for key, value in requirements.items():
                if isinstance(value, str):
                    value = [value]
                if isinstance(value, FieldSpec):
                    value = [value.path]
                if isinstance(value, (list, tuple, set, frozenset)):
                    groups.append({key, *value})
            requirements = groups
    elif isinstance(requirements, (str, bytes)) or isinstance(requirements, FieldSpec):
        requirements = [{requirements if isinstance(requirements, str) else requirements.path}]
    elif isinstance(requirements, (list, tuple, set, frozenset)) and all(
        isinstance(item, (str, bytes, FieldSpec)) for item in requirements
    ):
        requirements = [requirements]
    result = []
    for requirement in requirements:
        if isinstance(requirement, Mapping):
            fields = requirement.get("fields") or requirement.get("field_paths") or ()
            if isinstance(fields, str):
                fields = [fields]
            group = frozenset(_field_path(field) for field in fields)
            if group:
                result.append(group)
        elif isinstance(requirement, (set, frozenset, list, tuple)):
            group = frozenset(_field_path(field) for field in requirement)
            if group:
                result.append(group)
        else:
            result.append(frozenset({_field_path(requirement)}))
    return result


def _field_path(value: Any) -> str:
    if isinstance(value, FieldSpec):
        return value.path
    return str(value)


def _coerce_contract_version(name: str, value: Any) -> ContractVersion:
    if isinstance(value, ContractVersion):
        return value
    if isinstance(value, Mapping):
        metadata_keys = {
            "version",
            "field_owners",
            "ownership",
            "fields",
            "owners",
            "cosign_requirements",
            "must_sign_together",
            "namespaces",
        }
        if not metadata_keys.intersection(value):
            return ContractVersion(version=name, field_owners=value)
        version = value.get("version", name)
        owners = value.get("field_owners") or value.get("ownership") or value.get("fields") or value.get("owners") or {}
        requirements = value.get("cosign_requirements") or value.get("must_sign_together") or ()
        return ContractVersion(
            version=version,
            field_owners=owners,
            cosign_requirements=requirements,
            namespaces=value.get("namespaces"),
        )
    raise InvalidInput(f"Invalid contract version definition for {name!r}")


def _normalize_recipients(recipients: Any) -> tuple[Recipient, ...]:
    if recipients is None:
        return ()
    if isinstance(recipients, Recipient):
        return (recipients,)
    if isinstance(recipients, Mapping):
        result = []
        for name, value in recipients.items():
            if isinstance(value, Recipient):
                result.append(value)
            elif isinstance(value, Mapping):
                result.append(Recipient(name=name, **value))
            else:
                result.append(Recipient(name=name, supported_fields=value))
        return tuple(result)
    result = []
    for recipient in recipients:
        if isinstance(recipient, Recipient):
            result.append(recipient)
        elif isinstance(recipient, Mapping):
            result.append(Recipient(**recipient))
        elif isinstance(recipient, (tuple, list)):
            if not recipient:
                raise InvalidInput("Empty recipient declaration")
            name = recipient[0]
            supported = recipient[1] if len(recipient) > 1 else ()
            context = recipient[2] if len(recipient) > 2 else None
            result.append(Recipient(name=name, supported_fields=supported, context=context))
        else:
            result.append(Recipient(name=str(recipient)))
    return tuple(result)


def _context_version(context: Any) -> str | None:
    if isinstance(context, Mapping):
        for key in ("version", "contract_version", "contractVersion", "schema_version", "profile"):
            if key in context:
                return str(context[key])
    return None


def _version_sort_key(value: str) -> tuple[Any, ...]:
    return tuple(int(part) if part.isdigit() else part for part in re.split(r"(\d+)", str(value)))


def _resolve_version_alias(value: str, versions: Mapping[str, Any]) -> str | None:
    if not versions:
        return None
    text = value.strip().lower()
    if text in {"latest", "current", "new", "newest"}:
        return max(versions, key=_version_sort_key)
    if text in {"old", "legacy", "previous", "prior"}:
        return min(versions, key=_version_sort_key)
    return None


def _looks_like_version(value: str) -> bool:
    text = value.strip().lower()
    return bool(re.fullmatch(r"v?\d+(?:[._-]\d+)*", text)) or text in {"latest", "current", "old", "legacy"}


def _context_field_paths(context: Any) -> Mapping[str, str]:
    if not isinstance(context, Mapping):
        return {}
    for key in ("field_paths", "paths", "field_aliases", "fields"):
        value = context.get(key)
        if isinstance(value, Mapping):
            return {str(alias): str(path) for alias, path in value.items()}
    return {}


def _context_namespaces(context: Any) -> Mapping[str, str]:
    if isinstance(context, Mapping):
        for key in ("namespaces", "namespace_map", "ns"):
            value = context.get(key)
            if isinstance(value, Mapping):
                return {str(prefix): str(uri) for prefix, uri in value.items()}
    return {}


def _context_identity(context: Any) -> Any:
    if isinstance(context, Mapping):
        for key in (
            "object_identity",
            "identity",
            "signer",
            "owner",
            "expected_identity",
            "verified_identity",
        ):
            if key in context:
                return context[key]
    return None


@dataclass(frozen=True)
class _VerifiedInput:
    result: VerifyResult
    index: int
    signature_group: str
    identity: str | None


@dataclass(frozen=True)
class _FieldResolution:
    spec: FieldSpec
    path: str
    status: FieldStatus
    reason: str | None
    values: tuple[Any, ...] = ()
    signature_groups: tuple[str, ...] = ()
    owner: Any = None
    identity: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.path,
            "status": self.status.value,
            "reason": self.reason,
            "values": list(self.values),
            "owner": list(self.owner) if isinstance(self.owner, (list, tuple, set, frozenset)) else self.owner,
            "identity": list(self.identity)
            if isinstance(self.identity, (list, tuple, set, frozenset))
            else self.identity,
        }


def _coerce_verifications(verification: Any) -> tuple[_VerifiedInput, ...]:
    if isinstance(verification, Mapping):
        verification = verification.get("verification") or verification.get("result") or verification.get("results")
    if verification is None:
        raise InvalidInput("A successful SignXML VerifyResult is required")
    if isinstance(verification, (list, tuple)):
        results = list(verification)
    else:
        results = [verification]
    if not results:
        raise InvalidInput("At least one SignXML VerifyResult is required")
    verified = []
    for index, result in enumerate(results):
        if not hasattr(result, "signed_xml") or not hasattr(result, "signature_xml"):
            raise InvalidInput("Expected a successful SignXML VerifyResult from XMLVerifier.verify")
        verified.append(
            _VerifiedInput(
                result=result,
                index=index,
                signature_group=_signature_group(result),
                identity=_extract_identity(result),
            )
        )
    return tuple(verified)


def _signature_group(result: VerifyResult) -> str:
    hasher = hashlib.sha256()
    signature_xml = getattr(result, "signature_xml", None)
    if signature_xml is not None:
        hasher.update(etree.tostring(signature_xml))
    signature_key = getattr(result, "signature_key", None)
    if isinstance(signature_key, bytes):
        hasher.update(signature_key)
    return hasher.hexdigest()


def _extract_identity(result: VerifyResult) -> str | None:
    signed_xml = getattr(result, "signed_xml", None)
    if signed_xml is not None and hasattr(signed_xml, "get"):
        for attribute in XMLSignatureProcessor.id_attributes:
            value = signed_xml.get(attribute)
            if value:
                return value
    signature_xml = getattr(result, "signature_xml", None)
    if signature_xml is not None:
        cert_node = signature_xml.find(".//ds:X509Certificate", namespaces=_ds_namespaces)
        if cert_node is not None and cert_node.text:
            try:
                cert = x509.load_der_x509_certificate(_b64decode(cert_node.text))
            except ValueError:
                pass
            else:
                common_names = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                if common_names:
                    return str(common_names[0].value)
                return cert.subject.rfc4514_string()
    signature_key = getattr(result, "signature_key", None)
    if isinstance(signature_key, bytes):
        return "sha256:" + hashlib.sha256(signature_key).hexdigest()
    return None


def _b64decode(value: str) -> bytes:
    from base64 import b64decode

    return b64decode("".join(value.split()))


def _evaluate_recipient(
    recipient: Recipient,
    contract: DeliveryContract,
    verified_inputs: tuple[_VerifiedInput, ...],
    *,
    object_identity: str | Sequence[str] | Mapping[str, Any] | None,
    default_policy: str | None,
) -> DeliveryDecision:
    version = contract.view_for_context(recipient.context)
    context_identity = _context_identity(recipient.context)
    if version is None:
        reason = f"Receiver context {recipient.context!r} is not defined in the delivery contract"
        resolutions = tuple(
            _FieldResolution(
                spec=spec,
                path=spec.path,
                status=FieldStatus.CONTEXT_MISSING,
                reason=reason,
                owner=_declared_owner(contract, recipient, spec),
            )
            for spec in recipient.fields.values()
        )
        return _build_decision(
            recipient,
            resolutions,
            verified_inputs,
            object_identity=object_identity,
            policy=recipient.on_unexplained or default_policy,
            cosign_failures=(),
        )

    field_paths = _context_field_paths(recipient.context)
    namespaces = {
        **_ds_namespaces,
        **contract.namespaces,
        **version.namespaces,
        **(_context_namespaces(recipient.context)),
    }
    resolutions = []
    for spec in recipient.fields.values():
        resolutions.append(
            _evaluate_field(
                spec,
                version,
                verified_inputs,
                object_identity=object_identity,
                context_identity=context_identity,
                field_paths=field_paths,
                namespaces=namespaces,
                recipient_name=recipient.name,
            )
        )

    requirements = tuple(
        dict.fromkeys((*version.cosign_requirements, *contract.cosign_requirements, *recipient.must_sign_together))
    )
    cosign_failures = _evaluate_cosign_requirements(
        requirements,
        recipient,
        version,
        verified_inputs,
        resolutions,
        object_identity=object_identity,
        context_identity=context_identity,
        field_paths=field_paths,
        namespaces=namespaces,
    )
    return _build_decision(
        recipient,
        tuple(resolutions),
        verified_inputs,
        object_identity=object_identity,
        policy=recipient.on_unexplained or default_policy,
        cosign_failures=cosign_failures,
    )


def _evaluate_field(
    spec: FieldSpec,
    version: ContractVersion,
    verified_inputs: tuple[_VerifiedInput, ...],
    *,
    object_identity: str | Sequence[str] | Mapping[str, Any] | None,
    context_identity: Any,
    field_paths: Mapping[str, str],
    namespaces: Mapping[str, str],
    recipient_name: str | None = None,
) -> _FieldResolution:
    path = field_paths.get(spec.path, spec.path)
    owner_present, owner = _lookup_owner(version.field_owners, path, spec.owner)
    identities = _identities_for_field(path, object_identity, context_identity, verified_inputs)

    matches: list[tuple[_VerifiedInput, list[Any]]] = []
    for verified_input in verified_inputs:
        nodes = _resolve_nodes(verified_input.result.signed_xml, path, {**namespaces, **(spec.namespaces or {})})
        if nodes:
            matches.append((verified_input, nodes))

    if not matches:
        return _FieldResolution(
            spec=spec,
            path=path,
            status=FieldStatus.MISSING,
            reason=f"Field {path!r} is not present in the signed object",
            owner=owner,
            identity=identities,
        )

    groups = tuple(dict.fromkeys(verified_input.signature_group for verified_input, _ in matches))
    values = tuple(value for _, nodes in matches for value in (_node_value(node) for node in nodes))
    if len(matches) > 1 or len(values) > 1:
        return _FieldResolution(
            spec=spec,
            path=path,
            status=FieldStatus.AMBIGUOUS,
            reason=f"Field {path!r} resolves to more than one value in the signed object",
            values=values,
            signature_groups=groups,
            owner=owner,
            identity=identities,
        )

    if not owner_present and not _contract_has_ownership(version):
        owner_present, owner = True, None
    if not owner_present:
        return _FieldResolution(
            spec=spec,
            path=path,
            status=FieldStatus.UNKNOWN_OWNER,
            reason=f"Field {path!r} has no ownership declaration in contract version {version.version!r}",
            values=values,
            signature_groups=groups,
            owner=None,
            identity=identities,
        )

    if owner is not None:
        if not identities:
            return _FieldResolution(
                spec=spec,
                path=path,
                status=FieldStatus.UNKNOWN_IDENTITY,
                reason=f"Field {path!r} is owned by {owner!r} but no verified object identity is available",
                values=values,
                signature_groups=groups,
                owner=owner,
                identity=None,
            )
        owner_is_recipient = recipient_name is not None and _owner_matches(owner, (recipient_name,))
        if not _owner_matches(owner, identities) and not owner_is_recipient:
            return _FieldResolution(
                spec=spec,
                path=path,
                status=FieldStatus.OWNER_MISMATCH,
                reason=f"Field {path!r} is owned by {owner!r}, but the verified identity is {identities!r}",
                values=values,
                signature_groups=groups,
                owner=owner,
                identity=identities,
            )

    parser = spec.parser or spec.type
    if parser is not None:
        try:
            parser(values[0])
        except Exception as exc:
            return _FieldResolution(
                spec=spec,
                path=path,
                status=FieldStatus.UNPARSEABLE,
                reason=f"Field {path!r} cannot be interpreted with the declared context: {exc}",
                values=values,
                signature_groups=groups,
                owner=owner,
                identity=identities,
            )

    if spec.expected is not _UNSET and not _value_matches(values[0], spec.expected):
        return _FieldResolution(
            spec=spec,
            path=path,
            status=FieldStatus.VALUE_MISMATCH,
            reason=f"Field {path!r} has value {values[0]!r}, which does not match the expected value",
            values=values,
            signature_groups=groups,
            owner=owner,
            identity=identities,
        )

    return _FieldResolution(
        spec=spec,
        path=path,
        status=FieldStatus.DELIVERED,
        reason=None,
        values=values,
        signature_groups=groups,
        owner=owner,
        identity=identities,
    )


def _lookup_owner(
    owners: Mapping[str, Any],
    path: str,
    declared_owner: str | Sequence[str] | None,
) -> tuple[bool, Any]:
    for candidate in _path_candidates(path):
        if candidate in owners:
            return True, _owner_value(owners[candidate])
    if declared_owner is not None:
        return True, declared_owner
    return False, None


def _declared_owner(contract: DeliveryContract, recipient: Recipient, spec: FieldSpec) -> Any:
    version = contract.view_for_context(recipient.context)
    if version is None:
        return spec.owner
    _, owner = _lookup_owner(version.field_owners, spec.path, spec.owner)
    return owner


def _contract_has_ownership(version: ContractVersion) -> bool:
    return bool(version.field_owners)


def _owner_value(value: Any) -> Any:
    if value is _UNSET:
        return _UNSET
    if isinstance(value, FieldOwnership):
        return value.owner
    if isinstance(value, Mapping):
        for key in ("owner", "signer", "identity", "object", "object_identity", "recipient", "receiver"):
            if key in value:
                return value[key]
        return None
    return value


def _owner_matches(owner: Any, identities: Sequence[str]) -> bool:
    if owner is _UNSET or owner is None:
        return True
    if isinstance(owner, (list, tuple, set, frozenset)):
        return any(_owner_matches(candidate, identities) for candidate in owner)
    owner_text = str(owner)
    return any(identity == owner_text for identity in identities)


def _path_candidates(path: str) -> tuple[str, ...]:
    candidates = [path]
    stripped = path.strip()
    if stripped.startswith("./"):
        stripped = stripped[2:]
    if stripped.startswith("/"):
        stripped = stripped.lstrip("/")
    if stripped != path:
        candidates.append(stripped)
    return tuple(candidates)


def _identities_for_field(
    path: str,
    object_identity: str | Sequence[str] | Mapping[str, Any] | None,
    context_identity: Any,
    verified_inputs: tuple[_VerifiedInput, ...],
) -> tuple[str, ...]:
    values: list[Any] = []
    if object_identity is not None:
        if isinstance(object_identity, Mapping):
            for candidate in (*_path_candidates(path), "*", "default"):
                if candidate in object_identity:
                    value = object_identity[candidate]
                    values.extend(value if isinstance(value, (list, tuple, set, frozenset)) else [value])
        elif isinstance(object_identity, bytes):
            values.append("sha256:" + hashlib.sha256(object_identity).hexdigest())
            try:
                values.append(object_identity.decode())
            except UnicodeDecodeError:
                pass
        elif isinstance(object_identity, (list, tuple, set, frozenset)):
            values.extend(object_identity)
        else:
            values.append(object_identity)
    if context_identity is not None:
        values.extend(
            context_identity if isinstance(context_identity, (list, tuple, set, frozenset)) else [context_identity]
        )
    if not values:
        values.extend(
            verified_input.identity for verified_input in verified_inputs if verified_input.identity is not None
        )
    return tuple(dict.fromkeys(str(value) for value in values))


def _resolve_nodes(root: Any, path: str, namespaces: Mapping[str, str]) -> list[Any]:
    if root is None or not hasattr(root, "xpath"):
        return []
    try:
        result = root.xpath(path, namespaces=namespaces)
    except (etree.XPathError, TypeError, ValueError):
        result = []
    if isinstance(result, list) and result:
        return [node for node in result if isinstance(node, (etree._Element, etree._ElementUnicodeResult))]
    fallback = _local_name_xpath(path)
    if fallback is None:
        return []
    try:
        result = root.xpath(fallback)
    except (etree.XPathError, TypeError, ValueError):
        return []
    return [node for node in result if isinstance(node, (etree._Element, etree._ElementUnicodeResult))]


def _local_name_xpath(path: str) -> str | None:
    path = path.strip()
    if path.endswith("/text()"):
        path = path[: -len("/text()")]
    descendant = path.startswith(".//") or path.startswith("//")
    if descendant:
        path = path.lstrip(".").lstrip("/")
    elif path.startswith("./"):
        path = path[2:]
    elif path.startswith("/"):
        path = path[1:]
    if not path or path.startswith(("(", "@", "{")) or "[" in path or "::" in path:
        return None
    segments = []
    for segment in path.split("/"):
        if not segment:
            return None
        if segment.startswith("@"):
            segments.append(f"@*[local-name()={segment[1:]!r}]")
        elif re.fullmatch(r"[A-Za-z_][\w.-]*", segment):
            segments.append(f"*[local-name()={segment!r}]")
        else:
            return None
    prefix = "//" if descendant else "."
    return prefix + "".join("/" + segment for segment in segments)


def _node_value(node: Any) -> Any:
    if isinstance(node, etree._ElementUnicodeResult):
        return str(node)
    if hasattr(node, "itertext"):
        return "".join(node.itertext()).strip()
    return node


def _value_matches(actual: Any, expected: Any) -> bool:
    if callable(expected):
        return bool(expected(actual))
    if isinstance(expected, re.Pattern):
        return bool(expected.search(str(actual)))
    if isinstance(expected, (list, tuple, set, frozenset)):
        return actual in expected
    return str(actual) == str(expected)


def _evaluate_cosign_requirements(
    requirements: Iterable[frozenset[str]],
    recipient: Recipient,
    version: ContractVersion,
    verified_inputs: tuple[_VerifiedInput, ...],
    resolutions: Sequence[_FieldResolution],
    *,
    object_identity: str | Sequence[str] | Mapping[str, Any] | None,
    context_identity: Any,
    field_paths: Mapping[str, str],
    namespaces: Mapping[str, str],
) -> tuple[str, ...]:
    failures = []
    resolution_by_path = {resolution.path: resolution for resolution in resolutions}
    supported = set(recipient.fields)
    for requirement in requirements:
        group = frozenset(field_paths.get(field, field) for field in requirement)
        if not group.intersection(supported) and not group.intersection(resolution_by_path):
            continue
        groups = set()
        for field_name in sorted(group):
            resolution = resolution_by_path.get(field_name)
            if resolution is None:
                spec = recipient.fields.get(field_name, FieldSpec(path=field_name, required=True))
                resolution = _evaluate_field(
                    spec,
                    version,
                    verified_inputs,
                    object_identity=object_identity,
                    context_identity=context_identity,
                    field_paths=field_paths,
                    namespaces=namespaces,
                    recipient_name=recipient.name,
                )
            if resolution.status != FieldStatus.DELIVERED:
                failures.append(f"Co-sign requirement {sorted(group)!r} cannot be satisfied: {resolution.reason}")
                continue
            groups.update(resolution.signature_groups)
        if len(groups) > 1:
            failures.append(
                f"Co-sign requirement {sorted(group)!r} spans multiple signatures; the fields were not signed together"
            )
    return tuple(failures)


def _build_decision(
    recipient: Recipient,
    resolutions: tuple[_FieldResolution, ...],
    verified_inputs: tuple[_VerifiedInput, ...],
    *,
    object_identity: str | Sequence[str] | Mapping[str, Any] | None,
    policy: str | None,
    cosign_failures: tuple[str, ...],
) -> DeliveryDecision:
    unexplained = tuple(resolution for resolution in resolutions if resolution.status != FieldStatus.DELIVERED)
    refused = []
    review = []
    reasons = []
    for resolution in unexplained:
        reason = resolution.reason or f"Field {resolution.path!r} could not be explained"
        reasons.append(reason)
        if _should_refuse(resolution, policy):
            refused.append(resolution.path)
        else:
            review.append(resolution.path)
    cosign_policy = _normalize_delivery_status(policy) if policy is not None else None
    for failure in cosign_failures:
        reasons.append(failure)
        if cosign_policy == DeliveryStatus.MANUAL_REVIEW:
            review.append("<co-sign>")
        else:
            refused.append("<co-sign>")

    if not unexplained and not cosign_failures:
        status = DeliveryStatus.DELIVER
    elif refused:
        status = DeliveryStatus.REFUSE
    else:
        status = DeliveryStatus.MANUAL_REVIEW

    delivered = tuple(resolution.path for resolution in resolutions if resolution.status == FieldStatus.DELIVERED)
    unique_reasons = tuple(dict.fromkeys(reasons))
    review_ticket = None
    if status == DeliveryStatus.MANUAL_REVIEW:
        review_ticket = ReviewTicket(
            recipient=recipient.name,
            fields=tuple(review),
            reasons=unique_reasons,
            context=recipient.context,
            object_identity=object_identity,
        )
    identities = (
        tuple(sorted({verified_input.identity for verified_input in verified_inputs if verified_input.identity}))
        if object_identity is None
        else object_identity
    )
    return DeliveryDecision(
        recipient=recipient.name,
        status=status,
        delivered_fields=delivered,
        refused_fields=tuple(dict.fromkeys(refused)),
        review_fields=tuple(review),
        reasons=unique_reasons,
        context=recipient.context,
        object_identity=identities,
        field_results=tuple(resolution.to_dict() for resolution in resolutions),
        review_ticket=review_ticket,
    )


def _should_refuse(resolution: _FieldResolution, policy: str | None) -> bool:
    normalized = _normalize_delivery_status(policy) if policy is not None else None
    if normalized == DeliveryStatus.MANUAL_REVIEW:
        return False
    if normalized == DeliveryStatus.REFUSE:
        return True
    if resolution.status == FieldStatus.AMBIGUOUS:
        return False
    if resolution.status == FieldStatus.UNKNOWN_IDENTITY:
        return False
    return resolution.spec.required


def _ownership_maps(
    first: DeliveryContract,
    second: DeliveryContract,
    *,
    version: str | None,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if version is not None:
        first_version = first.versions.get(version)
        second_version = second.versions.get(version)
        return (
            {} if first_version is None else first_version.field_owners,
            {} if second_version is None else second_version.field_owners,
        )
    shared_versions = set(first.versions).intersection(second.versions)
    if shared_versions:
        old: dict[str, Any] = {}
        new: dict[str, Any] = {}
        for name in sorted(shared_versions):
            old.update(first.versions[name].field_owners)
            new.update(second.versions[name].field_owners)
        return old, new
    return first.field_owners, second.field_owners


def check_delivery_contract(
    verification: VerifyResult | Sequence[VerifyResult] | DeliveryContract | None = None,
    recipients: Any = None,
    *positional: Any,
    contract: DeliveryContract | None = None,
    object_identity: str | Sequence[str] | Mapping[str, Any] | None = None,
    identity: str | Sequence[str] | Mapping[str, Any] | None = None,
    field_owners: Mapping[str, Any] | None = None,
    ownership: Mapping[str, Any] | None = None,
    cosign_requirements: Any = (),
    must_sign_together: Any = None,
    version: str | None = None,
    versions: Mapping[str, Any] | None = None,
    namespaces: Mapping[str, str] | None = None,
    unexplained_policy: str | None = None,
    verified: VerifyResult | Sequence[VerifyResult] | None = None,
    result: VerifyResult | Sequence[VerifyResult] | None = None,
    verify_result: VerifyResult | Sequence[VerifyResult] | None = None,
    verification_result: VerifyResult | Sequence[VerifyResult] | None = None,
    verified_result: VerifyResult | Sequence[VerifyResult] | None = None,
    verified_identity: str | Sequence[str] | Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> DeliveryReport:
    """
    Check a successful SignXML verification result against a delivery contract.

    This is the post-verification entry point. It accepts either a :class:`DeliveryContract` as the
    first argument, or a verified result together with the contract components.

    :param verification: A :class:`signxml.VerifyResult`, a sequence of results, or a
        :class:`DeliveryContract` (in which case ``recipients`` is the verification input).
    :param recipients: Receiver declarations, or the verification input when the first argument is
        a contract.
    :param contract: An explicit delivery contract.
    :param object_identity: The identity that was actually verified by SignXML.
    :param field_owners: Field ownership map for a flat contract.
    :param ownership: Alias for ``field_owners``.
    :param cosign_requirements: Field groups that must be signed together.
    :param must_sign_together: Alias for ``cosign_requirements``.
    :param version: Contract version name.
    :param versions: Versioned ownership maps or :class:`ContractVersion` objects.
    :param namespaces: Namespace prefix map used to resolve fields.
    :param unexplained_policy: ``"refuse"`` or ``"manual_review"``.
    """

    if object_identity is None:
        object_identity = identity or verified_identity
    if verification is None:
        verification = verified or result or verify_result or verification_result or verified_result
    if positional:
        if isinstance(recipients, str) and object_identity is None:
            object_identity = recipients
            recipients = positional[0]
            positional = positional[1:]
        if positional and object_identity is None and isinstance(positional[0], (str, bytes)):
            object_identity = positional[0]
            positional = positional[1:]
        elif (
            positional
            and object_identity is None
            and isinstance(positional[0], (list, tuple))
            and all(isinstance(item, str) for item in positional[0])
        ):
            object_identity = positional[0]
            positional = positional[1:]
        if positional and field_owners is None:
            field_owners = positional[0]
            positional = positional[1:]
        if positional and must_sign_together is None:
            must_sign_together = positional[0]
            positional = positional[1:]
        if positional and version is None and isinstance(positional[0], str):
            version = positional[0]
            positional = positional[1:]
        if positional and versions is None and isinstance(positional[0], Mapping):
            versions = positional[0]
            positional = positional[1:]
    if isinstance(recipients, DeliveryContract) and contract is None:
        contract = recipients
        recipients = None
    if isinstance(verification, DeliveryContract):
        if contract is not None:
            raise InvalidInput("Specify the delivery contract only once")
        contract = verification
        verification = (
            recipients if recipients is not None else verified or result or verify_result or verification_result
        )
        recipients = None
    if contract is None:
        contract = DeliveryContract(
            version=version,
            field_owners=field_owners if field_owners is not None else ownership,
            recipients=recipients,
            cosign_requirements=cosign_requirements,
            versions=versions,
            must_sign_together=must_sign_together,
            namespaces=namespaces,
            unexplained_policy=unexplained_policy,
            **kwargs,
        )
    return contract.check(
        verification,
        object_identity=object_identity,
        recipients=recipients,
        unexplained_policy=unexplained_policy,
    )


check_contract = check_delivery_contract
reconcile_delivery = check_delivery_contract


def verify_and_check_delivery_contract(
    verifier: Any,
    data: Any,
    contract: DeliveryContract,
    *,
    object_identity: str | Sequence[str] | Mapping[str, Any] | None = None,
    **verify_kwargs: Any,
) -> DeliveryReport:
    """
    Verify an XML signature and then check the verified result against a delivery contract.

    Any signature failure is raised by :meth:`signxml.XMLVerifier.verify` before the contract check
    runs. A successful signature with unexplained fields returns a refusal or manual review in the
    report instead of raising.
    """

    if not hasattr(verifier, "verify"):
        raise InvalidInput("verifier must be an XMLVerifier instance")
    verification = verifier.verify(data, **verify_kwargs)
    return contract.check(verification, object_identity=object_identity)


def verify_delivery_contract(*args: Any, **kwargs: Any) -> DeliveryReport:
    """
    Check a verified result, or verify and check when the first argument is a verifier.

    verify_delivery_contract(verification, contract, ...) is equivalent to
    :func:`check_delivery_contract`. When called as
    verify_delivery_contract(verifier, data, contract, ...), the signature is verified first and
    signature failures are raised before the contract is checked.
    """

    if len(args) >= 3 and hasattr(args[0], "verify"):
        return verify_and_check_delivery_contract(*args, **kwargs)
    return check_delivery_contract(*args, **kwargs)


verify_with_contract = verify_and_check_delivery_contract
verify_and_check_contract = verify_and_check_delivery_contract
delivery_contract_check = check_delivery_contract
audit_delivery = check_delivery_contract
check_delivery = check_delivery_contract

ManualReviewTicket = ReviewTicket
ManualReview = ReviewTicket
DeliveryAudit = DeliveryReport
DeliveryOutcome = DeliveryDecision
ReleaseContract = DeliveryContract
ReceiverContract = DeliveryContract


def affected_recipients(
    previous_contract: DeliveryContract,
    new_contract: DeliveryContract,
    **kwargs: Any,
) -> AffectedRecipients:
    """
    Return receivers affected by a field ownership change between two contracts.
    """

    return previous_contract.affected_recipients(new_contract, **kwargs)


def changed_field_ownership(
    previous_contract: DeliveryContract,
    new_contract: DeliveryContract,
    **kwargs: Any,
) -> dict[str, tuple[Any, Any]]:
    """
    Return fields whose owner differs between two contracts.
    """

    return previous_contract.changed_field_ownership(new_contract, **kwargs)


def recipients_requiring_resignature(
    previous_contract: DeliveryContract,
    new_contract: DeliveryContract,
    **kwargs: Any,
) -> set[str]:
    """
    Alias for :func:`affected_recipients`.
    """

    return previous_contract.affected_recipients(new_contract, **kwargs)


resign_required = recipients_requiring_resignature
needs_resigning = recipients_requiring_resignature

ManualReviewSheet = ReviewTicket
ReviewSheet = ReviewTicket
FieldOwner = FieldOwnership
ReceiverDeclaration = Recipient
