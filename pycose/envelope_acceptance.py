from __future__ import annotations

import copy
import json
from collections import OrderedDict
from dataclasses import dataclass, field
from hashlib import sha256
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

import cbor2

from pycose import headers
from pycose.exceptions import CoseException
from pycose.keys.cosekey import CoseKey
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.enc0message import Enc0Message
from pycose.messages.encmessage import EncMessage


__all__ = [
    "AcceptanceConstraints",
    "AcceptanceReceipt",
    "AcceptanceReport",
    "AcceptedRecipient",
    "AuthorizedTestKey",
    "EnvelopeAcceptanceError",
    "EnvelopeAcceptor",
    "EnvelopeDecodeError",
    "EnvelopeIntegrityError",
    "EnvelopePolicyConflictError",
    "EnvelopeValidator",
    "EnvelopeVerifier",
    "LocalTestKey",
    "Manifest",
    "ManifestError",
    "MetadataConstraintError",
    "MetadataConstraints",
    "MissingTestKeyError",
    "PassReceipt",
    "PolicyConflictError",
    "ReceiptError",
    "RecipientCommitment",
    "RecipientConflictError",
    "RecipientRequest",
    "RecipientScopeError",
    "RecipientSetError",
    "ScopeViolationError",
    "TestKeyAuthorizationError",
    "TestKeyVerificationError",
    "UnauthorizedTestKeyError",
    "accept_cose_envelope",
    "accept_envelope",
    "check_envelope",
    "local_envelope_acceptance",
    "require_publication_receipt",
    "validate_envelope",
    "verify_envelope",
]


class EnvelopeAcceptanceError(CoseException):
    """Base class for local COSE envelope acceptance failures."""


class EnvelopeDecodeError(EnvelopeAcceptanceError):
    """The input is not a supported COSE encryption envelope."""


class ManifestError(EnvelopeAcceptanceError):
    """The business manifest is missing or malformed."""


class MetadataConstraintError(EnvelopeAcceptanceError):
    """The verified metadata constraints are malformed or do not bind."""


class PolicyConflictError(EnvelopeAcceptanceError):
    """One recipient node is bound to more than one commitment."""

    def __init__(self, node: str, commitments: Iterable["RecipientCommitment"]):
        self.node = node
        self.commitments = tuple(commitments)
        rendered = "; ".join(
            _describe_commitment(commitment) for commitment in self.commitments
        )
        super().__init__(
            "policy conflict: recipient node {!r} is bound to {} commitments ({})".format(
                node, len(self.commitments), rendered
            )
        )


class RecipientSetError(EnvelopeAcceptanceError):
    """Envelope recipient nodes do not match the manifest."""


class RecipientScopeError(EnvelopeAcceptanceError):
    """A recipient request falls outside its committed purpose or attachment group."""


class ScopeViolationError(RecipientScopeError):
    """A requested purpose or attachment group is not permitted."""


class UnauthorizedTestKeyError(EnvelopeAcceptanceError):
    """A local test key is not authorized for the requested recipient scope."""


class TestKeyAuthorizationError(UnauthorizedTestKeyError):
    """The authorization attached to a local test key is malformed or ambiguous."""

    __test__ = False


class TestKeyVerificationError(EnvelopeAcceptanceError):
    """A local test key could not unwrap or authenticate the envelope."""

    __test__ = False


class MissingTestKeyError(EnvelopeAcceptanceError):
    """A required local test key was not supplied."""


class EnvelopeIntegrityError(EnvelopeAcceptanceError):
    """Two authorized recipients produced different plaintext during verification."""


class ReceiptError(EnvelopeAcceptanceError):
    """A publication receipt is missing or does not bind to this acceptance."""


# Names that read naturally in calling code.
EnvelopePolicyConflictError = PolicyConflictError
RecipientConflictError = PolicyConflictError


def _as_node(value: Any, field_name: str = "recipient node") -> str:
    if isinstance(value, str):
        if not value:
            raise ManifestError("{} must not be empty".format(field_name))
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if not raw:
            raise ManifestError("{} must not be empty".format(field_name))
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return "hex:" + raw.hex()
    raise ManifestError(
        "{} must be a string or byte string, got {}".format(
            field_name, type(value).__name__
        )
    )


def _as_text(value: Any, field_name: str) -> str:
    if isinstance(value, str):
        if not value:
            raise ManifestError("{} must not be empty".format(field_name))
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ManifestError("{} must be UTF-8 text".format(field_name)) from exc
    raise ManifestError(
        "{} must be text, got {}".format(field_name, type(value).__name__)
    )


def _as_text_set(value: Any, field_name: str) -> FrozenSet[str]:
    if value is None:
        return frozenset()
    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return frozenset((_as_text(value, field_name),))
    if isinstance(value, Mapping):
        raise ManifestError(
            "{} must be text or a sequence of text values".format(field_name)
        )
    try:
        values = list(value)
    except TypeError as exc:
        raise ManifestError(
            "{} must be text or a sequence of text values".format(field_name)
        ) from exc
    return frozenset(_as_text(item, field_name) for item in values)


def _first_present(
    mapping: Mapping[str, Any], names: Sequence[str], default: Any = None
) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return default


def _normalize_digest(value: Any, field_name: str) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) == 32:
            return raw.hex()
        try:
            value = raw.decode("ascii")
        except UnicodeDecodeError:
            value = raw.hex()
    if not isinstance(value, str):
        raise MetadataConstraintError(
            "{} must be a hexadecimal digest".format(field_name)
        )
    digest = value.strip().lower()
    if digest.startswith("sha256:"):
        digest = digest[len("sha256:") :]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise MetadataConstraintError(
            "{} must be a 64-character SHA-256 digest".format(field_name)
        )
    return digest


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(_jsonable_key(key)): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return [_jsonable(item) for item in sorted(value, key=repr)]
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"$bytes": bytes(value).hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _jsonable_key(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "hex:" + bytes(value).hex()
    return repr(value)


def _digest(value: Any) -> str:
    encoded = json.dumps(
        _jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return sha256(encoded.encode("utf-8")).hexdigest()


def _describe_commitment(commitment: "RecipientCommitment") -> str:
    return "{}: purposes={} attachment_groups={}".format(
        commitment.node,
        list(commitment.sorted_purposes),
        list(commitment.sorted_attachment_groups),
    )


@dataclass(frozen=True)
class RecipientRequest:
    """The purpose and attachment groups actually requested for one node.

    ``None`` means that this dimension was not constrained by the caller.  An
    empty frozenset is an explicit request for no attachments.
    """

    purpose: Optional[str] = None
    attachment_groups: Optional[FrozenSet[str]] = None

    def __post_init__(self) -> None:
        if self.purpose is not None:
            object.__setattr__(self, "purpose", _as_text(self.purpose, "purpose"))
        if self.attachment_groups is not None:
            object.__setattr__(
                self,
                "attachment_groups",
                _as_text_set(self.attachment_groups, "attachment_groups"),
            )

    @classmethod
    def from_value(cls, value: Any) -> "RecipientRequest":
        if isinstance(value, cls):
            return value
        if value is None:
            return cls()
        if isinstance(value, (str, bytes, bytearray, memoryview)):
            return cls(purpose=_as_text(value, "purpose"))
        if isinstance(value, (list, tuple, set, frozenset)):
            purposes = list(value)
            if len(purposes) != 1:
                raise MetadataConstraintError(
                    "a recipient request must name exactly one purpose"
                )
            return cls(purpose=_as_text(purposes[0], "purpose"))
        if not isinstance(value, Mapping):
            raise MetadataConstraintError(
                "recipient request must be a mapping or purpose string"
            )

        purpose = _first_present(value, ("purpose", "purposes", "use", "usage"))
        if isinstance(purpose, (list, tuple, set, frozenset)):
            purposes = list(purpose)
            if len(purposes) != 1:
                raise MetadataConstraintError(
                    "a recipient request must name exactly one purpose"
                )
            purpose = purposes[0]

        groups = _first_present(
            value,
            (
                "attachment_groups",
                "attachment_group",
                "attachments",
                "attachment",
                "groups",
                "group",
            ),
            None,
        )
        return cls(purpose=purpose, attachment_groups=groups)

    @property
    def is_empty(self) -> bool:
        return self.purpose is None and self.attachment_groups is None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if self.purpose is not None:
            result["purpose"] = self.purpose
        if self.attachment_groups is not None:
            result["attachment_groups"] = sorted(self.attachment_groups)
        return result


@dataclass(frozen=True)
class RecipientCommitment:
    """The material scope a business manifest grants to one recipient node."""

    node: str
    purposes: FrozenSet[str] = frozenset()
    attachment_groups: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "node", _as_node(self.node))
        object.__setattr__(self, "purposes", _as_text_set(self.purposes, "purposes"))
        object.__setattr__(
            self,
            "attachment_groups",
            _as_text_set(self.attachment_groups, "attachment_groups"),
        )

    @classmethod
    def from_value(
        cls, value: Any, default_node: Optional[str] = None
    ) -> "RecipientCommitment":
        if isinstance(value, cls):
            if default_node is not None and value.node != default_node:
                raise ManifestError("commitment node does not match its manifest key")
            return value

        if isinstance(value, Mapping):
            node = _first_present(
                value, ("node", "recipient", "recipient_node", "kid", "key_id", "id")
            )
            if node is None:
                node = default_node
            if node is None:
                raise ManifestError("manifest commitment is missing a recipient node")

            scope = value.get("scope")
            scope_mapping = scope if isinstance(scope, Mapping) else value
            purposes = _first_present(
                scope_mapping,
                (
                    "purposes",
                    "purpose",
                    "allowed_purposes",
                    "allowed_purpose",
                    "uses",
                    "use",
                ),
                None,
            )
            if purposes is None and isinstance(
                scope, (str, bytes, bytearray, memoryview, list, tuple, set, frozenset)
            ):
                purposes = scope

            groups = _first_present(
                scope_mapping,
                (
                    "attachment_groups",
                    "attachment_group",
                    "attachments",
                    "groups",
                    "group",
                    "allowed_attachment_groups",
                    "allowed_groups",
                ),
                None,
            )
            return cls(
                node=node,
                purposes=purposes or frozenset(),
                attachment_groups=groups or frozenset(),
            )

        if default_node is None:
            raise ManifestError("manifest list entries must state a recipient node")
        if isinstance(value, (str, bytes, bytearray, memoryview)):
            return cls(node=default_node, purposes={_as_text(value, "purpose")})
        if isinstance(value, (list, tuple, set, frozenset)):
            return cls(node=default_node, purposes=value)
        raise ManifestError(
            "unsupported manifest commitment value: {}".format(type(value).__name__)
        )

    @property
    def sorted_purposes(self) -> Tuple[str, ...]:
        return tuple(sorted(self.purposes))

    @property
    def sorted_attachment_groups(self) -> Tuple[str, ...]:
        return tuple(sorted(self.attachment_groups))

    def permits(self, request: RecipientRequest) -> bool:
        if request.purpose is not None and request.purpose not in self.purposes:
            return False
        if (
            request.attachment_groups is not None
            and not request.attachment_groups.issubset(self.attachment_groups)
        ):
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node": self.node,
            "purposes": list(self.sorted_purposes),
            "attachment_groups": list(self.sorted_attachment_groups),
        }


@dataclass(frozen=True)
class Manifest:
    """A business manifest mapping each recipient node to exactly one scope."""

    commitments: Tuple[RecipientCommitment, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        commitments = tuple(
            item
            if isinstance(item, RecipientCommitment)
            else RecipientCommitment.from_value(item)
            for item in (self.commitments or ())
        )
        by_node: "OrderedDict[str, list]" = OrderedDict()
        for commitment in commitments:
            by_node.setdefault(commitment.node, []).append(commitment)
        for node, node_commitments in by_node.items():
            if len(node_commitments) > 1:
                raise PolicyConflictError(node, node_commitments)
        if not commitments:
            raise ManifestError("manifest must grant at least one recipient")
        object.__setattr__(
            self, "commitments", tuple(sorted(commitments, key=lambda item: item.node))
        )
        object.__setattr__(self, "metadata", dict(self.metadata or {}))

    @classmethod
    def from_value(cls, value: Any) -> "Manifest":
        if isinstance(value, cls):
            return value
        if value is None:
            raise ManifestError("a business manifest is required")
        if isinstance(value, RecipientCommitment):
            return cls(commitments=(value,))

        metadata: Mapping[str, Any] = {}
        if isinstance(value, Mapping):
            if "manifest" in value and len(value) == 1:
                return cls.from_value(value["manifest"])
            if any(
                key in value
                for key in ("node", "recipient", "recipient_node", "kid", "key_id")
            ) and any(
                key in value
                for key in (
                    "purposes",
                    "purpose",
                    "attachment_groups",
                    "attachment_group",
                    "attachments",
                    "groups",
                )
            ):
                metadata = value.get("metadata", {}) or {}
                return cls(
                    commitments=(RecipientCommitment.from_value(value),),
                    metadata=metadata,
                )
            for key in ("commitments", "entries", "recipients", "grants", "scopes"):
                if key in value:
                    metadata = value.get("metadata", {}) or {}
                    value = value[key]
                    break
            else:
                if "metadata" in value:
                    metadata = value.get("metadata", {}) or {}
                    value = {
                        key: item for key, item in value.items() if key != "metadata"
                    }

        commitments = []
        if isinstance(value, Mapping):
            for node, scope in value.items():
                commitments.append(
                    RecipientCommitment.from_value(scope, default_node=_as_node(node))
                )
        elif isinstance(value, RecipientCommitment):
            commitments.append(value)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for entry in value:
                commitments.append(RecipientCommitment.from_value(entry))
        else:
            raise ManifestError(
                "manifest must be a mapping or a sequence of commitments"
            )

        if not commitments:
            raise ManifestError("manifest must grant at least one recipient")
        return cls(commitments=tuple(commitments), metadata=metadata)

    def __iter__(self):
        return iter(self.commitments)

    @property
    def by_node(self) -> Dict[str, RecipientCommitment]:
        return {commitment.node: commitment for commitment in self.commitments}

    @property
    def nodes(self) -> Tuple[str, ...]:
        return tuple(commitment.node for commitment in self.commitments)

    @property
    def digest(self) -> str:
        return _digest(
            {
                "commitments": [
                    commitment.to_dict() for commitment in self.commitments
                ],
                "metadata": self.metadata,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitments": [commitment.to_dict() for commitment in self.commitments],
            "metadata": _jsonable(self.metadata),
        }


@dataclass(frozen=True)
class MetadataConstraints:
    """Caller-verified metadata used while accepting one envelope.

    A global request can be supplied with ``purpose`` and
    ``attachment_groups``.  Per-node requests override the global request.
    ``metadata_digest`` binds the verified metadata document; if
    ``metadata`` is also supplied it is hashed and compared, otherwise the
    manifest metadata is used.
    """

    purpose: Optional[str] = None
    attachment_groups: Optional[FrozenSet[str]] = None
    recipient_requests: Mapping[str, RecipientRequest] = field(default_factory=dict)
    metadata: Optional[Mapping[str, Any]] = None
    metadata_digest: Optional[str] = None
    manifest_digest: Optional[str] = None
    required_recipients: FrozenSet[str] = frozenset()
    require_exact_recipients: bool = True
    require_all_keys: bool = False
    require_test_key: bool = True
    verify_payload: bool = True

    def __post_init__(self) -> None:
        if self.purpose is not None:
            object.__setattr__(self, "purpose", _as_text(self.purpose, "purpose"))
        if self.attachment_groups is not None:
            object.__setattr__(
                self,
                "attachment_groups",
                _as_text_set(self.attachment_groups, "attachment_groups"),
            )

        requests: Dict[str, RecipientRequest] = {}
        for node, request in (self.recipient_requests or {}).items():
            normalized_node = _as_node(node)
            if normalized_node in requests:
                raise MetadataConstraintError(
                    "recipient request is specified more than once for node {!r}".format(
                        normalized_node
                    )
                )
            requests[normalized_node] = (
                request
                if isinstance(request, RecipientRequest)
                else RecipientRequest.from_value(request)
            )
        object.__setattr__(self, "recipient_requests", requests)
        object.__setattr__(
            self,
            "required_recipients",
            _as_text_set(self.required_recipients, "required_recipients"),
        )
        if self.metadata is not None:
            object.__setattr__(self, "metadata", dict(self.metadata))
        if self.metadata_digest is not None:
            object.__setattr__(
                self,
                "metadata_digest",
                _normalize_digest(self.metadata_digest, "metadata_digest"),
            )
        if self.manifest_digest is not None:
            object.__setattr__(
                self,
                "manifest_digest",
                _normalize_digest(self.manifest_digest, "manifest_digest"),
            )

    @classmethod
    def from_value(cls, value: Any) -> "MetadataConstraints":
        if value is None:
            return cls()
        if isinstance(value, cls):
            return value
        if isinstance(value, RecipientRequest):
            return cls(purpose=value.purpose, attachment_groups=value.attachment_groups)
        if isinstance(value, (str, bytes, bytearray, memoryview)):
            return cls(purpose=_as_text(value, "purpose"))
        if not isinstance(value, Mapping):
            raise MetadataConstraintError("metadata constraints must be a mapping")

        data = dict(value)
        if "constraints" in data and len(data) == 1:
            return cls.from_value(data["constraints"])

        known_keys = {
            "purpose",
            "purposes",
            "attachment_groups",
            "attachment_group",
            "attachments",
            "attachment",
            "groups",
            "group",
            "recipients",
            "recipient_requests",
            "requests",
            "metadata",
            "metadata_digest",
            "metadata_hash",
            "manifest_digest",
            "required_recipients",
            "require_recipients",
            "require_exact_recipients",
            "require_all_keys",
            "require_test_key",
            "require_test_keys",
            "verify_payload",
        }

        purpose = _first_present(data, ("purpose", "purposes"))
        if isinstance(purpose, (list, tuple, set, frozenset)):
            purposes = list(purpose)
            if len(purposes) != 1:
                raise MetadataConstraintError(
                    "constraints.purpose must name exactly one purpose"
                )
            purpose = purposes[0]

        groups_key_present = any(
            key in data
            for key in (
                "attachment_groups",
                "attachment_group",
                "attachments",
                "attachment",
                "groups",
                "group",
            )
        )
        if groups_key_present:
            groups = _first_present(
                data,
                (
                    "attachment_groups",
                    "attachment_group",
                    "attachments",
                    "attachment",
                    "groups",
                    "group",
                ),
            )
            groups = (
                None if groups is None else _as_text_set(groups, "attachment_groups")
            )
        else:
            groups = None

        recipient_requests = _first_present(
            data, ("recipients", "recipient_requests", "requests")
        )
        if recipient_requests is None:
            if not (set(data).intersection(known_keys)):
                recipient_requests = data
            else:
                recipient_requests = {}

        parsed_requests: Dict[str, RecipientRequest] = {}
        if isinstance(recipient_requests, Mapping):
            for node, request in recipient_requests.items():
                parsed_requests[_as_node(node)] = RecipientRequest.from_value(request)
        elif isinstance(recipient_requests, (list, tuple, set, frozenset)):
            for entry in recipient_requests:
                if not isinstance(entry, Mapping):
                    raise MetadataConstraintError(
                        "recipient request entries must be mappings"
                    )
                node = _first_present(
                    entry,
                    ("node", "recipient", "recipient_node", "kid", "key_id", "id"),
                )
                if node is None:
                    raise MetadataConstraintError(
                        "recipient request entry is missing a node"
                    )
                parsed_requests[_as_node(node)] = RecipientRequest.from_value(entry)
        else:
            raise MetadataConstraintError(
                "recipient requests must be a mapping or sequence"
            )

        required = _first_present(
            data, ("required_recipients", "require_recipients"), frozenset()
        )
        metadata = data.get("metadata")
        metadata_digest = _first_present(data, ("metadata_digest", "metadata_hash"))

        return cls(
            purpose=purpose,
            attachment_groups=groups,
            recipient_requests=parsed_requests,
            metadata=metadata,
            metadata_digest=metadata_digest,
            manifest_digest=data.get("manifest_digest"),
            required_recipients=_as_text_set(required, "required_recipients"),
            require_exact_recipients=bool(data.get("require_exact_recipients", True)),
            require_all_keys=bool(data.get("require_all_keys", False)),
            require_test_key=bool(
                data.get("require_test_key", data.get("require_test_keys", True))
            ),
            verify_payload=bool(data.get("verify_payload", True)),
        )

    def request_for(
        self, node: str, declared: Optional[RecipientRequest] = None
    ) -> Tuple[RecipientRequest, str]:
        if node in self.recipient_requests:
            return self.recipient_requests[node], "constraints"
        if self.purpose is not None or self.attachment_groups is not None:
            return RecipientRequest(self.purpose, self.attachment_groups), "constraints"
        if declared is not None and not declared.is_empty:
            return declared, "envelope"
        return RecipientRequest(), "unspecified"

    @property
    def digest(self) -> str:
        return _digest(
            {
                "purpose": self.purpose,
                "attachment_groups": None
                if self.attachment_groups is None
                else sorted(self.attachment_groups),
                "recipient_requests": {
                    node: request.to_dict()
                    for node, request in sorted(self.recipient_requests.items())
                },
                "metadata": self.metadata,
                "metadata_digest": self.metadata_digest,
                "manifest_digest": self.manifest_digest,
                "required_recipients": sorted(self.required_recipients),
                "require_exact_recipients": self.require_exact_recipients,
                "require_all_keys": self.require_all_keys,
                "require_test_key": self.require_test_key,
                "verify_payload": self.verify_payload,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "purpose": self.purpose,
            "attachment_groups": None
            if self.attachment_groups is None
            else sorted(self.attachment_groups),
            "recipient_requests": {
                node: request.to_dict()
                for node, request in sorted(self.recipient_requests.items())
            },
            "metadata": _jsonable(self.metadata),
            "metadata_digest": self.metadata_digest,
            "manifest_digest": self.manifest_digest,
            "required_recipients": sorted(self.required_recipients),
            "require_exact_recipients": self.require_exact_recipients,
            "require_all_keys": self.require_all_keys,
            "require_test_key": self.require_test_key,
            "verify_payload": self.verify_payload,
        }


AcceptanceConstraints = MetadataConstraints


@dataclass(frozen=True)
class LocalTestKey:
    """A caller-authorized local key and the scope it may be used for."""

    node: str
    key: CoseKey
    purposes: Optional[FrozenSet[str]] = None
    attachment_groups: Optional[FrozenSet[str]] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "node", _as_node(self.node))
        if not isinstance(self.key, CoseKey):
            raise TestKeyAuthorizationError("local test key must be a pycose CoseKey")
        if self.purposes is not None:
            object.__setattr__(
                self, "purposes", _as_text_set(self.purposes, "key purposes")
            )
        if self.attachment_groups is not None:
            object.__setattr__(
                self,
                "attachment_groups",
                _as_text_set(self.attachment_groups, "key attachment_groups"),
            )

    @classmethod
    def from_value(
        cls, value: Any, default_node: Optional[str] = None
    ) -> "LocalTestKey":
        if isinstance(value, cls):
            return value
        if isinstance(value, CoseKey):
            if default_node is None:
                raise TestKeyAuthorizationError(
                    "a bare CoseKey test key needs an authorized node"
                )
            return cls(node=default_node, key=value)
        if (
            isinstance(value, tuple)
            and len(value) == 2
            and isinstance(value[1], CoseKey)
        ):
            return cls(node=default_node or value[0], key=value[1])
        if isinstance(value, Mapping):
            node = _first_present(
                value, ("node", "recipient", "recipient_node", "kid", "key_id", "id")
            )
            if node is None:
                node = default_node
            key = value.get("key")
            if node is None or not isinstance(key, CoseKey):
                raise TestKeyAuthorizationError(
                    "local test key entry must contain a node and a CoseKey"
                )
            return cls(
                node=node,
                key=key,
                purposes=_first_present(value, ("purposes", "purpose"), None),
                attachment_groups=_first_present(
                    value,
                    ("attachment_groups", "attachment_group", "attachments", "groups"),
                    None,
                ),
            )
        raise TestKeyAuthorizationError(
            "unsupported local test key entry: {}".format(type(value).__name__)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node": self.node,
            "purposes": None if self.purposes is None else sorted(self.purposes),
            "attachment_groups": None
            if self.attachment_groups is None
            else sorted(self.attachment_groups),
        }


AuthorizedTestKey = LocalTestKey


@dataclass(frozen=True)
class _EnvelopeRecipient:
    node: Optional[str]
    recipient: Any
    index: int
    depth: int
    declared: RecipientRequest
    algorithm: Optional[str]


@dataclass(frozen=True)
class AcceptedRecipient:
    node: str
    allowed_purposes: Tuple[str, ...]
    allowed_attachment_groups: Tuple[str, ...]
    requested_purpose: Optional[str]
    requested_attachment_groups: Optional[Tuple[str, ...]]
    scope_source: str
    cryptographically_verified: bool
    algorithm: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node": self.node,
            "allowed_purposes": list(self.allowed_purposes),
            "allowed_attachment_groups": list(self.allowed_attachment_groups),
            "requested_purpose": self.requested_purpose,
            "requested_attachment_groups": None
            if self.requested_attachment_groups is None
            else list(self.requested_attachment_groups),
            "scope_source": self.scope_source,
            "cryptographically_verified": self.cryptographically_verified,
            "algorithm": self.algorithm,
        }


@dataclass(frozen=True)
class AcceptanceReceipt:
    """A local pass receipt.  It never contains plaintext or ciphertext."""

    envelope_digest: str
    manifest_digest: str
    constraints_digest: str
    metadata_digest: Optional[str]
    recipients: Tuple[AcceptedRecipient, ...]

    @property
    def verified_recipients(self) -> Tuple[str, ...]:
        return tuple(
            recipient.node
            for recipient in self.recipients
            if recipient.cryptographically_verified
        )

    @property
    def receipt_id(self) -> str:
        return _digest(
            {
                "version": 1,
                "envelope": self.envelope_digest,
                "manifest": self.manifest_digest,
                "constraints": self.constraints_digest,
                "metadata": self.metadata_digest,
                "recipients": [recipient.to_dict() for recipient in self.recipients],
            }
        )

    @property
    def id(self) -> str:
        return self.receipt_id

    @property
    def token(self) -> str:
        return self.receipt_id

    def matches(
        self,
        envelope: Any = None,
        manifest: Any = None,
        constraints: Any = None,
    ) -> bool:
        try:
            if envelope is not None:
                _, envelope_digest, _ = _decode_envelope(envelope)
                if envelope_digest != self.envelope_digest:
                    return False
            if (
                manifest is not None
                and Manifest.from_value(manifest).digest != self.manifest_digest
            ):
                return False
            if (
                constraints is not None
                and MetadataConstraints.from_value(constraints).digest
                != self.constraints_digest
            ):
                return False
        except (EnvelopeAcceptanceError, CoseException, TypeError, ValueError):
            return False
        return True

    def verify(
        self, envelope: Any = None, manifest: Any = None, constraints: Any = None
    ) -> bool:
        return self.matches(
            envelope=envelope, manifest=manifest, constraints=constraints
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "envelope_digest": self.envelope_digest,
            "manifest_digest": self.manifest_digest,
            "constraints_digest": self.constraints_digest,
            "metadata_digest": self.metadata_digest,
            "recipients": [recipient.to_dict() for recipient in self.recipients],
            "verified_recipients": list(self.verified_recipients),
        }

    def __bool__(self) -> bool:
        return True


PassReceipt = AcceptanceReceipt


@dataclass(frozen=True)
class AcceptanceReport:
    """The result of a local envelope check.

    ``receipt`` is only present when every check passed.  It intentionally has
    no plaintext field and no accessor that can recover the payload.
    """

    accepted: bool
    receipt: Optional[AcceptanceReceipt]
    recipients: Tuple[AcceptedRecipient, ...]
    envelope_digest: Optional[str]
    manifest_digest: Optional[str]
    errors: Tuple[str, ...] = ()
    error_type: Optional[str] = None
    conflicts: Tuple[Mapping[str, Any], ...] = ()

    def __bool__(self) -> bool:
        return self.accepted and self.receipt is not None

    @property
    def ok(self) -> bool:
        return bool(self)

    @property
    def receipt_id(self) -> Optional[str]:
        return None if self.receipt is None else self.receipt.receipt_id

    @property
    def verified_recipients(self) -> Tuple[str, ...]:
        if self.receipt is None:
            return tuple()
        return self.receipt.verified_recipients

    def raise_if_rejected(self) -> "AcceptanceReport":
        if not self:
            message = "; ".join(self.errors) or "envelope was not accepted"
            raise ReceiptError(message)
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "receipt": None if self.receipt is None else self.receipt.to_dict(),
            "recipients": [recipient.to_dict() for recipient in self.recipients],
            "envelope_digest": self.envelope_digest,
            "manifest_digest": self.manifest_digest,
            "errors": list(self.errors),
            "error_type": self.error_type,
            "conflicts": [dict(conflict) for conflict in self.conflicts],
        }


def _message_fingerprint(message: Union[EncMessage, Enc0Message]) -> str:
    if isinstance(message, EncMessage):
        encoded = [
            message.phdr_encoded,
            message.uhdr_encoded,
            message.payload,
            [_recipient_fingerprint(recipient) for recipient in message.recipients],
        ]
    else:
        encoded = [message.phdr_encoded, message.uhdr_encoded, message.payload]
    raw = cbor2.dumps(encoded, default=message._custom_cbor_encoder)
    return sha256(raw).hexdigest()


def _recipient_fingerprint(recipient: Any) -> list:
    return [
        recipient.phdr_encoded,
        recipient.uhdr_encoded,
        recipient.payload,
        [_recipient_fingerprint(nested) for nested in recipient.recipients],
    ]


def _decode_envelope(envelope: Any) -> Tuple[Union[EncMessage, Enc0Message], str, Any]:
    if isinstance(envelope, (bytes, bytearray, memoryview)):
        raw = bytes(envelope)
        if not raw:
            raise EnvelopeDecodeError("envelope bytes must not be empty")
        try:
            message = CoseMessage.decode(raw)
        except Exception as exc:
            raise EnvelopeDecodeError("input is not a decodable COSE message") from exc
    elif isinstance(envelope, (EncMessage, Enc0Message)):
        message = copy.deepcopy(envelope)
    else:
        raise TypeError("envelope must be COSE bytes or an Encrypt/Encrypt0 message")

    if not isinstance(message, (EncMessage, Enc0Message)):
        raise EnvelopeDecodeError(
            "envelope must be COSE_Encrypt or COSE_Encrypt0, got {}".format(
                type(message).__name__
            )
        )
    try:
        fingerprint = _message_fingerprint(message)
    except Exception as exc:
        raise EnvelopeDecodeError(
            "could not fingerprint the decoded COSE envelope"
        ) from exc
    return message, fingerprint, envelope


def _header_kid(cose_object: Any) -> Optional[str]:
    try:
        kid = cose_object.get_attr(headers.KID)
    except CoseException as exc:
        raise RecipientSetError(
            "recipient headers carry conflicting KID values"
        ) from exc
    if kid is None:
        key = getattr(cose_object, "key", None)
        if key is not None:
            kid = getattr(key, "kid", b"") or None
    if kid is None:
        return None
    return _as_node(kid, "KID")


def _declared_request(cose_object: Any) -> RecipientRequest:
    purpose = None
    groups = None
    for bucket in (cose_object.phdr, cose_object.uhdr):
        for attribute, value in bucket.items():
            label = getattr(attribute, "fullname", str(attribute)).upper()
            if (
                label in ("PURPOSE", "EVIDENCE_PURPOSE", "COSE_PURPOSE")
                and purpose is None
            ):
                if isinstance(value, (str, bytes, bytearray, memoryview)):
                    purpose = _as_text(value, "purpose")
                elif isinstance(value, (list, tuple)) and len(value) == 1:
                    purpose = _as_text(value[0], "purpose")
            elif (
                label
                in (
                    "ATTACHMENT_GROUPS",
                    "ATTACHMENT_GROUP",
                    "ATTACHMENTS",
                    "ATTACHMENT",
                    "GROUPS",
                    "GROUP",
                )
                and groups is None
            ):
                groups = _as_text_set(value, "attachment_groups")
    return RecipientRequest(purpose=purpose, attachment_groups=groups)


def _algorithm_name(cose_object: Any) -> Optional[str]:
    try:
        algorithm = cose_object.get_attr(headers.Algorithm)
    except CoseException:
        return None
    if algorithm is None:
        return None
    return getattr(algorithm, "fullname", str(algorithm))


def _collect_envelope_recipients(
    message: Union[EncMessage, Enc0Message],
) -> Tuple[_EnvelopeRecipient, ...]:
    collected = []

    if isinstance(message, Enc0Message):
        collected.append(
            _EnvelopeRecipient(
                node=_header_kid(message),
                recipient=None,
                index=0,
                depth=0,
                declared=_declared_request(message),
                algorithm=_algorithm_name(message),
            )
        )
        return tuple(collected)

    def walk(recipients: Sequence[Any], depth: int) -> None:
        for recipient in recipients:
            node = _header_kid(recipient)
            nested = list(getattr(recipient, "recipients", []) or [])
            if node is not None or not nested:
                collected.append(
                    _EnvelopeRecipient(
                        node=node,
                        recipient=recipient,
                        index=len(collected),
                        depth=depth,
                        declared=_declared_request(recipient),
                        algorithm=_algorithm_name(recipient),
                    )
                )
            if nested:
                walk(nested, depth + 1)

    walk(message.recipients, 0)
    if not collected:
        raise RecipientSetError("encrypted envelope does not contain a recipient node")
    return tuple(collected)


def _resolve_recipient_nodes(
    recipients: Sequence[_EnvelopeRecipient], manifest: Manifest
) -> Tuple[_EnvelopeRecipient, ...]:
    resolved = []
    for recipient in recipients:
        node = recipient.node
        if node is None:
            if len(manifest.commitments) != 1:
                raise RecipientSetError(
                    "recipient #{} has no KID and the manifest has more than one node".format(
                        recipient.index
                    )
                )
            node = manifest.commitments[0].node
        resolved.append(
            _EnvelopeRecipient(
                node=node,
                recipient=recipient.recipient,
                index=recipient.index,
                depth=recipient.depth,
                declared=recipient.declared,
                algorithm=recipient.algorithm,
            )
        )

    seen: Dict[str, list] = OrderedDict()
    for recipient in resolved:
        declared = recipient.declared
        seen.setdefault(recipient.node, []).append(
            RecipientCommitment(
                node=recipient.node,
                purposes=() if declared.purpose is None else (declared.purpose,),
                attachment_groups=()
                if declared.attachment_groups is None
                else declared.attachment_groups,
            )
        )
    for node, commitments in seen.items():
        if len(commitments) > 1:
            raise PolicyConflictError(node, commitments)
    return tuple(resolved)


def _coerce_test_keys(value: Any) -> Tuple[LocalTestKey, ...]:
    if value is None:
        return tuple()
    if isinstance(value, LocalTestKey):
        return (value,)
    if isinstance(value, CoseKey):
        node = getattr(value, "kid", b"")
        if not node:
            raise TestKeyAuthorizationError("a bare CoseKey test key must carry a KID")
        return (LocalTestKey(node=_as_node(node), key=value),)

    entries = []
    if isinstance(value, Mapping):
        descriptor_node = _first_present(
            value, ("node", "recipient", "recipient_node", "kid", "key_id")
        )
        descriptor_key = value.get("key")
        if descriptor_node is not None and isinstance(descriptor_key, CoseKey):
            entries.append(LocalTestKey.from_value(value))
        else:
            for node, key_value in value.items():
                normalized_node = _as_node(node)
                entry = LocalTestKey.from_value(key_value, default_node=normalized_node)
                if entry.node != normalized_node:
                    raise TestKeyAuthorizationError(
                        "local test key mapping key does not match its authorized node"
                    )
                entries.append(entry)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            entries.append(LocalTestKey.from_value(item))
    else:
        raise TestKeyAuthorizationError("local test keys must be a mapping or sequence")

    indexed: Dict[str, LocalTestKey] = {}
    for entry in entries:
        if entry.node in indexed:
            raise TestKeyAuthorizationError(
                "node {!r} is authorized with more than one local test key".format(
                    entry.node
                )
            )
        indexed[entry.node] = entry
    return tuple(entries)


def _verify_metadata_binding(
    constraints: MetadataConstraints, manifest: Manifest
) -> Optional[str]:
    if (
        constraints.manifest_digest is not None
        and constraints.manifest_digest != manifest.digest
    ):
        raise MetadataConstraintError(
            "manifest digest does not match the verified metadata constraints"
        )

    metadata = constraints.metadata
    if metadata is None and manifest.metadata:
        metadata = manifest.metadata

    computed = None if metadata is None else _digest(metadata)
    if constraints.metadata_digest is not None:
        if computed is None:
            raise MetadataConstraintError(
                "metadata_digest was supplied without a metadata document"
            )
        if constraints.metadata_digest != computed:
            raise MetadataConstraintError(
                "metadata digest does not match the verified metadata constraints"
            )
    return computed


def _check_key_authorization(
    keys: Sequence[LocalTestKey],
    manifest: Manifest,
    constraints: MetadataConstraints,
    declared_by_node: Mapping[str, RecipientRequest],
) -> None:
    commitments = manifest.by_node
    for key in keys:
        if key.node not in commitments:
            raise UnauthorizedTestKeyError(
                "local test key for {!r} is not authorized by the business manifest".format(
                    key.node
                )
            )

        key_kid = getattr(key.key, "kid", b"")
        if key_kid and _as_node(key_kid, "key KID") != key.node:
            raise UnauthorizedTestKeyError(
                "local test key KID does not match its authorized recipient node {!r}".format(
                    key.node
                )
            )

        commitment = commitments[key.node]
        request, _ = constraints.request_for(key.node, declared_by_node.get(key.node))

        if key.purposes is not None:
            if not key.purposes.issubset(commitment.purposes):
                raise TestKeyAuthorizationError(
                    "local test key scope for {!r} exceeds the manifest commitment".format(
                        key.node
                    )
                )
            if request.purpose is not None and request.purpose not in key.purposes:
                raise UnauthorizedTestKeyError(
                    "local test key for {!r} is not authorized for purpose {!r}".format(
                        key.node, request.purpose
                    )
                )

        if key.attachment_groups is not None:
            if not key.attachment_groups.issubset(commitment.attachment_groups):
                raise TestKeyAuthorizationError(
                    "local test key attachment scope for {!r} exceeds the manifest commitment".format(
                        key.node
                    )
                )
            if (
                request.attachment_groups is not None
                and not request.attachment_groups.issubset(key.attachment_groups)
            ):
                raise UnauthorizedTestKeyError(
                    "local test key for {!r} is not authorized for the requested attachment groups".format(
                        key.node
                    )
                )


def _check_scope(
    node: str,
    commitment: RecipientCommitment,
    request: RecipientRequest,
) -> None:
    if request.purpose is not None and request.purpose not in commitment.purposes:
        raise ScopeViolationError(
            "recipient {!r} is not permitted purpose {!r}; allowed purposes: {}".format(
                node, request.purpose, list(commitment.sorted_purposes)
            )
        )
    if request.attachment_groups is not None and not request.attachment_groups.issubset(
        commitment.attachment_groups
    ):
        denied = sorted(
            request.attachment_groups.difference(commitment.attachment_groups)
        )
        raise ScopeViolationError(
            "recipient {!r} is not permitted attachment groups {}; allowed groups: {}".format(
                node, denied, list(commitment.sorted_attachment_groups)
            )
        )


def _check_recipient_set(
    recipients: Sequence[_EnvelopeRecipient],
    manifest: Manifest,
    constraints: MetadataConstraints,
) -> None:
    envelope_nodes = {recipient.node for recipient in recipients}
    manifest_nodes = set(manifest.nodes)

    missing = sorted(manifest_nodes.difference(envelope_nodes))
    unexpected = sorted(envelope_nodes.difference(manifest_nodes))
    if unexpected:
        raise RecipientSetError(
            "envelope contains recipient nodes absent from the manifest: {}".format(
                unexpected
            )
        )
    if missing and constraints.require_exact_recipients:
        raise RecipientSetError(
            "manifest recipient nodes are missing from the envelope: {}".format(missing)
        )

    unknown_required = sorted(
        constraints.required_recipients.difference(manifest_nodes)
    )
    if unknown_required:
        raise RecipientSetError(
            "required recipient nodes are absent from the manifest: {}".format(
                unknown_required
            )
        )


def _verify_cryptography(
    message: Union[EncMessage, Enc0Message],
    recipients: Sequence[_EnvelopeRecipient],
    keys: Sequence[LocalTestKey],
    constraints: MetadataConstraints,
) -> FrozenSet[str]:
    if not constraints.verify_payload:
        return frozenset()

    if not keys and constraints.require_test_key:
        raise MissingTestKeyError(
            "at least one caller-authorized local test key is required"
        )

    entries = {recipient.node: recipient for recipient in recipients}
    verified = set()
    plaintext_digest = None

    for key in keys:
        if key.node not in entries:
            raise UnauthorizedTestKeyError(
                "local test key for {!r} has no recipient node in this envelope".format(
                    key.node
                )
            )
        entry = entries[key.node]
        try:
            if isinstance(message, EncMessage):
                message.key = key.key
                entry.recipient.key = key.key
                plaintext = message.decrypt(entry.recipient)
            else:
                message.key = key.key
                plaintext = message.decrypt()
        except Exception:
            raise TestKeyVerificationError(
                "local test key could not authenticate envelope for recipient {!r}".format(
                    key.node
                )
            ) from None

        try:
            digest = sha256(plaintext).digest()
        except Exception:
            raise TestKeyVerificationError(
                "local test key produced no authenticated payload for recipient {!r}".format(
                    key.node
                )
            ) from None
        finally:
            del plaintext
        if plaintext_digest is None:
            plaintext_digest = digest
        elif digest != plaintext_digest:
            raise EnvelopeIntegrityError(
                "authorized recipients produced different plaintext payloads"
            )
        verified.add(key.node)

    if constraints.require_all_keys:
        missing = sorted(set(entries).difference(verified))
        if missing:
            raise MissingTestKeyError(
                "local test keys are required for every recipient; missing: {}".format(
                    missing
                )
            )

    missing_required = sorted(constraints.required_recipients.difference(verified))
    if missing_required:
        raise MissingTestKeyError(
            "required recipients were not cryptographically verified: {}".format(
                missing_required
            )
        )

    return frozenset(verified)


def _accept(
    envelope: Any,
    manifest: Any,
    test_keys: Any,
    constraints: Any,
) -> AcceptanceReport:
    parsed_manifest = Manifest.from_value(manifest)
    parsed_constraints = MetadataConstraints.from_value(constraints)
    parsed_keys = _coerce_test_keys(test_keys)

    metadata_digest = _verify_metadata_binding(parsed_constraints, parsed_manifest)
    message, envelope_digest, _ = _decode_envelope(envelope)
    raw_recipients = _collect_envelope_recipients(message)
    recipients = _resolve_recipient_nodes(raw_recipients, parsed_manifest)

    _check_recipient_set(recipients, parsed_manifest, parsed_constraints)

    declared_by_node = {recipient.node: recipient.declared for recipient in recipients}
    _check_key_authorization(
        parsed_keys, parsed_manifest, parsed_constraints, declared_by_node
    )

    commitments = parsed_manifest.by_node
    accepted_recipients = []
    for recipient in recipients:
        commitment = commitments[recipient.node]
        request, source = parsed_constraints.request_for(
            recipient.node, recipient.declared
        )
        _check_scope(recipient.node, commitment, request)
        accepted_recipients.append(
            AcceptedRecipient(
                node=recipient.node,
                allowed_purposes=commitment.sorted_purposes,
                allowed_attachment_groups=commitment.sorted_attachment_groups,
                requested_purpose=request.purpose,
                requested_attachment_groups=None
                if request.attachment_groups is None
                else tuple(sorted(request.attachment_groups)),
                scope_source=source,
                cryptographically_verified=False,
                algorithm=recipient.algorithm,
            )
        )

    verified = _verify_cryptography(
        message, recipients, parsed_keys, parsed_constraints
    )
    if verified:
        accepted_recipients = [
            AcceptedRecipient(
                node=item.node,
                allowed_purposes=item.allowed_purposes,
                allowed_attachment_groups=item.allowed_attachment_groups,
                requested_purpose=item.requested_purpose,
                requested_attachment_groups=item.requested_attachment_groups,
                scope_source=item.scope_source,
                cryptographically_verified=item.node in verified,
                algorithm=item.algorithm,
            )
            for item in accepted_recipients
        ]

    # The receipt is constructed only after every check above has succeeded.
    receipt = AcceptanceReceipt(
        envelope_digest=envelope_digest,
        manifest_digest=parsed_manifest.digest,
        constraints_digest=parsed_constraints.digest,
        metadata_digest=metadata_digest,
        recipients=tuple(accepted_recipients),
    )
    return AcceptanceReport(
        accepted=True,
        receipt=receipt,
        recipients=tuple(accepted_recipients),
        envelope_digest=envelope_digest,
        manifest_digest=parsed_manifest.digest,
    )


def accept_envelope(
    envelope: Any,
    manifest: Any = None,
    test_keys: Any = None,
    constraints: Any = None,
    **kwargs: Any,
) -> AcceptanceReport:
    """Check a COSE encryption envelope and return a metadata-only pass report.

    The payload is never returned.  If payload verification is enabled (the
    default), local authorized test keys unwrap the CEK and authenticate the
    payload internally; only a structural hashes survive into the receipt.

    :raises EnvelopeAcceptanceError: if any check fails.  No receipt is
        constructed or returned in that case.
    """
    if manifest is None:
        manifest = kwargs.pop("business_manifest", None)
    if test_keys is None:
        test_keys = kwargs.pop("keys", None)
        if test_keys is None:
            test_keys = kwargs.pop("local_keys", None)
    if constraints is None:
        constraints = kwargs.pop("metadata_constraints", None)
        if constraints is None:
            constraints = kwargs.pop("metadata", None)

    overrides = {}
    for name in (
        "purpose",
        "attachment_groups",
        "recipient_requests",
        "required_recipients",
        "verify_payload",
        "require_exact_recipients",
        "require_all_keys",
        "require_test_key",
    ):
        if name in kwargs:
            overrides[name] = kwargs.pop(name)
    if overrides:
        if constraints is None:
            constraints = overrides
        else:
            merged = MetadataConstraints.from_value(constraints).to_dict()
            merged.update(overrides)
            constraints = merged
    if kwargs:
        raise TypeError(
            "unexpected acceptance arguments: {}".format(", ".join(sorted(kwargs)))
        )
    return _accept(envelope, manifest, test_keys, constraints)


def check_envelope(
    envelope: Any,
    manifest: Any = None,
    test_keys: Any = None,
    constraints: Any = None,
    **kwargs: Any,
) -> AcceptanceReport:
    """Non-raising variant of :func:`accept_envelope`.

    A rejected check returns ``accepted=False`` and ``receipt=None``.  It never
    returns a partial or stale pass receipt for a later publication step.
    """
    try:
        return accept_envelope(envelope, manifest, test_keys, constraints, **kwargs)
    except EnvelopeAcceptanceError as exc:
        conflicts = (
            tuple(commitment.to_dict() for commitment in exc.commitments)
            if isinstance(exc, PolicyConflictError)
            else tuple()
        )
        return AcceptanceReport(
            accepted=False,
            receipt=None,
            recipients=tuple(),
            envelope_digest=None,
            manifest_digest=None,
            errors=(str(exc),),
            error_type=type(exc).__name__,
            conflicts=conflicts,
        )


class EnvelopeAcceptor:
    """Reusable acceptance configuration for one manifest and key set."""

    def __init__(self, manifest: Any, test_keys: Any = None, constraints: Any = None):
        self.manifest = Manifest.from_value(manifest)
        self.test_keys = tuple(_coerce_test_keys(test_keys))
        self.constraints = MetadataConstraints.from_value(constraints)

    def accept(self, envelope: Any) -> AcceptanceReport:
        return accept_envelope(
            envelope, self.manifest, self.test_keys, self.constraints
        )

    def check(self, envelope: Any) -> AcceptanceReport:
        return check_envelope(envelope, self.manifest, self.test_keys, self.constraints)

    __call__ = accept


EnvelopeValidator = EnvelopeAcceptor
EnvelopeVerifier = EnvelopeAcceptor


def require_publication_receipt(
    receipt: Any,
    envelope: Any = None,
    manifest: Any = None,
    constraints: Any = None,
) -> AcceptanceReceipt:
    """Return a pass receipt for downstream publication or raise ``ReceiptError``.

    Passing an :class:`AcceptanceReport` is allowed; a rejected report has no
    receipt, so publication is blocked.  If envelope/manifest/constraints are
    supplied, the receipt must bind to them.
    """
    if isinstance(receipt, AcceptanceReport):
        receipt = receipt.receipt
    if receipt is None:
        raise ReceiptError("no acceptance receipt was issued; publication is blocked")
    if not isinstance(receipt, AcceptanceReceipt):
        raise ReceiptError("publication requires an AcceptanceReceipt")
    if not receipt.matches(
        envelope=envelope, manifest=manifest, constraints=constraints
    ):
        raise ReceiptError("acceptance receipt does not bind to this publication")
    return receipt


require_pass_receipt = require_publication_receipt
verify_envelope = accept_envelope
validate_envelope = accept_envelope
accept_cose_envelope = accept_envelope
local_envelope_acceptance = accept_envelope
