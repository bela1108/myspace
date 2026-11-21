"""Password-free inspection of the protection applied to Office files.

The decryption API in :mod:`msoffcrypto` is deliberately not used here.  An
attachment intake service often only needs to know which protection an old
Office document claims to use, not whether a particular password is correct.
Parsing the public protection headers is enough for that job and works for
files whose password cannot be recovered.

The central object is :class:`ProtectionRecord`: a small, JSON-friendly
mapping with a stable schema.  Records are produced by
:func:`inspect_protection` and can be compared with a caller supplied
:class:`ProtectionPolicy` (or a plain mapping / callable).

Three outcomes are kept distinct on purpose:

``plaintext``
    The document is not protected.

``unknown``
    The protection type is known (or at least detected), but one or more
    parameters needed by the policy could not be read.

``non_compliant``
    Enough protection parameters were read to prove that the policy is
    violated.  A known parameter always wins over a missing one: for
    example, an explicitly disallowed RC4 cipher is non-compliant even if
    the hash algorithm cannot be read.

A fourth outcome, ``compliant``, means the policy comparison succeeded.
"""

from __future__ import annotations

import io
import json
import os
from collections.abc import Iterable, Mapping
from enum import StrEnum
from struct import unpack, unpack_from
from typing import Any

from msoffcrypto import exceptions


class ProtectionStatus(StrEnum):
    """Outcome of comparing a protection record with a policy."""

    PLAINTEXT = "plaintext"
    UNKNOWN = "unknown"
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"

    # Descriptive aliases used by some callers.
    CLEAR = "plaintext"
    INDETERMINATE = "unknown"
    UNKNOWN_PARAMETERS = "unknown"
    PARAMETERS_UNKNOWN = "unknown"
    PASS = "compliant"
    FAIL = "non_compliant"
    NONCOMPLIANT = "non_compliant"


ACTION_ARCHIVE = "archive"
ACTION_SUPPLEMENT = "supplement"
ACTION_ACCEPT = ACTION_ARCHIVE
ACTION_REQUEST_MATERIALS = ACTION_SUPPLEMENT
ACTION_NEEDS_MATERIALS = ACTION_SUPPLEMENT
ACTION_REJECT = ACTION_SUPPLEMENT


class ProtectionRecord(dict):
    """A normalized, policy-comparable protection record.

    The object is a ordinary ``dict`` at heart, so it can be serialized or
    compared with a mapping directly.  Attribute access is provided as a
    convenience for callers that prefer ``record.status`` to
    ``record["status"]``.
    """

    _ALIASES = {
        "type": "protection_type",
        "encryption_type": "protection_type",
        "file_format": "format",
        "source_name": "source",
        "method": "protection_type",
        "key_bits": "key_size",
        "cipher": "algorithm",
        "cipher_algorithm": "algorithm",
        "hash": "hash_algorithm",
        "name": "source",
        "path": "source",
        "attributes": "details",
        "raw": "details",
        "reason": "reasons",
    }

    def __getattr__(self, name: str) -> Any:
        name = self._ALIASES.get(name, name)
        if name == "is_plaintext":
            return self["status"] == ProtectionStatus.PLAINTEXT
        try:
            value = self[name]
        except KeyError as exc:  # pragma: no cover - normal Python attribute error
            raise AttributeError(name) from exc
        if name == "status":
            return ProtectionStatus(value)
        return value

    @property
    def is_encrypted(self) -> bool:
        return bool(self["encrypted"])

    @property
    def archivable(self) -> bool:
        return self["action"] == ACTION_ARCHIVE

    @property
    def needs_materials(self) -> bool:
        return self["action"] == ACTION_SUPPLEMENT

    @property
    def request_materials(self) -> bool:
        return self["action"] == ACTION_SUPPLEMENT

    @property
    def decision(self) -> str:
        return self["action"]

    @property
    def is_compliant(self) -> bool | None:
        return self["compliant"]

    @property
    def status_label(self) -> str:
        return {
            "plaintext": "plaintext",
            "unknown": "protection known, parameters unknown",
            "non_compliant": "parameters confirmed non-compliant",
            "compliant": "parameters compliant",
        }.get(str(self["status"]), str(self["status"]))

    def evaluate(self, policy: Any = None) -> "ProtectionRecord":
        """Return a copy evaluated against *policy*."""
        return _apply_policy(ProtectionRecord(self), policy)

    check = evaluate
    with_policy = evaluate

    @classmethod
    def from_attributes(cls, **attributes: Any) -> "ProtectionRecord":
        """Build a record from already-read public attributes."""
        return record_from_attributes(**attributes)

    @classmethod
    def from_dict(cls, mapping: Mapping[str, Any]) -> "ProtectionRecord":
        return cls(mapping)

    @classmethod
    def from_source(
        cls, source: Any, policy: Any = None, **kwargs: Any
    ) -> "ProtectionRecord":
        return inspect_protection(source, policy=policy, **kwargs)

    # Namedtuple-like helper for callers that use the traditional API shape.
    def _asdict(self) -> dict:
        return dict(self)

    def to_dict(self) -> dict:
        return dict(self)

    def to_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("ensure_ascii", False)
        return json.dumps(dict(self), **kwargs)


def _as_frozenset(value: Any) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return frozenset([value])
    return frozenset(str(item) for item in value)


def _normalize_token(value: Any) -> str:
    """Case/punctuation-insensitive token used for policy matching."""

    if value is None:
        return ""
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def _algorithm_matches(actual: str | None, allowed: frozenset[str] | None) -> bool:
    if allowed is None:
        return True
    if actual is None:
        return False
    actual_token = _normalize_token(actual)
    for item in allowed:
        token = _normalize_token(item)
        if not token:
            continue
        if actual_token == token:
            return True
        # "AES" should cover AES-128/AES-192/AES-256, and "SHA" should
        # cover SHA1/SHA256/... without listing every family member.
        if token in {"aes", "rc4", "sha", "des", "3des"} and actual_token.startswith(token):
            return True
    return False


def _type_matches(actual: str | None, allowed: frozenset[str] | None) -> bool:
    if allowed is None:
        return True
    if actual is None:
        return False
    actual_token = _normalize_token(actual)
    aliases = {
        "rc4cryptoapi": {"rc4cryptoapi", "rc4"},
        "rc4": {"rc4", "rc4legacy"},
        "xor": {"xor", "xorobfuscation"},
        "agile": {"agile", "ecma376agile"},
        "standard": {"standard", "ecma376standard"},
        "extensible": {"extensible", "ecma376extensible"},
        "plaintext": {"plaintext", "plain", "none"},
    }
    actual_aliases = aliases.get(actual_token, {actual_token})
    for item in allowed:
        token = _normalize_token(item)
        if token in actual_aliases:
            return True
        # Also accept the algorithm when callers say e.g. "AES".
        if token and actual_token.startswith(token):
            return True
    return False


class ProtectionPolicy:
    """Caller supplied rules for comparing protection records.

    The defaults are intentionally permissive: they only require that a
    protection, if present, can be fully described.  Anything stronger must
    be injected by the service that owns the internal policy.

    ``allowed_types`` and ``allowed_algorithms`` accept either a single
    string or an iterable.  ``min_key_size`` is expressed in bits.
    """

    __slots__ = (
        "allow_plaintext",
        "allowed_types",
        "allowed_algorithms",
        "allowed_hash_algorithms",
        "allowed_key_sizes",
        "min_key_size",
        "max_key_size",
        "min_spin_count",
        "max_spin_count",
        "forbidden_types",
        "forbidden_algorithms",
    )

    def __init__(
        self,
        *,
        allow_plaintext: bool = True,
        allowed_types: Any = None,
        allowed_algorithms: Any = None,
        allowed_hash_algorithms: Any = None,
        allowed_key_sizes: Any = None,
        min_key_size: int | None = None,
        max_key_size: int | None = None,
        min_spin_count: int | None = None,
        max_spin_count: int | None = None,
        forbidden_types: Any = None,
        forbidden_algorithms: Any = None,
        require_encryption: bool | None = None,
    ) -> None:
        if require_encryption is not None:
            allow_plaintext = not require_encryption
        self.allow_plaintext = bool(allow_plaintext)
        self.allowed_types = _as_frozenset(allowed_types)
        self.allowed_algorithms = _as_frozenset(allowed_algorithms)
        self.allowed_hash_algorithms = _as_frozenset(allowed_hash_algorithms)
        self.allowed_key_sizes = _as_frozenset(allowed_key_sizes)
        self.min_key_size = None if min_key_size is None else int(min_key_size)
        self.max_key_size = None if max_key_size is None else int(max_key_size)
        self.min_spin_count = None if min_spin_count is None else int(min_spin_count)
        self.max_spin_count = None if max_spin_count is None else int(max_spin_count)
        self.forbidden_types = _as_frozenset(forbidden_types)
        self.forbidden_algorithms = _as_frozenset(forbidden_algorithms)

    @property
    def require_encryption(self) -> bool:
        return not self.allow_plaintext

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProtectionPolicy":
        aliases = {
            "plaintext_allowed": "allow_plaintext",
            "permit_plaintext": "allow_plaintext",
            "protection_types": "allowed_types",
            "allowed_protection_types": "allowed_types",
            "algorithms": "allowed_algorithms",
            "allowed_ciphers": "allowed_algorithms",
            "hash_algorithms": "allowed_hash_algorithms",
            "minimum_key_size": "min_key_size",
            "min_key_bits": "min_key_size",
            "maximum_key_size": "max_key_size",
            "max_key_bits": "max_key_size",
            "allowed_key_bits": "allowed_key_sizes",
            "allowed_methods": "allowed_types",
            "minimum_spin_count": "min_spin_count",
            "maximum_spin_count": "max_spin_count",
            "denied_types": "forbidden_types",
            "denied_algorithms": "forbidden_algorithms",
        }
        kwargs: dict[str, Any] = {}
        for key, val in value.items():
            normalized = aliases.get(key, key)
            if normalized in ("deny_plaintext", "plaintext_forbidden"):
                kwargs["allow_plaintext"] = not val
            elif normalized in cls.__slots__ or normalized == "require_encryption":
                kwargs[normalized] = val
        return cls(**kwargs)

    def to_dict(self) -> dict:
        def _list(value: frozenset[str] | None) -> list[str] | None:
            return None if value is None else sorted(value)

        return {
            "allow_plaintext": self.allow_plaintext,
            "require_encryption": self.require_encryption,
            "allowed_types": _list(self.allowed_types),
            "allowed_algorithms": _list(self.allowed_algorithms),
            "allowed_hash_algorithms": _list(self.allowed_hash_algorithms),
            "allowed_key_sizes": _list(self.allowed_key_sizes),
            "min_key_size": self.min_key_size,
            "max_key_size": self.max_key_size,
            "min_spin_count": self.min_spin_count,
            "max_spin_count": self.max_spin_count,
            "forbidden_types": _list(self.forbidden_types),
            "forbidden_algorithms": _list(self.forbidden_algorithms),
        }

    def evaluate(self, record: Mapping[str, Any]) -> tuple[str, bool | None, str, list[str]]:
        """Return ``(status, compliant, action, reasons)`` for *record*."""

        reasons: list[str] = []
        encrypted = bool(record.get("encrypted"))

        if not encrypted:
            if self.allow_plaintext:
                return ProtectionStatus.PLAINTEXT, True, ACTION_ARCHIVE, reasons
            reasons.append("plaintext is not allowed by policy")
            return ProtectionStatus.PLAINTEXT, False, ACTION_SUPPLEMENT, reasons

        protection_type = record.get("protection_type")
        algorithm = record.get("algorithm")
        key_size = record.get("key_size")
        hash_algorithm = record.get("hash_algorithm")
        spin_count = record.get("spin_count")
        missing = list(record.get("missing_parameters") or [])

        if protection_type in (None, "", "unknown"):
            missing.append("protection_type")

        # A known violation is decisive even when other parameters are
        # missing.  This is the "confirmed non-compliant" bucket.
        if protection_type not in (None, "", "unknown"):
            if self.forbidden_types and _type_matches(protection_type, self.forbidden_types):
                reasons.append(
                    "protection type {!r} is forbidden by policy".format(protection_type)
                )
            elif self.allowed_types is not None and not _type_matches(
                protection_type, self.allowed_types
            ):
                reasons.append(
                    "protection type {!r} is not allowed by policy".format(
                        protection_type
                    )
                )

        if algorithm is not None:
            if self.forbidden_algorithms and _algorithm_matches(
                algorithm, self.forbidden_algorithms
            ):
                reasons.append(
                    "algorithm {!r} is forbidden by policy".format(algorithm)
                )
            elif self.allowed_algorithms is not None and not _algorithm_matches(
                algorithm, self.allowed_algorithms
            ):
                reasons.append("algorithm {!r} is not allowed by policy".format(algorithm))
        elif self.allowed_algorithms is not None:
            missing.append("algorithm")

        if key_size is not None:
            if self.allowed_key_sizes is not None and str(key_size) not in {
                _normalize_token(v) for v in self.allowed_key_sizes
            }:
                reasons.append(
                    "key size {} bits is not an allowed key size".format(key_size)
                )
            if self.min_key_size is not None and key_size < self.min_key_size:
                reasons.append(
                    "key size {} bits is below the {} bit minimum".format(
                        key_size, self.min_key_size
                    )
                )
            if self.max_key_size is not None and key_size > self.max_key_size:
                reasons.append(
                    "key size {} bits is above the {} bit maximum".format(
                        key_size, self.max_key_size
                    )
                )
        elif (
            self.min_key_size is not None
            or self.max_key_size is not None
            or self.allowed_key_sizes is not None
        ):
            missing.append("key_size")

        if hash_algorithm is not None:
            if self.allowed_hash_algorithms is not None and not _algorithm_matches(
                hash_algorithm, self.allowed_hash_algorithms
            ):
                reasons.append(
                    "hash algorithm {!r} is not allowed by policy".format(
                        hash_algorithm
                    )
                )
        elif self.allowed_hash_algorithms is not None:
            missing.append("hash_algorithm")

        if spin_count is not None:
            if self.min_spin_count is not None and spin_count < self.min_spin_count:
                reasons.append(
                    "spin count {} is below the {} minimum".format(
                        spin_count, self.min_spin_count
                    )
                )
            if self.max_spin_count is not None and spin_count > self.max_spin_count:
                reasons.append(
                    "spin count {} is above the {} maximum".format(
                        spin_count, self.max_spin_count
                    )
                )
        elif self.min_spin_count is not None or self.max_spin_count is not None:
            missing.append("spin_count")

        if reasons:
            return ProtectionStatus.NON_COMPLIANT, False, ACTION_SUPPLEMENT, reasons

        if missing:
            for name in dict.fromkeys(missing):
                reasons.append("{} is not available".format(name))
            return ProtectionStatus.UNKNOWN, None, ACTION_SUPPLEMENT, reasons

        return ProtectionStatus.COMPLIANT, True, ACTION_ARCHIVE, reasons


def _coerce_policy(policy: Any) -> Any:
    if policy is None:
        return ProtectionPolicy()
    if isinstance(policy, ProtectionPolicy):
        return policy
    if isinstance(policy, Mapping):
        return ProtectionPolicy.from_mapping(policy)
    if hasattr(policy, "evaluate") and callable(policy.evaluate):
        return policy
    if callable(policy):
        return policy
    raise TypeError(
        "policy must be a ProtectionPolicy, mapping, callable, or object with evaluate()"
    )


def _apply_policy(record: ProtectionRecord, policy: Any) -> ProtectionRecord:
    policy = _coerce_policy(policy)

    if isinstance(policy, ProtectionPolicy):
        status, compliant, action, reasons = policy.evaluate(record)
    elif callable(policy):
        result = policy(record)
        status, compliant, action, reasons = _interpret_policy_result(result, record)
    else:  # object with evaluate()
        result = policy.evaluate(record)
        status, compliant, action, reasons = _interpret_policy_result(result, record)

    record["status"] = str(status)
    record["compliant"] = compliant
    record["action"] = action
    record["reasons"] = reasons
    return record


def _interpret_policy_result(
    result: Any, record: Mapping[str, Any]
) -> tuple[str, bool | None, str, list[str]]:
    if isinstance(result, ProtectionStatus):
        status = result
        reasons: list[str] = []
        compliant = status == ProtectionStatus.COMPLIANT
        if status == ProtectionStatus.PLAINTEXT:
            compliant = True
            action = ACTION_ARCHIVE
        else:
            action = (
                ACTION_ARCHIVE if status == ProtectionStatus.COMPLIANT else ACTION_SUPPLEMENT
            )
        return str(status), compliant, action, reasons

    if isinstance(result, str):
        try:
            status = ProtectionStatus(result)
        except ValueError as exc:
            raise ValueError("unknown policy status: {!r}".format(result)) from exc
        return _interpret_policy_result(status, record)

    if isinstance(result, bool) or result is None:
        if result is None:
            return ProtectionStatus.UNKNOWN, None, ACTION_SUPPLEMENT, []
        if result:
            return ProtectionStatus.COMPLIANT, True, ACTION_ARCHIVE, []
        return ProtectionStatus.NON_COMPLIANT, False, ACTION_SUPPLEMENT, []

    if isinstance(result, tuple):
        status = result[0]
        reasons = list(result[1]) if len(result) > 1 and result[1] is not None else []
        if isinstance(status, ProtectionStatus):
            return _interpret_policy_result(status, record)[0:3] + (reasons,)
        if isinstance(status, str):
            return _interpret_policy_result(status, record)[0:3] + (reasons,)
        if isinstance(status, bool):
            base = _interpret_policy_result(status, record)
            return base[0], base[1], base[2], reasons

    if isinstance(result, Mapping):
        status = result.get("status")
        if status is None:
            compliant = result.get("compliant")
            status = (
                ProtectionStatus.COMPLIANT
                if compliant
                else ProtectionStatus.NON_COMPLIANT
                if compliant is False
                else ProtectionStatus.UNKNOWN
            )
        reasons = list(result.get("reasons") or [])
        return _interpret_policy_result(status, record)[0:3] + (reasons,)

    raise TypeError("unsupported result from policy callable: {!r}".format(result))


def evaluate(record: Mapping[str, Any], policy: Any = None) -> ProtectionRecord:
    """Re-evaluate an already normalized record against *policy*."""
    result = ProtectionRecord(record)
    return _apply_policy(result, policy)


evaluate_record = evaluate
apply_policy = evaluate


def record_from_attributes(
    format: str,
    encrypted: bool,
    protection_type: str | None = None,
    algorithm: str | None = None,
    key_size: int | None = None,
    hash_algorithm: str | None = None,
    spin_count: int | None = None,
    provider_type: int | None = None,
    parameters_known: bool = True,
    missing_parameters: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    source: str | None = None,
    policy: Any = None,
) -> ProtectionRecord:
    """Convert already-read public attributes into a protection record."""

    missing = list(dict.fromkeys(str(name) for name in missing_parameters))
    if not parameters_known and not missing:
        missing.append("parameters")
    if not encrypted:
        protection_type = "plaintext"
        missing = []

    record = ProtectionRecord(
        source=source,
        format=format,
        encrypted=bool(encrypted),
        protection_type=protection_type,
        algorithm=algorithm,
        key_size=key_size,
        hash_algorithm=hash_algorithm,
        spin_count=spin_count,
        provider_type=provider_type,
        parameters_known=bool(parameters_known) and not missing,
        missing_parameters=missing,
        details=dict(details or {}),
        status="",  # filled in by the policy comparison
        compliant=None,
        action="",
        reasons=[],
    )
    return _apply_policy(record, policy)


def _header_algorithm(alg_id: int | None) -> str | None:
    if alg_id is None:
        return None
    return {
        0x00000000: "RC4",
        0x00006801: "RC4",
        0x0000660E: "AES-128",
        0x0000660F: "AES-192",
        0x00006610: "AES-256",
    }.get(alg_id)


def _header_hash(alg_id: int | None) -> str | None:
    if alg_id is None:
        return None
    return {
        0x00000000: "SHA1",
        0x00008003: "MD5",
        0x00008004: "SHA1",
        0x0000800C: "SHA256",
        0x0000800D: "SHA384",
        0x0000800E: "SHA512",
    }.get(alg_id)


def _read_version(stream: Any) -> tuple[int, int] | None:
    data = stream.read(4)
    if len(data) != 4:
        return None
    return unpack("<HH", data)


def parse_encryption_header(
    data: bytes | bytearray | memoryview | Any,
) -> dict:
    """Parse an ``EncryptionHeader`` blob (without the outer prefix).

    The mapping contains the specification names (``algId``, ``keySize``,
    ...) as well as snake_case aliases used by the rest of this module.
    """

    if isinstance(data, (bytes, bytearray, memoryview)):
        blob = bytes(data)
    else:
        blob = data.read()
    if len(blob) < 32:
        raise exceptions.ParseError("Incomplete encryption header")
    (
        flags,
        size_extra,
        alg_id,
        alg_id_hash,
        key_size,
        provider_type,
        reserved1,
        reserved2,
    ) = unpack_from("<IIIIIIII", blob, 0)
    csp_name = ""
    if len(blob) > 32:
        try:
            csp_name = blob[32:].decode("utf-16le").rstrip("\x00")
        except UnicodeDecodeError:
            csp_name = ""
    return {
        "flags": flags,
        "sizeExtra": size_extra,
        "algId": alg_id,
        "algIdHash": alg_id_hash,
        "keySize": key_size,
        "providerType": provider_type,
        "reserved1": reserved1,
        "reserved2": reserved2,
        "cspName": csp_name,
        "header_flags": flags,
        "size_extra": size_extra,
        "alg_id": alg_id,
        "alg_id_hash": alg_id_hash,
        "key_size": key_size,
        "provider_type": provider_type,
        "csp_name": csp_name,
    }


def parse_cryptoapi_header(data: bytes | bytearray | memoryview | Any) -> dict:
    """Parse the public part of an RC4 CryptoAPI encryption header.

    *data* may be bytes or a seekable binary stream positioned at the
    reserved/header-size fields (that is, immediately after the four-byte
    version field).  No verifier or password material is required.

    The returned mapping uses the raw specification names.  A short or
    malformed header raises :class:`msoffcrypto.exceptions.ParseError`.
    """

    if isinstance(data, (bytes, bytearray, memoryview)):
        stream = io.BytesIO(bytes(data))
    else:
        stream = data

    prefix = stream.read(8)
    if len(prefix) != 8:
        raise exceptions.ParseError("Incomplete RC4 CryptoAPI header prefix")
    flags, header_size = unpack("<II", prefix)
    blob = stream.read(header_size)
    if len(blob) != header_size or header_size < 32:
        raise exceptions.ParseError("Incomplete RC4 CryptoAPI encryption header")

    inner = parse_encryption_header(blob)
    result = {
        "flags": flags,
        "header_size": header_size,
    }
    result.update(inner)
    result["flags"] = flags
    return result


def _cryptoapi_attributes(
    *,
    format: str,
    version: tuple[int, int] | None,
    header: Mapping[str, Any],
    source: str | None = None,
) -> dict:
    alg_id = header.get("alg_id")
    alg_id_hash = header.get("alg_id_hash")
    raw_key_size = header.get("key_size")
    key_size = 40 if raw_key_size in (None, 0) else int(raw_key_size)
    algorithm = _header_algorithm(alg_id)
    hash_algorithm = _header_hash(alg_id_hash)
    missing: list[str] = []
    if algorithm is None:
        missing.append("algorithm")
    if hash_algorithm is None:
        missing.append("hash_algorithm")

    details = {
        "encryption_header": {
            "version": None if version is None else "{}.{}".format(*version),
            "flags": header.get("flags"),
            "size_extra": header.get("size_extra"),
            "alg_id": None if alg_id is None else "0x{:08x}".format(alg_id),
            "alg_id_hash": (
                None if alg_id_hash is None else "0x{:08x}".format(alg_id_hash)
            ),
            "provider_type": header.get("provider_type"),
            "csp_name": header.get("csp_name"),
        }
    }
    return {
        "format": format,
        "encrypted": True,
        "protection_type": "rc4_cryptoapi",
        "algorithm": algorithm,
        "key_size": key_size,
        "hash_algorithm": hash_algorithm,
        "provider_type": header.get("provider_type"),
        "parameters_known": not missing,
        "missing_parameters": missing,
        "details": details,
        "source": source,
    }


def _partial_attributes(
    *,
    format: str,
    protection_type: str,
    missing: Iterable[str],
    details: Mapping[str, Any] | None = None,
    algorithm: str | None = None,
    key_size: int | None = None,
    hash_algorithm: str | None = None,
    source: str | None = None,
) -> dict:
    return {
        "format": format,
        "encrypted": True,
        "protection_type": protection_type,
        "algorithm": algorithm,
        "key_size": key_size,
        "hash_algorithm": hash_algorithm,
        "parameters_known": False,
        "missing_parameters": list(dict.fromkeys(missing)),
        "details": dict(details or {}),
        "source": source,
    }


def _plain_attributes(
    *, format: str, details: Mapping[str, Any] | None = None, source: str | None = None
) -> dict:
    return {
        "format": format,
        "encrypted": False,
        "protection_type": "plaintext",
        "algorithm": None,
        "key_size": None,
        "hash_algorithm": None,
        "parameters_known": True,
        "missing_parameters": [],
        "details": dict(details or {}),
        "source": source,
    }


def _legacy_rc4_attributes(
    *, format: str, details: Mapping[str, Any] | None = None, source: str | None = None
) -> dict:
    # Office binary RC4 (version 1.1) has no parameter block.  The method
    # itself fixes RC4/128-bit/MD5 key derivation.
    return {
        "format": format,
        "encrypted": True,
        "protection_type": "rc4",
        "algorithm": "RC4",
        "key_size": 128,
        "hash_algorithm": "MD5",
        "parameters_known": True,
        "missing_parameters": [],
        "details": dict(details or {}),
        "source": source,
    }


def _xor_attributes(
    *, format: str, details: Mapping[str, Any] | None = None, source: str | None = None
) -> dict:
    return {
        "format": format,
        "encrypted": True,
        "protection_type": "xor",
        "algorithm": "XOR",
        "key_size": None,
        "hash_algorithm": None,
        "parameters_known": True,
        "missing_parameters": [],
        "details": dict(details or {}),
        "source": source,
    }


def _unreadable_encryption(
    *,
    format: str,
    details: Mapping[str, Any] | None = None,
    protection_type: str = "unknown",
    missing: Iterable[str] = ("protection_type", "algorithm", "key_size", "hash_algorithm"),
    source: str | None = None,
) -> dict:
    return _partial_attributes(
        format=format,
        protection_type=protection_type,
        missing=missing,
        details=details,
        source=source,
    )


def doc97_protection_attributes(file: Any, source: str | None = None) -> dict:
    """Read protection attributes from an already-open Doc97File."""

    fib = file.info.fib.base
    details = {
        "nFib": fib.nFib,
        "envr": fib.envr,
        "fEncrypted": fib.fEncrypted,
        "fObfuscation": fib.fObfuscation,
        "IKey": fib.IKey,
    }
    if not fib.fEncrypted:
        return _plain_attributes(format="doc97", details=details, source=source)
    if fib.fObfuscation:
        return _xor_attributes(format="doc97", details=details, source=source)

    try:
        with file.ole.openstream(file.info.tablename) as table:
            version = _read_version(table)
            if version is None:
                return _unreadable_encryption(
                    format="doc97",
                    details=details,
                    protection_type="rc4_cryptoapi",
                    missing=("version", "algorithm", "key_size", "hash_algorithm"),
                    source=source,
                )
            details["version"] = "{}.{}".format(*version)
            if version == (1, 1):
                return _legacy_rc4_attributes(
                    format="doc97", details=details, source=source
                )
            if version[0] in (2, 3, 4) and version[1] == 2:
                try:
                    header = parse_cryptoapi_header(table)
                except Exception as exc:
                    partial = _unreadable_encryption(
                        format="doc97",
                        details=details,
                        protection_type="rc4_cryptoapi",
                        missing=("algorithm", "key_size", "hash_algorithm"),
                        source=source,
                    )
                    partial["details"]["error"] = str(exc)
                    return partial
                return _cryptoapi_attributes(
                    format="doc97", version=version, header=header, source=source
                )
            return _unreadable_encryption(
                format="doc97",
                details=details,
                protection_type="unknown",
                source=source,
            )
    except Exception as exc:
        partial = _unreadable_encryption(
            format="doc97",
            details=details,
            protection_type="unknown",
            source=source,
        )
        partial["details"]["error"] = str(exc)
        return partial


def _iter_biff_globals(workbook: Any) -> tuple[str, dict]:
    """Walk the BIFF Globals substream without decrypting it.

    Returns ``(state, details)`` where *state* is one of ``plaintext``,
    ``filepass``, or ``truncated``.
    """

    workbook.seek(0)
    header = workbook.read(4)
    if len(header) < 4:
        return "truncated", {}
    record_id, size = unpack("<HH", header)
    if record_id != 2057:  # BOF
        return "truncated", {"error": "Workbook does not start with BOF"}
    if len(workbook.read(size)) != size:
        return "truncated", {}

    while True:
        header = workbook.read(4)
        if not header:
            return "truncated", {}
        if len(header) < 4:
            return "truncated", {}
        record_id, size = unpack("<HH", header)
        payload = workbook.read(size)
        if len(payload) != size:
            if record_id == 47:  # FilePass; keep the bytes needed to identify the type.
                return "filepass", {"payload": payload, "truncated": True}
            return "truncated", {"record": record_id}
        if record_id == 47:  # FilePass
            return "filepass", {"payload": payload}
        if record_id == 10:  # EOF of Globals
            return "plaintext", {}


def xls97_protection_attributes(file: Any, source: str | None = None) -> dict:
    """Read protection attributes from an already-open Xls97File."""

    state, details = _iter_biff_globals(file.data.workbook)
    if state == "plaintext":
        return _plain_attributes(format="xls97", details=details, source=source)
    if state == "truncated":
        return _unreadable_encryption(
            format="xls97",
            details=details,
            protection_type="unknown",
            source=source,
        )

    payload = details.pop("payload")
    truncated = details.pop("truncated", False)
    if len(payload) < 2:
        return _unreadable_encryption(
            format="xls97", details=details, protection_type="unknown", source=source
        )
    (encryption_type,) = unpack("<H", payload[:2])
    details["wEncryptionType"] = encryption_type
    if encryption_type == 0x0000:
        attributes = _xor_attributes(format="xls97", details=details, source=source)
        if truncated:
            attributes["parameters_known"] = False
            attributes["missing_parameters"] = ["verifier"]
        return attributes
    if encryption_type != 0x0001:
        return _unreadable_encryption(
            format="xls97", details=details, protection_type="unknown", source=source
        )

    stream = io.BytesIO(payload[2:])
    version = _read_version(stream)
    if version is None:
        return _unreadable_encryption(
            format="xls97",
            details=details,
            protection_type="rc4",
            missing=("version", "algorithm", "key_size", "hash_algorithm"),
            source=source,
        )
    details["version"] = "{}.{}".format(*version)
    if version == (1, 1):
        attributes = _legacy_rc4_attributes(
            format="xls97", details=details, source=source
        )
        if truncated:
            attributes["parameters_known"] = False
            attributes["missing_parameters"] = ["verifier"]
        return attributes
    if version[0] in (2, 3, 4) and version[1] == 2:
        try:
            header = parse_cryptoapi_header(stream)
        except Exception as exc:
            partial = _unreadable_encryption(
                format="xls97",
                details=details,
                protection_type="rc4_cryptoapi",
                missing=("algorithm", "key_size", "hash_algorithm"),
                source=source,
            )
            partial["details"]["error"] = str(exc)
            return partial
        return _cryptoapi_attributes(
            format="xls97", version=version, header=header, source=source
        )
    return _unreadable_encryption(
        format="xls97",
        details=details,
        protection_type="rc4",
        missing=("algorithm", "key_size", "hash_algorithm"),
        source=source,
    )


def ppt97_protection_attributes(file: Any, source: str | None = None) -> dict:
    """Read protection attributes from an already-open Ppt97File."""

    from msoffcrypto.format.ppt97 import (
        _parseCryptSession10Container,
        _parseCurrentUser,
        _parseUserEditAtom,
        construct_persistobjectdirectory,
    )

    details: dict[str, Any] = {}
    try:
        file.data.currentuser.seek(0)
        currentuser = _parseCurrentUser(file.data.currentuser)
        details["headerToken"] = currentuser.currentuseratom.headerToken
        details["offsetToCurrentEdit"] = currentuser.currentuseratom.offsetToCurrentEdit

        file.data.powerpointdocument.seek(
            currentuser.currentuseratom.offsetToCurrentEdit
        )
        usereditatom = _parseUserEditAtom(file.data.powerpointdocument)
        details["userEditRecordLen"] = usereditatom.rh.recLen
        encrypted = bool(
            currentuser.currentuseratom.headerToken != 0xE391C05F
            or usereditatom.rh.recLen == 0x00000020
            or usereditatom.encryptSessionPersistIdRef
        )
        if not encrypted:
            return _plain_attributes(format="ppt97", details=details, source=source)

        details["encryptSessionPersistIdRef"] = usereditatom.encryptSessionPersistIdRef
        persist_directory = construct_persistobjectdirectory(file.data)
        persist_id = usereditatom.encryptSessionPersistIdRef
        if persist_id is None or persist_id not in persist_directory:
            return _unreadable_encryption(
                format="ppt97",
                details=details,
                protection_type="unknown",
                source=source,
            )

        file.data.powerpointdocument.seek(persist_directory[persist_id])
        container = _parseCryptSession10Container(file.data.powerpointdocument)
        stream = io.BytesIO(container.data)
        version = _read_version(stream)
        if version is None:
            return _unreadable_encryption(
                format="ppt97",
                details=details,
                protection_type="unknown",
                source=source,
            )
        details["version"] = "{}.{}".format(*version)
        if version == (1, 1):
            return _legacy_rc4_attributes(format="ppt97", details=details, source=source)
        if version[0] in (2, 3, 4) and version[1] == 2:
            try:
                header = parse_cryptoapi_header(stream)
            except Exception as exc:
                partial = _unreadable_encryption(
                    format="ppt97",
                    details=details,
                    protection_type="rc4_cryptoapi",
                    missing=("algorithm", "key_size", "hash_algorithm"),
                    source=source,
                )
                partial["details"]["error"] = str(exc)
                return partial
            return _cryptoapi_attributes(
                format="ppt97", version=version, header=header, source=source
            )
        return _unreadable_encryption(
            format="ppt97",
            details=details,
            protection_type="unknown",
            source=source,
        )
    except Exception as exc:
        partial = _unreadable_encryption(
            format="ppt97",
            details=details,
            protection_type="unknown",
            source=source,
        )
        partial["details"]["error"] = str(exc)
        return partial


def ooxml_protection_attributes(file: Any, source: str | None = None) -> dict:
    """Read protection attributes from an already-open OOXMLFile."""

    file_type = getattr(file, "type", None)
    if file_type == "plain":
        return _plain_attributes(format="ooxml", details={"type": "plain"}, source=source)
    if file_type == "extensible":
        return _unreadable_encryption(
            format="ooxml",
            details={"type": "extensible"},
            protection_type="extensible",
            missing=("algorithm", "key_size", "hash_algorithm"),
            source=source,
        )
    if file_type not in ("agile", "standard"):
        return _unreadable_encryption(
            format="ooxml", details={"type": file_type}, source=source
        )

    info = getattr(file, "info", {})
    if file_type == "agile":
        key_size = info.get("passwordKeyBits") or info.get("keyDataKeyBits")
        hash_algorithm = info.get("passwordHashAlgorithm") or info.get(
            "keyDataHashAlgorithm"
        )
        spin_count = info.get("spinValue")
        algorithm = (
            info.get("cipherAlgorithm")
            or info.get("keyDataCipherAlgorithm")
            or info.get("passwordCipherAlgorithm")
            or "AES"
        )
        missing = []
        if key_size is None:
            missing.append("key_size")
        if hash_algorithm is None:
            missing.append("hash_algorithm")
        details = {
            "type": "agile",
            "keyDataBlockSize": info.get("keyDataBlockSize"),
            "keyDataHashAlgorithm": info.get("keyDataHashAlgorithm"),
        }
        return {
            "format": "ooxml",
            "encrypted": True,
            "protection_type": "agile",
            "algorithm": algorithm,
            "key_size": key_size,
            "hash_algorithm": hash_algorithm,
            "spin_count": spin_count,
            "provider_type": None,
            "parameters_known": not missing,
            "missing_parameters": missing,
            "details": details,
            "source": source,
        }

    header = info.get("header", {}) if isinstance(info, Mapping) else {}
    alg_id = header.get("algId")
    alg_id_hash = header.get("algIdHash")
    key_size = header.get("keySize")
    if key_size in (None, 0) and alg_id in (None, 0, 0x00006801):
        key_size = 40
    algorithm = _header_algorithm(alg_id)
    hash_algorithm = _header_hash(alg_id_hash)
    missing = []
    if algorithm is None:
        missing.append("algorithm")
    if key_size is None:
        missing.append("key_size")
    if hash_algorithm is None:
        missing.append("hash_algorithm")
    return {
        "format": "ooxml",
        "encrypted": True,
        "protection_type": "standard",
        "algorithm": algorithm,
        "key_size": key_size,
        "hash_algorithm": hash_algorithm,
        "spin_count": None,
        "provider_type": header.get("providerType"),
        "parameters_known": not missing,
        "missing_parameters": missing,
        "details": {
            "type": "standard",
            "algId": None if alg_id is None else "0x{:08x}".format(alg_id),
            "algIdHash": (
                None if alg_id_hash is None else "0x{:08x}".format(alg_id_hash)
            ),
        },
        "source": source,
    }


def attributes_for(file: Any, source: str | None = None) -> dict:
    """Dispatch to the extractor matching *file*."""

    format_name = getattr(file, "format", None)
    if format_name == "doc97":
        return doc97_protection_attributes(file, source=source)
    if format_name == "xls97":
        return xls97_protection_attributes(file, source=source)
    if format_name == "ppt97":
        return ppt97_protection_attributes(file, source=source)
    if format_name == "ooxml":
        return ooxml_protection_attributes(file, source=source)
    raise exceptions.FileFormatError(
        "Cannot inspect protection for format {!r}".format(format_name)
    )


def _source_label(source: Any) -> str | None:
    name = getattr(source, "name", None)
    if isinstance(name, str):
        return name
    if isinstance(source, (str, os.PathLike)):
        return os.fspath(source)
    return None


def _open_source(source: Any) -> tuple[Any, bool, str | None]:
    """Return ``(OfficeFile, should_close, label)``."""

    from msoffcrypto import OfficeFile

    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        handle = open(path, "rb")
        try:
            return OfficeFile(handle), True, str(path)
        except Exception:
            handle.close()
            raise

    if isinstance(source, (bytes, bytearray, memoryview)):
        return OfficeFile(io.BytesIO(bytes(source))), True, None

    if hasattr(source, "read"):
        label = _source_label(source)
        source.seek(0)
        return OfficeFile(source), False, label

    if getattr(source, "format", None):
        return source, False, _source_label(getattr(source, "file", None))

    raise TypeError("source must be a path, file handle, bytes, or OfficeFile")


def inspect_protection(
    source: Any = None,
    policy: Any = None,
    *,
    source_name: str | None = None,
    path: Any = None,
    file: Any = None,
) -> ProtectionRecord:
    """Return a policy-evaluated :class:`ProtectionRecord` for *source*.

    No password is requested and no decryption is attempted.  *policy* may
    be a :class:`ProtectionPolicy`, a mapping, a callable, or an object with
    an ``evaluate(record)`` method.
    """

    if source is None:
        source = path if path is not None else file
    if source is None:
        raise TypeError("inspect_protection() requires a source")

    if isinstance(source, ProtectionRecord) or (
        isinstance(source, Mapping)
        and "format" in source
        and "encrypted" in source
    ):
        record = ProtectionRecord(source)
        if source_name is not None:
            record["source"] = source_name
        if policy is None:
            return record
        return _apply_policy(record, policy)

    ofile, should_close, label = _open_source(source)
    try:
        attrs = attributes_for(ofile, source=source_name or label)
    finally:
        if should_close:
            try:
                ofile.file.close()
            except Exception:
                pass
    return record_from_attributes(policy=policy, **attrs)


def protection_attributes(source: Any, *, source_name: str | None = None) -> dict:
    """Return normalized protection attributes without policy evaluation."""

    ofile, should_close, label = _open_source(source)
    try:
        return attributes_for(ofile, source=source_name or label)
    finally:
        if should_close:
            try:
                ofile.file.close()
            except Exception:
                pass


# Convenient aliases for embedding callers.
inspect = inspect_protection
analyze = inspect_protection
protection_record = inspect_protection
get_protection_info = inspect_protection
get_encryption_info = inspect_protection
classify = inspect_protection
get_protection_attributes = protection_attributes


class ProtectionReport(dict):
    """A consistent report for one or more protection records."""

    def __init__(
        self,
        records: Iterable[ProtectionRecord],
        policy: Any = None,
    ) -> None:
        records = tuple(records)
        coerced_policy = _coerce_policy(policy)
        policy_dict = (
            coerced_policy.to_dict()
            if isinstance(coerced_policy, ProtectionPolicy)
            else None
        )
        by_status = {status.value: 0 for status in ProtectionStatus}
        by_format: dict[str, dict[str, int]] = {}
        for record in records:
            status = str(record.get("status"))
            if status in by_status:
                by_status[status] += 1
            format_name = str(record.get("format") or "unknown")
            bucket = by_format.setdefault(
                format_name, {"total": 0, "archive": 0, "supplement": 0}
            )
            bucket["total"] += 1
            if record.get("action") == ACTION_ARCHIVE:
                bucket["archive"] += 1
            else:
                bucket["supplement"] += 1
        archive = sum(1 for record in records if record.get("action") == ACTION_ARCHIVE)
        supplement = len(records) - archive
        super().__init__(
            schema_version=1,
            policy=policy_dict,
            summary={
                "total": len(records),
                "archive": archive,
                "archivable": archive,
                "supplement": supplement,
                "needs_materials": supplement,
                "by_status": by_status,
                "by_action": {
                    ACTION_ARCHIVE: archive,
                    ACTION_SUPPLEMENT: supplement,
                },
                "by_format": by_format,
            },
            records=[ProtectionRecord(record) for record in records],
        )

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    @property
    def records(self) -> list[ProtectionRecord]:
        return [ProtectionRecord(item) for item in self["records"]]

    def to_dict(self) -> dict:
        return dict(self)

    def to_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("ensure_ascii", False)
        return json.dumps(dict(self), **kwargs)

    def format_text(self) -> str:
        """Render the report as a compact, operator-friendly table."""

        columns = (
            ("Source", "source"),
            ("Format", "format"),
            ("Protection", "protection_type"),
            ("Key size", "key_size"),
            ("Hash", "hash_algorithm"),
            ("Status", "status"),
            ("Action", "action"),
        )
        rows = []
        for record in self["records"]:
            row = []
            for _, key in columns:
                value = record.get(key)
                if value is None:
                    value = "-"
                elif key == "key_size":
                    value = "{} bit".format(value)
                row.append(str(value))
            rows.append(row)

        widths = [
            max([len(title)] + [len(row[index]) for row in rows])
            for index, (title, _) in enumerate(columns)
        ]
        lines = [
            "  ".join(title.ljust(widths[index]) for index, (title, _) in enumerate(columns)),
            "  ".join("-" * width for width in widths),
        ]
        for row in rows:
            lines.append(
                "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
            )
        return "\n".join(lines)


def build_report(
    sources: Any = None,
    policy: Any = None,
    *,
    source_name: str | None = None,
    files: Any = None,
    paths: Any = None,
) -> ProtectionReport:
    """Inspect *sources* and return one report with a stable schema.

    *sources* may be a single source or an iterable of sources.  A single
    path, file handle, bytes object, or OfficeFile instance is accepted.
    For callers that prefer named arguments, ``files`` and ``paths`` are
    accepted as aliases for *sources*.
    """

    if sources is None:
        sources = files if files is not None else paths
    if sources is None:
        raise TypeError("build_report() requires sources, files, or paths")

    if isinstance(sources, (str, os.PathLike, bytes, bytearray, memoryview)):
        sources = [sources]
    elif (
        getattr(sources, "format", None)
        or hasattr(sources, "read")
        or (isinstance(sources, Mapping) and "format" in sources)
    ):
        sources = [sources]
    else:
        try:
            sources = list(sources)
        except TypeError:
            sources = [sources]

    records = [
        inspect_protection(source, policy=policy, source_name=source_name)
        for source in sources
    ]
    return ProtectionReport(records, policy=policy)


report = build_report
compare = build_report

parse_rc4_cryptoapi_header = parse_cryptoapi_header

ProtectionInfo = ProtectionRecord
ProtectionResult = ProtectionRecord
Policy = ProtectionPolicy
Report = ProtectionReport
inspect_file = inspect_protection
get_protection = inspect_protection
make_report = build_report
generate_report = build_report

# Encryption-oriented aliases for services that use that vocabulary.
EncryptionRecord = ProtectionRecord
EncryptionStatus = ProtectionStatus
EncryptionPolicy = ProtectionPolicy
EncryptionReport = ProtectionReport
inspect_encryption = inspect_protection
build_encryption_report = build_report
