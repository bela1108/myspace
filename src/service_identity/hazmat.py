"""
Common verification code.
"""

from __future__ import annotations

import ipaddress
import re

from collections.abc import Sequence
from enum import Enum
from typing import Protocol, runtime_checkable

import attr

from .exceptions import (
    CertificateError,
    DNSMismatch,
    IdentityConflict,
    IdentityPolicyError,
    IPLiteralConflict,
    IPAddressMismatch,
    Mismatch,
    MissingPrincipalConflict,
    MixedNamespaceConflict,
    MultiplePrincipalsConflict,
    SRVMismatch,
    URIMismatch,
    VerificationError,
    WildcardConflict,
)


try:
    import idna
except ImportError:
    idna = None  # type: ignore[assignment]


@attr.s(slots=True)
class ServiceMatch:
    """
    A match of a service id and a certificate pattern.
    """

    service_id: ServiceID = attr.ib()
    cert_pattern: CertificatePattern = attr.ib()


def verify_service_identity(
    cert_patterns: Sequence[CertificatePattern],
    obligatory_ids: Sequence[ServiceID],
    optional_ids: Sequence[ServiceID],
) -> list[ServiceMatch]:
    """
    Verify whether *cert_patterns* are valid for *obligatory_ids* and
    *optional_ids*.

    *obligatory_ids* must be both present and match.  *optional_ids* must match
    if a pattern of the respective type is present.
    """
    if not cert_patterns:
        msg = "Certificate does not contain any `subjectAltName`s."
        raise CertificateError(msg)

    errors = []
    matches = _find_matches(cert_patterns, obligatory_ids) + _find_matches(
        cert_patterns, optional_ids
    )

    matched_ids = [match.service_id for match in matches]
    for i in obligatory_ids:
        if i not in matched_ids:
            errors.append(  # noqa: PERF401
                i.error_on_mismatch(mismatched_id=i)
            )

    for i in optional_ids:
        # If an optional ID is not matched by a certificate pattern *but* there
        # is a pattern of the same type , it is an error and the verification
        # fails.  Example: the user passes a SRV-ID for "_mail.domain.com" but
        # the certificate contains an SRV-Pattern for "_xmpp.domain.com".
        if i not in matched_ids and _contains_instance_of(
            cert_patterns, i.pattern_class
        ):
            errors.append(  # noqa: PERF401
                i.error_on_mismatch(mismatched_id=i)
            )

    if errors:
        raise VerificationError(errors=errors)

    return matches


def _find_matches(
    cert_patterns: Sequence[CertificatePattern],
    service_ids: Sequence[ServiceID],
) -> list[ServiceMatch]:
    """
    Search for matching certificate patterns and service_ids.

    Args:
        service_ids: List of service IDs like DNS_ID.
    """
    matches = []
    for sid in service_ids:
        for cid in cert_patterns:
            if sid.verify(cid):
                matches.append(  # noqa: PERF401
                    ServiceMatch(cert_pattern=cid, service_id=sid)
                )

    return matches


def _contains_instance_of(seq: Sequence[object], cl: type) -> bool:
    return any(isinstance(e, cl) for e in seq)


def _is_ip_address(pattern: str | bytes) -> bool:
    """
    Check whether *pattern* could be/match an IP address.

    Args:
        pattern: A pattern for a host name.

    Returns:
        `True` if *pattern* could be an IP address, else `False`.
    """
    if isinstance(pattern, bytes):
        try:
            pattern = pattern.decode("ascii")
        except UnicodeError:
            return False

    try:
        int(pattern)
    except ValueError:
        pass
    else:
        return True

    try:
        ipaddress.ip_address(pattern.replace("*", "1"))
    except ValueError:
        return False

    return True


@attr.s(slots=True)
class DNSPattern:
    """
    A DNS pattern as extracted from certificates.
    """

    #: The pattern.
    pattern: bytes = attr.ib()

    _RE_LEGAL_CHARS = re.compile(rb"^[a-z0-9\-_.]+$")

    @classmethod
    def from_bytes(cls, pattern: bytes) -> DNSPattern:
        if not isinstance(pattern, bytes):
            msg = "The DNS pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip()

        if pattern == b"" or _is_ip_address(pattern) or b"\0" in pattern:
            msg = f"Invalid DNS pattern {pattern!r}."
            raise CertificateError(msg)

        pattern = pattern.translate(_TRANS_TO_LOWER)
        if b"*" in pattern:
            _validate_pattern(pattern)

        return cls(pattern=pattern)


@attr.s(slots=True)
class IPAddressPattern:
    """
    An IP address pattern as extracted from certificates.
    """

    #: The pattern.
    pattern: ipaddress.IPv4Address | ipaddress.IPv6Address = attr.ib()

    @classmethod
    def from_bytes(cls, bs: bytes) -> IPAddressPattern:
        try:
            return cls(pattern=ipaddress.ip_address(bs))
        except ValueError:
            msg = f"Invalid IP address pattern {bs!r}."
            raise CertificateError(msg) from None


@attr.s(slots=True)
class URIPattern:
    """
    An URI pattern as extracted from certificates.
    """

    #: The pattern for the protocol part.
    protocol_pattern: bytes = attr.ib()
    #: The pattern for the DNS part.
    dns_pattern: DNSPattern = attr.ib()

    @classmethod
    def from_bytes(cls, pattern: bytes) -> URIPattern:
        if not isinstance(pattern, bytes):
            msg = "The URI pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip().translate(_TRANS_TO_LOWER)

        if b":" not in pattern or b"*" in pattern or _is_ip_address(pattern):
            msg = f"Invalid URI pattern {pattern!r}."
            raise CertificateError(msg)

        protocol_pattern, hostname = pattern.split(b":")

        return cls(
            protocol_pattern=protocol_pattern,
            dns_pattern=DNSPattern.from_bytes(hostname),
        )


@attr.s(slots=True)
class SRVPattern:
    """
    An SRV pattern as extracted from certificates.
    """

    #: The pattern for the name part.
    name_pattern: bytes = attr.ib()
    #: The pattern for the DNS part.
    dns_pattern: DNSPattern = attr.ib()

    @classmethod
    def from_bytes(cls, pattern: bytes) -> SRVPattern:
        if not isinstance(pattern, bytes):
            msg = "The SRV pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip().translate(_TRANS_TO_LOWER)

        if (
            pattern[0] != b"_"[0]
            or b"." not in pattern
            or b"*" in pattern
            or _is_ip_address(pattern)
        ):
            msg = f"Invalid SRV pattern {pattern!r}."
            raise CertificateError(msg)

        name, hostname = pattern.split(b".", 1)
        return cls(
            name_pattern=name[1:], dns_pattern=DNSPattern.from_bytes(hostname)
        )


CertificatePattern = SRVPattern | URIPattern | DNSPattern | IPAddressPattern
"""
A :class:`Union` of all possible patterns that can be extracted from a
certificate.
"""


@runtime_checkable
class ServiceID(Protocol):
    @property
    def pattern_class(self) -> type[CertificatePattern]: ...

    @property
    def error_on_mismatch(self) -> type[Mismatch]: ...

    def verify(self, pattern: CertificatePattern) -> bool: ...


@attr.s(init=False, slots=True)
class DNS_ID:
    """
    A DNS service ID, aka hostname.
    """

    hostname: bytes = attr.ib()

    # characters that are legal in a normalized hostname
    _RE_LEGAL_CHARS = re.compile(rb"^[a-z0-9\-_.]+$")
    pattern_class = DNSPattern
    error_on_mismatch = DNSMismatch

    def __init__(self, hostname: str):
        if not isinstance(hostname, str):
            msg = "DNS-ID must be a text string."
            raise TypeError(msg)

        hostname = hostname.strip()
        if not hostname or _is_ip_address(hostname):
            msg = "Invalid DNS-ID."
            raise ValueError(msg)

        if any(ord(c) > 127 for c in hostname):
            if idna:
                ascii_id = idna.encode(hostname)
            else:
                msg = "idna library is required for non-ASCII IDs."
                raise ImportError(msg)
        else:
            ascii_id = hostname.encode("ascii")

        self.hostname = ascii_id.translate(_TRANS_TO_LOWER)
        if self._RE_LEGAL_CHARS.match(self.hostname) is None:
            msg = "Invalid DNS-ID."
            raise ValueError(msg)

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.4
        """
        if isinstance(pattern, self.pattern_class):
            return _hostname_matches(pattern.pattern, self.hostname)

        return False


@attr.s(slots=True)
class IPAddress_ID:
    """
    An IP address service ID.
    """

    ip: ipaddress.IPv4Address | ipaddress.IPv6Address = attr.ib(
        converter=ipaddress.ip_address
    )

    pattern_class = IPAddressPattern
    error_on_mismatch = IPAddressMismatch

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc2818#section-3.1
        """
        if isinstance(pattern, self.pattern_class):
            return self.ip == pattern.pattern

        return False


@attr.s(init=False, slots=True)
class URI_ID:
    """
    An URI service ID.
    """

    protocol: bytes = attr.ib()
    dns_id: DNS_ID = attr.ib()

    pattern_class = URIPattern
    error_on_mismatch = URIMismatch

    def __init__(self, uri: str):
        if not isinstance(uri, str):
            msg = "URI-ID must be a text string."
            raise TypeError(msg)

        uri = uri.strip()
        if ":" not in uri or _is_ip_address(uri):
            msg = "Invalid URI-ID."
            raise ValueError(msg)

        prot, hostname = uri.split(":")

        self.protocol = prot.encode("ascii").translate(_TRANS_TO_LOWER)
        self.dns_id = DNS_ID(hostname.strip("/"))

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.5.2
        """
        if isinstance(pattern, self.pattern_class):
            return (
                pattern.protocol_pattern == self.protocol
                and self.dns_id.verify(pattern.dns_pattern)
            )

        return False


@attr.s(init=False, slots=True)
class SRV_ID:
    """
    An SRV service ID.
    """

    name: bytes = attr.ib()
    dns_id: DNS_ID = attr.ib()

    pattern_class = SRVPattern
    error_on_mismatch = SRVMismatch

    def __init__(self, srv: str):
        if not isinstance(srv, str):
            msg = "SRV-ID must be a text string."
            raise TypeError(msg)

        srv = srv.strip()
        if "." not in srv or _is_ip_address(srv) or srv[0] != "_":
            msg = "Invalid SRV-ID."
            raise ValueError(msg)

        name, hostname = srv.split(".", 1)

        self.name = name[1:].encode("ascii").translate(_TRANS_TO_LOWER)
        self.dns_id = DNS_ID(hostname)

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.5.1
        """
        if isinstance(pattern, self.pattern_class):
            return self.name == pattern.name_pattern and self.dns_id.verify(
                pattern.dns_pattern
            )

        return False


def _hostname_matches(cert_pattern: bytes, actual_hostname: bytes) -> bool:
    """
    :return: `True` if *cert_pattern* matches *actual_hostname*, else `False`.
    """
    if b"*" in cert_pattern:
        if b"." not in actual_hostname:
            return False
        cert_head, cert_tail = cert_pattern.split(b".", 1)
        actual_head, actual_tail = actual_hostname.split(b".", 1)
        if cert_tail != actual_tail:
            return False
        # No patterns for IDNA
        if actual_head.startswith(b"xn--"):
            return False

        return cert_head in (b"*", actual_head)

    return cert_pattern == actual_hostname


def _validate_pattern(cert_pattern: bytes) -> None:
    """
    Check whether the usage of wildcards within *cert_pattern* conforms with
    our expectations.
    """
    cnt = cert_pattern.count(b"*")
    if cnt > 1:
        msg = f"Certificate's DNS-ID {cert_pattern!r} contains too many wildcards."
        raise CertificateError(msg)
    parts = cert_pattern.split(b".")
    if len(parts) < 3:
        msg = f"Certificate's DNS-ID {cert_pattern!r} has too few host components for wildcard usage."
        raise CertificateError(msg)
    # We assume there will always be only one wildcard allowed.
    if b"*" not in parts[0]:
        msg = f"Certificate's DNS-ID {cert_pattern!r} has a wildcard outside the left-most part."
        raise CertificateError(msg)
    if any(not len(p) for p in parts):
        msg = f"Certificate's DNS-ID {cert_pattern!r} contains empty parts."
        raise CertificateError(msg)


# Ensure no locale magic interferes.
_TRANS_TO_LOWER = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
)


# --- Namespaced identity policies --------------------------------------

_SAN_TYPE_NAMES: dict[type[CertificatePattern], str] = {
    DNSPattern: "DNS",
    URIPattern: "URI",
    IPAddressPattern: "IPAddress",
    SRVPattern: "SRV",
}


@attr.s(frozen=True, slots=True)
class RawSAN:
    """
    A SAN entry kept in its raw, unparsed form together with the SAN
    type (namespace) it was stored under in the certificate.

    Raw entries let the policy layer inspect values that the regular
    pattern constructors reject outright -- notably IP-address literals
    smuggled into a ``dNSName`` slot -- so they can be reported as
    enumerable conflicts instead of aborting parsing.
    """

    san_type: str = attr.ib()
    value: bytes = attr.ib()

    @san_type.validator
    def _check_san_type(
        self, attribute: attr.Attribute, value: str
    ) -> None:
        if value not in _SAN_TYPE_NAMES.values():
            msg = f"Unknown SAN type {value!r}."
            raise ValueError(msg)

    @property
    def normalized_name(self) -> str:
        """
        The lower-cased ASCII name carried by the raw entry.
        """
        return self.value.strip().translate(_TRANS_TO_LOWER).decode(
            "ascii"
        )


class PrincipalRule(Enum):
    """
    How a SAN namespace decides which identity is the service principal.
    """

    #: Fail if more than one distinct principal is present.
    REQUIRE_UNIQUE = "require-unique"
    #: Accept every distinct principal within the namespace.
    ALLOW_MULTIPLE = "allow-multiple"


@attr.s(frozen=True, slots=True)
class NamespacePolicy:
    """
    Selection rules for one SAN namespace, i.e. one SAN type.

    Args:
        san_type: The only SAN type accepted in this namespace.
        principal_rule: Whether a single unique principal is required.
        optional: If `True`, an absent identity is allowed instead of
            raising a MissingPrincipalConflict.
    """

    san_type: str = attr.ib()
    principal_rule: PrincipalRule = attr.ib(
        default=PrincipalRule.REQUIRE_UNIQUE
    )
    optional: bool = attr.ib(default=False)

    def __attrs_post_init__(self) -> None:
        if self.san_type not in _SAN_TYPE_NAMES.values():
            msg = f"Unknown SAN type {self.san_type!r}."
            raise ValueError(msg)


@attr.s(frozen=True, slots=True)
class IdentityPolicy:
    """
    A namespace-aware identity policy.

    Each namespace policy names the SAN types a caller accepts together
    with the uniqueness rule applied within that namespace.
    """

    namespaces: tuple[NamespacePolicy, ...] = attr.ib(converter=tuple)

    @namespaces.validator
    def _check_namespaces(
        self,
        attribute: attr.Attribute,
        value: tuple[NamespacePolicy, ...],
    ) -> None:
        seen: set[str] = set()
        for namespace in value:
            if namespace.san_type in seen:
                msg = (
                    "Duplicate namespace policy for "
                    f"{namespace.san_type!r}."
                )
                raise ValueError(msg)
            seen.add(namespace.san_type)


@attr.s(frozen=True, slots=True)
class PrincipalIdentity:
    """
    A principal selected within one SAN namespace.

    Only the SAN type and the normalized name are retained; the
    certificate pattern itself is never referenced.
    """

    san_type: str = attr.ib()
    name: str = attr.ib()


@attr.s(frozen=True, slots=True)
class IdentityDecision:
    """
    The per-namespace result of applying an IdentityPolicy.
    """

    principals: tuple[PrincipalIdentity, ...] = attr.ib(converter=tuple)

    def for_namespace(self, san_type: str) -> PrincipalIdentity:
        """
        Return the principal selected for *san_type*.
        """
        for principal in self.principals:
            if principal.san_type == san_type:
                return principal

        msg = f"No principal selected for namespace {san_type!r}."
        raise KeyError(msg)


def _san_type_of(pattern: CertificatePattern) -> str:
    return _SAN_TYPE_NAMES[type(pattern)]


def _normalized_name(pattern: CertificatePattern) -> str:
    """
    Return the canonical, lower-cased ASCII name carried by *pattern*.
    """
    if isinstance(pattern, DNSPattern):
        return pattern.pattern.decode("ascii")
    if isinstance(pattern, IPAddressPattern):
        return str(pattern.pattern)
    if isinstance(pattern, URIPattern):
        return (
            pattern.protocol_pattern.decode("ascii")
            + ":"
            + pattern.dns_pattern.pattern.decode("ascii")
        )

    return (
        b"_"
        + pattern.name_pattern
        + b"."
        + pattern.dns_pattern.pattern
    ).decode("ascii")


IdentityPolicyInput = CertificatePattern | RawSAN


def verify_identity_policy(
    policy: IdentityPolicy,
    cert_patterns: Sequence[IdentityPolicyInput],
) -> IdentityDecision:
    """
    Apply *policy* to *cert_patterns* and select the service principal of
    every SAN namespace.

    Conflicts are enumerated and raised together; selection never depends
    on the order of the certificate's SAN entries.

    Args:
        policy: The namespace policy supplied by the caller.
        cert_patterns: Patterns (or raw SAN entries) extracted from the
            peer certificate.

    Returns:
        An IdentityDecision holding one PrincipalIdentity per present
        namespace.

    Raises:
        IdentityPolicyError: If a namespace contains a conflict or an
            obligatory namespace is absent.  The error only carries SAN
            types and normalized names, never the full certificate.
    """
    if not policy.namespaces:
        msg = "Identity policy must declare at least one namespace."
        raise ValueError(msg)

    allowed = {namespace.san_type for namespace in policy.namespaces}

    candidates: dict[str, set[str]] = {
        namespace.san_type: set() for namespace in policy.namespaces
    }
    for pattern in cert_patterns:
        san_type = (
            pattern.san_type
            if isinstance(pattern, RawSAN)
            else _san_type_of(pattern)
        )
        if san_type in allowed:
            name = (
                pattern.normalized_name
                if isinstance(pattern, RawSAN)
                else _normalized_name(pattern)
            )
            candidates[san_type].add(name)

    present = [
        namespace.san_type
        for namespace in policy.namespaces
        if candidates[namespace.san_type]
    ]
    mixed_namespaces = len(present) > 1

    conflicts: list[IdentityConflict] = []
    for namespace in policy.namespaces:
        names = candidates[namespace.san_type]

        if not names:
            if not namespace.optional:
                conflicts.append(
                    MissingPrincipalConflict(
                        san_type=namespace.san_type, name=""
                    )
                )
            continue

        ordered = sorted(names)

        if mixed_namespaces:
            conflicts.extend(
                MixedNamespaceConflict(namespace.san_type, name)
                for name in ordered
            )

        if namespace.san_type == "DNS":
            conflicts.extend(
                IPLiteralConflict(namespace.san_type, name)
                for name in ordered
                if _is_ip_address(name)
            )

        conflicts.extend(
            WildcardConflict(namespace.san_type, name)
            for name in ordered
            if "*" in name
        )

        if (
            namespace.principal_rule is PrincipalRule.REQUIRE_UNIQUE
            and len(names) > 1
        ):
            conflicts.extend(
                MultiplePrincipalsConflict(namespace.san_type, name)
                for name in ordered
            )

    if conflicts:
        conflicts.sort(
            key=lambda conflict: (
                conflict.san_type,
                type(conflict).__name__,
                conflict.name,
            )
        )
        raise IdentityPolicyError(conflicts=conflicts)

    principals: list[PrincipalIdentity] = []
    for namespace in policy.namespaces:
        principals.extend(
            PrincipalIdentity(san_type=namespace.san_type, name=name)
            for name in sorted(candidates[namespace.san_type])
        )

    return IdentityDecision(principals=principals)
