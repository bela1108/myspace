"""
All exceptions and warnings thrown by ``service-identity``.

Separated into an own package for nicer tracebacks, you should still import
them from __init__.py.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .hazmat import ServiceID

import attr


class SubjectAltNameWarning(DeprecationWarning):
    """
    This warning is not used anymore and will be removed in a future version.

    Formerly:

    Server Certificate does not contain a ``SubjectAltName``.

    Hostname matching is performed on the ``CommonName`` which is deprecated.

    .. deprecated:: 23.1.0
    """


@attr.s(slots=True)
class Mismatch:
    mismatched_id: ServiceID = attr.ib()


class DNSMismatch(Mismatch):
    """
    No matching DNSPattern could be found.
    """


class SRVMismatch(Mismatch):
    """
    No matching SRVPattern could be found.
    """


class URIMismatch(Mismatch):
    """
    No matching URIPattern could be found.
    """


class IPAddressMismatch(Mismatch):
    """
    No matching IPAddressPattern could be found.
    """


@attr.s(frozen=True, slots=True)
class IdentityConflict:
    """
    A conflict discovered while selecting a service principal.

    A conflict only carries the SAN *type* (namespace) and the
    *normalized name* of the offending identity.  It never references the
    certificate itself, so audit logs cannot leak the full certificate.
    """

    #: The SAN type / namespace, e.g. ``"DNS"`` or ``"URI"``.
    san_type: str = attr.ib()
    #: The normalized identity name (lower-cased ASCII / canonical IP).
    name: str = attr.ib()


class MixedNamespaceConflict(IdentityConflict):
    """
    A principal of a SAN type that is mixed with another SAN type within
    the same policy.
    """


class MultiplePrincipalsConflict(IdentityConflict):
    """
    More than one principal matched within a single SAN namespace while
    the policy requires a unique principal.
    """


class WildcardConflict(IdentityConflict):
    """
    A matchable identity contains a wildcard and therefore cannot denote a
    unique principal.
    """


class IPLiteralConflict(IdentityConflict):
    """
    An IP-address literal is masquerading as a DNS host name.
    """


class MissingPrincipalConflict(IdentityConflict):
    """
    An obligatory namespace carries no identity at all.
    """


@attr.s(auto_exc=True, slots=True)
class IdentityPolicyError(Exception):
    """
    Service principal selection failed because of enumerable identity
    conflicts.

    Every conflict is reported; nothing is selected according to SAN
    traversal order.
    """

    conflicts: Sequence[IdentityConflict] = attr.ib()

    def __str__(self) -> str:
        return self.__repr__()


@attr.s(auto_exc=True)
class VerificationError(Exception):
    """
    Service identity verification failed.
    """

    errors: Sequence[Mismatch] = attr.ib()

    def __str__(self) -> str:
        return self.__repr__()


class CertificateError(Exception):
    r"""
    Certificate contains invalid or unexpected data.

    This includes the case where s certificate contains no
    ``subjectAltName``\ s.
    """
