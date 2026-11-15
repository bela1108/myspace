"""
Tests for namespace-based service identity policies.
"""

from __future__ import annotations

import ipaddress

import attr
import pytest

from service_identity.exceptions import (
    IdentityPolicyError,
    IPLiteralConflict,
    MissingPrincipalConflict,
    MixedNamespaceConflict,
    MultiplePrincipalsConflict,
    WildcardConflict,
)
from service_identity.hazmat import (
    DNSPattern,
    IdentityDecision,
    IdentityPolicy,
    IPAddressPattern,
    NamespacePolicy,
    PrincipalIdentity,
    PrincipalRule,
    RawSAN,
    URIPattern,
    verify_identity_policy,
)


CERT_DNS = [DNSPattern.from_bytes(b"svc.example.com")]
CERT_SPIFFE = [
    URIPattern.from_bytes(b"spiffe://trust-domain.example/ns/prod/sa/billing")
]
CERT_MIXED = CERT_DNS + CERT_SPIFFE
CERT_TWO_DNS = [
    DNSPattern.from_bytes(b"a.example.com"),
    DNSPattern.from_bytes(b"b.example.com"),
]
CERT_WILDCARD = [DNSPattern.from_bytes(b"*.example.com")]


class TestNamespacePolicy:
    def test_rejects_unknown_san_type(self):
        """
        Only known SAN type names are accepted.
        """
        with pytest.raises(ValueError, match="Unknown SAN type"):
            NamespacePolicy(san_type="MAIL")

    @pytest.mark.parametrize("san_type", ["DNS", "URI", "IPAddress", "SRV"])
    def test_accepts_known_san_types(self, san_type):
        """
        All SAN types that hazmat knows about are valid namespaces.
        """
        assert san_type == NamespacePolicy(san_type=san_type).san_type

    def test_defaults_are_obligatory_and_unique(self):
        """
        A namespace defaults to requiring a unique principal.
        """
        namespace = NamespacePolicy(san_type="DNS")

        assert namespace.optional is False
        assert namespace.principal_rule is PrincipalRule.REQUIRE_UNIQUE


class TestIdentityPolicy:
    def test_rejects_duplicate_namespace(self):
        """
        The same SAN type must not be declared twice.
        """
        with pytest.raises(ValueError, match="Duplicate namespace"):
            IdentityPolicy(
                [
                    NamespacePolicy("DNS"),
                    NamespacePolicy("DNS", optional=True),
                ]
            )

    def test_empty_policy_rejected(self):
        """
        A policy without namespaces cannot select anything.
        """
        with pytest.raises(ValueError, match="at least one namespace"):
            verify_identity_policy(IdentityPolicy([]), CERT_DNS)


class TestSelectPrincipal:
    def test_single_dns_principal(self):
        """
        A unique DNS identity is selected within the DNS namespace.
        """
        decision = verify_identity_policy(
            IdentityPolicy([NamespacePolicy("DNS")]), CERT_DNS
        )

        assert decision == IdentityDecision(
            [PrincipalIdentity(san_type="DNS", name="svc.example.com")]
        )
        assert decision.for_namespace("DNS").name == "svc.example.com"

    def test_single_spiffe_principal(self):
        """
        A unique SPIFFE URI is selected within the URI namespace.
        """
        decision = verify_identity_policy(
            IdentityPolicy([NamespacePolicy("URI")]), CERT_SPIFFE
        )

        assert decision.principals == (
            PrincipalIdentity(
                san_type="URI",
                name="spiffe://trust-domain.example/ns/prod/sa/billing",
            ),
        )

    def test_same_cert_gives_per_namespace_conclusions(self):
        """
        A DNS-only caller and a URI-only caller each get their own
        deterministic conclusion from the same certificate.
        """
        dns_decision = verify_identity_policy(
            IdentityPolicy([NamespacePolicy("DNS")]), CERT_MIXED
        )
        uri_decision = verify_identity_policy(
            IdentityPolicy([NamespacePolicy("URI")]), CERT_MIXED
        )

        assert dns_decision.for_namespace("DNS").name == "svc.example.com"
        assert (
            uri_decision.for_namespace("URI").name
            == "spiffe://trust-domain.example/ns/prod/sa/billing"
        )

    def test_mixed_namespaces_conflict(self):
        """
        Allowing DNS and URI in one policy while both are present fails
        with one enumerable conflict per principal.
        """
        policy = IdentityPolicy(
            [NamespacePolicy("DNS"), NamespacePolicy("URI")]
        )

        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(policy, CERT_MIXED)

        assert exc_info.value.conflicts == [
            MixedNamespaceConflict("DNS", "svc.example.com"),
            MixedNamespaceConflict(
                "URI",
                "spiffe://trust-domain.example/ns/prod/sa/billing",
            ),
        ]

    def test_mixed_namespaces_order_independent(self):
        """
        The conflict set does not depend on SAN order or declaration order.
        """
        policy_a = IdentityPolicy(
            [NamespacePolicy("DNS"), NamespacePolicy("URI")]
        )
        policy_b = IdentityPolicy(
            [NamespacePolicy("URI"), NamespacePolicy("DNS")]
        )

        with pytest.raises(IdentityPolicyError) as exc_a:
            verify_identity_policy(policy_a, CERT_DNS + CERT_SPIFFE)
        with pytest.raises(IdentityPolicyError) as exc_b:
            verify_identity_policy(policy_b, CERT_SPIFFE + CERT_DNS)

        assert exc_a.value.conflicts == exc_b.value.conflicts

    def test_multiple_matching_principals_conflict(self):
        """
        Two distinct DNS principals violate uniqueness; both are reported
        rather than the first one winning.
        """
        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(
                IdentityPolicy([NamespacePolicy("DNS")]), CERT_TWO_DNS
            )

        assert exc_info.value.conflicts == [
            MultiplePrincipalsConflict("DNS", "a.example.com"),
            MultiplePrincipalsConflict("DNS", "b.example.com"),
        ]

    def test_multiple_principals_order_independent(self):
        """
        Reversing the SAN order yields the same sorted conflict list.
        """
        with pytest.raises(IdentityPolicyError) as exc_a:
            verify_identity_policy(
                IdentityPolicy([NamespacePolicy("DNS")]), CERT_TWO_DNS
            )
        with pytest.raises(IdentityPolicyError) as exc_b:
            verify_identity_policy(
                IdentityPolicy([NamespacePolicy("DNS")]),
                list(reversed(CERT_TWO_DNS)),
            )

        assert exc_a.value.conflicts == exc_b.value.conflicts

    def test_allow_multiple_returns_all_principals(self):
        """
        A namespace that explicitly allows multiple principals returns all
        of them in a stable order.
        """
        decision = verify_identity_policy(
            IdentityPolicy(
                [
                    NamespacePolicy(
                        "DNS",
                        principal_rule=PrincipalRule.ALLOW_MULTIPLE,
                    )
                ]
            ),
            CERT_TWO_DNS,
        )

        assert decision.principals == (
            PrincipalIdentity("DNS", "a.example.com"),
            PrincipalIdentity("DNS", "b.example.com"),
        )

    def test_wildcard_conflict(self):
        """
        Wildcard patterns cannot denote a unique principal.
        """
        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(
                IdentityPolicy([NamespacePolicy("DNS")]), CERT_WILDCARD
            )

        assert exc_info.value.conflicts == [
            WildcardConflict("DNS", "*.example.com")
        ]

    def test_ipv4_literal_in_dns_san_conflicts(self):
        """
        An IPv4 literal placed into a dNSName slot is reported as an
        enumerable conflict instead of being treated as a hostname.
        """
        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(
                IdentityPolicy([NamespacePolicy("DNS")]),
                [RawSAN(san_type="DNS", value=b"203.0.113.7")],
            )

        assert exc_info.value.conflicts == [
            IPLiteralConflict("DNS", "203.0.113.7")
        ]

    def test_ipv6_literal_in_dns_san_conflicts(self):
        """
        IPv6 text in a dNSName slot is likewise an enumerable conflict.
        """
        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(
                IdentityPolicy([NamespacePolicy("DNS")]),
                [RawSAN(san_type="DNS", value=b"2001:db8::7")],
            )

        assert exc_info.value.conflicts == [
            IPLiteralConflict("DNS", "2001:db8::7")
        ]

    def test_raw_san_rejects_unknown_type(self):
        """
        Raw SAN entries are bound to known SAN namespaces.
        """
        with pytest.raises(ValueError, match="Unknown SAN type"):
            RawSAN(san_type="MAIL", value=b"user@example.com")

    def test_raw_san_normalizes_case_and_whitespace(self):
        """
        Raw names are lower-cased ASCII and stripped before comparison.
        """
        raw = RawSAN(san_type="DNS", value=b"  SVC.Example.COM  ")

        assert raw.normalized_name == "svc.example.com"

    def test_ip_address_namespace_accepts_ip_san(self):
        """
        A genuine iPAddress SAN is valid in its own namespace and does not
        trigger the DNS IP-literal conflict.
        """
        ip = ipaddress.ip_address("203.0.113.7")
        decision = verify_identity_policy(
            IdentityPolicy([NamespacePolicy("IPAddress")]),
            [IPAddressPattern(ip)],
        )

        assert decision.principals == (
            PrincipalIdentity("IPAddress", "203.0.113.7"),
        )

    def test_obligatory_namespace_missing_fails(self):
        """
        An obligatory namespace without any identity is a conflict.
        """
        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(
                IdentityPolicy([NamespacePolicy("DNS")]), CERT_SPIFFE
            )

        assert exc_info.value.conflicts == [
            MissingPrincipalConflict("DNS", "")
        ]

    def test_optional_namespace_missing_allowed(self):
        """
        An optional namespace may be absent and yields no principal.
        """
        decision = verify_identity_policy(
            IdentityPolicy([NamespacePolicy("DNS", optional=True)]),
            CERT_SPIFFE,
        )

        assert decision.principals == ()
        with pytest.raises(KeyError):
            decision.for_namespace("DNS")

    def test_optional_namespace_present_still_validated(self):
        """
        An optional namespace is still conflict-checked when present.
        """
        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(
                IdentityPolicy([NamespacePolicy("DNS", optional=True)]),
                CERT_TWO_DNS,
            )

        assert all(
            isinstance(conflict, MultiplePrincipalsConflict)
            for conflict in exc_info.value.conflicts
        )

    def test_disallowed_san_types_ignored(self):
        """
        SAN types outside the policy do not participate in selection.
        """
        decision = verify_identity_policy(
            IdentityPolicy([NamespacePolicy("DNS")]),
            CERT_MIXED,
        )

        assert decision.principals == (
            PrincipalIdentity("DNS", "svc.example.com"),
        )

    def test_conflicts_are_sorted_and_fully_enumerated(self):
        """
        Every conflict kind is enumerated together, sorted deterministically.
        """
        patterns = CERT_TWO_DNS + CERT_WILDCARD + CERT_SPIFFE
        policy = IdentityPolicy(
            [NamespacePolicy("DNS"), NamespacePolicy("URI")]
        )

        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(policy, patterns)

        conflicts = exc_info.value.conflicts
        keys = [
            (conflict.san_type, type(conflict).__name__, conflict.name)
            for conflict in conflicts
        ]

        assert keys == sorted(keys)
        assert any(
            isinstance(conflict, MixedNamespaceConflict)
            for conflict in conflicts
        )
        assert any(
            isinstance(conflict, MultiplePrincipalsConflict)
            for conflict in conflicts
        )
        assert any(
            isinstance(conflict, WildcardConflict)
            for conflict in conflicts
        )


class TestConflictHygiene:
    def test_conflicts_only_carry_type_and_name(self):
        """
        Conflicts expose SAN type and normalized name only.
        """
        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(
                IdentityPolicy([NamespacePolicy("DNS")]), CERT_TWO_DNS
            )

        for conflict in exc_info.value.conflicts:
            assert {
                field.name for field in attr.fields(type(conflict))
            } == {"san_type", "name"}

    def test_conflicts_are_frozen(self):
        """
        Audit entries are immutable.
        """
        with pytest.raises(attr.exceptions.FrozenInstanceError):
            MixedNamespaceConflict("DNS", "a").san_type = "URI"

    def test_str_does_not_echo_certificate(self):
        """
        The rendered error contains only normalized names, never raw
        certificate material.
        """
        with pytest.raises(IdentityPolicyError) as exc_info:
            verify_identity_policy(
                IdentityPolicy(
                    [NamespacePolicy("DNS"), NamespacePolicy("URI")]
                ),
                CERT_MIXED,
            )

        rendered = str(exc_info.value)

        assert "svc.example.com" in rendered
        assert "spiffe://trust-domain.example" in rendered
        assert "BEGIN CERTIFICATE" not in rendered
