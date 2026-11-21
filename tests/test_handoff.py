# vim: set ai et ts=4 sw=4 sts=4:
"""
Tests for the handoff pre-check module (jks.handoff).

The pre-check only reasons about entry identity (aliases); it must never
touch certificate/key material or modify the keystore read path.
"""

from __future__ import print_function
import hashlib
import unittest

import jks
from jks.util import b2, b4, b8
from jks.jks import MAGIC_NUMBER_JKS, SIGNATURE_WHITENING
from jks import handoff
from jks.handoff import (
    AbstractAliasRule,
    AliasNotMappableException,
    CaseFoldRule,
    DuplicateBackupAliasException,
    ExactRule,
    LowerCaseRule,
    MappedRule,
    precheck_handoff,
)


def _utf(text):
    encoded = text.encode("utf-8")
    return b2.pack(len(encoded)) + encoded


def _trusted_cert_entry(alias, der):
    entry = b4.pack(2)  # trusted certificate entry tag
    entry += _utf(alias)
    entry += b8.pack(0)
    entry += _utf("X.509")
    entry += b4.pack(len(der)) + der
    return entry


def _build_jks(aliases, store_password="storepass"):
    """Build raw JKS bytes carrying the given aliases verbatim.

    Unlike TrustedCertEntry.new(), this does not lower-case aliases, so it
    lets us exercise the untouched read path with mixed-case and Unicode
    aliases."""
    body = MAGIC_NUMBER_JKS + b4.pack(2) + b4.pack(len(aliases))
    for index, alias in enumerate(aliases):
        body += _trusted_cert_entry(alias, b"cert-%d" % index)
    digest = hashlib.sha1(
        store_password.encode("utf-16be") + SIGNATURE_WHITENING + body
    ).digest()
    return jks.KeyStore.loads(body + digest, store_password)


class HandoffPrecheckTests(unittest.TestCase):
    # Aliases exercising distinct folding conventions:
    #   - "RootCA" vs "rootca"          -> differ only in case
    #   - "stra\u00dfe" vs "strasse"    -> U+00DF folds to "ss" under casefold
    #   - "Fullwidth\uff21"             -> full-width capital A (U+FF21)
    BACKUP_ALIASES = [
        "RootCA",
        "rootca",
        "stra\u00dfe",
        "strasse",
        "Fullwidth\uff21",
    ]

    def _targets(self):
        return [
            ("exact", ExactRule(), ["RootCA"]),
            ("lower", LowerCaseRule(), ["rootca"]),
            ("fold", CaseFoldRule(), ["rootca", "strasse"]),
            ("legacy", MappedRule({"rootca": "rootca"}), ["rootca"]),
        ]

    def test_each_alias_classified_exactly_once_per_target(self):
        report = precheck_handoff(self.BACKUP_ALIASES, self._targets())
        self.assertEqual(len(report), 4)
        self.assertEqual(report.backup_aliases, sorted(self.BACKUP_ALIASES))

        for result in report:
            classified = result.conflicts + result.unconfirmed + result.conflict_free
            self.assertEqual(sorted(classified), sorted(self.BACKUP_ALIASES))
            self.assertEqual(len(classified), len(set(classified)))

    def test_exact_target_only_matches_identical_alias(self):
        result = precheck_handoff(self.BACKUP_ALIASES, self._targets()).get("exact")
        self.assertEqual(result.conflicts, ["RootCA"])
        self.assertEqual(result.unconfirmed, [])
        self.assertEqual(
            result.conflict_free,
            ["rootca", "stra\u00dfe", "strasse", "Fullwidth\uff21"],
        )
        self.assertFalse(result.is_clear)

    def test_lowercase_target_flags_case_collision_as_unconfirmed(self):
        result = precheck_handoff(self.BACKUP_ALIASES, self._targets()).get("lower")
        # "RootCA" and "rootca" both fold to "rootca": the surviving identity
        # depends on import order, so neither may be reported conflict-free.
        self.assertEqual(result.conflicts, [])
        self.assertEqual(result.unconfirmed, ["RootCA", "rootca"])
        self.assertEqual(
            result.conflict_free,
            ["stra\u00dfe", "strasse", "Fullwidth\uff21"],
        )

    def test_casefold_target_collapses_unicode_representations(self):
        result = precheck_handoff(self.BACKUP_ALIASES, self._targets()).get("fold")
        # Case folding makes both pairs ambiguous; nothing may be marked safe
        # just because the lower-case target happened to accept some of them.
        self.assertEqual(result.conflicts, [])
        self.assertEqual(
            result.unconfirmed,
            ["RootCA", "rootca", "strasse", "stra\u00dfe"],
        )
        self.assertEqual(result.conflict_free, ["Fullwidth\uff21"])
        self.assertFalse(result.is_clear)

    def test_mapped_target_reports_unmappable_identities(self):
        result = precheck_handoff(self.BACKUP_ALIASES, self._targets()).get("legacy")
        # Only "rootca" is known to the legacy mapping and it already exists.
        self.assertEqual(result.conflicts, ["rootca"])
        self.assertEqual(
            result.unconfirmed,
            ["Fullwidth\uff21", "RootCA", "strasse", "stra\u00dfe"],
        )
        self.assertEqual(result.conflict_free, [])

    def test_targets_are_evaluated_independently(self):
        # A target on which everything is safe must not flip any other target
        # to conflict-free.
        safe_target = ("safe", ExactRule(), [])
        report = precheck_handoff(
            self.BACKUP_ALIASES, [safe_target] + self._targets()[1:]
        )
        self.assertTrue(report.get("safe").is_clear)
        self.assertFalse(report.all_clear)
        self.assertFalse(report.get("fold").is_clear)
        self.assertFalse(report.get("legacy").is_clear)

    def test_all_clear_only_when_every_target_is_clear(self):
        report = precheck_handoff(
            ["alpha", "beta"],
            [
                ("one", ExactRule(), []),
                ("two", LowerCaseRule(), []),
            ],
        )
        self.assertTrue(report.all_clear)
        for result in report:
            self.assertEqual(result.conflict_free, ["alpha", "beta"])

    def test_existing_aliases_go_through_the_same_folding_rule(self):
        # Existing list uses upper case; the lower-case rule must still fold
        # it to "rootca" and detect the overwrite risk.
        result = precheck_handoff(
            ["rootca"], [("t", LowerCaseRule(), ["RootCA"])]
        ).get("t")
        self.assertEqual(result.conflicts, ["rootca"])

    def test_callable_rule_is_supported(self):
        def rule(alias):
            if alias == "known":
                return "known"
            raise AliasNotMappableException("not in mapping")

        result = precheck_handoff(
            ["known", "unknown"], [("t", rule, [])]
        ).get("t")
        self.assertEqual(result.conflict_free, ["known"])
        self.assertEqual(result.unconfirmed, ["unknown"])

    def test_invalid_rule_type_rejected(self):
        self.assertRaises(
            TypeError, precheck_handoff, ["a"], [("t", 123, [])]
        )

    def test_nfc_equivalent_aliases_count_as_duplicates(self):
        self.assertRaises(
            DuplicateBackupAliasException,
            precheck_handoff,
            ["\u00e9", "e\u0301"],
            [("t", ExactRule(), [])],
        )

    def test_non_string_alias_rejected(self):
        self.assertRaises(
            TypeError, precheck_handoff, ["ok", 42], [("t", ExactRule(), [])]
        )

    def test_accepts_loaded_keystore_without_modifying_it(self):
        keystore = _build_jks(self.BACKUP_ALIASES)
        before = dict(keystore.entries)
        self.assertEqual(sorted(keystore.entries.keys()), sorted(self.BACKUP_ALIASES))

        report = precheck_handoff(keystore, self._targets())

        # Read path untouched: same entry objects, same aliases, cert data
        # never consulted by the pre-check.
        self.assertEqual(keystore.entries, before)
        self.assertEqual(report.backup_aliases, sorted(self.BACKUP_ALIASES))
        self.assertEqual(report.get("exact").conflicts, ["RootCA"])

    def test_unknown_target_name_raises_keyerror(self):
        report = precheck_handoff(["a"], [("t", ExactRule(), [])])
        self.assertRaises(KeyError, report.get, "missing")


if __name__ == "__main__":
    unittest.main()
