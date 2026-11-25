"""Tests for the read-only JKS retention decision engine."""

from __future__ import print_function

import datetime

import pytest

import jks
from jks import retention as R
from jks import synthetic as S


NOW = datetime.datetime(2026, 6, 1)


@pytest.fixture
def hierarchy():
    root = S.build_cert("Root CA", serial=1)
    inter = S.build_cert("Intermediate CA",
                         issuer_name=S._dn("Root CA"), serial=2)
    leaf = S.build_cert("service",
                        issuer_name=S._dn("Intermediate CA"), serial=3)
    return {"root": root, "inter": inter, "leaf": leaf}


@pytest.fixture
def keystore(hierarchy):
    entry = S.build_private_key_entry(
        "svc", [hierarchy["leaf"], hierarchy["inter"], hierarchy["root"]])
    store, _password = S.build_keystore([entry])
    return store


def test_x509_identity_uses_der_and_links(hierarchy):
    leaf = R.X509Cert(hierarchy["leaf"])
    inter = R.X509Cert(hierarchy["inter"])
    root = R.X509Cert(hierarchy["root"])

    assert leaf.issuer_fp == inter.subject_fp
    assert inter.issuer_fp == root.subject_fp
    assert root.is_self_issued
    assert not leaf.is_self_issued
    assert leaf.not_before == datetime.datetime(2024, 1, 1)
    assert leaf.not_after == datetime.datetime(2026, 1, 1)


def test_catalog_deduplicates_identical_cert(hierarchy):
    catalog = R.PublicMaterialCatalog()
    first = catalog.add(hierarchy["root"], source="bundle-a")
    second = catalog.add(hierarchy["root"], source="bundle-b")

    assert first.fingerprint == second.fingerprint
    assert len(catalog) == 1
    # the first recorded source wins; duplicates add no new evidence
    assert catalog.source_of(first.fingerprint) == "bundle-a"
    assert first.fingerprint in catalog


def test_catalog_lookup_by_subject_dn(hierarchy):
    catalog = R.PublicMaterialCatalog([hierarchy["root"], hierarchy["inter"]])
    inter = R.X509Cert(hierarchy["inter"])
    issuers = catalog.issuers_of(inter.issuer_fp)
    assert len(issuers) == 1
    assert issuers[0].fingerprint == R.X509Cert(hierarchy["root"]).fingerprint


def test_rule_window_verdicts():
    rule = R.RetentionRule(
        "r1",
        in_use_until=datetime.datetime(2026, 1, 1),
        retain_until=datetime.datetime(2027, 1, 1),
        aliases=["svc"])

    assert rule.verdict("svc", datetime.datetime(2025, 1, 1)) == (True, True)
    assert rule.verdict("svc", datetime.datetime(2026, 3, 1)) == (False, True)
    assert rule.verdict("svc", datetime.datetime(2028, 1, 1)) == (False, False)
    assert rule.verdict("other", NOW) == (False, False)


def test_rule_rejects_inverted_windows():
    with pytest.raises(R.InvalidRuleException):
        R.RetentionRule("bad",
                        in_use_until=datetime.datetime(2027, 1, 1),
                        retain_until=datetime.datetime(2026, 1, 1))


def test_rebuild_chain_complete_from_catalog(hierarchy):
    catalog = R.PublicMaterialCatalog(
        [hierarchy["root"], hierarchy["inter"], hierarchy["leaf"]])
    leaf = R.X509Cert(hierarchy["leaf"])

    rebuilt, gaps = R.rebuild_chain(leaf, catalog)
    assert gaps == []
    assert [c.fingerprint for c in rebuilt] == [
        R.X509Cert(hierarchy["leaf"]).fingerprint,
        R.X509Cert(hierarchy["inter"]).fingerprint,
        R.X509Cert(hierarchy["root"]).fingerprint,
    ]


def test_rebuild_chain_reports_missing_intermediate(hierarchy):
    catalog = R.PublicMaterialCatalog([hierarchy["root"], hierarchy["leaf"]])
    leaf = R.X509Cert(hierarchy["leaf"])

    rebuilt, gaps = R.rebuild_chain(leaf, catalog)
    assert len(gaps) == 1
    assert gaps[0].reason == "missing_intermediate"
    assert gaps[0].issuer_fp == leaf.issuer_fp


def test_duplicate_cert_does_not_fill_a_gap(hierarchy):
    catalog = R.PublicMaterialCatalog([hierarchy["leaf"], hierarchy["leaf"]])
    leaf = R.X509Cert(hierarchy["leaf"])

    _rebuilt, gaps = R.rebuild_chain(leaf, catalog)
    assert len(gaps) == 1
    assert gaps[0].reason == "missing_intermediate"


def test_leaf_not_archived_is_its_own_gap(hierarchy):
    catalog = R.PublicMaterialCatalog(
        [hierarchy["root"], hierarchy["inter"]])
    leaf = R.X509Cert(hierarchy["leaf"])

    _rebuilt, gaps = R.rebuild_chain(leaf, catalog)
    reasons = sorted(g.reason for g in gaps)
    assert "leaf_not_archived" in reasons
    leaf_gap = next(g for g in gaps if g.reason == "leaf_not_archived")
    assert leaf_gap.needed_fingerprint == leaf.fingerprint


def _rule(alias, in_use, retain):
    return R.RetentionRule(
        "rule-%s" % alias,
        in_use_until=in_use, retain_until=retain, aliases=[alias])


def _full_catalog(hierarchy):
    return R.PublicMaterialCatalog(
        [hierarchy["root"], hierarchy["inter"], hierarchy["leaf"]])


def test_audit_destroys_when_rules_expired_and_chain_rebuildable(
        keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2025, 1, 1),
                 datetime.datetime(2026, 1, 1))
    report = R.audit_keystore(keystore, [rule], _full_catalog(hierarchy), now=NOW)

    decision = report.decisions["svc"]
    assert decision.can_destroy is True
    assert decision.status == R.DESTROY
    assert report.destroyable == ["svc"]


def test_audit_retains_while_retention_window_open(keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2025, 1, 1),
                 datetime.datetime(2030, 1, 1))
    report = R.audit_keystore(keystore, [rule], _full_catalog(hierarchy), now=NOW)

    decision = report.decisions["svc"]
    assert decision.status == R.RETAIN
    assert decision.blockers[0].code == "retention_window_open"
    assert report.retained == ["svc"]


def test_audit_retains_while_still_in_use(keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2030, 1, 1),
                 datetime.datetime(2031, 1, 1))
    report = R.audit_keystore(keystore, [rule], _full_catalog(hierarchy), now=NOW)

    decision = report.decisions["svc"]
    assert decision.status == R.RETAIN
    assert decision.blockers[0].code == "still_in_use"


def test_audit_insufficient_evidence_on_missing_intermediate(
        keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2025, 1, 1),
                 datetime.datetime(2026, 1, 1))
    # leaf archived but the intermediate is not available anywhere
    catalog = R.PublicMaterialCatalog(
        [hierarchy["root"], hierarchy["leaf"]])
    report = R.audit_keystore(keystore, [rule], catalog, now=NOW)

    decision = report.decisions["svc"]
    assert decision.status == R.INSUFFICIENT_EVIDENCE
    assert any(b.code == "missing_intermediate" for b in decision.blockers)
    assert report.blocked == ["svc"]


def test_audit_never_destroys_on_incomplete_evidence(keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2025, 1, 1),
                 datetime.datetime(2026, 1, 1))
    catalog = R.PublicMaterialCatalog()  # nothing archived at all
    report = R.audit_keystore(keystore, [rule], catalog, now=NOW)

    assert report.decisions["svc"].status == R.INSUFFICIENT_EVIDENCE
    assert report.destroyable == []


def test_open_pending_item_blocks_even_when_chain_rebuildable(
        keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2025, 1, 1),
                 datetime.datetime(2026, 1, 1))
    leaf_fp = R.X509Cert(hierarchy["leaf"]).fingerprint
    pending = [R.PendingItem("verify", fingerprint=leaf_fp, resolved=False)]
    report = R.audit_keystore(keystore, [rule], _full_catalog(hierarchy),
                              pending, now=NOW)

    decision = report.decisions["svc"]
    assert decision.status == R.INSUFFICIENT_EVIDENCE
    blocker = next(b for b in decision.blockers if b.code == "pending_item_open")
    assert blocker.resolvable_by == leaf_fp

    # resolving the pending item frees the entry
    pending[0].resolved = True
    report2 = R.audit_keystore(keystore, [rule], _full_catalog(hierarchy),
                               pending, now=NOW)
    assert report2.decisions["svc"].status == R.DESTROY


def test_archiving_specific_cert_unblocks_entry(keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2025, 1, 1),
                 datetime.datetime(2026, 1, 1))
    catalog = R.PublicMaterialCatalog(
        [hierarchy["root"], hierarchy["leaf"]])  # intermediate missing

    before = R.audit_keystore(keystore, [rule], catalog, now=NOW)
    assert before.decisions["svc"].status == R.INSUFFICIENT_EVIDENCE

    catalog.add(hierarchy["inter"], source="newly-archived")
    after = R.audit_keystore(keystore, [rule], catalog, now=NOW)
    assert after.decisions["svc"].status == R.DESTROY


def test_missing_intermediate_gap_names_required_issuer_dn(keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2025, 1, 1),
                 datetime.datetime(2026, 1, 1))
    catalog = R.PublicMaterialCatalog(
        [hierarchy["root"], hierarchy["leaf"]])
    report = R.audit_keystore(keystore, [rule], catalog, now=NOW)

    decision = report.decisions["svc"]
    gap = next(g for g in decision.chain_gaps
               if g.reason == "missing_intermediate")
    # we do not hold the cert, so no fingerprint is known; the required
    # issuer DN is what tells the archivist which public cert to obtain
    inter = R.X509Cert(hierarchy["inter"])
    assert gap.needed_fingerprint is None
    assert gap.issuer_fp == inter.subject_fp
    assert gap.subject_fp == R.X509Cert(hierarchy["leaf"]).subject_fp


def test_known_material_gap_offers_concrete_unblock_cert(keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2025, 1, 1),
                 datetime.datetime(2026, 1, 1))
    # the leaf cert is known but not archived: its fingerprint is the
    # concrete public material whose archiving clears the blocker
    catalog = R.PublicMaterialCatalog(
        [hierarchy["root"], hierarchy["inter"]])
    report = R.audit_keystore(keystore, [rule], catalog, now=NOW)

    leaf_fp = R.X509Cert(hierarchy["leaf"]).fingerprint
    recs = report.unblock_recommendations()
    assert leaf_fp in recs
    assert recs[leaf_fp] == {"svc"}


def test_audit_does_not_mutate_keystore(keystore, hierarchy):
    rule = _rule("svc", datetime.datetime(2025, 1, 1),
                 datetime.datetime(2026, 1, 1))
    entry_before = keystore.private_keys["svc"]
    chain_before = [c[1] for c in entry_before.cert_chain]

    R.audit_keystore(keystore, [rule], R.PublicMaterialCatalog(), now=NOW)

    entry_after = keystore.private_keys["svc"]
    assert [c[1] for c in entry_after.cert_chain] == chain_before
    assert set(keystore.entries) == {"svc"}


def test_multiple_entries_independent_decisions(hierarchy):
    other_leaf = S.build_cert(
        "other-service", issuer_name=S._dn("Intermediate CA"), serial=4)
    entries = [
        S.build_private_key_entry(
            "svc", [hierarchy["leaf"], hierarchy["inter"],
                     hierarchy["root"]]),
        S.build_private_key_entry("other", [other_leaf]),
    ]
    store, _ = S.build_keystore(entries)
    rules = [
        R.RetentionRule("keep-other",
                        datetime.datetime(2025, 1, 1),
                        datetime.datetime(2030, 1, 1),
                        aliases=["other"]),
        R.RetentionRule("expired-svc",
                        datetime.datetime(2025, 1, 1),
                        datetime.datetime(2026, 1, 1),
                        aliases=["svc"]),
    ]
    catalog = R.PublicMaterialCatalog([
        hierarchy["root"], hierarchy["inter"], hierarchy["leaf"],
        other_leaf])
    report = R.audit_keystore(store, rules, catalog, now=NOW)

    assert report.decisions["svc"].status == R.DESTROY
    assert report.decisions["other"].status == R.RETAIN
    assert report.destroyable == ["svc"]
    assert report.retained == ["other"]
