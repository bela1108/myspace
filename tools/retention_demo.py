#!/usr/bin/env python3
"""Read-only JKS retention-decision demo on a fully synthetic keystore.

Run:  python3 tools/retention_demo.py

The keystore, certificates, retention rules, external public-material catalog
and pending items are all generated in memory; nothing is read from or written
to a real keystore. The report shows, per private-key entry, whether it may be
destroyed and, when blocked, exactly which public certificate would lift the
block once archived.
"""

from __future__ import print_function

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jks import retention as R
from jks import synthetic as S


NOW = datetime.datetime(2026, 6, 1)


def build_fixture():
    # Two independent hierarchies so a duplicate cert can never paper over a
    # genuinely missing intermediate.
    alpha_root = S.build_cert("Alpha Root CA", serial=100)
    alpha_inter = S.build_cert(
        "Alpha Intermediate CA", issuer_name=S._dn("Alpha Root CA"), serial=101)
    alpha_leaf_a = S.build_cert(
        "alpha-service-a", issuer_name=S._dn("Alpha Intermediate CA"), serial=102)
    alpha_leaf_b = S.build_cert(
        "alpha-service-b", issuer_name=S._dn("Alpha Intermediate CA"), serial=103)

    beta_root = S.build_cert("Beta Root CA", serial=200)
    beta_inter = S.build_cert(
        "Beta Intermediate CA", issuer_name=S._dn("Beta Root CA"), serial=201)
    beta_leaf = S.build_cert(
        "beta-service", issuer_name=S._dn("Beta Intermediate CA"), serial=202)

    entries = [
        S.build_private_key_entry(
            "alpha-full", [alpha_leaf_a, alpha_inter, alpha_root]),
        S.build_private_key_entry("alpha-leaf-only", [alpha_leaf_b]),
        S.build_private_key_entry(
            "beta-incomplete", [beta_leaf, beta_inter, beta_root]),
    ]
    keystore, password = S.build_keystore(entries)

    certs = {
        "alpha_root": alpha_root,
        "alpha_inter": alpha_inter,
        "alpha_leaf_a": alpha_leaf_a,
        "alpha_leaf_b": alpha_leaf_b,
        "beta_root": beta_root,
        "beta_inter": beta_inter,
        "beta_leaf": beta_leaf,
    }
    return keystore, password, certs


def build_rules():
    # Three distinct retention policies expressed through in-use and retention
    # windows. They deliberately produce all three outcomes across the entries.
    return [
        R.RetentionRule(
            "rule-archive-long",
            in_use_until=datetime.datetime(2025, 1, 1),
            retain_until=datetime.datetime(2030, 1, 1),
            aliases=["alpha-full"],
            description="Long archival duty for the flagship service key"),
        R.RetentionRule(
            "rule-standard",
            in_use_until=datetime.datetime(2025, 6, 1),
            retain_until=datetime.datetime(2026, 1, 1),
            aliases=["alpha-leaf-only"],
            description="Standard 1-year post-use retention"),
        R.RetentionRule(
            "rule-beta-expired",
            in_use_until=datetime.datetime(2025, 1, 1),
            retain_until=datetime.datetime(2025, 12, 1),
            aliases=["beta-incomplete"],
            description="Beta policy already fully expired"),
    ]


def build_catalog(certs):
    # Public material held OUTSIDE the keystore. The Beta intermediate is
    # conspicuously absent; an extra copy of the Alpha leaf cannot substitute.
    catalog = R.PublicMaterialCatalog()
    catalog.add(certs["alpha_root"], source="published-root-bundle")
    catalog.add(certs["alpha_inter"], source="intermediate-archive")
    catalog.add(certs["alpha_leaf_a"], source="public-record")
    catalog.add(certs["alpha_leaf_b"], source="public-record")
    catalog.add(certs["beta_root"], source="published-root-bundle")
    catalog.add(certs["beta_leaf"], source="public-record")
    # Deliberately no beta_inter: this is the missing intermediate.
    return catalog


def build_pending(certs):
    return [
        R.PendingItem(
            "verify-alpha-leaf-b-checksum",
            fingerprint=R.X509Cert(certs["alpha_leaf_b"]).fingerprint,
            resolved=False,
            description="Confirm archived checksum of alpha-service-b leaf"),
    ]


def short(fp):
    return fp[:12]


def print_report(title, report, certs):
    print("=" * 72)
    print(title)
    print("=" * 72)
    for alias in sorted(report.decisions):
        decision = report.decisions[alias]
        print("\n[%s] %s -> %s" % (alias, "PRIVATE KEY", decision.status.upper()))
        for rule_id, verdict in sorted(decision.rule_matches.items()):
            print("    rule %-18s in_use=%-5s retained=%s"
                  % (rule_id, verdict["in_use"], verdict["retained"]))
        for blocker in decision.blockers:
            extra = (" | archive cert %s to unblock"
                     % short(blocker.resolvable_by)) if blocker.resolvable_by else ""
            print("    BLOCKER %-22s %s%s"
                  % (blocker.code, blocker.message, extra))
        if not decision.blockers:
            print("    no blockers: public chain rebuilt externally, safe to destroy")
    print("\nSummary: destroyable=%s retained=%s blocked=%s"
          % (report.destroyable, report.retained, report.blocked))


def main():
    keystore, _password, certs = build_fixture()
    rules = build_rules()
    pending = build_pending(certs)
    catalog = build_catalog(certs)

    report = R.audit_keystore(keystore, rules, catalog, pending, now=NOW)
    print_report("BASELINE AUDIT (read-only, synthetic JKS)", report, certs)

    recs = report.unblock_recommendations()
    print("\n" + "-" * 72)
    print("Unblock recommendations (public material -> entries freed):")
    for fingerprint, aliases in sorted(recs.items()):
        source = catalog.source_of(fingerprint)
        print("  %s  unblocks %s  (already in catalog: %s)"
              % (short(fingerprint), sorted(aliases), source is not None))

    # Path 1: the alpha leaf chain is fully rebuildable externally; only the
    # unresolved checksum pending item keeps it from being destroyed.
    for item in pending:
        item.resolved = True
    report_resolved = R.audit_keystore(keystore, rules, catalog, pending, now=NOW)
    alpha_before = report.decisions["alpha-leaf-only"].status
    alpha_after = report_resolved.decisions["alpha-leaf-only"].status
    print("\nAfter resolving the pending evidence item:")
    print("  alpha-leaf-only: %s -> %s" % (alpha_before, alpha_after))

    # Path 2: beta needs a certificate that exists nowhere. Duplicate copies of
    # other public material cannot help; only archiving the Beta intermediate
    # clears the concrete chain blocker.
    missing = R.X509Cert(certs["beta_inter"])
    beta_before = report_resolved.decisions["beta-incomplete"].status
    print("\nArchiving the one missing public material: "
          "Beta Intermediate CA (%s)" % short(missing.fingerprint))
    catalog.add(certs["beta_inter"], source="newly-archived-intermediate")
    report_final = R.audit_keystore(keystore, rules, catalog, pending, now=NOW)
    beta_after = report_final.decisions["beta-incomplete"].status
    print("  beta-incomplete: %s -> %s" % (beta_before, beta_after))

    assert alpha_before == R.INSUFFICIENT_EVIDENCE
    assert alpha_after == R.DESTROY
    assert beta_before == R.INSUFFICIENT_EVIDENCE
    assert beta_after == R.DESTROY
    print("\nFinal: destroyable=%s retained=%s blocked=%s"
          % (report_final.destroyable, report_final.retained,
             report_final.blocked))
    print("\nConfirmed: archiving the single Beta intermediate certificate")
    print("lifted one specific blocker; duplicate certs could not substitute.")


if __name__ == "__main__":
    main()
