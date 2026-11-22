#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""
Tests for the offline recovery audit (jks.recovery).

The expected manifests live next to the samples in tests/recovery/ so
that every recovery/retention decision can be traced back to the
original change tickets and certificate entries.
"""
from __future__ import print_function

import json
import os
import unittest

from jks.recovery import (
    RecoveryAuditError,
    audit_recovery,
    load_audit_input,
)

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
RECOVERY_PATH = os.path.join(CUR_PATH, "recovery")

ROLLBACK_SAMPLE = os.path.join(RECOVERY_PATH, "rollback_sample.json")
ROLLBACK_MANIFEST = os.path.join(RECOVERY_PATH,
                                 "rollback_recovery_manifest.json")
INTERLEAVED_SAMPLE = os.path.join(RECOVERY_PATH,
                                  "interleaved_signoff_sample.json")
INTERLEAVED_MANIFEST = os.path.join(RECOVERY_PATH,
                                    "interleaved_retention_manifest.json")


def load_json(path):
    with open(path, "r") as fh:
        return json.load(fh)


def run_sample(sample_path):
    listings, tickets, signoffs = load_audit_input(sample_path)
    scenario = tickets[0].scenario
    return audit_recovery(listings, tickets, signoffs, scenario)


class ManifestTest(unittest.TestCase):
    def check_manifest_matches_expected(self, sample_path, manifest_path):
        plan = run_sample(sample_path)
        self.assertEqual(load_json(manifest_path), plan.to_manifest())

    def check_traceable_to_tickets_and_entries(self, sample_path,
                                               manifest_path):
        sample = load_json(sample_path)
        manifest = load_json(manifest_path)

        ticket_ids = set(t["ticket_id"] for t in sample["tickets"])
        ticket_fingerprints = set()
        for ticket in sample["tickets"]:
            ticket_fingerprints.add(ticket["previous_fingerprint"])
            ticket_fingerprints.add(ticket["new_fingerprint"])
        store_ids = set(l["store_id"] for l in sample["listings"])
        entry_fingerprints = set()
        for listing in sample["listings"]:
            for entry in listing["entries"]:
                entry_fingerprints.add(entry["cert_fingerprint"])

        for ticket_ref in manifest["tickets"]:
            self.assertIn(ticket_ref["ticket_id"], ticket_ids)

        restore = manifest["restore"]
        self.assertIn(restore["cert_fingerprint"], ticket_fingerprints)
        self.assertIn(restore["cert_fingerprint"], entry_fingerprints)
        self.assertIn(restore["source_store"], store_ids)
        self.assertIn(restore["documented_by"], ticket_ids)

        for retained in manifest["retain"]:
            self.assertIn(retained["store_id"], store_ids)
            for entry in retained["entries"]:
                self.assertIn(entry["cert_fingerprint"], entry_fingerprints)
            for reason in retained["reasons"]:
                self.assertIn(reason["cert_fingerprint"],
                              ticket_fingerprints)
                self.assertIn(reason["ticket_id"], ticket_ids)

    def test_rollback_recovery_manifest(self):
        self.check_manifest_matches_expected(ROLLBACK_SAMPLE,
                                             ROLLBACK_MANIFEST)

    def test_rollback_manifest_traceable(self):
        self.check_traceable_to_tickets_and_entries(ROLLBACK_SAMPLE,
                                                    ROLLBACK_MANIFEST)

    def test_interleaved_retention_manifest(self):
        self.check_manifest_matches_expected(INTERLEAVED_SAMPLE,
                                             INTERLEAVED_MANIFEST)

    def test_interleaved_manifest_traceable(self):
        self.check_traceable_to_tickets_and_entries(INTERLEAVED_SAMPLE,
                                                    INTERLEAVED_MANIFEST)


class RollbackSampleTest(unittest.TestCase):
    def test_rollback_to_previous_generation(self):
        plan = run_sample(ROLLBACK_SAMPLE)
        sample = load_json(ROLLBACK_SAMPLE)
        ticket = sample["tickets"][0]

        self.assertEqual("rollback", plan.decision)
        # consumer-b never signed off the new certificate, so the
        # previous generation must be restored even though consumer-a
        # accepted the new one.
        self.assertEqual(ticket["previous_fingerprint"],
                         plan.restore["cert_fingerprint"])
        self.assertEqual("duty-backup-20260201",
                         plan.restore["source_store"])
        self.assertTrue(any("consumer-b" in note for note in plan.notes))

    def test_retains_store_with_signed_off_new_generation(self):
        plan = run_sample(ROLLBACK_SAMPLE)
        retained = dict((r["store_id"], r) for r in plan.retain)
        self.assertIn("duty-backup-20260305", retained)
        reasons = retained["duty-backup-20260305"]["reasons"]
        self.assertEqual("generation_still_signed_off", reasons[0]["reason"])
        self.assertEqual(["consumer-a"], reasons[0]["consumers"])


class InterleavedSignoffSampleTest(unittest.TestCase):
    def test_retains_both_generations(self):
        plan = run_sample(INTERLEAVED_SAMPLE)
        sample = load_json(INTERLEAVED_SAMPLE)
        ticket = sample["tickets"][0]

        self.assertEqual("current", plan.decision)
        self.assertEqual(ticket["new_fingerprint"],
                         plan.restore["cert_fingerprint"])

        # Interleaved sign-offs keep the previous generation referenced,
        # so every historical store is retained.
        self.assertEqual(
            ["edge-backup-20260315", "edge-backup-20260403",
             "edge-backup-20260410"],
            [r["store_id"] for r in plan.retain])

    def test_export_time_not_used_for_generation(self):
        plan = run_sample(INTERLEAVED_SAMPLE)
        sample = load_json(INTERLEAVED_SAMPLE)
        ticket = sample["tickets"][0]

        # edge-backup-20260403 was exported after the switch became
        # effective but still carries the previous certificate; it must
        # be classified by fingerprint, not by export time.
        retained = dict((r["store_id"], r) for r in plan.retain)
        entry = retained["edge-backup-20260403"]["entries"][0]
        self.assertEqual(ticket["previous_fingerprint"],
                         entry["cert_fingerprint"])
        self.assertTrue(any("edge-backup-20260403" in note
                            and "not by export time" in note
                            for note in plan.notes))


class SignoffIndependenceTest(unittest.TestCase):
    def test_missing_signoff_not_inferred_from_other_consumer(self):
        sample = load_json(INTERLEAVED_SAMPLE)
        ticket = sample["tickets"][0]
        # Drop consumer-b's sign-off of the new generation; consumer-a
        # still signs it.  The audit must fall back to the previous
        # generation instead of inferring consumer-b's acceptance.
        sample["signoffs"] = [
            s for s in sample["signoffs"]
            if not (s["consumer"] == "consumer-b"
                    and s["fingerprint"] == ticket["new_fingerprint"])
        ]
        listings, tickets, signoffs = load_audit_input(sample)
        plan = audit_recovery(listings, tickets, signoffs,
                              ticket["scenario"])
        self.assertEqual("rollback", plan.decision)
        self.assertEqual(ticket["previous_fingerprint"],
                         plan.restore["cert_fingerprint"])
        self.assertTrue(any("consumer-b" in note for note in plan.notes))

    def test_no_fully_signed_generation_raises(self):
        sample = load_json(ROLLBACK_SAMPLE)
        ticket = sample["tickets"][0]
        sample["signoffs"] = [
            s for s in sample["signoffs"]
            if s["fingerprint"] != ticket["previous_fingerprint"]
        ]
        listings, tickets, signoffs = load_audit_input(sample)
        self.assertRaises(RecoveryAuditError, audit_recovery,
                          listings, tickets, signoffs, ticket["scenario"])

    def test_unknown_scenario_raises(self):
        listings, tickets, signoffs = load_audit_input(ROLLBACK_SAMPLE)
        self.assertRaises(RecoveryAuditError, audit_recovery,
                          listings, tickets, signoffs, "no-such-scenario")


if __name__ == "__main__":
    unittest.main()
