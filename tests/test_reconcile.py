import os
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory

from truststore.reconcile import (
    ENTRY_POINT_CONFIGURE_CONTEXT,
    ENTRY_POINT_VERIFY_PEERCERTS,
    SOURCE_APPROVAL,
    SOURCE_EXPLICIT,
    SOURCE_SYSTEM,
    Approval,
    ExplicitLocation,
    ProcessConfig,
    SystemTrustStandIn,
    diff_reports,
    load_pem_cert_record,
    reconcile,
    reconcile_process,
)

BEFORE_EXPIRY = datetime(2026, 5, 1, tzinfo=timezone.utc)
APPROVAL_EXPIRY = datetime(2026, 6, 1, tzinfo=timezone.utc)
AFTER_EXPIRY = datetime(2026, 7, 1, tzinfo=timezone.utc)


def make_public_cert(directory: str, common_name: str) -> str:
    """Generates a temporary self-signed certificate; only the public
    certificate is used by the reconciliation."""
    key_path = os.path.join(directory, f"{common_name}.key")
    pem_path = os.path.join(directory, f"{common_name}.pem")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            pem_path,
            "-days",
            "30",
            "-nodes",
            "-subj",
            f"/CN={common_name}",
        ],
        check=True,
        capture_output=True,
    )
    return pem_path


class ReconcileTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.managed = load_pem_cert_record(
            make_public_cert(cls.tmp.name, "managed-root")
        )
        cls.exception = load_pem_cert_record(
            make_public_cert(cls.tmp.name, "exception-ca")
        )
        cls.extra = load_pem_cert_record(make_public_cert(cls.tmp.name, "extra-ca"))

    def make_stand_in(self, fully_observed=(), partially_observed=()):
        stand_in = SystemTrustStandIn()
        for fingerprint in fully_observed:
            stand_in.record(fingerprint, ENTRY_POINT_CONFIGURE_CONTEXT)
            stand_in.record(fingerprint, ENTRY_POINT_VERIFY_PEERCERTS)
        for fingerprint in partially_observed:
            stand_in.record(fingerprint, ENTRY_POINT_CONFIGURE_CONTEXT)
        return stand_in

    def make_approval(self, fingerprint, processes, not_after=APPROVAL_EXPIRY):
        return Approval(
            reference="EXC-0001",
            fingerprint=fingerprint,
            processes=frozenset(processes),
            not_after=not_after,
        )

    def test_claimable_scope_combines_all_three_inputs(self):
        stand_in = self.make_stand_in(fully_observed=[self.managed.fingerprint])
        location = ExplicitLocation(
            kind="cafile",
            location="/etc/app/roots.pem",
            fingerprints=frozenset([self.extra.fingerprint]),
        )
        approval = self.make_approval(self.exception.fingerprint, ["worker"])
        config = ProcessConfig(
            name="worker",
            explicit_locations=(location,),
            exception_fingerprints=frozenset([self.exception.fingerprint]),
        )

        report = reconcile_process(
            config, stand_in=stand_in, approvals=[approval], as_of=BEFORE_EXPIRY
        )

        assert report.claimable() == frozenset(
            [
                self.managed.fingerprint,
                self.extra.fingerprint,
                self.exception.fingerprint,
            ]
        )
        system_sources = {
            e.source for e in report.general_entry[self.managed.fingerprint]
        }
        assert system_sources == {SOURCE_SYSTEM}
        explicit_sources = {e.source for e in report.general_entry[self.extra.fingerprint]}
        assert explicit_sources == {SOURCE_EXPLICIT}
        approved = report.approved_entry[self.exception.fingerprint]
        assert {e.source for e in approved} == {SOURCE_APPROVAL}
        assert approved[0].detail == "approval:EXC-0001"
        assert report.revocations == []
        assert report.pending_evidence == []

    def test_expired_approval_revoked_but_system_lineage_kept(self):
        # The exception certificate is *also* trusted by the system; both
        # independent lineages must remain visible after the approval lapses.
        stand_in = self.make_stand_in(fully_observed=[self.exception.fingerprint])
        approval = self.make_approval(self.exception.fingerprint, ["worker"])
        config = ProcessConfig(
            name="worker",
            exception_fingerprints=frozenset([self.exception.fingerprint]),
        )

        report = reconcile_process(
            config, stand_in=stand_in, approvals=[approval], as_of=AFTER_EXPIRY
        )

        assert self.exception.fingerprint in report.general_entry
        assert {
            e.source for e in report.general_entry[self.exception.fingerprint]
        } == {SOURCE_SYSTEM}
        assert report.approved_entry == {}
        assert len(report.revocations) == 1
        revocation = report.revocations[0]
        assert revocation.reference == "EXC-0001"
        assert revocation.fingerprint == self.exception.fingerprint
        assert "expired" in revocation.reason

    def test_approval_for_other_process_not_claimable(self):
        stand_in = self.make_stand_in()
        approval = self.make_approval(self.exception.fingerprint, ["other-proc"])
        config = ProcessConfig(
            name="worker",
            exception_fingerprints=frozenset([self.exception.fingerprint]),
        )

        report = reconcile_process(
            config, stand_in=stand_in, approvals=[approval], as_of=BEFORE_EXPIRY
        )

        assert report.approved_entry == {}
        assert len(report.revocations) == 1
        assert report.revocations[0].reference == "<none>"

    def test_partial_observation_listed_as_pending_evidence(self):
        stand_in = self.make_stand_in(
            fully_observed=[self.managed.fingerprint],
            partially_observed=[self.extra.fingerprint],
        )
        config = ProcessConfig(name="worker")

        report = reconcile_process(
            config, stand_in=stand_in, approvals=[], as_of=BEFORE_EXPIRY
        )

        assert len(report.pending_evidence) == 1
        pending = report.pending_evidence[0]
        assert pending.fingerprint == self.extra.fingerprint
        assert pending.missing_entry_points == (ENTRY_POINT_VERIFY_PEERCERTS,)
        # A partially observed certificate is still reported, flagged as pending.
        assert self.extra.fingerprint in report.general_entry

    def test_unknown_entry_point_rejected(self):
        stand_in = SystemTrustStandIn()
        with self.assertRaises(ValueError):
            stand_in.record(self.managed.fingerprint, "not-an-entry-point")

    def test_diff_reports_across_approval_expiry(self):
        # Acceptance: compare the evidence of the general entry and the
        # approved entry before and after the exception approval expires.
        stand_in = self.make_stand_in(
            fully_observed=[self.managed.fingerprint, self.exception.fingerprint]
        )
        location = ExplicitLocation(
            kind="cadata",
            location="<memory>",
            fingerprints=frozenset([self.extra.fingerprint]),
        )
        approval = self.make_approval(self.exception.fingerprint, ["worker"])
        config = ProcessConfig(
            name="worker",
            explicit_locations=(location,),
            exception_fingerprints=frozenset([self.exception.fingerprint]),
        )

        before, = reconcile(
            [config], stand_in=stand_in, approvals=[approval], as_of=BEFORE_EXPIRY
        )
        after, = reconcile(
            [config], stand_in=stand_in, approvals=[approval], as_of=AFTER_EXPIRY
        )
        diff = diff_reports(before, after)

        # The general entry is untouched by the approval expiry: system trust
        # and explicit locations are independent lineages.
        assert diff.general_added == frozenset()
        assert diff.general_removed == frozenset()
        # The approved entry loses exactly the exception certificate evidence.
        assert diff.approved_added == frozenset()
        assert {e.fingerprint for e in diff.approved_removed} == {
            self.exception.fingerprint
        }
        # The expired approval shows up as a reference to revoke.
        assert {r.reference for r in diff.revocations_added} == {"EXC-0001"}
        # The certificate itself remains claimable through the general entry.
        assert self.exception.fingerprint in after.claimable()

    def test_pending_evidence_resolves_when_observation_completes(self):
        config = ProcessConfig(name="worker")
        partial = self.make_stand_in(partially_observed=[self.managed.fingerprint])
        complete = self.make_stand_in(fully_observed=[self.managed.fingerprint])

        before = reconcile_process(
            config, stand_in=partial, approvals=[], as_of=BEFORE_EXPIRY
        )
        after = reconcile_process(
            config, stand_in=complete, approvals=[], as_of=BEFORE_EXPIRY
        )
        diff = diff_reports(before, after)

        assert len(diff.pending_resolved) == 1
        assert diff.pending_added == frozenset()

    def test_load_pem_cert_record_reads_public_cert(self):
        record = self.managed
        assert record.fingerprint.count(":") == 31  # SHA-256 hex pairs
        assert record.subject is not None and "managed-root" in record.subject
        assert record.not_after is not None
        assert record.not_after > datetime.now(timezone.utc)
        assert record.not_after < datetime.now(timezone.utc) + timedelta(days=31)


if __name__ == "__main__":
    unittest.main()
