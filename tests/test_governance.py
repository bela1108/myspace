"""Tests for the sigma.governance purpose-gate module."""

from datetime import datetime, timezone

import pytest

from sigma.exceptions import SampleSourceError, SigmaGovernanceError
from sigma.governance import (
    CoverageEntry,
    DualPersonConfirmation,
    EvidenceKind,
    MatchResultRecord,
    OfflineRunResult,
    PurposeGate,
    RejectedEntry,
    SampleKey,
    SamplePurpose,
    SampleRecord,
    SampleSource,
    run_offline_coverage,
)

TRAINING_PACKAGE = SampleSource("training-package", "Internal detection training pack")
RELEASE_EVIDENCE = SampleSource("rule-release-evidence", "Curated rule release evidence")
SHARED_SAMPLE_ID = "event-42"

RULE_YAML = """
title: Mimikatz Execution
name: mimikatz_execution
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "mimikatz"
    condition: selection
"""


def make_sample(
    source: SampleSource, purpose: SamplePurpose, sample_id: str = SHARED_SAMPLE_ID
) -> SampleRecord:
    return SampleRecord(
        sample_id=sample_id,
        source=source,
        purpose=purpose,
        data={"CommandLine": "C:\\tools\\mimikatz.exe"},
        logsource_category="process_creation",
        logsource_product="windows",
        timestamp=datetime(2026, 11, 28, tzinfo=timezone.utc),
    )


class TestSampleIdentity:
    def test_identical_sample_id_from_different_sources_is_distinct(self):
        training_key = SampleKey(TRAINING_PACKAGE, SHARED_SAMPLE_ID)
        release_key = SampleKey(RELEASE_EVIDENCE, SHARED_SAMPLE_ID)

        assert training_key != release_key
        assert len({training_key, release_key}) == 2
        assert training_key.source_name == "training-package"
        assert release_key.source_name == "rule-release-evidence"

    def test_same_source_and_id_are_equal_even_with_different_shared_fields(self):
        first = SampleKey.of("training-package", SHARED_SAMPLE_ID)
        second = SampleKey.of(SampleSource("training-package"), SHARED_SAMPLE_ID)
        assert first == second
        assert hash(first) == hash(second)

    def test_empty_source_or_sample_id_rejected(self):
        with pytest.raises(SampleSourceError):
            SampleSource("   ")
        with pytest.raises(SampleSourceError):
            SampleKey(TRAINING_PACKAGE, "")

    def test_record_requires_explicit_source_and_purpose(self):
        with pytest.raises(SampleSourceError):
            SampleRecord(
                sample_id="x",
                source="training-package",  # type: ignore[arg-type]
                purpose=SamplePurpose.TRAINING,
                data={},
            )
        with pytest.raises(SampleSourceError):
            SampleRecord(
                sample_id="x",
                source=TRAINING_PACKAGE,
                purpose="training",  # type: ignore[arg-type]
                data={},
            )


class TestDualPersonConfirmation:
    def test_submitter_and_reviewer_must_differ(self):
        with pytest.raises(SampleSourceError):
            DualPersonConfirmation(submitter="alice", reviewer="alice")

    def test_valid_confirmation_accepted(self):
        confirmation = DualPersonConfirmation(submitter="alice", reviewer="bob")
        assert confirmation.submitter == "alice"
        assert confirmation.reviewer == "bob"


class TestPurposeGate:
    def test_grants_are_independent_per_evidence_kind(self):
        gate = PurposeGate()
        gate.grant(EvidenceKind.SAMPLE_SOURCE, TRAINING_PACKAGE, SamplePurpose.TRAINING)

        assert gate.is_allowed(EvidenceKind.SAMPLE_SOURCE, TRAINING_PACKAGE, SamplePurpose.TRAINING)
        for kind in (EvidenceKind.MATCH_RESULT, EvidenceKind.DUAL_CONFIRMATION):
            assert not gate.is_allowed(kind, TRAINING_PACKAGE, SamplePurpose.TRAINING)
        assert not gate.is_allowed(
            EvidenceKind.SAMPLE_SOURCE, TRAINING_PACKAGE, SamplePurpose.FORMAL
        )

    def test_training_grant_never_satisfies_formal_purpose(self):
        gate = PurposeGate()
        gate.grant(EvidenceKind.SAMPLE_SOURCE, TRAINING_PACKAGE, SamplePurpose.TRAINING)

        gate.require_allowed(EvidenceKind.SAMPLE_SOURCE, TRAINING_PACKAGE, SamplePurpose.TRAINING)
        with pytest.raises(SigmaGovernanceError):
            gate.require_allowed(EvidenceKind.SAMPLE_SOURCE, TRAINING_PACKAGE, SamplePurpose.FORMAL)

    def test_grants_are_scoped_per_source_and_do_not_leak(self):
        gate = PurposeGate()
        gate.grant(EvidenceKind.MATCH_RESULT, RELEASE_EVIDENCE, SamplePurpose.FORMAL)

        assert not gate.is_allowed(
            EvidenceKind.MATCH_RESULT, TRAINING_PACKAGE, SamplePurpose.FORMAL
        )
        assert gate.allowed_purposes(EvidenceKind.MATCH_RESULT, RELEASE_EVIDENCE) == frozenset(
            {SamplePurpose.FORMAL}
        )

    def test_revoke_removes_only_targeted_grant(self):
        gate = PurposeGate()
        gate.grant(EvidenceKind.SAMPLE_SOURCE, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.grant(EvidenceKind.MATCH_RESULT, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.revoke(EvidenceKind.SAMPLE_SOURCE, RELEASE_EVIDENCE, SamplePurpose.FORMAL)

        assert not gate.is_allowed(
            EvidenceKind.SAMPLE_SOURCE, RELEASE_EVIDENCE, SamplePurpose.FORMAL
        )
        assert gate.is_allowed(EvidenceKind.MATCH_RESULT, RELEASE_EVIDENCE, SamplePurpose.FORMAL)

    def test_register_sample_requires_source_grant(self):
        gate = PurposeGate()
        sample = make_sample(TRAINING_PACKAGE, SamplePurpose.TRAINING)
        with pytest.raises(SigmaGovernanceError):
            gate.register_sample(sample)

        gate.grant(EvidenceKind.SAMPLE_SOURCE, TRAINING_PACKAGE, SamplePurpose.TRAINING)
        gate.register_sample(sample)
        assert gate.get_sample(sample.key) is sample

    def test_same_id_samples_coexist_and_are_gated_independently(self):
        gate = PurposeGate()
        training_sample = make_sample(TRAINING_PACKAGE, SamplePurpose.TRAINING)
        release_sample = make_sample(RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.grant(EvidenceKind.SAMPLE_SOURCE, TRAINING_PACKAGE, SamplePurpose.TRAINING)
        gate.grant(EvidenceKind.SAMPLE_SOURCE, RELEASE_EVIDENCE, SamplePurpose.FORMAL)

        gate.register_sample(training_sample)
        gate.register_sample(release_sample)

        assert gate.get_sample(training_sample.key) is training_sample
        assert gate.get_sample(release_sample.key) is release_sample
        assert len(gate.reportable_keys()) == 0

    def test_confirmation_requires_its_own_grant(self):
        gate = PurposeGate()
        gate.grant(EvidenceKind.SAMPLE_SOURCE, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        sample = make_sample(RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_sample(sample)

        with pytest.raises(SigmaGovernanceError):
            gate.register_confirmation(
                sample.key, DualPersonConfirmation(submitter="alice", reviewer="bob")
            )

        gate.grant(EvidenceKind.DUAL_CONFIRMATION, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_confirmation(
            sample.key, DualPersonConfirmation(submitter="alice", reviewer="bob")
        )
        assert gate.get_confirmation(sample.key) is not None

    def test_confirmation_for_unknown_sample_rejected(self):
        gate = PurposeGate()
        key = SampleKey(RELEASE_EVIDENCE, "unknown")
        gate.grant(EvidenceKind.DUAL_CONFIRMATION, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        with pytest.raises(SampleSourceError):
            gate.register_confirmation(
                key, DualPersonConfirmation(submitter="alice", reviewer="bob")
            )

    def test_match_result_registration_requires_match_grant(self):
        gate = PurposeGate()
        gate.grant(EvidenceKind.SAMPLE_SOURCE, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        sample = make_sample(RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_sample(sample)
        record = MatchResultRecord(
            rule_name="mimikatz_execution",
            sample_key=sample.key,
            sample_purpose=sample.purpose,
            matched=True,
        )
        with pytest.raises(SigmaGovernanceError):
            gate.register_match_result(record)

        gate.grant(EvidenceKind.MATCH_RESULT, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_match_result(record)
        assert gate.get_match_result(sample.key) is record


class TestFormalReport:
    def test_duplicate_composite_key_in_input_is_rejected(self, prepared_gate):
        sample = make_sample(RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        with pytest.raises(SampleSourceError):
            run_offline_coverage(RULE_YAML, prepared_gate, [sample, sample])

    @pytest.fixture
    def prepared_gate(self):
        gate = PurposeGate()
        for source in (TRAINING_PACKAGE, RELEASE_EVIDENCE):
            gate.grant(EvidenceKind.SAMPLE_SOURCE, source, SamplePurpose.FORMAL)
            gate.grant(EvidenceKind.MATCH_RESULT, source, SamplePurpose.FORMAL)
            gate.grant(EvidenceKind.DUAL_CONFIRMATION, source, SamplePurpose.FORMAL)
        # Training source additionally receives a training grant but no formal path abuse.
        gate.grant(EvidenceKind.SAMPLE_SOURCE, TRAINING_PACKAGE, SamplePurpose.TRAINING)
        return gate

    def test_only_formally_approved_sample_is_listed(self, prepared_gate):
        gate = prepared_gate
        training_sample = make_sample(TRAINING_PACKAGE, SamplePurpose.TRAINING)
        release_sample = make_sample(RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_sample(training_sample)
        gate.register_sample(release_sample)
        gate.register_confirmation(
            release_sample.key, DualPersonConfirmation(submitter="alice", reviewer="bob")
        )

        result = run_offline_coverage(RULE_YAML, gate, [training_sample, release_sample])

        assert isinstance(result, OfflineRunResult)
        assert result.consistent is True
        assert result.discrepancies == []
        assert result.report.rule_name == "mimikatz_execution"
        assert [entry.sample_key for entry in result.report.entries] == [release_sample.key]
        assert all(isinstance(entry, CoverageEntry) for entry in result.report.entries)
        assert result.report.entries[0].matched is True
        rejected_keys = {entry.sample_key: entry for entry in result.report.rejected}
        assert training_sample.key in rejected_keys
        assert all(isinstance(entry, RejectedEntry) for entry in result.report.rejected)

    def test_missing_dual_confirmation_excludes_formal_sample(self, prepared_gate):
        gate = prepared_gate
        release_sample = make_sample(RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_sample(release_sample)

        result = run_offline_coverage(RULE_YAML, gate, [release_sample])

        assert result.report.entries == []
        assert result.report.rejected[0].reason == "missing dual-person confirmation"

    def test_missing_one_kind_grant_excludes_sample(self):
        gate = PurposeGate()
        gate.grant(EvidenceKind.SAMPLE_SOURCE, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.grant(EvidenceKind.MATCH_RESULT, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        # No DUAL_CONFIRMATION grant.
        sample = make_sample(RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_sample(sample)

        result = run_offline_coverage(RULE_YAML, gate, [sample])

        assert result.report.entries == []
        assert "dual_confirmation" in result.report.rejected[0].reason

    def test_two_runs_are_independent_and_verified(self, prepared_gate):
        gate = prepared_gate
        sample = make_sample(RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_sample(sample)
        gate.register_confirmation(
            sample.key, DualPersonConfirmation(submitter="alice", reviewer="bob")
        )

        result = run_offline_coverage(
            RULE_YAML,
            gate,
            [sample],
            first_run_label="offline-a",
            second_run_label="offline-b",
        )

        assert result.first_run_label == "offline-a"
        assert result.second_run_label == "offline-b"
        assert result.consistent is True
        assert len(result.report.entries) == 1

    def test_non_matching_sample_is_rejected_even_when_fully_approved(self, prepared_gate):
        gate = prepared_gate
        sample = SampleRecord(
            sample_id=SHARED_SAMPLE_ID,
            source=RELEASE_EVIDENCE,
            purpose=SamplePurpose.FORMAL,
            data={"CommandLine": "notepad.exe"},
            logsource_category="process_creation",
            logsource_product="windows",
            timestamp=datetime(2026, 11, 28, tzinfo=timezone.utc),
        )
        gate.register_sample(sample)
        gate.register_confirmation(
            sample.key, DualPersonConfirmation(submitter="alice", reviewer="bob")
        )

        result = run_offline_coverage(RULE_YAML, gate, [sample])

        assert result.report.entries == []
        assert result.report.rejected[0].reason == "rule did not match the sample"

    def test_reportable_keys_requires_all_three_kinds_and_confirmation(self, prepared_gate):
        gate = prepared_gate
        sample = make_sample(RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_sample(sample)
        assert gate.reportable_keys() == []

        gate.grant(EvidenceKind.MATCH_RESULT, RELEASE_EVIDENCE, SamplePurpose.FORMAL)
        gate.register_match_result(
            MatchResultRecord(
                rule_name="mimikatz_execution",
                sample_key=sample.key,
                sample_purpose=sample.purpose,
                matched=True,
            )
        )
        assert gate.reportable_keys() == []

        gate.register_confirmation(
            sample.key, DualPersonConfirmation(submitter="alice", reviewer="bob")
        )
        assert gate.reportable_keys() == [sample.key]
