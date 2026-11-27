import pytest

from detect_secrets.audit.reasoning import Evidence
from detect_secrets.audit.reasoning import Exclusion
from detect_secrets.audit.reasoning import Explanation
from detect_secrets.audit.reasoning import Finding
from detect_secrets.audit.reasoning import FindingStatus
from detect_secrets.audit.reasoning import InvalidReasoningError
from detect_secrets.audit.reasoning import ReasoningCase


def build_case() -> ReasoningCase:
    return ReasoningCase(
        case_id='sample-1',
        evidence=[
            Evidence('eA', 'evidence backing interpretation A'),
            Evidence('eB', 'evidence backing interpretation B'),
        ],
        explanations=[
            Explanation('A', 'first interpretation', ('eA',)),
            Explanation('B', 'second interpretation', ('eB',)),
            Explanation('C', 'uncontested interpretation', ()),
        ],
        exclusions=[Exclusion('A', 'B', 'the two readings cannot coexist')],
        findings=[
            Finding('F1', 'allowed by either reading', ('A', 'B')),
            Finding('F2', 'only the first reading supports it', ('A',)),
            Finding('F3', 'supported by the uncontested reading', ('C',)),
        ],
    )


class TestRecords:
    def test_stores_exclusion_relation_and_reason(self) -> None:
        case = build_case()

        assert len(case.exclusions) == 1
        exclusion = case.exclusions[0]
        assert exclusion.pair() == ('A', 'B')
        assert exclusion.reason == 'the two readings cannot coexist'

        # The relation is symmetric regardless of how it was declared.
        case.add_exclusion(Exclusion('B', 'A', 'duplicate declaration'))
        assert len(case.exclusions) == 1
        assert case.exclusions[0].reason == 'duplicate declaration'

    def test_stores_per_explanation_rationale(self) -> None:
        case = build_case()

        assert case.explanations['A'].reason == 'first interpretation'
        assert case.explanations['A'].evidence_ids == ('eA',)

    def test_unknown_references_are_rejected(self) -> None:
        with pytest.raises(InvalidReasoningError):
            ReasoningCase(
                case_id='bad',
                explanations=[Explanation('A', 'reason', ('missing',))],
            )

        case = ReasoningCase(case_id='bad')
        with pytest.raises(InvalidReasoningError):
            case.add_explanation(Explanation('A', 'reason', ('missing',)))
        with pytest.raises(InvalidReasoningError):
            case.add_exclusion(Exclusion('A', 'B', 'reason'))
        with pytest.raises(InvalidReasoningError):
            case.add_finding(Finding('F', 'reason', ('A',)))

    def test_add_exclusion_reports_unknown_right_reference(self) -> None:
        case = ReasoningCase(
            case_id='bad',
            explanations=[Explanation('A', 'reason')],
        )
        with pytest.raises(InvalidReasoningError):
            case.add_exclusion(Exclusion('A', 'missing', 'reason'))

    def test_exclusion_cannot_reference_self(self) -> None:
        case = ReasoningCase(
            case_id='bad',
            explanations=[Explanation('A', 'reason')],
        )
        with pytest.raises(InvalidReasoningError):
            case.add_exclusion(Exclusion('A', 'A', 'reason'))


class TestConsistency:
    def test_mutually_exclusive_explanations_form_separate_worlds(self) -> None:
        case = build_case()

        worlds = case.consistent_worlds()
        assert sorted(sorted(world) for world in worlds) == [
            ['A', 'C'],
            ['B', 'C'],
        ]

    def test_no_viable_world_when_all_evidence_withdrawn(self) -> None:
        case = build_case()
        case.withdraw_evidence('eA')
        case.withdraw_evidence('eB')

        assert case.consistent_worlds() == [frozenset({'C'})]

    def test_empty_case_has_single_empty_world(self) -> None:
        case = ReasoningCase(case_id='empty')
        assert case.consistent_worlds() == [frozenset()]


class TestFindings:
    def test_common_support_is_required_for_registration(self) -> None:
        case = build_case()
        statuses = {
            evaluation.finding.id: evaluation.status
            for evaluation in case.evaluate_findings()
        }

        # F1 is allowed by both worlds, but A and B never share a world: there
        # is no common supporting explanation, so it must stay pending.
        assert statuses['F1'] == FindingStatus.PENDING
        assert statuses['F2'] == FindingStatus.PENDING
        # C survives every self-consistent world.
        assert statuses['F3'] == FindingStatus.REGISTERED
        assert [finding.id for finding in case.registered_findings()] == ['F3']

    def test_finding_registers_once_evidence_forces_one_world(self) -> None:
        case = build_case()
        case.withdraw_evidence('eB')

        assert case.consistent_worlds() == [frozenset({'A', 'C'})]
        statuses = {
            evaluation.finding.id: evaluation.status
            for evaluation in case.evaluate_findings()
        }
        assert statuses['F1'] == FindingStatus.REGISTERED
        assert statuses['F2'] == FindingStatus.REGISTERED
        assert statuses['F3'] == FindingStatus.REGISTERED

    def test_export_keeps_non_robust_findings_pending(self) -> None:
        export = build_case().export()

        assert export['case_id'] == 'sample-1'
        assert export['selected_explanation_id'] is None
        statuses = {item['id']: item['status'] for item in export['findings']}
        assert statuses == {
            'F1': 'pending',
            'F2': 'pending',
            'F3': 'registered',
        }

    def test_all_findings_pending_without_any_viable_world(self) -> None:
        case = ReasoningCase(
            case_id='no-world',
            evidence=[Evidence('e', 'reason')],
            explanations=[Explanation('A', 'reason', ('e',))],
            findings=[Finding('F', 'reason', ('A',))],
        )
        case.withdraw_evidence('e')

        assert case.consistent_worlds() == []
        assert case.registered_findings() == []
        assert all(
            evaluation.status == FindingStatus.PENDING
            for evaluation in case.evaluate_findings()
        )


class TestEvidenceLifecycle:
    def test_withdrawal_restores_unknown_selection(self) -> None:
        case = build_case()
        case.select_explanation('A')
        assert case.selected_explanation_id == 'A'

        case.withdraw_evidence('eA')

        assert case.evidence['eA'].active is False
        assert 'A' not in case.viable_explanation_ids()
        assert case.selected_explanation_id is None

    def test_withdrawal_keeps_unrelated_selection(self) -> None:
        case = build_case()
        case.select_explanation('A')

        case.withdraw_evidence('eB')

        assert case.selected_explanation_id == 'A'

    def test_restore_evidence_makes_explanation_viable_again(self) -> None:
        case = build_case()
        case.withdraw_evidence('eA')
        assert 'A' not in case.viable_explanation_ids()

        case.restore_evidence('eA')

        assert case.evidence['eA'].active is True
        assert 'A' in case.viable_explanation_ids()

    def test_withdraw_unknown_evidence_raises(self) -> None:
        with pytest.raises(InvalidReasoningError):
            ReasoningCase(case_id='x').withdraw_evidence('missing')

    def test_cannot_select_non_viable_explanation(self) -> None:
        case = build_case()
        case.withdraw_evidence('eA')

        with pytest.raises(InvalidReasoningError):
            case.select_explanation('A')

    def test_clear_selection(self) -> None:
        case = build_case()
        case.select_explanation('C')
        case.clear_selection()
        assert case.selected_explanation_id is None


class TestSerialization:
    def test_round_trip_preserves_full_state(self) -> None:
        case = build_case()
        case.select_explanation('C')
        case.withdraw_evidence('eB')

        restored = ReasoningCase.from_dict(case.json())

        assert restored.case_id == case.case_id
        assert restored.evidence == case.evidence
        assert restored.explanations == case.explanations
        assert restored.exclusions == case.exclusions
        assert restored.findings == case.findings
        assert restored.selected_explanation_id == 'C'
        assert restored.export() == case.export()

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(InvalidReasoningError):
            ReasoningCase.from_dict({'version': '1.0'})


class TestMutatorsAndValidation:
    def test_add_records_individually(self) -> None:
        case = ReasoningCase(case_id='built-incrementally')
        case.add_evidence(Evidence('e', 'reason'))
        case.add_explanation(Explanation('A', 'reason', ('e',)))
        case.add_explanation(Explanation('B', 'reason'))
        case.add_exclusion(Exclusion('A', 'B', 'incompatible'))
        case.add_finding(Finding('F', 'reason', ('A',)))

        assert case.evidence['e'].reason == 'reason'
        assert set(case.explanations) == {'A', 'B'}
        assert case.exclusions[0].pair() == ('A', 'B')
        assert case.findings['F'].support == {'A'}

    def test_add_finding_rejects_unknown_support(self) -> None:
        case = ReasoningCase(case_id='x')
        with pytest.raises(InvalidReasoningError):
            case.add_finding(Finding('F', 'reason', ('missing',)))

    def test_restore_unknown_evidence_raises(self) -> None:
        with pytest.raises(InvalidReasoningError):
            ReasoningCase(case_id='x').restore_evidence('missing')

    def test_select_unknown_explanation_raises(self) -> None:
        with pytest.raises(InvalidReasoningError):
            ReasoningCase(case_id='x').select_explanation('missing')

    def test_constructor_validates_self_exclusion(self) -> None:
        with pytest.raises(InvalidReasoningError):
            ReasoningCase(
                case_id='bad',
                explanations=[Explanation('A', 'reason')],
                exclusions=[Exclusion('A', 'A', 'reason')],
            )

    def test_constructor_validates_unknown_exclusion_reference(self) -> None:
        with pytest.raises(InvalidReasoningError):
            ReasoningCase(
                case_id='bad',
                explanations=[Explanation('A', 'reason')],
                exclusions=[Exclusion('A', 'missing', 'reason')],
            )

    def test_constructor_validates_unknown_finding_support(self) -> None:
        with pytest.raises(InvalidReasoningError):
            ReasoningCase(
                case_id='bad',
                explanations=[Explanation('A', 'reason')],
                findings=[Finding('F', 'reason', ('missing',))],
            )

    def test_constructor_validates_selected_explanation(self) -> None:
        with pytest.raises(InvalidReasoningError):
            ReasoningCase(case_id='bad', selected_explanation_id='missing')

    def test_withdraw_is_idempotent(self) -> None:
        case = ReasoningCase(
            case_id='x',
            evidence=[Evidence('e', 'reason')],
        )
        case.withdraw_evidence('e')
        case.withdraw_evidence('e')

        assert case.evidence['e'].active is False

    def test_restore_is_idempotent(self) -> None:
        case = ReasoningCase(case_id='x', evidence=[Evidence('e', 'reason')])
        case.restore_evidence('e')

        assert case.evidence['e'].active is True
