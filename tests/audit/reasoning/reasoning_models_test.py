from detect_secrets.audit.reasoning import Evidence
from detect_secrets.audit.reasoning import Exclusion
from detect_secrets.audit.reasoning import Explanation
from detect_secrets.audit.reasoning import Finding
from detect_secrets.audit.reasoning import FindingStatus
from detect_secrets.audit.reasoning.models import FindingEvaluation


class TestEvidence:
    def test_round_trip_with_default_active_state(self) -> None:
        data = Evidence('e', 'reason').json()
        assert data == {'id': 'e', 'reason': 'reason', 'active': True}
        assert Evidence.from_dict(data) == Evidence('e', 'reason')

    def test_round_trip_withdrawn_evidence(self) -> None:
        evidence = Evidence.from_dict({
            'id': 'e',
            'reason': 'reason',
            'active': False,
        })
        assert evidence.active is False
        assert Evidence.from_dict(evidence.json()) == evidence


class TestExplanation:
    def test_round_trip(self) -> None:
        explanation = Explanation('A', 'reason', ('e1', 'e2'))
        restored = Explanation.from_dict(explanation.json())
        assert restored == explanation
        assert restored.evidence_ids == ('e1', 'e2')

    def test_defaults_to_no_supporting_evidence(self) -> None:
        explanation = Explanation.from_dict({'id': 'A', 'reason': 'reason'})
        assert explanation.evidence_ids == ()


class TestExclusion:
    def test_pair_is_sorted_and_symmetric(self) -> None:
        assert Exclusion('A', 'B', 'reason').pair() == ('A', 'B')
        assert Exclusion('B', 'A', 'reason').pair() == ('A', 'B')

    def test_round_trip(self) -> None:
        exclusion = Exclusion('B', 'A', 'reason')
        assert Exclusion.from_dict(exclusion.json()) == exclusion


class TestFinding:
    def test_support_is_exposed_as_a_set(self) -> None:
        finding = Finding('F', 'reason', ('A', 'B'))
        assert finding.support == {'A', 'B'}

    def test_round_trip(self) -> None:
        finding = Finding('F', 'reason', ('A', 'B'))
        assert Finding.from_dict(finding.json()) == finding


class TestFindingEvaluation:
    def test_json_exposes_status_and_supporting_worlds(self) -> None:
        evaluation = FindingEvaluation(
            finding=Finding('F', 'reason', ('A', 'B')),
            status=FindingStatus.PENDING,
            supporting_worlds=(frozenset({'A'}), frozenset({'B'})),
            world_count=2,
        )

        assert evaluation.json() == {
            'id': 'F',
            'reason': 'reason',
            'status': 'pending',
            'supporting_explanation_ids': ['A', 'B'],
            'supporting_worlds': [['A'], ['B']],
            'world_count': 2,
        }
