import json
from pathlib import Path

import pytest

from detect_secrets.audit.reasoning import Evidence
from detect_secrets.audit.reasoning import Exclusion
from detect_secrets.audit.reasoning import Explanation
from detect_secrets.audit.reasoning import Finding
from detect_secrets.audit.reasoning import InvalidReasoningError
from detect_secrets.audit.reasoning import ReasoningCase
from detect_secrets.audit.reasoning.io import load_case
from detect_secrets.audit.reasoning.io import load_legacy_baseline
from detect_secrets.audit.reasoning.io import save_case


def build_case() -> ReasoningCase:
    return ReasoningCase(
        case_id='sample-1',
        evidence=[Evidence('eA', 'reason A'), Evidence('eB', 'reason B')],
        explanations=[
            Explanation('A', 'reading A', ('eA',)),
            Explanation('B', 'reading B', ('eB',)),
        ],
        exclusions=[Exclusion('A', 'B', 'incompatible readings')],
        findings=[Finding('F1', 'shared finding', ('A', 'B'))],
    )


class TestReasoningBaseline:
    def test_save_and_load_round_trip(self, tmp_path: Path) -> None:
        case = build_case()
        filename = tmp_path / 'reasoning.baseline'

        save_case(case, str(filename))
        restored = load_case(str(filename))

        assert restored.json() == case.json()
        assert restored.export() == case.export()

    def test_saved_document_is_versioned_json(self, tmp_path: Path) -> None:
        filename = tmp_path / 'reasoning.baseline'
        save_case(build_case(), str(filename))

        data = json.loads(filename.read_text())
        assert data['version'] == '1.0'
        assert data['case_id'] == 'sample-1'
        assert data['exclusions'] == [
            {
                'left_id': 'A',
                'right_id': 'B',
                'reason': 'incompatible readings',
            },
        ]

    def test_load_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidReasoningError):
            load_case(str(tmp_path / 'missing'))

    def test_load_malformed_json_raises(self, tmp_path: Path) -> None:
        filename = tmp_path / 'broken'
        filename.write_text('{not json')

        with pytest.raises(InvalidReasoningError):
            load_case(str(filename))

    def test_load_unsupported_version_raises(self, tmp_path: Path) -> None:
        filename = tmp_path / 'old'
        filename.write_text(json.dumps({'version': '0.9', 'case_id': 'x'}))

        with pytest.raises(InvalidReasoningError):
            load_case(str(filename))

    def test_load_non_object_document_raises(self, tmp_path: Path) -> None:
        filename = tmp_path / 'list'
        filename.write_text(json.dumps(['not', 'an', 'object']))

        with pytest.raises(InvalidReasoningError):
            load_case(str(filename))


class TestLegacyBaseline:
    def test_existing_audited_baseline_remains_readable(self, tmp_path: Path) -> None:
        baseline = tmp_path / 'legacy.baseline'
        baseline.write_text(json.dumps({
            'version': '1.5.0',
            'plugins_used': [],
            'filters_used': [],
            'results': {
                'audited.txt': [
                    {
                        'type': 'Secret Keyword',
                        'filename': 'audited.txt',
                        'hashed_secret': '0' * 40,
                        'is_verified': False,
                        'is_secret': True,
                        'line_number': 1,
                    },
                ],
            },
        }))

        secrets = load_legacy_baseline(str(baseline))

        assert 'audited.txt' in secrets.files
        audited_secret = next(iter(secrets['audited.txt']))
        assert audited_secret.is_secret is True

    def test_legacy_baseline_without_results_is_rejected(self, tmp_path: Path) -> None:
        filename = tmp_path / 'not-a-baseline'
        filename.write_text(json.dumps({'version': '1.5.0'}))

        with pytest.raises(Exception):
            load_legacy_baseline(str(filename))
