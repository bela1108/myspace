import json
from math import comb

import pytest

from detect_secrets.offline_acceptance import InvalidAcceptanceEvidence
from detect_secrets.offline_acceptance import build_acceptance_report
from detect_secrets.offline_acceptance import hypergeometric_upper_bound


def evidence():
    return {
        'alpha_budget': 0.1,
        'alpha_by_stratum': {'values': {'core': 0.05, 'edge': 0.05}},
        'frozen_manifest': {
            'strata': [{'stratum': 'core'}, {'stratum': 'edge'}],
            'files': [
                {'file_id': 'F1', 'stratum': 'core'},
                {'file_id': 'F2', 'stratum': 'core'},
                {'file_id': 'F3', 'stratum': 'core'},
                {'file_id': 'F4', 'stratum': 'core'},
                {'file_id': 'F5', 'stratum': 'edge'},
                {'file_id': 'F6', 'stratum': 'edge'},
                {'file_id': 'F7', 'stratum': 'edge'},
            ],
        },
        'scan_completion': {
            'scanned_files': [
                {'file_id': 'F1', 'status': 'complete', 'is_positive': False},
                {'file_id': 'F2', 'status': 'complete', 'is_positive': False},
                {'file_id': 'F3', 'status': 'complete', 'is_positive': False},
                {'file_id': 'F4', 'status': 'complete', 'is_positive': True},
                {'file_id': 'F5', 'status': 'complete', 'is_positive': False},
                {'file_id': 'F6', 'status': 'complete', 'is_positive': False},
            ],
        },
        'sampling_records': [
            {
                'stratum': 'core',
                'sampled_files': [
                    {'file_id': 'F1'},
                    {'file_id': 'F2'},
                ],
            },
            {
                'stratum': 'edge',
                'sampled_files': [
                    {'file_id': 'F5'},
                    {'file_id': 'F6'},
                ],
            },
        ],
        'blind_reviews': {
            'files': [
                {
                    'file_id': 'F1',
                    'verdict': 'positive',
                    'problem_locations': [1, 7],
                },
                {'file_id': 'F2', 'verdict': 'negative'},
                {'file_id': 'F5', 'verdict': 'inconclusive'},
            ],
        },
    }


class TestHypergeometricUpperBound:
    @staticmethod
    @pytest.mark.parametrize(
        ('population_size', 'sample_size', 'observed', 'expected'),
        (
            (10, 0, 0, 10),
            (10, 3, 0, 5),
            (10, 3, 1, 8),
            (10, 3, 2, 9),
            (10, 3, 3, 10),
            (10, 10, 2, 2),
        ),
    )
    def test_boundary_values(population_size, sample_size, observed, expected):
        assert hypergeometric_upper_bound(
            population_size,
            sample_size,
            observed,
            0.05,
        ) == expected

    @staticmethod
    def test_ten_file_exhaustive_coverage():
        population_size = 10
        alpha = 0.05

        for sample_size in range(population_size + 1):
            for true_defective in range(population_size + 1):
                coverage = 0
                total_ways = comb(population_size, sample_size)
                for observed in range(min(sample_size, true_defective) + 1):
                    observed_ways = (
                        comb(true_defective, observed)
                        * comb(population_size - true_defective, sample_size - observed)
                    )
                    upper_bound = hypergeometric_upper_bound(
                        population_size,
                        sample_size,
                        observed,
                        alpha,
                    )
                    if true_defective <= upper_bound:
                        coverage += observed_ways

                assert coverage / total_ways >= 1 - alpha

    @staticmethod
    def test_rejects_invalid_counts():
        with pytest.raises(ValueError):
            hypergeometric_upper_bound(2, 3, 0, 0.05)
        with pytest.raises(ValueError):
            hypergeometric_upper_bound(2, 1, 2, 0.05)
        with pytest.raises(ValueError):
            hypergeometric_upper_bound(2, 1, 0, 0)


class TestAcceptanceReport:
    @staticmethod
    def test_aligns_evidence_and_counts_files_once():
        report = build_acceptance_report(evidence())

        assert report == {
            'strata': [
                {
                    'stratum': 'core',
                    'negative_files': 3,
                    'sample_size': 2,
                    'problem_files': 1,
                    'missing_review_files': 0,
                    'upper_bound': 3,
                },
                {
                    'stratum': 'edge',
                    'negative_files': 2,
                    'sample_size': 2,
                    'problem_files': 1,
                    'missing_review_files': 1,
                    'upper_bound': 2,
                },
            ],
            'totals': {
                'negative_files': 5,
                'sample_size': 4,
                'problem_files': 2,
                'missing_review_files': 1,
                'unscanned_files': 1,
                'upper_bound': 5,
            },
        }
        assert 'F1' not in json.dumps(report)

    @staticmethod
    def test_missing_review_counts_as_possible_missed_file():
        source = evidence()
        source['blind_reviews']['files'] = [
            {'file_id': 'F1', 'verdict': 'negative'},
            {'file_id': 'F2', 'verdict': 'negative'},
            {'file_id': 'F5', 'verdict': 'negative'},
        ]

        report = build_acceptance_report(source)

        assert report['strata'][1]['problem_files'] == 1
        assert report['strata'][1]['missing_review_files'] == 1

    @staticmethod
    def test_rejects_alpha_budget_overrun():
        source = evidence()
        source['alpha_by_stratum']['values'] = {'core': 0.06, 'edge': 0.05}

        with pytest.raises(InvalidAcceptanceEvidence):
            build_acceptance_report(source)

    @staticmethod
    def test_rejects_sampling_positive_or_unscanned_file():
        source = evidence()
        source['sampling_records'][0]['sampled_files'][0]['file_id'] = 'F4'

        with pytest.raises(InvalidAcceptanceEvidence):
            build_acceptance_report(source)

    @staticmethod
    def test_rejects_duplicate_sampled_file():
        source = evidence()
        source['sampling_records'][0]['sampled_files'][1]['file_id'] = 'F1'

        with pytest.raises(InvalidAcceptanceEvidence):
            build_acceptance_report(source)

    @staticmethod
    def test_rejects_manifest_file_without_stratum_membership():
        source = evidence()
        source['frozen_manifest']['files'].append(
            {'file_id': 'F8', 'stratum': 'other'},
        )

        with pytest.raises(InvalidAcceptanceEvidence):
            build_acceptance_report(source)
