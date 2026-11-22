# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
from datetime import datetime, timedelta, tzinfo

from time_explanation import (
    DEFAULT_MAX_EVIDENCE,
    STATUS_CONFLICTING_EVIDENCE,
    STATUS_SELF_REPORTED_ONLY,
    STATUS_TRUSTED_WINDOW,
    CertValidity,
    EvidenceBudgetExceeded,
    ExplanationMismatch,
    MaterialIdentity,
    TsaTimestamp,
    conflicting_evidence_explanation,
    explain_signing_time,
    self_reported_only_explanation,
    trusted_window_explanation,
)
from ._unittest_compat import patch

patch()


class _UTC(tzinfo):

    def utcoffset(self, dt):
        return timedelta(0)

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return 'UTC'


UTC = _UTC()


def _dt(*args):
    return datetime(*args, tzinfo=UTC)


def _material():
    return MaterialIdentity('sha256', 'AB' * 32)


class TimeExplanationTests(unittest.TestCase):

    def test_trusted_window_from_two_timestamps_and_validity(self):
        material = _material()
        cert = CertValidity(_dt(2026, 1, 1), _dt(2027, 1, 1), source='cert')
        stamps = [
            TsaTimestamp(_dt(2026, 6, 1, 12), accuracy=timedelta(seconds=1), source='tsa-a'),
            TsaTimestamp(_dt(2026, 6, 1, 13), accuracy=timedelta(seconds=2), source='tsa-b'),
        ]

        explanation = trusted_window_explanation(
            material,
            tsa_timestamps=stamps,
            cert_validity=cert,
        )

        self.assertEqual(STATUS_TRUSTED_WINDOW, explanation.status)
        self.assertEqual(_dt(2026, 1, 1), explanation.lower)
        self.assertEqual(_dt(2026, 6, 1, 12, 0, 1), explanation.upper)
        self.assertEqual(timedelta(0), explanation.lower_precision)
        self.assertEqual(timedelta(seconds=1), explanation.upper_precision)
        self.assertEqual('cert', explanation.lower_source)
        self.assertEqual('tsa-a', explanation.upper_source)
        self.assertEqual(3, explanation.evidence_count)

    def test_trusted_window_upper_bound_comes_from_validity(self):
        material = _material()
        cert = CertValidity(_dt(2026, 1, 1), _dt(2026, 2, 1))
        stamps = [TsaTimestamp(_dt(2026, 6, 1))]

        explanation = explain_signing_time(
            material,
            tsa_timestamps=stamps,
            cert_validity=cert,
        )

        self.assertEqual(STATUS_TRUSTED_WINDOW, explanation.status)
        self.assertEqual(_dt(2026, 1, 1), explanation.lower)
        self.assertEqual(_dt(2026, 2, 1), explanation.upper)

    def test_conflicting_evidence_yields_no_window(self):
        material = _material()
        cert = CertValidity(_dt(2026, 6, 1), _dt(2027, 1, 1))
        stamps = [TsaTimestamp(_dt(2026, 1, 1))]

        explanation = conflicting_evidence_explanation(
            material,
            tsa_timestamps=stamps,
            cert_validity=cert,
        )

        self.assertEqual(STATUS_CONFLICTING_EVIDENCE, explanation.status)
        self.assertIsNone(explanation.lower)
        self.assertIsNone(explanation.upper)
        self.assertTrue(any('contradictory' in remark for remark in explanation.remarks))

    def test_self_reported_only_records_remark_without_window(self):
        material = _material()
        claimed = _dt(2026, 3, 15, 10, 30)

        explanation = self_reported_only_explanation(material, claimed)

        self.assertEqual(STATUS_SELF_REPORTED_ONLY, explanation.status)
        self.assertIsNone(explanation.lower)
        self.assertIsNone(explanation.upper)
        self.assertEqual(claimed, explanation.signing_time)
        self.assertTrue(any('remark only' in remark for remark in explanation.remarks))

    def test_self_reported_time_does_not_narrow_trusted_window(self):
        material = _material()
        cert = CertValidity(_dt(2026, 1, 1), _dt(2027, 1, 1))
        stamps = [TsaTimestamp(_dt(2026, 6, 1))]
        claimed = _dt(2026, 3, 15, 10, 30)

        explanation = explain_signing_time(
            material,
            tsa_timestamps=stamps,
            cert_validity=cert,
            signing_time=claimed,
        )

        self.assertEqual(STATUS_TRUSTED_WINDOW, explanation.status)
        self.assertEqual(_dt(2026, 1, 1), explanation.lower)
        self.assertEqual(_dt(2026, 6, 1), explanation.upper)
        self.assertEqual(claimed, explanation.signing_time)
        self.assertTrue(any('remark only' in remark for remark in explanation.remarks))

    def test_evidence_budget_is_enforced(self):
        material = _material()
        stamps = [TsaTimestamp(_dt(2026, 6, 1)) for _ in range(DEFAULT_MAX_EVIDENCE + 1)]

        with self.assertRaises(EvidenceBudgetExceeded):
            explain_signing_time(material, tsa_timestamps=stamps)

        explanation = explain_signing_time(
            material,
            tsa_timestamps=stamps,
            max_evidence=DEFAULT_MAX_EVIDENCE + 1,
        )
        self.assertEqual(DEFAULT_MAX_EVIDENCE + 1, explanation.evidence_count)

    def test_wrapper_rejects_mismatched_outcome(self):
        material = _material()
        cert = CertValidity(_dt(2026, 6, 1), _dt(2027, 1, 1))
        stamps = [TsaTimestamp(_dt(2026, 1, 1))]

        with self.assertRaises(ExplanationMismatch):
            trusted_window_explanation(
                material,
                tsa_timestamps=stamps,
                cert_validity=cert,
            )

    def test_naive_datetimes_are_rejected(self):
        with self.assertRaises(ValueError):
            TsaTimestamp(datetime(2026, 6, 1))
        with self.assertRaises(ValueError):
            CertValidity(datetime(2026, 1, 1), _dt(2027, 1, 1))

    def test_as_dict_is_serializable_and_bound_to_material(self):
        material = _material()
        explanation = self_reported_only_explanation(material, _dt(2026, 3, 15))

        data = explanation.as_dict()

        self.assertEqual('sha256', data['material']['algorithm'])
        self.assertEqual('ab' * 32, data['material']['digest_hex'])
        self.assertEqual(STATUS_SELF_REPORTED_ONLY, data['status'])
        self.assertIsNone(data['lower'])
        self.assertIsNone(data['upper'])
        self.assertIsNotNone(data['self_reported_signing_time'])
