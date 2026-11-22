# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime, timedelta

"""
Offline signing-time explanation for archival backends.

The verification service has already validated the cryptography. This module
only explains what the validated evidence says about when a signature was
created, at a precision the caller can re-check:

 - Each verified RFC 3161 timestamp proves the material existed by
   ``gen_time``; with the TSA accuracy, signing is no later than
   ``gen_time + accuracy``.
 - The certificate validity period bounds signing to
   ``[not_before, not_after]``.
 - A self-reported ``signing_time`` is kept as a remark only. It never
   contributes to the computed window and can never pick a unique time.

The interface is budget-limited: at most ``max_evidence`` evidence items are
consumed per call, so a request can never cause unbounded work. Everything is
computed offline from the caller-supplied evidence; no I/O is performed.
"""

__all__ = [
    'STATUS_TRUSTED_WINDOW',
    'STATUS_CONFLICTING_EVIDENCE',
    'STATUS_SELF_REPORTED_ONLY',
    'DEFAULT_MAX_EVIDENCE',
    'MaterialIdentity',
    'TsaTimestamp',
    'CertValidity',
    'TimeExplanation',
    'EvidenceBudgetExceeded',
    'ExplanationMismatch',
    'explain_signing_time',
    'trusted_window_explanation',
    'conflicting_evidence_explanation',
    'self_reported_only_explanation',
]


STATUS_TRUSTED_WINDOW = 'trusted_window'
STATUS_CONFLICTING_EVIDENCE = 'conflicting_evidence'
STATUS_SELF_REPORTED_ONLY = 'self_reported_only'

DEFAULT_MAX_EVIDENCE = 8


class EvidenceBudgetExceeded(ValueError):
    """
    Raised when a request carries more evidence items than the budget allows.
    """

    pass


class ExplanationMismatch(ValueError):
    """
    Raised by a scenario wrapper when the evidence does not yield the
    explanation status the wrapper stands for.
    """

    pass


def _require_aware(value, field_name):
    if not isinstance(value, datetime):
        raise TypeError('%s must be a datetime' % field_name)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('%s must be timezone-aware so the precision is checkable' % field_name)


def _require_accuracy(value, field_name):
    if not isinstance(value, timedelta):
        raise TypeError('%s must be a timedelta' % field_name)
    if value < timedelta(0):
        raise ValueError('%s must not be negative' % field_name)


class MaterialIdentity(object):
    """
    Identity of the signed material the explanation refers to, as verified by
    the caller (digest algorithm name and lowercase hex digest).
    """

    def __init__(self, algorithm, digest_hex):
        if not algorithm:
            raise ValueError('algorithm must not be empty')
        if not digest_hex:
            raise ValueError('digest_hex must not be empty')
        self.algorithm = algorithm
        self.digest_hex = digest_hex.lower()

    def as_dict(self):
        return {
            'algorithm': self.algorithm,
            'digest_hex': self.digest_hex,
        }


class TsaTimestamp(object):
    """
    A caller-verified RFC 3161 timestamp. ``accuracy`` is the TSA-declared
    accuracy of ``gen_time``; both together define the checkable precision of
    the upper bound this evidence contributes.
    """

    def __init__(self, gen_time, accuracy=None, source=None):
        _require_aware(gen_time, 'gen_time')
        if accuracy is None:
            accuracy = timedelta(0)
        _require_accuracy(accuracy, 'accuracy')
        self.gen_time = gen_time
        self.accuracy = accuracy
        self.source = source

    @property
    def latest_signing_time(self):
        return self.gen_time + self.accuracy


class CertValidity(object):
    """
    The validity period of the signing certificate, as verified by the caller.
    """

    def __init__(self, not_before, not_after, source=None):
        _require_aware(not_before, 'not_before')
        _require_aware(not_after, 'not_after')
        if not_before > not_after:
            raise ValueError('not_before must not be after not_after')
        self.not_before = not_before
        self.not_after = not_after
        self.source = source


class TimeExplanation(object):
    """
    The offline explanation of when signing happened.

    ``lower``/``upper`` are the bounds of the trusted window, or None when no
    such window exists (conflicting evidence, or self-reported time only).
    ``lower_precision``/``upper_precision`` give the checkable precision of
    each bound, taken from the evidence that contributed it.
    """

    def __init__(self, material, status, lower=None, upper=None,
                 lower_precision=None, upper_precision=None,
                 lower_source=None, upper_source=None,
                 signing_time=None, remarks=None,
                 evidence_count=0, max_evidence=DEFAULT_MAX_EVIDENCE):
        self.material = material
        self.status = status
        self.lower = lower
        self.upper = upper
        self.lower_precision = lower_precision
        self.upper_precision = upper_precision
        self.lower_source = lower_source
        self.upper_source = upper_source
        self.signing_time = signing_time
        self.remarks = tuple(remarks or ())
        self.evidence_count = evidence_count
        self.max_evidence = max_evidence

    def as_dict(self):
        def render(value):
            return value.isoformat() if isinstance(value, datetime) else None

        def render_delta(value):
            return value.total_seconds() if isinstance(value, timedelta) else None

        return {
            'material': self.material.as_dict(),
            'status': self.status,
            'lower': render(self.lower),
            'upper': render(self.upper),
            'lower_precision_seconds': render_delta(self.lower_precision),
            'upper_precision_seconds': render_delta(self.upper_precision),
            'lower_source': self.lower_source,
            'upper_source': self.upper_source,
            'self_reported_signing_time': render(self.signing_time),
            'remarks': list(self.remarks),
            'evidence_count': self.evidence_count,
            'max_evidence': self.max_evidence,
        }


def explain_signing_time(material, tsa_timestamps=None, cert_validity=None,
                         signing_time=None, max_evidence=DEFAULT_MAX_EVIDENCE):
    """
    Explains the signing time of the material from caller-verified evidence.

    :param material:
        A MaterialIdentity of the signed material.

    :param tsa_timestamps:
        An iterable of verified TsaTimestamp objects, or None.

    :param cert_validity:
        A verified CertValidity object, or None.

    :param signing_time:
        A self-reported signing time. Recorded as a remark only; it never
        contributes to the computed window.

    :param max_evidence:
        Budget of evidence items this call may consume. Exceeding it raises
        EvidenceBudgetExceeded instead of doing unbounded work.

    :return:
        A TimeExplanation.
    """

    if not isinstance(material, MaterialIdentity):
        raise TypeError('material must be a MaterialIdentity')
    if max_evidence < 0:
        raise ValueError('max_evidence must not be negative')

    tsa_timestamps = list(tsa_timestamps or [])
    evidence_count = len(tsa_timestamps) + (1 if cert_validity is not None else 0)
    if evidence_count > max_evidence:
        raise EvidenceBudgetExceeded(
            'evidence budget exceeded: %d items supplied, budget is %d' % (evidence_count, max_evidence)
        )

    remarks = []
    if signing_time is not None:
        _require_aware(signing_time, 'signing_time')
        remarks.append(
            'self-reported signing_time %s is a remark only and does not '
            'determine the signing time' % signing_time.isoformat()
        )

    lower = upper = None
    lower_precision = upper_precision = None
    lower_source = upper_source = None

    if cert_validity is not None:
        lower = cert_validity.not_before
        upper = cert_validity.not_after
        lower_precision = timedelta(0)
        upper_precision = timedelta(0)
        lower_source = cert_validity.source
        upper_source = cert_validity.source

    for timestamp in tsa_timestamps:
        bound = timestamp.latest_signing_time
        if upper is None or bound < upper:
            upper = bound
            upper_precision = timestamp.accuracy
            upper_source = timestamp.source

    if lower is None and upper is None:
        status = STATUS_SELF_REPORTED_ONLY
        remarks.append('no verified time evidence; no trusted window can be stated')
    elif lower is not None and upper is not None and lower > upper:
        status = STATUS_CONFLICTING_EVIDENCE
        remarks.append(
            'verified evidence is contradictory: earliest possible time %s is '
            'after latest possible time %s' % (lower.isoformat(), upper.isoformat())
        )
        lower = upper = None
        lower_precision = upper_precision = None
        lower_source = upper_source = None
    else:
        status = STATUS_TRUSTED_WINDOW

    return TimeExplanation(
        material=material,
        status=status,
        lower=lower,
        upper=upper,
        lower_precision=lower_precision,
        upper_precision=upper_precision,
        lower_source=lower_source,
        upper_source=upper_source,
        signing_time=signing_time,
        remarks=remarks,
        evidence_count=evidence_count,
        max_evidence=max_evidence,
    )


def _expect(material, status, explanation):
    if explanation.status != status:
        raise ExplanationMismatch(
            'evidence for material %s:%s yields %s, not %s' % (
                material.algorithm,
                material.digest_hex,
                explanation.status,
                status,
            )
        )
    return explanation


def trusted_window_explanation(material, tsa_timestamps=None, cert_validity=None,
                               signing_time=None, max_evidence=DEFAULT_MAX_EVIDENCE):
    """
    Wrapper for the trusted-window case: the verified timestamps and the
    certificate validity period intersect into a usable signing-time window.
    Raises ExplanationMismatch if they do not.
    """

    return _expect(
        material,
        STATUS_TRUSTED_WINDOW,
        explain_signing_time(
            material,
            tsa_timestamps=tsa_timestamps,
            cert_validity=cert_validity,
            signing_time=signing_time,
            max_evidence=max_evidence,
        ),
    )


def conflicting_evidence_explanation(material, tsa_timestamps=None, cert_validity=None,
                                     signing_time=None, max_evidence=DEFAULT_MAX_EVIDENCE):
    """
    Wrapper for the conflicting-evidence case: the verified timestamps and the
    certificate validity period cannot all hold at once. Raises
    ExplanationMismatch if they are consistent instead.
    """

    return _expect(
        material,
        STATUS_CONFLICTING_EVIDENCE,
        explain_signing_time(
            material,
            tsa_timestamps=tsa_timestamps,
            cert_validity=cert_validity,
            signing_time=signing_time,
            max_evidence=max_evidence,
        ),
    )


def self_reported_only_explanation(material, signing_time, max_evidence=DEFAULT_MAX_EVIDENCE):
    """
    Wrapper for the self-reported-only case: no verified evidence exists, so
    the self-reported signing_time is recorded as a remark and no trusted
    window is stated.
    """

    return _expect(
        material,
        STATUS_SELF_REPORTED_ONLY,
        explain_signing_time(
            material,
            signing_time=signing_time,
            max_evidence=max_evidence,
        ),
    )
