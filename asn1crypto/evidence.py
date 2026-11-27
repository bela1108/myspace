# coding: utf-8

"""
Read-only comparison helpers for preserved certificate status evidence.

The helpers in this module normalize status records and locate conflicts. They
do not verify signatures, certificates, timestamps, or any caller-provided
validation conclusion.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import re
from collections import namedtuple
from datetime import datetime, timedelta

from ._types import str_cls
from .util import timezone


StatusEvidence = namedtuple(
    'StatusEvidence',
    [
        'record_id',
        'source',
        'object_id',
        'domain',
        'coverage',
        'observed_at',
        'claim',
        'testimony',
        'verification',
        'record',
    ]
)

EvidenceConflict = namedtuple(
    'EvidenceConflict',
    [
        'object_id',
        'domain',
        'overlap',
        'left',
        'right',
    ]
)

class EvidenceComparison(namedtuple(
    'EvidenceComparison',
    [
        'records',
        'conflicts',
    ]
)):

    __slots__ = ()

    @property
    def conflict_count(self):
        return len(self.conflicts)

_OBJECT_KEYS = (
    'object_id', 'object', 'subject_id', 'subject', 'certificate_id',
    'cert_id', 'certificate', 'cert_serial_number', 'serial_number', 'serial',
)
_DOMAIN_KEYS = (
    'coverage_domain', 'scope_domain', 'domain', 'scope', 'window_domain',
    'context', 'realm',
)
_START_KEYS = (
    'coverage_start', 'scope_start', 'valid_from', 'not_before',
    'effective_from', 'effective_start', 'start', 'start_time',
    'this_update',
)
_END_KEYS = (
    'coverage_end', 'scope_end', 'valid_to', 'not_after', 'effective_to',
    'effective_end', 'end', 'end_time', 'next_update',
)
_OBSERVED_AT_KEYS = (
    'observed_at', 'observed_time', 'observation_time', 'observed_on',
    'recorded_at', 'recorded_time', 'captured_at', 'collected_at',
    'produced_at',
)
_CLAIM_KEYS = (
    'claim', 'status_claim', 'certificate_status', 'cert_status', 'status',
    'original_claim',
)
_RECORD_ID_KEYS = (
    'record_id', 'evidence_id', 'id', 'identifier',
)
_SOURCE_KEYS = (
    'source_type', 'record_type', 'evidence_type', 'source', 'type',
)
_VERIFICATION_KEYS = (
    'verification', 'verification_result', 'validation',
    'validation_result', 'validation_conclusion', 'independent_verification',
    'independent_validation',
)
_TESTIMONY_KEYS = (
    'testimony', 'original_testimony', 'original_claim',
)


def compare_evidence(records, verification=None):
    """
    Normalize status evidence and find pairwise conflicts.

    A conflict requires the same claimed object, the same coverage domain, and
    overlapping coverage intervals with unequal status claims. Coverage is
    treated as the half-open interval [start, end), so adjacent intervals do
    not conflict.

    :param records:
        A list of mapping objects or OCSP SingleResponse objects, an
        OCSPResponse, or a mapping containing a list under ``records`` or
        ``evidence``

    :param verification:
        An optional independent verification conclusion supplied by the caller.
        The value is preserved but never interpreted.

    :return:
        An EvidenceComparison namedtuple
    """

    normalized = normalize_evidence(records, verification=verification)
    groups = {}
    for record in normalized:
        key = _group_key(record)
        if key not in groups:
            groups[key] = []
        groups[key].append(record)

    conflicts = []
    for group in groups.values():
        group_records = sorted(group, key=lambda item: item.coverage[0])
        for left_index in range(len(group_records)):
            left = group_records[left_index]
            for right in group_records[left_index + 1:]:
                if not _intervals_overlap(left.coverage, right.coverage):
                    continue
                if left.claim == right.claim:
                    continue
                conflicts.append(EvidenceConflict(
                    object_id=left.object_id,
                    domain=left.domain,
                    overlap=_overlap(left.coverage, right.coverage),
                    left=left,
                    right=right,
                ))

    return EvidenceComparison(records=normalized, conflicts=tuple(conflicts))


def normalize_evidence(records, verification=None):
    """
    Normalize offline status records without mutating the supplied data.

    :param records:
        A list of mapping objects or OCSP SingleResponse objects, an
        OCSPResponse, or a mapping containing a list under ``records`` or
        ``evidence``

    :param verification:
        An optional independent verification conclusion supplied by the caller

    :return:
        A tuple of StatusEvidence namedtuples
    """

    if _is_ocsp_response(records):
        raw_records = _records_from_ocsp_response(records)
    elif isinstance(records, dict):
        if 'records' in records:
            raw_records = records['records']
        else:
            raw_records = records.get('evidence', [records])
        if verification is None:
            verification = _first_present(records, _VERIFICATION_KEYS)
    elif isinstance(records, (list, tuple)):
        raw_records = records
    else:
        raise TypeError('records must be a list, tuple, mapping, or OCSPResponse')

    return tuple(
        _normalize_record(record, index, verification)
        for index, record in enumerate(raw_records)
    )


def _normalize_record(record, index, caller_verification):
    if _is_single_ocsp_response(record):
        return _normalize_ocsp_response(record, index, caller_verification)

    if not isinstance(record, dict):
        raise TypeError('each record must be a mapping or OCSP SingleResponse')

    object_id = _first_present(record, _OBJECT_KEYS)
    if object_id is None:
        raise ValueError('record at index %d does not identify an object' % index)

    try:
        claim = _normalize_claim(_extract_claim(record))
    except ValueError:
        raise ValueError('record at index %d does not contain a status claim' % index)
    domain = _normalize_domain(_first_scalar_present(record, _DOMAIN_KEYS))
    coverage = _extract_coverage(record)
    observed_at = _coerce_time(_first_present(record, _OBSERVED_AT_KEYS))
    record_id = _first_present(record, _RECORD_ID_KEYS)
    if record_id is None:
        record_id = index

    return StatusEvidence(
        record_id=record_id,
        source=_first_present(record, _SOURCE_KEYS) or 'offline_record',
        object_id=object_id,
        domain=domain,
        coverage=coverage,
        observed_at=observed_at,
        claim=claim,
        testimony=_extract_testimony(record),
        verification=_first_present(record, _VERIFICATION_KEYS, caller_verification),
        record=record,
    )


def _records_from_ocsp_response(response):
    return list(response.response_data['responses'])


def _normalize_ocsp_response(single_response, index, caller_verification):
    cert_id = single_response['cert_id']
    object_id = (
        cert_id['serial_number'].native,
        cert_id['issuer_name_hash'].native,
        cert_id['issuer_key_hash'].native,
    )
    cert_status = single_response['cert_status']
    claim = _normalize_claim(cert_status.name)
    start = single_response['this_update'].native
    end = single_response['next_update'].native

    return StatusEvidence(
        record_id=index,
        source='ocsp_response',
        object_id=object_id,
        domain=None,
        coverage=(start, end),
        observed_at=start,
        claim=claim,
        testimony=cert_status.native,
        verification=caller_verification,
        record=single_response,
    )


def _extract_claim(record):
    for key in _CLAIM_KEYS:
        if key in record and record[key] is not None:
            return record[key]
    raise ValueError('record does not contain a status claim')


def _extract_testimony(record):
    for key in _TESTIMONY_KEYS:
        if key in record and record[key] is not None:
            return record[key]
    return _extract_claim(record)


def _extract_coverage(record):
    coverage = record.get('coverage')
    if coverage is None and isinstance(record.get('scope'), (dict, list, tuple)):
        coverage = record['scope']
    if coverage is None:
        coverage = record.get('window')
    if isinstance(coverage, dict):
        start = _first_present(coverage, _START_KEYS)
        end = _first_present(coverage, _END_KEYS)
    elif isinstance(coverage, (list, tuple)):
        if len(coverage) != 2:
            raise ValueError('coverage intervals must contain exactly two values')
        start, end = coverage
    else:
        start = _first_present(record, _START_KEYS)
        end = _first_present(record, _END_KEYS)

    start = _coerce_time(start)
    end = _coerce_time(end)
    if start is not None and end is not None and start > end:
        raise ValueError('coverage start must not be later than coverage end')
    return start, end


def _normalize_claim(value):
    if isinstance(value, dict):
        status = value.get('status', value.get('name'))
        if status is None:
            raise ValueError('status claim mappings must contain a status')
        value = status
    elif isinstance(value, (list, tuple)) and value:
        value = value[0]

    if value is None or (isinstance(value, str_cls) and not value.strip()):
        raise ValueError('record does not contain a status claim')

    if not isinstance(value, str_cls):
        raise TypeError('status claims must be strings')

    normalized = value.strip().lower().replace(' ', '_').replace('-', '_')
    revoked_names = ('revoked', 'certificate_revoked', 'certificate_status_revoked')
    if normalized in revoked_names or normalized.endswith('_revoked'):
        return 'revoked'
    return normalized


def _normalize_domain(domain):
    if domain is None:
        return None
    if isinstance(domain, (list, tuple)):
        return tuple(domain)
    return domain


def _coerce_time(value):
    if value is None or isinstance(value, datetime):
        return _to_utc(value)
    if not isinstance(value, str_cls):
        raise TypeError('time values must be datetime instances or ISO 8601 strings')

    text = value.strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'

    if 'T' not in text:
        parsed = datetime.strptime(text, '%Y-%m-%d')
        return parsed.replace(tzinfo=timezone.utc)

    offset_match = re.search(r'[+-]\d{2}:\d{2}$', text)
    if offset_match:
        offset = offset_match.group(0)
        text_without_offset = text[:offset_match.start()]
    else:
        offset = None
        text_without_offset = text
    match = re.match(
        r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::\d{2})?(?:\.(\d+))?$',
        text_without_offset
    )
    if not match:
        raise ValueError('invalid ISO 8601 time: %s' % value)

    date_part, time_part, fraction = match.groups()
    if len(time_part) == 5:
        time_part += ':00'
    microseconds = int(((fraction or '') + '000000')[:6])
    parsed = datetime.strptime(
        '%sT%s' % (date_part, time_part),
        '%Y-%m-%dT%H:%M:%S'
    ).replace(microsecond=microseconds)

    if offset:
        sign = 1 if offset[0] == '+' else -1
        hours, minutes = offset[1:].split(':')
        offset_delta = sign * timedelta(hours=int(hours), minutes=int(minutes))
        parsed = parsed.replace(tzinfo=timezone(offset_delta))
    else:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return _to_utc(parsed)


def _to_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _intervals_overlap(left, right):
    if left[0] is None or left[1] is None or right[0] is None or right[1] is None:
        raise ValueError('coverage intervals must include a start and end time')
    return left[0] < right[1] and right[0] < left[1]


def _overlap(left, right):
    return max(left[0], right[0]), min(left[1], right[1])


def _group_key(record):
    return _hashable(record.object_id), _hashable(record.domain)


def _hashable(value):
    if isinstance(value, (list, tuple)):
        return tuple(_hashable(item) for item in value)
    if isinstance(value, dict):
        return tuple((key, _hashable(value[key])) for key in sorted(value, key=repr))
    return value


def _first_present(mapping, keys, default=None):
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _first_scalar_present(mapping, keys):
    for key in keys:
        value = mapping.get(key)
        if value is not None and not isinstance(value, (dict, list, tuple)):
            return value
    return None


def _is_ocsp_response(value):
    return value.__class__.__name__ == 'OCSPResponse'


def _is_single_ocsp_response(value):
    return value.__class__.__name__ == 'SingleResponse'
