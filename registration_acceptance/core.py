# coding: utf-8
"""Structural Name comparison and approved name-change policy checks."""

from __future__ import unicode_literals, division, absolute_import, print_function

import datetime
import json
import os

from asn1crypto import csr as _csr
from asn1crypto import pem as _pem
from asn1crypto.x509 import Name as _Name
from asn1crypto.x509 import NameType as _NameType
from asn1crypto.x509 import RDNSequence as _RDNSequence
from asn1crypto.x509 import RelativeDistinguishedName as _RDN


POLICY_VERSION = 'asn1crypto-rfc5280-rdn-hierarchy-v1'


def _as_path(source):
    # type: (...) -> str
    if hasattr(source, '__fspath__'):
        return os.fspath(source)
    return source


def load_csr(source):
    """
    Load a DER/PEM CSR from bytes or a filesystem path.

    The returned object is the parsed asn1crypto CertificationRequest. Callers
    only read from it; acceptance checks never re-encode the request.
    """

    if isinstance(source, (_csr.CertificationRequest,)):
        return source

    if isinstance(source, (str, os.PathLike)):
        with open(_as_path(source), 'rb') as handle:
            raw = handle.read()
    elif isinstance(source, bytes):
        raw = source
    else:
        raise TypeError('CSR source must be bytes, a path, or CertificationRequest')

    if b'-----BEGIN' in raw:
        _, _, der_bytes = _pem.unarmor(raw)
    else:
        der_bytes = raw

    return _csr.CertificationRequest.load(der_bytes)


def subject_of(source):
    """Return the X.509 Name from a CSR, Name, or CSR byte/path source."""

    if isinstance(source, _Name):
        return source
    if isinstance(source, _csr.CertificationRequest):
        return source['certification_request_info']['subject']
    return load_csr(source)['certification_request_info']['subject']


def oid_of(name_type):
    """Return the dotted OID for an alias or OID accepted by NameType."""

    return _NameType(name_type).dotted


def attribute_type_set(name):
    """Return the exact set of AttributeType OIDs present in a Name."""

    name = subject_of(name)
    return frozenset(
        ntv['type'].dotted
        for rdn in name.chosen
        for ntv in rdn
    )


def hierarchy_key(name):
    """
    Build a hashable key that preserves RDN order and multi-valued RDN groups.

    Attributes inside one RDN are sorted because SET OF ordering is not
    semantically meaningful in DER. RDN sequence order and the boundary between
    singleton and multi-valued RDNs remain significant.
    """

    name = subject_of(name)
    rdns = []
    for rdn in name.chosen:
        attributes = []
        for ntv in rdn:
            attributes.append((ntv['type'].dotted, ntv.prepped_value))
        rdns.append(tuple(sorted(attributes)))
    return tuple(rdns)


def flat_attribute_key(name):
    """
    Return a hierarchy-insensitive key for legacy text/archive comparisons.

    Two names can have the same flat key while hierarchy_key() differs. This is
    intentionally not sufficient for registration identity.
    """

    attributes = []
    for rdn in subject_of(name).chosen:
        for ntv in rdn:
            attributes.append((ntv['type'].dotted, ntv.prepped_value))
    return tuple(sorted(attributes))


def flattened_name_text(name):
    """Serialize the hierarchy-insensitive legacy text used by archive forms."""

    attributes = []
    for rdn in subject_of(name).chosen:
        for ntv in rdn:
            attributes.append((ntv['type'].dotted, ntv['value'].native))
    return ', '.join(
        '%s=%s' % (oid, value)
        for oid, value in sorted(attributes, key=lambda item: item[0])
    )


def build_declared_name(rdn_spec):
    """Build an asn1crypto Name from a checked-in RDN specification."""

    rdns = []
    for rdn_specification in rdn_spec:
        attributes = []
        for attribute in rdn_specification:
            attribute_type = attribute.get('type', attribute.get('oid'))
            if attribute_type is None:
                raise ValueError('declared RDN attribute requires type or oid')
            built = _Name.build({attribute_type: attribute['value']})
            attributes.append(built.chosen[0][0])
        rdns.append(_RDN(attributes))
    return _Name(name='', value=_RDNSequence(rdns))


def declared_hierarchy_key(rdn_spec):
    return hierarchy_key(build_declared_name(rdn_spec))


def declared_oid_set(type_names):
    return frozenset(oid_of(value) for value in type_names)


def coerce_date(value, field_name='date'):
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str):
        return datetime.date.fromisoformat(value)
    raise TypeError('%s must be an ISO date or date object' % field_name)


def period_covers(valid_from, valid_to, as_of):
    day = coerce_date(as_of, 'as_of') or datetime.date.today()
    start = coerce_date(valid_from, 'valid_from')
    end = coerce_date(valid_to, 'valid_to')
    return (start is None or start <= day) and (end is None or day <= end)


class ArchiveRecord(object):
    """Old application-archive coordinates retained outside the certificate."""

    def __init__(self, application_id, legacy_department, normalized_name,
                 valid_from=None, valid_to=None):
        self.application_id = application_id
        self.legacy_department = legacy_department
        self.normalized_name = normalized_name
        self.valid_from = coerce_date(valid_from, 'valid_from')
        self.valid_to = coerce_date(valid_to, 'valid_to')

    @classmethod
    def from_dict(cls, data):
        return cls(
            application_id=data['application_id'],
            legacy_department=data['legacy_department'],
            normalized_name=data['normalized_name'],
            valid_from=data.get('applicable_from', data.get('valid_from')),
            valid_to=data.get('applicable_to', data.get('valid_to')),
        )

    def period_covers(self, as_of):
        return period_covers(self.valid_from, self.valid_to, as_of)


class NameChangeMapping(object):
    def __init__(self, data):
        self.data = data
        self.mapping_id = data['mapping_id']
        self.status = data.get('status', 'approved')
        self.policy = data.get('normalization_policy', POLICY_VERSION)
        self.legacy_department = data['legacy_department']
        self.normalized_name = data['normalized_name']
        self.valid_from = data.get('applicable_from', data.get('valid_from'))
        self.valid_to = data.get('applicable_to', data.get('valid_to'))
        self.legacy_rdn_spec = data.get('legacy_subject_rdns')
        self.new_rdn_spec = data['new_subject_rdns']
        self.new_key = declared_hierarchy_key(self.new_rdn_spec)
        self.new_attribute_types = declared_oid_set(
            data.get('new_attribute_types', [])
        ) if data.get('new_attribute_types') else frozenset(
            oid for rdn in self.new_key for oid, _ in rdn
        )
        if self.legacy_rdn_spec is not None:
            self.legacy_key = declared_hierarchy_key(self.legacy_rdn_spec)
            legacy_types = data.get('legacy_attribute_types')
            self.legacy_attribute_types = (
                declared_oid_set(legacy_types)
                if legacy_types
                else frozenset(oid for rdn in self.legacy_key for oid, _ in rdn)
            )
        else:
            self.legacy_key = None
            self.legacy_attribute_types = frozenset()

    def period_covers(self, as_of):
        return period_covers(self.valid_from, self.valid_to, as_of)

    def coordinates_match(self, record):
        return (
            record is not None
            and record.legacy_department == self.legacy_department
            and record.normalized_name == self.normalized_name
        )


class ApprovedNameChanges(object):
    """Collection loaded from the checked-in change declaration."""

    def __init__(self, mappings=None, declaration_id=None, policy=POLICY_VERSION):
        self.mappings = list(mappings or [])
        self.declaration_id = declaration_id
        self.policy = policy

    @classmethod
    def from_dict(cls, data):
        mappings = [NameChangeMapping(item) for item in data.get('mappings', [])]
        return cls(
            mappings=mappings,
            declaration_id=data.get('declaration_id'),
            policy=data.get('normalization_policy', POLICY_VERSION),
        )

    @classmethod
    def load(cls, path):
        return load_name_changes(path)

    def for_archive(self, record):
        return [
            mapping for mapping in self.mappings
            if mapping.coordinates_match(record)
        ]

    def for_legacy_subject(self, source):
        target_key = hierarchy_key(source)
        return [
            mapping for mapping in self.mappings
            if mapping.legacy_key == target_key
        ]


def load_name_changes(source):
    if isinstance(source, ApprovedNameChanges):
        return source
    if source is None:
        return ApprovedNameChanges()
    if isinstance(source, (str, os.PathLike)):
        with open(_as_path(source), 'r', encoding='utf-8') as handle:
            data = json.load(handle)
    elif hasattr(source, 'read'):
        data = json.load(source)
    elif isinstance(source, dict):
        data = source
    else:
        raise TypeError('declaration must be a path, file object, or dict')
    return ApprovedNameChanges.from_dict(data)


class AcceptanceDecision(object):
    def __init__(self, accepted, code, as_of, mapping_id=None,
                 period_applicable=False, attribute_set_matches=False,
                 mapping_approved=False, hierarchy_matches=False,
                 reasons=None, details=None):
        self.accepted = bool(accepted)
        self.code = code
        self.as_of = as_of
        self.mapping_id = mapping_id
        self.period_applicable = period_applicable
        self.attribute_set_matches = attribute_set_matches
        self.mapping_approved = mapping_approved
        self.hierarchy_matches = hierarchy_matches
        self.reasons = tuple(reasons or ())
        self.details = dict(details or {})

    def __bool__(self):
        return self.accepted

    __nonzero__ = __bool__

    def to_dict(self):
        return {
            'accepted': self.accepted,
            'code': self.code,
            'as_of': self.as_of,
            'mapping_id': self.mapping_id,
            'period_applicable': self.period_applicable,
            'attribute_set_matches': self.attribute_set_matches,
            'mapping_approved': self.mapping_approved,
            'hierarchy_matches': self.hierarchy_matches,
            'reasons': list(self.reasons),
            'details': self.details,
        }


def _as_of_text(as_of):
    day = coerce_date(as_of, 'as_of') or datetime.date.today()
    return day.isoformat(), day


def _evaluate_current_subject(mapping, subject, as_of_day):
    actual_oids = attribute_type_set(subject)
    actual_key = hierarchy_key(subject)
    return {
        'attribute_ok': actual_oids == mapping.new_attribute_types,
        'hierarchy_ok': actual_key == mapping.new_key,
        'actual_oids': actual_oids,
        'expected_oids': mapping.new_attribute_types,
        'actual_key': actual_key,
        'expected_key': mapping.new_key,
    }


def compare_archive_csr(record, csr, declarations, as_of=None):
    """
    Compare an old archive record with a new CSR subject.

    Acceptance requires an approved mapping for the archive coordinates, an
    as_of date inside both applicable periods, the exact declared AttributeType
    set, and the declared hierarchical normalized Name.
    """

    day_text, day = _as_of_text(as_of)
    if not isinstance(record, ArchiveRecord):
        record = ArchiveRecord.from_dict(record)
    declarations = load_name_changes(declarations)
    subject = subject_of(csr)

    candidates = declarations.for_archive(record)
    if not candidates:
        return AcceptanceDecision(
            False,
            'no_approved_normalization_mapping',
            day_text,
            reasons=('No checked-in mapping matches legacy coordinates.',),
        )

    decisions = []
    for mapping in candidates:
        reasons = []
        mapping_ok = (
            mapping.status == 'approved'
            and mapping.policy == declarations.policy == POLICY_VERSION
        )
        period_ok = mapping.period_covers(day) and record.period_covers(day)
        current = _evaluate_current_subject(mapping, subject, day)

        if not mapping_ok:
            reasons.append('mapping_not_approved')
        if not period_ok:
            reasons.append('outside_applicable_period')
        if not current['attribute_ok']:
            reasons.append('attribute_set_mismatch')
        if not current['hierarchy_ok']:
            reasons.append('normalized_hierarchy_mismatch')

        accepted = not reasons
        decision = AcceptanceDecision(
            accepted,
            'same_registered_entity' if accepted else 'not_same_registered_entity',
            day_text,
            mapping_id=mapping.mapping_id,
            period_applicable=period_ok,
            attribute_set_matches=current['attribute_ok'],
            mapping_approved=mapping_ok,
            hierarchy_matches=current['hierarchy_ok'],
            reasons=reasons,
            details={
                'actual_attribute_types': sorted(current['actual_oids']),
                'expected_attribute_types': sorted(current['expected_oids']),
            },
        )
        decisions.append(decision)
        if accepted:
            return decision

    return decisions[0]


def compare_csr_pair(legacy_csr, current_csr, declarations, as_of=None,
                     archive_record=None):
    """
    Connect two structurally different CSR subjects only via a declared change.
    """

    day_text, day = _as_of_text(as_of)
    declarations = load_name_changes(declarations)
    legacy_subject = subject_of(legacy_csr)
    current_subject = subject_of(current_csr)

    if archive_record is not None and not isinstance(archive_record, ArchiveRecord):
        archive_record = ArchiveRecord.from_dict(archive_record)

    if archive_record is not None:
        candidates = declarations.for_archive(archive_record)
    else:
        candidates = declarations.for_legacy_subject(legacy_subject)

    candidates = [
        mapping for mapping in candidates
        if mapping.legacy_key is not None
        and mapping.legacy_key == hierarchy_key(legacy_subject)
    ]
    if archive_record is not None:
        candidates = [
            mapping for mapping in candidates
            if mapping.coordinates_match(archive_record)
        ]

    if not candidates:
        return AcceptanceDecision(
            False,
            'no_approved_normalization_mapping',
            day_text,
            reasons=('No checked-in mapping connects these Name hierarchies.',),
        )

    for mapping in candidates:
        reasons = []
        mapping_ok = (
            mapping.status == 'approved'
            and mapping.policy == declarations.policy == POLICY_VERSION
        )
        period_ok = mapping.period_covers(day)
        if archive_record is not None:
            period_ok = period_ok and archive_record.period_covers(day)

        legacy_oids = attribute_type_set(legacy_subject)
        legacy_attr_ok = legacy_oids == mapping.legacy_attribute_types
        legacy_hierarchy_ok = hierarchy_key(legacy_subject) == mapping.legacy_key
        current = _evaluate_current_subject(mapping, current_subject, day)

        if not mapping_ok:
            reasons.append('mapping_not_approved')
        if not period_ok:
            reasons.append('outside_applicable_period')
        if not legacy_attr_ok or not current['attribute_ok']:
            reasons.append('attribute_set_mismatch')
        if not legacy_hierarchy_ok or not current['hierarchy_ok']:
            reasons.append('normalized_hierarchy_mismatch')

        accepted = not reasons
        if accepted:
            return AcceptanceDecision(
                True,
                'same_registered_entity',
                day_text,
                mapping_id=mapping.mapping_id,
                period_applicable=period_ok,
                attribute_set_matches=legacy_attr_ok and current['attribute_ok'],
                mapping_approved=mapping_ok,
                hierarchy_matches=legacy_hierarchy_ok and current['hierarchy_ok'],
            )

    return AcceptanceDecision(
        False,
        'not_same_registered_entity',
        day_text,
        mapping_id=candidates[0].mapping_id,
        reasons=reasons,
        period_applicable=period_ok,
        attribute_set_matches=legacy_attr_ok and current['attribute_ok'],
        mapping_approved=mapping_ok,
        hierarchy_matches=legacy_hierarchy_ok and current['hierarchy_ok'],
    )


def is_same_registered_entity(left, right, declarations=None, as_of=None,
                              archive_record=None):
    """
    Apply the registration policy to two CSR/Name sources.

    Structural Name equality alone is not enough: the applicable period,
    declared attribute set, and approved normalization mapping must also pass.
    """

    decision = compare_csr_pair(
        left,
        right,
        declarations,
        as_of=as_of,
        archive_record=archive_record,
    )
    return decision.accepted
