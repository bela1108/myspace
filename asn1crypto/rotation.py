# coding: utf-8

"""
ASN.1 structures and read-only helpers for certificate rotation reconciliation.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import os

from . import cms, pem
from .core import (
    Boolean,
    Enumerated,
    Integer,
    OctetString,
    Sequence,
    SequenceOf,
    UTF8String,
)
from .x509 import Certificate, Name


__all__ = [
    'CertificateIdentityEvidence',
    'EvidenceObject',
    'ExternalRotationApproval',
    'RotationConflictReasons',
    'RotationLink',
    'RotationLinks',
    'RotationReconciliationReport',
    'RotationStatus',
    'build_rotation_reconciliation',
]


class ReadOnlyValue(object):
    _frozen = False

    def freeze(self):
        self._frozen = True
        return self

    def __setitem__(self, key, value):
        if self._frozen:
            raise TypeError('Rotation reconciliation evidence is read-only')
        super(ReadOnlyValue, self).__setitem__(key, value)

    def __delitem__(self, key):
        if self._frozen:
            raise TypeError('Rotation reconciliation evidence is read-only')
        super(ReadOnlyValue, self).__delitem__(key)

    def append(self, value):
        if self._frozen:
            raise TypeError('Rotation reconciliation evidence is read-only')
        super(ReadOnlyValue, self).append(value)

    def __init__(self, *args, **kwargs):
        self._frozen = False
        super(ReadOnlyValue, self).__init__(*args, **kwargs)
        self.freeze()


class ReadOnlyPrimitive(ReadOnlyValue):
    def __init__(self, *args, **kwargs):
        self._frozen = False
        super(ReadOnlyPrimitive, self).__init__(*args, **kwargs)
        self.freeze()

    def set(self, value):
        if self._frozen:
            raise TypeError('Rotation reconciliation evidence is read-only')
        super(ReadOnlyPrimitive, self).set(value)


class ReadOnlyOctetString(ReadOnlyPrimitive, OctetString):
    pass


class ReadOnlyUTF8String(ReadOnlyPrimitive, UTF8String):
    pass


class ReadOnlyInteger(ReadOnlyPrimitive, Integer):
    pass


class ReadOnlyEnumerated(ReadOnlyPrimitive, Enumerated):
    pass


class ReadOnlyBoolean(ReadOnlyPrimitive, Boolean):
    pass


class ReadOnlyName(ReadOnlyValue, Name):
    pass


class RotationStatus(ReadOnlyEnumerated):
    _map = {
        0: 'unchanged',
        1: 'rotated',
        2: 'conflict',
    }


class EvidenceObject(ReadOnlyValue, Sequence):
    _fields = [
        ('display_label', ReadOnlyUTF8String),
        ('sha256_fingerprint', ReadOnlyOctetString),
    ]


class CertificateIdentityEvidence(ReadOnlyValue, Sequence):
    _fields = [
        ('exhibit_label', ReadOnlyUTF8String),
        ('subject', ReadOnlyName),
        ('issuer', ReadOnlyName),
        ('serial_number', ReadOnlyInteger),
        ('subject_der_fingerprint', ReadOnlyOctetString),
        ('public_key', EvidenceObject),
        ('certificate_fingerprint', ReadOnlyOctetString),
    ]


class ExternalRotationApproval(ReadOnlyValue, Sequence):
    _fields = [
        ('exhibit_label', ReadOnlyUTF8String),
        ('cms_fingerprint', ReadOnlyOctetString),
        ('encapsulated_content_fingerprint', ReadOnlyOctetString),
        ('approver_issuer', ReadOnlyName),
        ('approver_serial_number', ReadOnlyInteger),
        ('signature_fingerprint', ReadOnlyOctetString),
        ('single_signer', ReadOnlyBoolean),
        ('signer_certificate_evidence', CertificateIdentityEvidence),
    ]


class RotationConflictReasons(ReadOnlyValue, SequenceOf):
    _child_spec = ReadOnlyUTF8String


class RotationLink(ReadOnlyValue, Sequence):
    _fields = [
        ('group_label', ReadOnlyUTF8String),
        ('previous_evidence', CertificateIdentityEvidence),
        ('current_evidence', CertificateIdentityEvidence),
        ('subject_status', RotationStatus),
        ('issuer_status', RotationStatus),
        ('serial_status', RotationStatus),
        ('public_key_status', RotationStatus),
        ('external_approval', ExternalRotationApproval, {'optional': True}),
        ('approval_conflict', ReadOnlyBoolean, {'default': False}),
        ('conflict_reasons', RotationConflictReasons),
    ]


class RotationLinks(ReadOnlyValue, SequenceOf):
    _child_spec = RotationLink


class RotationReconciliationReport(ReadOnlyValue, Sequence):
    _fields = [
        ('links', RotationLinks),
    ]


def _sha256(value):
    return hashlib.sha256(value).digest()


def _load_certificate(data, exhibit_label):
    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    certificate = Certificate.load(data)
    return _certificate_evidence(certificate, exhibit_label)


def _certificate_evidence(certificate, exhibit_label):
    public_key = certificate.public_key
    public_key_bytes = public_key.dump()
    subject_bytes = certificate.subject.dump()
    certificate_bytes = certificate.dump()
    return CertificateIdentityEvidence({
        'exhibit_label': exhibit_label,
        'subject': ReadOnlyName.load(certificate.subject.dump()),
        'issuer': ReadOnlyName.load(certificate.issuer.dump()),
        'serial_number': certificate.serial_number,
        'subject_der_fingerprint': _sha256(subject_bytes),
        'public_key': EvidenceObject({
            'display_label': 'subjectPublicKeyInfo',
            'sha256_fingerprint': _sha256(public_key_bytes),
        }),
        'certificate_fingerprint': _sha256(certificate_bytes),
    })


def _load_approval(data, exhibit_label):
    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    content_info = cms.ContentInfo.load(data)
    if content_info['content_type'].native != 'signed_data':
        raise ValueError('External rotation approval must be CMS signed_data')

    signed_data = content_info['content']
    signer_infos = signed_data['signer_infos']
    single_signer = len(signer_infos) == 1
    if not single_signer:
        raise ValueError('External rotation approval must contain exactly one signer')

    signer_info = signer_infos[0]
    signer_id = signer_info['sid']
    if signer_id.name != 'issuer_and_serial_number':
        raise ValueError('External rotation approval must identify the signer by issuer and serial')

    issuer_and_serial = signer_id.chosen
    content = signed_data['encap_content_info']['content'].native
    certificates = signed_data['certificates']
    if len(certificates) != 1:
        raise ValueError('External rotation approval must contain exactly one signer certificate')
    certificate_choice = certificates[0]
    if certificate_choice.name != 'certificate':
        raise ValueError('External rotation approval must contain an X.509 signer certificate')
    signer_certificate = certificate_choice.chosen
    if (
        issuer_and_serial['issuer'].dump() != signer_certificate.issuer.dump() or
        issuer_and_serial['serial_number'].native != signer_certificate.serial_number
    ):
        raise ValueError('External approval signer identifier does not match its signer certificate')
    return ExternalRotationApproval({
        'exhibit_label': exhibit_label,
        'cms_fingerprint': _sha256(data),
        'encapsulated_content_fingerprint': _sha256(content),
        'approver_issuer': ReadOnlyName.load(issuer_and_serial['issuer'].dump()),
        'approver_serial_number': issuer_and_serial['serial_number'].native,
        'signature_fingerprint': _sha256(signer_info['signature'].native),
        'single_signer': single_signer,
        'signer_certificate_evidence': _certificate_evidence(signer_certificate, 'cms-signer-certificate'),
    })


def _status(same):
    return 'unchanged' if same else 'rotated'


def build_rotation_reconciliation(archive_groups):
    """
    Builds a read-only ASN.1 rotation reconciliation report.

    :param archive_groups:
        A list of dicts, each containing a unicode ``label`` and an ordered
        ``exhibits`` list. Exhibit dicts contain an optional ``label`` and
        either certificate ``data`` or a certificate ``path``. They may also
        contain external approval ``approval_data`` or ``approval_path``.

    :return:
        A RotationReconciliationReport object
    """

    links = []
    for group in archive_groups:
        group_label = group['label']
        exhibits = group['exhibits']
        for index in range(1, len(exhibits)):
            previous_exhibit = exhibits[index - 1]
            current_exhibit = exhibits[index]
            previous = _exhibit_evidence(previous_exhibit)
            current = _exhibit_evidence(current_exhibit)
            approval = _optional_approval(current_exhibit)

            subject_same = previous['subject_der_fingerprint'].native == current['subject_der_fingerprint'].native
            issuer_same = previous['issuer'].dump() == current['issuer'].dump()
            serial_same = previous['serial_number'].native == current['serial_number'].native
            public_key_same = (
                previous['public_key']['sha256_fingerprint'].native ==
                current['public_key']['sha256_fingerprint'].native
            )

            conflict_reasons = []
            if approval is None:
                conflict_reasons.append('missing external rotation approval')
            elif _approval_conflicts(approval, current, previous):
                conflict_reasons.append('approval does not identify both certificate fingerprints')

            links.append(RotationLink({
                'group_label': group_label,
                'previous_evidence': previous,
                'current_evidence': current,
                'subject_status': _status(subject_same),
                'issuer_status': _status(issuer_same),
                'serial_status': _status(serial_same),
                'public_key_status': _status(public_key_same),
                'external_approval': approval,
                'approval_conflict': bool(conflict_reasons),
                'conflict_reasons': conflict_reasons,
            }))

    return RotationReconciliationReport({'links': links})


def _exhibit_evidence(exhibit):
    label = exhibit.get('label')
    data = exhibit.get('data')
    if data is None:
        with open(exhibit['path'], 'rb') as file_handle:
            data = file_handle.read()
        if not label:
            label = os.path.basename(exhibit['path'])
    return _load_certificate(data, label)


def _optional_approval(exhibit):
    data = exhibit.get('approval_data')
    path = exhibit.get('approval_path')
    if data is None and path is None:
        return None
    label = exhibit.get('approval_label')
    if not label:
        label = 'external-rotation-approval'
    if data is None:
        with open(path, 'rb') as file_handle:
            data = file_handle.read()
        if label == 'external-rotation-approval':
            label = os.path.basename(path)
    return _load_approval(data, label)


def _approval_conflicts(approval, current, previous):
    expected = _sha256(_approval_content(current, previous))
    return approval['encapsulated_content_fingerprint'].native != expected


def _approval_content(current, previous):
    return b''.join([
        previous['certificate_fingerprint'].native,
        current['certificate_fingerprint'].native,
        previous['public_key']['sha256_fingerprint'].native,
        current['public_key']['sha256_fingerprint'].native,
    ])
