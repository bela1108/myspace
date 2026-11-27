# coding: utf-8

"""
Offline allocation helpers for CSRs, issued certificates and approvals.

The module performs structural matching only. Parsing a CSR or certificate is
never treated as proof that its signature is valid.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import itertools

from . import pem
from .csr import CertificationRequest
from .x509 import Certificate


def _der(value, expected_pem_type, asn1_class):
    if pem.detect(value):
        pem_type, _, der_bytes = pem.unarmor(value)
        if pem_type != expected_pem_type:
            raise ValueError('Expected a PEM %s, but found a PEM %s' % (expected_pem_type, pem_type))
        return der_bytes
    return value


def _fingerprint(public_key_info):
    return hashlib.sha256(public_key_info.dump()).hexdigest()


def load_application(source, application_id=None, lab=None, certificate_type=None,
                     metadata=None):
    """
    Load a CSR from DER or PEM bytes.

    Signature validation is intentionally outside the responsibility of this
    function. The returned record therefore reports ``signature_verified`` as
    ``False`` even when the ASN.1 structure parses successfully.
    """

    der_bytes = _der(source, 'CERTIFICATE REQUEST', CertificationRequest)
    csr = CertificationRequest.load(der_bytes)
    public_key_info = csr['certification_request_info']['subject_pk_info']
    return HandoffRecord(
        record_id=application_id,
        kind='application',
        public_key_fingerprint=_fingerprint(public_key_info),
        lab=lab,
        certificate_type=certificate_type,
        subject=csr['certification_request_info']['subject'].native,
        metadata=dict(metadata or {}),
        raw=csr,
        signature_verified=False
    )


def load_certificate(source, certificate_id=None, lab=None, certificate_type=None,
                     metadata=None):
    """
    Load an X.509 certificate from DER or PEM bytes without verifying it.
    """

    der_bytes = _der(source, 'CERTIFICATE', Certificate)
    certificate = Certificate.load(der_bytes)
    tbs = certificate['tbs_certificate']
    public_key_info = tbs['subject_public_key_info']
    return HandoffRecord(
        record_id=certificate_id,
        kind='certificate',
        public_key_fingerprint=_fingerprint(public_key_info),
        lab=lab,
        certificate_type=certificate_type,
        subject=tbs['subject'].native,
        serial_number=tbs['serial_number'].native,
        metadata=dict(metadata or {}),
        raw=certificate,
        signature_verified=False
    )


def make_approval(approval_id, public_key_fingerprint=None, lab=None,
                  certificate_type=None, serial_number=None, application_id=None,
                  certificate_id=None, metadata=None, signature_verified=False):
    """
    Create an external approval record from data supplied out of band.
    """

    return HandoffRecord(
        record_id=approval_id,
        kind='approval',
        public_key_fingerprint=public_key_fingerprint,
        lab=lab,
        certificate_type=certificate_type,
        serial_number=serial_number,
        application_id=application_id,
        certificate_id=certificate_id,
        metadata=dict(metadata or {}),
        raw=None,
        signature_verified=signature_verified
    )


class HandoffRecord(object):
    """A normalized application, certificate or external approval."""

    def __init__(self, record_id, kind, public_key_fingerprint=None, lab=None,
                 certificate_type=None, subject=None, serial_number=None,
                 application_id=None, certificate_id=None, metadata=None,
                 raw=None, signature_verified=False):
        self.record_id = record_id
        self.kind = kind
        self.public_key_fingerprint = public_key_fingerprint
        self.lab = lab
        self.certificate_type = certificate_type
        self.subject = subject
        self.serial_number = serial_number
        self.application_id = application_id
        self.certificate_id = certificate_id
        self.metadata = dict(metadata or {})
        self.raw = raw
        self.signature_verified = bool(signature_verified)

    def as_dict(self):
        return {
            'id': self.record_id,
            'kind': self.kind,
            'public_key_fingerprint': self.public_key_fingerprint,
            'lab': self.lab,
            'certificate_type': self.certificate_type,
            'subject': self.subject,
            'serial_number': self.serial_number,
            'application_id': self.application_id,
            'certificate_id': self.certificate_id,
            'metadata': self.metadata,
            'signature_verified': self.signature_verified,
        }


class HandoffResult(object):
    """Result set produced by an offline handoff ledger."""

    def __init__(self, solutions, minimum_confirmations, confirmation_facts):
        self.solutions = solutions
        self.minimum_confirmations = minimum_confirmations
        self.confirmation_facts = confirmation_facts

    @property
    def has_solution(self):
        return bool(self.solutions)

    @property
    def is_unique(self):
        return len(self.solutions) == 1

    def as_dict(self):
        return {
            'solutions': self.solutions,
            'minimum_confirmations': self.minimum_confirmations,
            'confirmation_facts': self.confirmation_facts,
            'has_solution': self.has_solution,
            'is_unique': self.is_unique,
        }


class HandoffLedger(object):
    """Match applications to distinct certificates and distinct approvals."""

    def __init__(self, applications, certificates, approvals=None):
        self.applications = self._records(applications, 'application')
        self.certificates = self._records(certificates, 'certificate')
        self.approvals = self._records(approvals or [], 'approval')
        if not self.applications:
            raise ValueError('At least one application is required')
        if len(self.applications) != len(self.certificates):
            raise ValueError('Applications and certificates must have the same count')
        if self.approvals and len(self.approvals) != len(self.applications):
            raise ValueError('Approvals must match the application count when supplied')

    @staticmethod
    def _records(records, kind):
        normalized = []
        seen = set()
        for index, record in enumerate(records):
            if not isinstance(record, HandoffRecord):
                record_id = record.get('id') or record.get('record_id') or '%s-%d' % (kind, index + 1)
                values = {
                    'public_key_fingerprint': record.get(
                        'public_key_fingerprint',
                        record.get('fingerprint')
                    ),
                    'lab': record.get('lab'),
                    'certificate_type': record.get(
                        'certificate_type',
                        record.get('type')
                    ),
                    'subject': record.get('subject'),
                    'serial_number': record.get(
                        'serial_number',
                        record.get('serial')
                    ),
                    'application_id': record.get('application_id'),
                    'certificate_id': record.get('certificate_id'),
                    'metadata': record.get('metadata'),
                    'raw': record.get('raw'),
                    'signature_verified': record.get('signature_verified', False),
                }
                if values['public_key_fingerprint'] is None:
                    public_key = record.get('public_key') or record.get('spki_der')
                    if public_key is not None:
                        values['public_key_fingerprint'] = hashlib.sha256(bytes(public_key)).hexdigest()
                values = {
                    key: value for key, value in values.items() if value is not None
                }
                record = HandoffRecord(record_id=record_id, kind=kind, **values)
            if record.kind != kind:
                raise ValueError('Expected a %s record, but got %s' % (kind, record.kind))
            if record.record_id in seen:
                raise ValueError('Duplicate %s id: %s' % (kind, record.record_id))
            seen.add(record.record_id)
            normalized.append(record)
        return normalized

    @staticmethod
    def _same_optional(left, right):
        return left is None or right is None or left == right

    def _certificate_matches(self, application, certificate):
        if application.public_key_fingerprint != certificate.public_key_fingerprint:
            return False
        if not self._same_optional(application.certificate_type, certificate.certificate_type):
            return False
        if not self._same_optional(application.lab, certificate.lab):
            return False
        return True

    def _approval_matches(self, application, certificate, approval):
        if approval.application_id is not None and approval.application_id != application.record_id:
            return False
        if approval.certificate_id is not None and approval.certificate_id != certificate.record_id:
            return False
        if approval.public_key_fingerprint is not None:
            if approval.public_key_fingerprint != application.public_key_fingerprint:
                return False
            if approval.public_key_fingerprint != certificate.public_key_fingerprint:
                return False
        if not self._same_optional(approval.lab, application.lab):
            return False
        if not self._same_optional(approval.lab, certificate.lab):
            return False
        if not self._same_optional(approval.certificate_type, application.certificate_type):
            return False
        if not self._same_optional(approval.certificate_type, certificate.certificate_type):
            return False
        if approval.serial_number is not None and approval.serial_number != certificate.serial_number:
            return False
        return True

    def _eligible_certificates(self):
        return {
            application.record_id: [
                certificate.record_id
                for certificate in self.certificates
                if self._certificate_matches(application, certificate)
            ]
            for application in self.applications
        }

    def _eligible_approvals(self, application, certificate):
        return [
            approval.record_id
            for approval in self.approvals
            if self._approval_matches(application, certificate, approval)
        ]

    def _solution(self, pairs, approvals):
        solution = {}
        for application_id, certificate_id in pairs:
            item = {
                'application': application_id,
                'certificate': certificate_id,
            }
            if approvals is not None:
                item['approval'] = approvals[application_id]
            solution[application_id] = item
        return solution

    @staticmethod
    def _solution_contains_fact(solution, fact):
        for item in solution.values():
            if all(item.get(key) == value for key, value in fact.items()):
                return True
        return False

    def _satisfies_confirmations(self, solution, confirmations):
        return all(
            self._solution_contains_fact(solution, fact)
            for fact in confirmations
        )

    def solve(self, limit=None, confirmations=None):
        """
        Enumerate feasible allocations.

        Confirmation facts are dictionaries containing any two of ``application``,
        ``certificate`` and ``approval``.
        """

        confirmations = confirmations or ()
        if confirmations:
            limit = None
        eligible = self._eligible_certificates()
        solutions = []
        applications = list(self.applications)
        certificates = dict(
            (record.record_id, record)
            for record in self.certificates
        )

        def visit(index, used_certificates, used_approvals, pairs, selected_approvals):
            if limit is not None and len(solutions) >= limit:
                return
            if index == len(applications):
                solution = self._solution(pairs, selected_approvals or None)
                if self._satisfies_confirmations(solution, confirmations):
                    solutions.append(solution)
                return

            application = applications[index]
            for certificate_id in eligible[application.record_id]:
                if certificate_id in used_certificates:
                    continue
                certificate = certificates[certificate_id]
                if not self.approvals:
                    visit(
                        index + 1,
                        used_certificates | {certificate_id},
                        used_approvals,
                        pairs + [(application.record_id, certificate_id)],
                        selected_approvals
                    )
                    continue

                for approval in self._eligible_approvals(application, certificate):
                    if approval in used_approvals:
                        continue
                    next_approvals = dict(selected_approvals)
                    next_approvals[application.record_id] = approval
                    visit(
                        index + 1,
                        used_certificates | {certificate_id},
                        used_approvals | {approval},
                        pairs + [(application.record_id, certificate_id)],
                        next_approvals
                    )

        visit(0, set(), set(), [], {})
        return solutions

    def minimum_confirmation(self, limit=None):
        """Return the smallest fact set that leaves exactly one allocation."""

        if limit is not None:
            solutions = self.solve()
        else:
            solutions = self.solve(limit=limit)
        if not solutions:
            return None, []
        if len(solutions) == 1:
            return 0, []

        facts = self._candidate_facts(solutions)
        for size in range(1, len(facts) + 1):
            for combination in itertools.combinations(facts, size):
                if len(self.solve(limit=2, confirmations=list(combination))) == 1:
                    return size, [dict(fact) for fact in combination]
        return None, []

    def _candidate_facts(self, solutions):
        application_certificate_facts = []
        approval_facts = []
        seen = set()
        has_approvals = bool(self.approvals)

        def add(fact):
            key = tuple(sorted(fact.items()))
            if key not in seen:
                seen.add(key)
                if 'approval' in fact:
                    approval_facts.append(fact)
                else:
                    application_certificate_facts.append(fact)

        for solution in solutions:
            for application_id, item in solution.items():
                add({
                    'application': application_id,
                    'certificate': item['certificate'],
                })
                if has_approvals:
                    add({'application': application_id, 'approval': item['approval']})
                    add({'certificate': item['certificate'], 'approval': item['approval']})
        return application_certificate_facts + approval_facts

    def result(self, limit=None):
        solutions = self.solve(limit=limit)
        minimum, facts = self.minimum_confirmation(limit=limit)
        return HandoffResult(solutions, minimum, facts)


def solve_handoff(applications, certificates, approvals=None, confirmations=None, limit=None):
    """Convenience wrapper for :meth:`HandoffLedger.solve`."""

    return HandoffLedger(applications, certificates, approvals).solve(
        confirmations=confirmations,
        limit=limit
    )


def handoff_result(applications, certificates, approvals=None, limit=None):
    """Return allocations together with the smallest distinguishing fact set."""

    return HandoffLedger(applications, certificates, approvals).result(limit=limit)
