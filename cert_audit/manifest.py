# coding: utf-8
"""
Credential manifest describing approved leaf and intermediate certificates.

A manifest is a JSON document (YAML is also accepted when a YAML loader is
installed). Selectors identify certificates by public data such as the
SHA-256 fingerprint, subject key identifier, subject/issuer name, serial
number or PKCS#12 friendly name. No private data is required.

Example::

    {
        "allowed_usage": ["server_auth", "client_auth"],
        "leaves": [
            {
                "sha256_fingerprint": "AA:BB...",
                "usage": ["server_auth"],
                "allowed_issuers": [
                    {"subject_key_identifier": "01:23:..."}
                ]
            }
        ],
        "intermediates": [
            {"subject_key_identifier": "01:23:..."}
        ]
    }
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import json
import re


_FINGERPRINT_RE = re.compile(r'^[0-9A-F]{64}$')
_KEY_ID_RE = re.compile(r'^[0-9A-F]+$')
_SELECTOR_FIELDS = frozenset([
    'sha256_fingerprint', 'subject_key_identifier', 'authority_key_identifier',
    'subject', 'issuer', 'serial_number', 'friendly_name',
])


def _normalize_hex(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError('Hex identifier must be a string, not %s' % type(value).__name__)
    cleaned = re.sub(r'[^0-9a-fA-F]', '', value)
    if not _KEY_ID_RE.match(cleaned):
        raise ValueError('Invalid hex identifier: %r' % value)
    return cleaned.upper()


def _string_list(value, field_name):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ValueError('%s must be a string or list of strings' % field_name)


class Selector(object):
    """A set of public-data fields that must all match one certificate."""

    __slots__ = [
        'sha256_fingerprint', 'subject_key_identifier', 'authority_key_identifier',
        'subject', 'issuer', 'serial_number', 'friendly_name',
    ]

    def __init__(self, raw):
        if not isinstance(raw, dict) or not raw:
            raise ValueError('A selector must be a non-empty object')
        unknown = sorted(set(raw) - _SELECTOR_FIELDS)
        if unknown:
            raise ValueError('Unknown selector field(s): %s' % ', '.join(unknown))

        fingerprint = _normalize_hex(raw.get('sha256_fingerprint'))
        if fingerprint and not _FINGERPRINT_RE.match(fingerprint):
            raise ValueError('sha256_fingerprint must contain exactly 32 bytes (64 hex chars)')

        self.sha256_fingerprint = fingerprint
        self.subject_key_identifier = _normalize_hex(raw.get('subject_key_identifier'))
        self.authority_key_identifier = _normalize_hex(raw.get('authority_key_identifier'))
        self.subject = raw.get('subject')
        self.issuer = raw.get('issuer')
        serial = raw.get('serial_number')
        self.serial_number = str(serial) if serial is not None else None
        self.friendly_name = raw.get('friendly_name')

        if self.subject is not None and not isinstance(self.subject, str):
            raise ValueError('subject selector must be a string')
        if self.issuer is not None and not isinstance(self.issuer, str):
            raise ValueError('issuer selector must be a string')
        if self.friendly_name is not None and not isinstance(self.friendly_name, str):
            raise ValueError('friendly_name selector must be a string')

    def matches(self, archive_cert):
        if self.sha256_fingerprint and archive_cert.fingerprint != self.sha256_fingerprint:
            return False
        if self.subject_key_identifier and archive_cert.subject_key_identifier != self.subject_key_identifier:
            return False
        if self.authority_key_identifier and \
                archive_cert.authority_key_identifier != self.authority_key_identifier:
            return False
        if self.subject and archive_cert.subject != self.subject:
            return False
        if self.issuer and archive_cert.issuer != self.issuer:
            return False
        if self.serial_number and str(archive_cert.serial_number) != self.serial_number:
            return False
        if self.friendly_name and self.friendly_name not in archive_cert.friendly_names:
            return False
        return True

    def describe(self):
        parts = []
        for field in self.__slots__:
            value = getattr(self, field)
            if value is not None:
                parts.append('%s=%s' % (field, value))
        return ','.join(parts)


class Approval(object):
    __slots__ = ['selector', 'usage', 'allowed_issuer_selectors']

    def __init__(self, raw, allow_issuers):
        selector_raw = dict(
            (key, value) for key, value in raw.items()
            if key in _SELECTOR_FIELDS
        )
        self.selector = Selector(selector_raw)
        self.usage = _string_list(raw.get('usage'), 'usage')
        self.allowed_issuer_selectors = []
        if allow_issuers:
            issuer_entries = raw.get('allowed_issuers', [])
            if not isinstance(issuer_entries, list):
                raise ValueError('allowed_issuers must be a list of selector objects')
            for issuer_entry in issuer_entries:
                self.allowed_issuer_selectors.append(Selector(issuer_entry))


class CredentialManifest(object):
    """
    Parsed manifest of approved leaf and intermediate associations.
    """

    def __init__(self, raw):
        if not isinstance(raw, dict):
            raise ValueError('Manifest root must be a JSON/YAML object')

        self.allowed_usage = _string_list(raw.get('allowed_usage'), 'allowed_usage')
        self.leaf_approvals = [Approval(entry, allow_issuers=True) for entry in raw.get('leaves', [])]
        self.intermediate_approvals = [
            Approval(entry, allow_issuers=False) for entry in raw.get('intermediates', [])
        ]

        if not self.leaf_approvals and not self.intermediate_approvals:
            raise ValueError('Manifest must contain at least one leaf or intermediate entry')

    def leaf_approvals_for(self, archive_cert):
        return [approval for approval in self.leaf_approvals if approval.selector.matches(archive_cert)]

    def intermediate_approvals_for(self, archive_cert):
        return [
            approval for approval in self.intermediate_approvals
            if approval.selector.matches(archive_cert)
        ]

    def as_dict(self):
        def approval_dict(approval, include_issuers):
            result = {
                'selector': approval.selector.describe(),
                'usage': list(approval.usage),
            }
            if include_issuers:
                result['allowed_issuers'] = [
                    selector.describe() for selector in approval.allowed_issuer_selectors
                ]
            return result

        return {
            'allowed_usage': list(self.allowed_usage),
            'leaves': [approval_dict(approval, True) for approval in self.leaf_approvals],
            'intermediates': [
                approval_dict(approval, False) for approval in self.intermediate_approvals
            ],
        }


def _parse_document(text):
    try:
        return json.loads(text)
    except ValueError:
        try:
            import yaml
        except ImportError:
            raise ValueError('Manifest is not valid JSON and no YAML loader is installed')
        return yaml.safe_load(text)


def load_manifest(source):
    """
    Load a manifest from a file path, raw text, or an already parsed dict.
    """
    if isinstance(source, dict):
        return CredentialManifest(source)
    if isinstance(source, bytes):
        source = source.decode('utf-8')
    if not isinstance(source, str):
        raise TypeError('Manifest source must be a path, string or dict, not %s' % type(source).__name__)
    try:
        with open(source, 'rb') as file_handle:
            text = file_handle.read().decode('utf-8')
    except (IOError, OSError):
        text = source
    return CredentialManifest(_parse_document(text))
