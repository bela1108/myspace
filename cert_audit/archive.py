# coding: utf-8
"""
Read-only extraction of public certificate material from PKCS#12 and X.509
data.

Only certificate bags and certificate files are parsed into
:class:`asn1crypto.x509.Certificate` objects. Key bags are counted by bag type
without ever decoding or dumping their contents, so private key material is
never exported or retained.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import os

from asn1crypto import pem, pkcs12
from asn1crypto.x509 import Certificate


_CERTIFICATE_PEM_LABELS = frozenset(['CERTIFICATE', 'X509 CERTIFICATE'])
_PFX_PEM_LABELS = frozenset(['PKCS12', 'PFX'])
_PRIVATE_KEY_PEM_MARKER = 'PRIVATE KEY'


def _hex(byte_string):
    if not byte_string:
        return ''
    # bytearray yields integer byte values on both Python 2 and Python 3.
    byte_string = bytearray(byte_string)
    return ''.join('%02X' % byte_value for byte_value in byte_string)


class ArchiveCert(object):
    """
    Public information about one distinct certificate in an archive.

    The underlying :class:`asn1crypto.x509.Certificate` is available through
    :attr:`certificate`; it contains only the certificate's public material.
    """

    __slots__ = [
        'certificate', 'fingerprint', 'friendly_names', 'local_key_ids',
        'trusted_key_usages', 'cert_bag_count',
    ]

    def __init__(self, certificate):
        self.certificate = certificate
        self.fingerprint = _hex(certificate.sha256)
        self.friendly_names = []
        self.local_key_ids = []
        self.trusted_key_usages = []
        self.cert_bag_count = 0

    @property
    def subject(self):
        return self.certificate.subject.human_friendly

    @property
    def issuer(self):
        return self.certificate.issuer.human_friendly

    @property
    def serial_number(self):
        return self.certificate.serial_number

    @property
    def is_ca(self):
        return bool(self.certificate.ca)

    @property
    def is_self_issued(self):
        return self.certificate.self_issued

    @property
    def subject_key_identifier(self):
        return _hex(self.certificate.key_identifier) if self.certificate.key_identifier else None

    @property
    def authority_key_identifier(self):
        akid = self.certificate.authority_key_identifier
        return _hex(akid) if akid else None

    @property
    def key_usages(self):
        value = self.certificate.key_usage_value
        return sorted(value.native) if value else []

    @property
    def extended_key_usages(self):
        value = self.certificate.extended_key_usage_value
        return list(value.native) if value else []

    @property
    def not_valid_before(self):
        return self.certificate.not_valid_before

    @property
    def not_valid_after(self):
        return self.certificate.not_valid_after

    def as_dict(self):
        return {
            'fingerprint_sha256': self.fingerprint,
            'subject': self.subject,
            'issuer': self.issuer,
            'serial_number': str(self.serial_number),
            'is_ca': self.is_ca,
            'is_self_issued': self.is_self_issued,
            'subject_key_identifier': self.subject_key_identifier,
            'authority_key_identifier': self.authority_key_identifier,
            'key_usages': self.key_usages,
            'extended_key_usages': self.extended_key_usages,
            'friendly_names': list(self.friendly_names),
            'local_key_ids': list(self.local_key_ids),
            'trusted_key_usages': list(self.trusted_key_usages),
            'not_valid_before': self.not_valid_before.isoformat() if self.not_valid_before else None,
            'not_valid_after': self.not_valid_after.isoformat() if self.not_valid_after else None,
        }


class Archive(object):
    """
    The public-material inventory extracted from one PKCS#12 or X.509 source.
    """

    def __init__(self, source):
        self.source = source
        self.certs = []
        self._by_fingerprint = {}
        self.friendly_name_index = {}
        self.cert_bag_count = 0
        self.key_bag_count = 0
        self.shrouded_key_bag_count = 0
        self.crl_bag_count = 0
        self.secret_bag_count = 0
        self.encrypted_safe_count = 0

    @property
    def private_key_material_present(self):
        """
        :return:
            A boolean indicating whether key bags (or opaque encrypted safe
            contents that may contain them) are present. No key material is
            ever extracted.
        """
        return bool(
            self.key_bag_count
            or self.shrouded_key_bag_count
            or self.encrypted_safe_count
        )

    def get(self, fingerprint):
        return self._by_fingerprint.get(fingerprint.upper())

    def _cert_for_bag(self, cert_source):
        if isinstance(cert_source, Certificate):
            certificate = cert_source
        else:
            certificate = cert_source['cert_value'].parsed
        fingerprint = _hex(certificate.sha256)
        archive_cert = self._by_fingerprint.get(fingerprint)
        if archive_cert is None:
            archive_cert = ArchiveCert(certificate)
            self._by_fingerprint[fingerprint] = archive_cert
            self.certs.append(archive_cert)
        archive_cert.cert_bag_count += 1
        return archive_cert

    def _index_attributes(self, archive_cert, bag_attributes):
        if not bag_attributes:
            return
        for attribute in bag_attributes:
            attribute_type = attribute['type'].native
            values = attribute['values'].native
            if attribute_type == 'friendly_name':
                for name in values:
                    if name not in archive_cert.friendly_names:
                        archive_cert.friendly_names.append(name)
                    self.friendly_name_index.setdefault(name, []).append(archive_cert)
            elif attribute_type == 'local_key_id':
                for key_id in values:
                    hex_key_id = _hex(key_id)
                    if hex_key_id not in archive_cert.local_key_ids:
                        archive_cert.local_key_ids.append(hex_key_id)
            elif attribute_type == 'trusted_key_usage':
                for usage in values:
                    if usage not in archive_cert.trusted_key_usages:
                        archive_cert.trusted_key_usages.append(usage)

    def _walk_safe_contents(self, safe_contents):
        for safe_bag in safe_contents:
            bag_id = safe_bag['bag_id'].native
            if bag_id == 'cert_bag':
                self.cert_bag_count += 1
                archive_cert = self._cert_for_bag(safe_bag['bag_value'])
                self._index_attributes(archive_cert, safe_bag['bag_attributes'])
            elif bag_id == 'key_bag':
                # Counted only: the bag value is never parsed or dumped.
                self.key_bag_count += 1
            elif bag_id == 'pkcs8_shrouded_key_bag':
                self.shrouded_key_bag_count += 1
            elif bag_id == 'crl_bag':
                self.crl_bag_count += 1
            elif bag_id == 'secret_bag':
                self.secret_bag_count += 1
            elif bag_id == 'safe_contents':
                self._walk_safe_contents(safe_bag['bag_value'])

    def _load_pfx(self, der_bytes):
        pfx = pkcs12.Pfx.load(der_bytes)
        for content_info in pfx.authenticated_safe:
            content_type = content_info['content_type'].native
            if content_type == 'data':
                safe_contents = pkcs12.SafeContents.load(content_info['content'].native)
                self._walk_safe_contents(safe_contents)
            elif content_type == 'encrypted_data':
                # Opaque without a password. It may hold key bags, so flag it
                # instead of attempting decryption.
                self.encrypted_safe_count += 1
            else:
                raise ValueError('Unsupported authenticated safe content type: %s' % content_type)

    def _load_certificate_der(self, der_bytes):
        certificate = Certificate.load(der_bytes)
        archive_cert = self._cert_for_bag(certificate)
        archive_cert.cert_bag_count += 1

    def _load_pem(self, pem_bytes):
        for object_name, _headers, der_bytes in pem.unarmor(pem_bytes, multiple=True):
            if _PRIVATE_KEY_PEM_MARKER in object_name:
                raise ValueError(
                    'Private key PEM block "%s" is not accepted; review is public-material only' % object_name
                )
            if object_name in _CERTIFICATE_PEM_LABELS:
                self._load_certificate_der(der_bytes)
            elif object_name in _PFX_PEM_LABELS:
                self._load_pfx(der_bytes)
            else:
                raise ValueError('Unsupported PEM block type: %s' % object_name)

    def load_bytes(self, data):
        if not isinstance(data, bytes):
            raise TypeError('Archive data must be a byte string, not %s' % type(data).__name__)
        if pem.detect(data):
            self._load_pem(data)
            return self
        try:
            self._load_pfx(data)
        except (ValueError, TypeError):
            parsed_anything = any([
                self.cert_bag_count,
                self.key_bag_count,
                self.shrouded_key_bag_count,
                self.crl_bag_count,
                self.secret_bag_count,
                self.encrypted_safe_count,
            ])
            if parsed_anything:
                raise
            self._load_certificate_der(data)
        return self

    def inventory(self):
        return {
            'source': self.source,
            'distinct_certificates': len(self.certs),
            'cert_bags': self.cert_bag_count,
            'key_bags': self.key_bag_count,
            'shrouded_key_bags': self.shrouded_key_bag_count,
            'encrypted_safe_contents': self.encrypted_safe_count,
            'crl_bags': self.crl_bag_count,
            'secret_bags': self.secret_bag_count,
            'private_key_material_present': self.private_key_material_present,
            'certificates': [cert.as_dict() for cert in self.certs],
        }


def load_archive(source, data=None):
    """
    Load an archive from a file path (or from raw bytes when ``data`` is given).

    :param source:
        A unicode file path or label for the archive
    :param data:
        Optional byte string of PFX/PEM/DER data. When omitted, ``source`` is
        read from disk.
    :return:
        A populated :class:`Archive`
    """
    if data is None:
        with open(source, 'rb') as file_handle:
            data = file_handle.read()
        label = os.path.basename(source)
    else:
        label = source
    return Archive(label).load_bytes(data)
