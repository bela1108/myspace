# coding: utf-8

"""
ASN.1 type classes for cryptographic message syntax (CMS). Structures are also
compatible with PKCS#7. Exports the following items:

 - AuthenticatedData()
 - AuthEnvelopedData()
 - CompressedData()
 - ContentInfo()
 - DigestedData()
 - EncryptedData()
 - EnvelopedData()
 - SignedAndEnvelopedData()
 - SignedData()

Other type classes are defined that help compose the types listed above.

Most CMS structures in the wild are formatted as ContentInfo encapsulating one of the other types.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

try:
    import zlib
except (ImportError):
    zlib = None

from .algos import (
    _ForceNullParameters,
    DigestAlgorithm,
    EncryptionAlgorithm,
    EncryptionAlgorithmId,
    HmacAlgorithm,
    KdfAlgorithm,
    RSAESOAEPParams,
    SignedDigestAlgorithm,
)
from .core import (
    Any,
    BitString,
    Choice,
    Enumerated,
    GeneralizedTime,
    Integer,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    ParsableOctetString,
    Sequence,
    SequenceOf,
    SetOf,
    UTCTime,
    UTF8String,
)
from .crl import CertificateList
from .keys import PublicKeyInfo
from .ocsp import OCSPResponse
from ._ordereddict import OrderedDict
from .parser import parse
from ._types import str_cls
from .x509 import Attributes, Certificate, Extensions, GeneralName, GeneralNames, Name


# These structures are taken from
# ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-6.asc

class ExtendedCertificateInfo(Sequence):
    _fields = [
        ('version', Integer),
        ('certificate', Certificate),
        ('attributes', Attributes),
    ]


class ExtendedCertificate(Sequence):
    _fields = [
        ('extended_certificate_info', ExtendedCertificateInfo),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


# These structures are taken from https://tools.ietf.org/html/rfc5652,
# https://tools.ietf.org/html/rfc5083, http://tools.ietf.org/html/rfc2315,
# https://tools.ietf.org/html/rfc5940, https://tools.ietf.org/html/rfc3274,
# https://tools.ietf.org/html/rfc3281


class CMSVersion(Integer):
    _map = {
        0: 'v0',
        1: 'v1',
        2: 'v2',
        3: 'v3',
        4: 'v4',
        5: 'v5',
    }


class CMSAttributeType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.3': 'content_type',
        '1.2.840.113549.1.9.4': 'message_digest',
        '1.2.840.113549.1.9.5': 'signing_time',
        '1.2.840.113549.1.9.6': 'counter_signature',
        # https://datatracker.ietf.org/doc/html/rfc2633#section-2.5.2
        '1.2.840.113549.1.9.15': 'smime_capabilities',
        # https://tools.ietf.org/html/rfc2633#page-26
        '1.2.840.113549.1.9.16.2.11': 'encrypt_key_pref',
        # https://tools.ietf.org/html/rfc3161#page-20
        '1.2.840.113549.1.9.16.2.14': 'signature_time_stamp_token',
        # https://tools.ietf.org/html/rfc6211#page-5
        '1.2.840.113549.1.9.52': 'cms_algorithm_protection',
        # https://docs.microsoft.com/en-us/previous-versions/hh968145(v%3Dvs.85)
        '1.3.6.1.4.1.311.2.4.1': 'microsoft_nested_signature',
        # Some places refer to this as SPC_RFC3161_OBJID, others szOID_RFC3161_counterSign.
        # https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier
        # refers to szOID_RFC3161_counterSign as "1.2.840.113549.1.9.16.1.4",
        # but that OID is also called szOID_TIMESTAMP_TOKEN. Because of there being
        # no canonical source for this OID, we give it our own name
        '1.3.6.1.4.1.311.3.3.1': 'microsoft_time_stamp_token',
    }


class Time(Choice):
    _alternatives = [
        ('utc_time', UTCTime),
        ('generalized_time', GeneralizedTime),
    ]


class ContentType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.7.1': 'data',
        '1.2.840.113549.1.7.2': 'signed_data',
        '1.2.840.113549.1.7.3': 'enveloped_data',
        '1.2.840.113549.1.7.4': 'signed_and_enveloped_data',
        '1.2.840.113549.1.7.5': 'digested_data',
        '1.2.840.113549.1.7.6': 'encrypted_data',
        '1.2.840.113549.1.9.16.1.2': 'authenticated_data',
        '1.2.840.113549.1.9.16.1.9': 'compressed_data',
        '1.2.840.113549.1.9.16.1.23': 'authenticated_enveloped_data',
    }


class CMSAlgorithmProtection(Sequence):
    _fields = [
        ('digest_algorithm', DigestAlgorithm),
        ('signature_algorithm', SignedDigestAlgorithm, {'implicit': 1, 'optional': True}),
        ('mac_algorithm', HmacAlgorithm, {'implicit': 2, 'optional': True}),
    ]


class SetOfContentType(SetOf):
    _child_spec = ContentType


class SetOfOctetString(SetOf):
    _child_spec = OctetString


class SetOfTime(SetOf):
    _child_spec = Time


class SetOfAny(SetOf):
    _child_spec = Any


class SetOfCMSAlgorithmProtection(SetOf):
    _child_spec = CMSAlgorithmProtection


class CMSAttribute(Sequence):
    _fields = [
        ('type', CMSAttributeType),
        ('values', None),
    ]

    _oid_specs = {}

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class CMSAttributes(SetOf):
    _child_spec = CMSAttribute


class IssuerSerial(Sequence):
    _fields = [
        ('issuer', GeneralNames),
        ('serial', Integer),
        ('issuer_uid', OctetBitString, {'optional': True}),
    ]


class AttCertVersion(Integer):
    _map = {
        0: 'v1',
        1: 'v2',
    }


class AttCertSubject(Choice):
    _alternatives = [
        ('base_certificate_id', IssuerSerial, {'explicit': 0}),
        ('subject_name', GeneralNames, {'explicit': 1}),
    ]


class AttCertValidityPeriod(Sequence):
    _fields = [
        ('not_before_time', GeneralizedTime),
        ('not_after_time', GeneralizedTime),
    ]


class AttributeCertificateInfoV1(Sequence):
    _fields = [
        ('version', AttCertVersion, {'default': 'v1'}),
        ('subject', AttCertSubject),
        ('issuer', GeneralNames),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', Attributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV1(Sequence):
    _fields = [
        ('ac_info', AttributeCertificateInfoV1),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class DigestedObjectType(Enumerated):
    _map = {
        0: 'public_key',
        1: 'public_key_cert',
        2: 'other_objy_types',
    }


class ObjectDigestInfo(Sequence):
    _fields = [
        ('digested_object_type', DigestedObjectType),
        ('other_object_type_id', ObjectIdentifier, {'optional': True}),
        ('digest_algorithm', DigestAlgorithm),
        ('object_digest', OctetBitString),
    ]


class Holder(Sequence):
    _fields = [
        ('base_certificate_id', IssuerSerial, {'implicit': 0, 'optional': True}),
        ('entity_name', GeneralNames, {'implicit': 1, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'implicit': 2, 'optional': True}),
    ]


class V2Form(Sequence):
    _fields = [
        ('issuer_name', GeneralNames, {'optional': True}),
        ('base_certificate_id', IssuerSerial, {'explicit': 0, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'explicit': 1, 'optional': True}),
    ]


class AttCertIssuer(Choice):
    _alternatives = [
        ('v1_form', GeneralNames),
        ('v2_form', V2Form, {'implicit': 0}),
    ]


class IetfAttrValue(Choice):
    _alternatives = [
        ('octets', OctetString),
        ('oid', ObjectIdentifier),
        ('string', UTF8String),
    ]


class IetfAttrValues(SequenceOf):
    _child_spec = IetfAttrValue


class IetfAttrSyntax(Sequence):
    _fields = [
        ('policy_authority', GeneralNames, {'implicit': 0, 'optional': True}),
        ('values', IetfAttrValues),
    ]


class SetOfIetfAttrSyntax(SetOf):
    _child_spec = IetfAttrSyntax


class SvceAuthInfo(Sequence):
    _fields = [
        ('service', GeneralName),
        ('ident', GeneralName),
        ('auth_info', OctetString, {'optional': True}),
    ]


class SetOfSvceAuthInfo(SetOf):
    _child_spec = SvceAuthInfo


class RoleSyntax(Sequence):
    _fields = [
        ('role_authority', GeneralNames, {'implicit': 0, 'optional': True}),
        ('role_name', GeneralName, {'explicit': 1}),
    ]


class SetOfRoleSyntax(SetOf):
    _child_spec = RoleSyntax


class ClassList(BitString):
    _map = {
        0: 'unmarked',
        1: 'unclassified',
        2: 'restricted',
        3: 'confidential',
        4: 'secret',
        5: 'top_secret',
    }


class SecurityCategory(Sequence):
    _fields = [
        ('type', ObjectIdentifier, {'implicit': 0}),
        ('value', Any, {'explicit': 1}),
    ]


class SetOfSecurityCategory(SetOf):
    _child_spec = SecurityCategory


class Clearance(Sequence):
    _fields = [
        ('policy_id', ObjectIdentifier),
        ('class_list', ClassList, {'default': set(['unclassified'])}),
        ('security_categories', SetOfSecurityCategory, {'optional': True}),
    ]


class SetOfClearance(SetOf):
    _child_spec = Clearance


class BigTime(Sequence):
    _fields = [
        ('major', Integer),
        ('fractional_seconds', Integer),
        ('sign', Integer, {'optional': True}),
    ]


class LeapData(Sequence):
    _fields = [
        ('leap_time', BigTime),
        ('action', Integer),
    ]


class SetOfLeapData(SetOf):
    _child_spec = LeapData


class TimingMetrics(Sequence):
    _fields = [
        ('ntp_time', BigTime),
        ('offset', BigTime),
        ('delay', BigTime),
        ('expiration', BigTime),
        ('leap_event', SetOfLeapData, {'optional': True}),
    ]


class SetOfTimingMetrics(SetOf):
    _child_spec = TimingMetrics


class TimingPolicy(Sequence):
    _fields = [
        ('policy_id', SequenceOf, {'spec': ObjectIdentifier}),
        ('max_offset', BigTime, {'explicit': 0, 'optional': True}),
        ('max_delay', BigTime, {'explicit': 1, 'optional': True}),
    ]


class SetOfTimingPolicy(SetOf):
    _child_spec = TimingPolicy


class AttCertAttributeType(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.10.1': 'authentication_info',
        '1.3.6.1.5.5.7.10.2': 'access_identity',
        '1.3.6.1.5.5.7.10.3': 'charging_identity',
        '1.3.6.1.5.5.7.10.4': 'group',
        '2.5.4.72': 'role',
        '2.5.4.55': 'clearance',
        '1.3.6.1.4.1.601.10.4.1': 'timing_metrics',
        '1.3.6.1.4.1.601.10.4.2': 'timing_policy',
    }


class AttCertAttribute(Sequence):
    _fields = [
        ('type', AttCertAttributeType),
        ('values', None),
    ]

    _oid_specs = {
        'authentication_info': SetOfSvceAuthInfo,
        'access_identity': SetOfSvceAuthInfo,
        'charging_identity': SetOfIetfAttrSyntax,
        'group': SetOfIetfAttrSyntax,
        'role': SetOfRoleSyntax,
        'clearance': SetOfClearance,
        'timing_metrics': SetOfTimingMetrics,
        'timing_policy': SetOfTimingPolicy,
    }

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class AttCertAttributes(SequenceOf):
    _child_spec = AttCertAttribute


class AttributeCertificateInfoV2(Sequence):
    _fields = [
        ('version', AttCertVersion),
        ('holder', Holder),
        ('issuer', AttCertIssuer),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', AttCertAttributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV2(Sequence):
    # Handle the situation where a V2 cert is encoded as V1
    _bad_tag = 1

    _fields = [
        ('ac_info', AttributeCertificateInfoV2),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class OtherCertificateFormat(Sequence):
    _fields = [
        ('other_cert_format', ObjectIdentifier),
        ('other_cert', Any),
    ]


class CertificateChoices(Choice):
    _alternatives = [
        ('certificate', Certificate),
        ('extended_certificate', ExtendedCertificate, {'implicit': 0}),
        ('v1_attr_cert', AttributeCertificateV1, {'implicit': 1}),
        ('v2_attr_cert', AttributeCertificateV2, {'implicit': 2}),
        ('other', OtherCertificateFormat, {'implicit': 3}),
    ]

    def validate(self, class_, tag, contents):
        """
        Ensures that the class and tag specified exist as an alternative. This
        custom version fixes parsing broken encodings there a V2 attribute
        # certificate is encoded as a V1

        :param class_:
            The integer class_ from the encoded value header

        :param tag:
            The integer tag from the encoded value header

        :param contents:
            A byte string of the contents of the value - used when the object
            is explicitly tagged

        :raises:
            ValueError - when value is not a valid alternative
        """

        super(CertificateChoices, self).validate(class_, tag, contents)
        if self._choice == 2:
            if AttCertVersion.load(Sequence.load(contents)[0].dump()).native == 'v2':
                self._choice = 3


class CertificateSet(SetOf):
    _child_spec = CertificateChoices


class ContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', Any, {'explicit': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}


class SetOfContentInfo(SetOf):
    _child_spec = ContentInfo


class EncapsulatedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', ParsableOctetString, {'explicit': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}


class IssuerAndSerialNumber(Sequence):
    _fields = [
        ('issuer', Name),
        ('serial_number', Integer),
    ]


class SignerIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
    ]


class DigestAlgorithms(SetOf):
    _child_spec = DigestAlgorithm


class CertificateRevocationLists(SetOf):
    _child_spec = CertificateList


class SCVPReqRes(Sequence):
    _fields = [
        ('request', ContentInfo, {'explicit': 0, 'optional': True}),
        ('response', ContentInfo),
    ]


class OtherRevInfoFormatId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.16.2': 'ocsp_response',
        '1.3.6.1.5.5.7.16.4': 'scvp',
    }


class OtherRevocationInfoFormat(Sequence):
    _fields = [
        ('other_rev_info_format', OtherRevInfoFormatId),
        ('other_rev_info', Any),
    ]

    _oid_pair = ('other_rev_info_format', 'other_rev_info')
    _oid_specs = {
        'ocsp_response': OCSPResponse,
        'scvp': SCVPReqRes,
    }


class RevocationInfoChoice(Choice):
    _alternatives = [
        ('crl', CertificateList),
        ('other', OtherRevocationInfoFormat, {'implicit': 1}),
    ]


class RevocationInfoChoices(SetOf):
    _child_spec = RevocationInfoChoice


class SignerInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('sid', SignerIdentifier),
        ('digest_algorithm', DigestAlgorithm),
        ('signed_attrs', CMSAttributes, {'implicit': 0, 'optional': True}),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetString),
        ('unsigned_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]

    def certificate_candidates(self, certificates):
        """
        Returns the certificates from a certificate set that match the
        signer identifier of this SignerInfo.

        This is useful when a caller needs the raw candidate material before
        deciding which certificate to use for signature verification. The
        returned records include the certificate and the identifier checks
        that matched, but do not assert that the certificate is trusted.

        :param certificates:
            A CertificateSet, a list of CertificateChoices objects, or a list
            of Certificate objects

        :return:
            A list of dicts, one per matching certificate
        """

        entries = _certificate_entries(certificates)
        layer = {
            'layer': 'certificate_set',
            'layer_id': 'certificate_set',
            'depth': 0,
            'layer_path': [],
        }

        by_der = OrderedDict()
        for entry in entries:
            by_der.setdefault(entry['certificate_der'], []).append(entry)
        for duplicate_entries in by_der.values():
            occurrences = [_certificate_occurrence(entry) for entry in duplicate_entries]
            for entry in duplicate_entries:
                entry['duplicate_count'] = len(duplicate_entries)
                entry['duplicate_occurrences'] = occurrences

        matching_entries = [
            entry
            for entry in entries
            if _signer_matches_certificate_entry(self, entry)
        ]
        distinct_certificates = set([
            entry['certificate_der'] for entry in matching_entries
        ])

        matches = []
        for entry in matching_entries:
            status = _CANDIDATE_STATUS_OK
            state = _CANDIDATE_STATE_MATCHED
            if len(distinct_certificates) > 1:
                status = _CANDIDATE_STATUS_CONFLICT
                state = _CANDIDATE_STATE_CONFLICT
            elif entry['duplicate_count'] > 1:
                status = _CANDIDATE_STATUS_DUPLICATE
                state = _CANDIDATE_STATE_DUPLICATE
            matches.append(_candidate_record(
                self,
                None,
                entry,
                layer,
                status,
                state
            ))
        return matches

    def matches_certificate(self, certificate):
        """
        Checks whether a certificate matches the signer identifier of this
        SignerInfo.

        :param certificate:
            An x509.Certificate or CertificateChoices object

        :return:
            A boolean
        """

        entry = _certificate_entry(certificate, 0)
        if entry is None:
            return False
        return _signer_matches_certificate_entry(self, entry)

    def issuer_serial_matches(self, certificate):
        """
        Checks the issuer and serial number identifier of this SignerInfo
        against a certificate.

        :param certificate:
            An x509.Certificate or CertificateChoices object

        :return:
            A boolean
        """

        entry = _certificate_entry(certificate, 0)
        if entry is None:
            return False
        return _signer_matches_issuer_serial(self, entry)

    def subject_key_identifier_matches(self, certificate):
        """
        Checks the subject key identifier identifier of this SignerInfo
        against a certificate.

        :param certificate:
            An x509.Certificate or CertificateChoices object

        :return:
            A boolean
        """

        entry = _certificate_entry(certificate, 0)
        if entry is None:
            return False
        return _signer_matches_subject_key_identifier(self, entry)

    matches_subject_key_identifier = subject_key_identifier_matches
    matches_issuer_serial = issuer_serial_matches


class SignerInfos(SetOf):
    _child_spec = SignerInfo


class SignedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithms', DigestAlgorithms),
        ('encap_content_info', None),
        ('certificates', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }

    def signer_certificate_candidates(self):
        """
        Resolves the certificates in this SignedData against every SignerInfo,
        including SignerInfo objects found in Microsoft nested signatures.

        Outer and nested signer evidence is kept separate in the report, while
        each signer and candidate record also has enough provenance to find
        the exact layer and SignerInfo it came from.

        :return:
            A dict with the keys "outer", "nested", "signers", "layers",
            "duplicates" and "conflicts"
        """

        return _build_certificate_candidate_report(self)

    def certificate_candidate_report(self):
        """
        Alias for signer_certificate_candidates().

        :return:
            A dict containing the certificate candidate report
        """

        return self.signer_certificate_candidates()

    def certificate_candidates(self):
        """
        Returns all candidate records for all signers, outer and nested.

        :return:
            A list of candidate dicts
        """

        report = self.signer_certificate_candidates()
        return [
            candidate
            for signer in report['signers']
            for candidate in signer['candidates']
        ]

    def get_signer_certificates(self):
        """
        Alias for signer_certificate_candidates().

        :return:
            A dict containing the certificate candidate report
        """

        return self.signer_certificate_candidates()

    def get_certificate_candidates(self):
        """
        Alias for signer_certificate_candidates().

        :return:
            A dict containing the certificate candidate report
        """

        return self.signer_certificate_candidates()

    signer_certificates = signer_certificate_candidates
    resolve_signer_certificates = signer_certificate_candidates


class OriginatorInfo(Sequence):
    _fields = [
        ('certs', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
    ]


class RecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
    ]


class KeyEncryptionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.1.1': 'rsaes_pkcs1v15',
        '1.2.840.113549.1.1.7': 'rsaes_oaep',
        '2.16.840.1.101.3.4.1.5': 'aes128_wrap',
        '2.16.840.1.101.3.4.1.8': 'aes128_wrap_pad',
        '2.16.840.1.101.3.4.1.25': 'aes192_wrap',
        '2.16.840.1.101.3.4.1.28': 'aes192_wrap_pad',
        '2.16.840.1.101.3.4.1.45': 'aes256_wrap',
        '2.16.840.1.101.3.4.1.48': 'aes256_wrap_pad',
    }

    _reverse_map = {
        'rsa': '1.2.840.113549.1.1.1',
        'rsaes_pkcs1v15': '1.2.840.113549.1.1.1',
        'rsaes_oaep': '1.2.840.113549.1.1.7',
        'aes128_wrap': '2.16.840.1.101.3.4.1.5',
        'aes128_wrap_pad': '2.16.840.1.101.3.4.1.8',
        'aes192_wrap': '2.16.840.1.101.3.4.1.25',
        'aes192_wrap_pad': '2.16.840.1.101.3.4.1.28',
        'aes256_wrap': '2.16.840.1.101.3.4.1.45',
        'aes256_wrap_pad': '2.16.840.1.101.3.4.1.48',
    }


class KeyEncryptionAlgorithm(_ForceNullParameters, Sequence):
    _fields = [
        ('algorithm', KeyEncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'rsaes_oaep': RSAESOAEPParams,
    }


class KeyTransRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('rid', RecipientIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OriginatorIdentifierOrKey(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
        ('originator_key', PublicKeyInfo, {'implicit': 1}),
    ]


class OtherKeyAttribute(Sequence):
    _fields = [
        ('key_attr_id', ObjectIdentifier),
        ('key_attr', Any),
    ]


class RecipientKeyIdentifier(Sequence):
    _fields = [
        ('subject_key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]

    def _setup(self):
        super(RecipientKeyIdentifier, self)._setup()
        # This creates a backwards compatible shim for an
        # incorrect format field name that was in old versions
        self._field_map['subjectKeyIdentifier'] = self._field_map['subject_key_identifier']


class KeyAgreementRecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('r_key_id', RecipientKeyIdentifier, {'implicit': 0}),
    ]


class RecipientEncryptedKey(Sequence):
    _fields = [
        ('rid', KeyAgreementRecipientIdentifier),
        ('encrypted_key', OctetString),
    ]


class RecipientEncryptedKeys(SequenceOf):
    _child_spec = RecipientEncryptedKey


class KeyAgreeRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator', OriginatorIdentifierOrKey, {'explicit': 0}),
        ('ukm', OctetString, {'explicit': 1, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('recipient_encrypted_keys', RecipientEncryptedKeys),
    ]


class KEKIdentifier(Sequence):
    _fields = [
        ('key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]


class KEKRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('kekid', KEKIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class PasswordRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('key_derivation_algorithm', KdfAlgorithm, {'implicit': 0, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OtherRecipientInfo(Sequence):
    _fields = [
        ('ori_type', ObjectIdentifier),
        ('ori_value', Any),
    ]


class RecipientInfo(Choice):
    _alternatives = [
        ('ktri', KeyTransRecipientInfo),
        ('kari', KeyAgreeRecipientInfo, {'implicit': 1}),
        ('kekri', KEKRecipientInfo, {'implicit': 2}),
        ('pwri', PasswordRecipientInfo, {'implicit': 3}),
        ('ori', OtherRecipientInfo, {'implicit': 4}),
    ]


class RecipientInfos(SetOf):
    _child_spec = RecipientInfo


class EncryptedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content_encryption_algorithm', EncryptionAlgorithm),
        ('encrypted_content', OctetString, {'implicit': 0, 'optional': True}),
    ]


class EnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class SignedAndEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('recipient_infos', RecipientInfos),
        ('digest_algorithms', DigestAlgorithms),
        ('encrypted_content_info', EncryptedContentInfo),
        ('certificates', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', CertificateRevocationLists, {'implicit': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]


class DigestedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithm', DigestAlgorithm),
        ('encap_content_info', None),
        ('digest', OctetString),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }


class EncryptedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class AuthenticatedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('mac_algorithm', HmacAlgorithm),
        ('digest_algorithm', DigestAlgorithm, {'implicit': 1, 'optional': True}),
        # This does not require the _spec_callbacks approach of SignedData and
        # DigestedData since AuthenticatedData was not part of PKCS#7
        ('encap_content_info', EncapsulatedContentInfo),
        ('auth_attrs', CMSAttributes, {'implicit': 2, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'implicit': 3, 'optional': True}),
    ]


class AuthEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('auth_encrypted_content_info', EncryptedContentInfo),
        ('auth_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'implicit': 2, 'optional': True}),
    ]


class CompressionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.16.3.8': 'zlib',
    }


class CompressionAlgorithm(Sequence):
    _fields = [
        ('algorithm', CompressionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class CompressedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('compression_algorithm', CompressionAlgorithm),
        ('encap_content_info', EncapsulatedContentInfo),
    ]

    _decompressed = None

    @property
    def decompressed(self):
        if self._decompressed is None:
            if zlib is None:
                raise SystemError('The zlib module is not available')
            self._decompressed = zlib.decompress(self['encap_content_info']['content'].native)
        return self._decompressed


class SMIMEEncryptionKeyPreference(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber, {'implicit': 0}),
        ('recipient_key_id', RecipientKeyIdentifier, {'implicit': 1}),
        ('subject_alt_key_identifier', PublicKeyInfo, {'implicit': 2}),
    ]

    def _setup(self):
        super(SMIMEEncryptionKeyPreference, self)._setup()
        # This creates backwards compatible shims for two
        # incorrect format alternative names that were in old versions
        self._name_map['recipientKeyId'] = self._name_map['recipient_key_id']
        self._name_map['subjectAltKeyIdentifier'] = self._name_map['subject_alt_key_identifier']


class SMIMEEncryptionKeyPreferences(SetOf):
    _child_spec = SMIMEEncryptionKeyPreference


class SMIMECapabilityIdentifier(Sequence):
    _fields = [
        ('capability_id', EncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class SMIMECapabilites(SequenceOf):
    _child_spec = SMIMECapabilityIdentifier


class SetOfSMIMECapabilites(SetOf):
    _child_spec = SMIMECapabilites


ContentInfo._oid_specs = {
    'data': OctetString,
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


EncapsulatedContentInfo._oid_specs = {
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


CMSAttribute._oid_specs = {
    'content_type': SetOfContentType,
    'message_digest': SetOfOctetString,
    'signing_time': SetOfTime,
    'counter_signature': SignerInfos,
    'signature_time_stamp_token': SetOfContentInfo,
    'cms_algorithm_protection': SetOfCMSAlgorithmProtection,
    'microsoft_nested_signature': SetOfContentInfo,
    'microsoft_time_stamp_token': SetOfContentInfo,
    'encrypt_key_pref': SMIMEEncryptionKeyPreferences,
    'smime_capabilities': SetOfSMIMECapabilites,
}


_CANDIDATE_STATUS_OK = 'ok'
_CANDIDATE_STATUS_CONFLICT = 'certificate_conflict'
_CANDIDATE_STATUS_DUPLICATE = 'duplicate_certificate'
_CANDIDATE_STATUS_MISSING = 'missing_certificate'

_CANDIDATE_STATE_MATCHED = 'matched'
_CANDIDATE_STATE_CONFLICT = 'conflict'
_CANDIDATE_STATE_DUPLICATE = 'duplicate'
_CANDIDATE_STATE_MISSING = 'missing'


class SignerCertificateReport(OrderedDict):
    """
    A report of signer certificate candidates, broken down by CMS layer.

    The canonical keys are "outer", "nested", "signers", "layers",
    "duplicates" and "conflicts". A number of descriptive aliases are also
    accepted for convenience.
    """

    _aliases = {
        'outer_signers': 'outer',
        'nested_signers': 'nested',
        'all_signers': 'signers',
        'duplicate_certificates': 'duplicates',
        'certificate_conflicts': 'conflicts',
        'certificate_duplicates': 'duplicates',
        'missing_certificate': 'missing',
    }

    def __getitem__(self, key):
        key = self._aliases.get(key, key)
        return super(SignerCertificateReport, self).__getitem__(key)

    def get(self, key, default=None):
        key = self._aliases.get(key, key)
        return super(SignerCertificateReport, self).get(key, default)

    def __contains__(self, key):
        key = self._aliases.get(key, key)
        return super(SignerCertificateReport, self).__contains__(key)

    @property
    def outer(self):
        return self['outer']

    @property
    def nested(self):
        return self['nested']

    @property
    def signers(self):
        return self['signers']

    @property
    def duplicates(self):
        return self['duplicates']

    @property
    def conflicts(self):
        return self['conflicts']


def _coerce_signed_data(value):
    """
    Accepts a SignedData, a ContentInfo wrapping SignedData, or a DER byte
    string of either.
    """

    if isinstance(value, SignedData):
        return value

    if isinstance(value, ContentInfo):
        if value['content_type'].native != 'signed_data':
            raise TypeError('ContentInfo does not contain SignedData')
        content = value['content']
        if isinstance(content, SignedData):
            return content
        return SignedData.load(content.dump())

    if isinstance(value, (bytes, bytearray)):
        encoded = bytes(value)
        try:
            loaded = ContentInfo.load(encoded)
            if loaded['content_type'].native == 'signed_data':
                content = loaded['content']
                if isinstance(content, SignedData):
                    return content
                return SignedData.load(content.dump())
        except (ValueError, TypeError):
            pass

        try:
            parsed = parse(encoded)
            if parsed[0] == 2 and parsed[2] == 0:
                return SignedData.load(parsed[4])
        except (ValueError, TypeError):
            pass

        return SignedData.load(encoded)

    if hasattr(value, 'chosen'):
        chosen = value.chosen
        if isinstance(chosen, SignedData):
            return chosen

    raise TypeError('value must be a SignedData, ContentInfo or DER byte string')


def _as_certificate(value):
    """
    Returns an x509.Certificate from a Certificate or CertificateChoices, or
    None when the choice is not an X.509 certificate.
    """

    if isinstance(value, Certificate):
        return value

    if isinstance(value, CertificateChoices):
        if value.name != 'certificate':
            return None
        return value.chosen

    if hasattr(value, 'name') and hasattr(value, 'chosen'):
        if value.name != 'certificate':
            return None
        chosen = value.chosen
        if isinstance(chosen, Certificate):
            return chosen

    return None


def _is_certificate_collection(value):
    return isinstance(value, (CertificateSet, list, tuple, set))


def _certificate_entry(value, index):
    """
    Builds an internal certificate entry with the identifier material needed
    for later matching and conflict detection.
    """

    certificate = _as_certificate(value)
    if certificate is None:
        return None

    try:
        certificate_der = certificate.dump()
    except (ValueError, TypeError):
        return None

    try:
        issuer_serial = certificate.issuer_serial
    except (ValueError, TypeError):
        issuer_serial = None

    try:
        subject_key_identifier = certificate.key_identifier
    except (ValueError, TypeError):
        subject_key_identifier = None

    return {
        'certificate': certificate,
        'certificate_der': certificate_der,
        'certificate_sha256': certificate.sha256,
        'certificate_index': index,
        'issuer_serial': issuer_serial,
        'subject_key_identifier': subject_key_identifier,
        'duplicate_count': 1,
        'duplicate_occurrences': [],
        'issuer_serial_conflict': False,
        'subject_key_identifier_conflict': False,
    }


def _certificate_entries(certificates):
    """
    Normalizes a certificate collection into internal certificate entries.
    """

    if certificates is None:
        return []

    if isinstance(certificates, (Certificate, CertificateChoices)):
        certificates = [certificates]

    entries = []
    for index, value in enumerate(certificates):
        entry = _certificate_entry(value, index)
        if entry is not None:
            entries.append(entry)
    return entries


def _signer_matches_issuer_serial(signer_info, entry):
    sid = signer_info['sid']
    if sid.name != 'issuer_and_serial_number':
        return False

    try:
        chosen = sid.chosen
        certificate = entry['certificate']
        return (
            certificate.issuer == chosen['issuer'] and
            certificate.serial_number == chosen['serial_number'].native
        )
    except (ValueError, TypeError, KeyError):
        return False


def _signer_matches_subject_key_identifier(signer_info, entry):
    sid = signer_info['sid']
    if sid.name != 'subject_key_identifier':
        return False

    try:
        certificate_key_identifier = entry['certificate'].key_identifier
        if certificate_key_identifier is None:
            return False
        return certificate_key_identifier == sid.chosen.native
    except (ValueError, TypeError, KeyError):
        return False


def _signer_matches_certificate_entry(signer_info, entry):
    return (
        _signer_matches_issuer_serial(signer_info, entry) or
        _signer_matches_subject_key_identifier(signer_info, entry)
    )


def _certificate_occurrence(entry):
    return {
        'layer': entry.get('layer'),
        'layer_id': entry.get('layer_id'),
        'depth': entry.get('depth'),
        'layer_path': list(entry.get('layer_path', [])),
        'certificate_index': entry['certificate_index'],
        'certificate_sha256': entry['certificate_sha256'],
    }


def _mark_duplicate_certificates(layers):
    by_der = OrderedDict()
    for layer in layers:
        for entry in layer['certificates']:
            by_der.setdefault(entry['certificate_der'], []).append(entry)

    duplicates = []
    for entries in by_der.values():
        if len(entries) < 2:
            continue

        occurrences = [_certificate_occurrence(entry) for entry in entries]
        for entry in entries:
            entry['duplicate_count'] = len(entries)
            entry['duplicate_occurrences'] = occurrences
            entry['duplicate_in_layer'] = (
                len(set([occ['layer_id'] for occ in occurrences])) < len(occurrences)
            )

        duplicates.append({
            'certificate_sha256': entries[0]['certificate_sha256'],
            'count': len(entries),
            'occurrences': occurrences,
        })

    return duplicates


def _mark_certificate_conflicts(layers):
    conflicts = []
    by_issuer_serial = OrderedDict()
    by_subject_key_identifier = OrderedDict()

    for layer in layers:
        for entry in layer['certificates']:
            if entry['issuer_serial'] is not None:
                by_issuer_serial.setdefault(entry['issuer_serial'], []).append(entry)
            if entry['subject_key_identifier'] is not None:
                by_subject_key_identifier.setdefault(
                    entry['subject_key_identifier'],
                    []
                ).append(entry)

    groups = [
        ('issuer_and_serial_number', by_issuer_serial, 'issuer_serial'),
        ('subject_key_identifier', by_subject_key_identifier, 'subject_key_identifier'),
    ]

    for identifier_type, by_identifier, entry_flag in groups:
        for identifier, entries in by_identifier.items():
            distinct_ders = set([entry['certificate_der'] for entry in entries])
            if len(distinct_ders) < 2:
                continue

            for entry in entries:
                entry[entry_flag + '_conflict'] = True

            conflict = {
                'identifier_type': identifier_type,
                'occurrences': [_certificate_occurrence(entry) for entry in entries],
                'certificate_count': len(entries),
                'distinct_certificate_count': len(distinct_ders),
            }
            if identifier_type == 'issuer_and_serial_number':
                first = entries[0]
                conflict['issuer_serial'] = first['issuer_serial']
            else:
                conflict['subject_key_identifier'] = identifier
            conflicts.append(conflict)

    return conflicts


def _candidate_record(signer_info, signer_index, entry, layer, status, state):
    sid = signer_info['sid']
    matches = []
    if _signer_matches_issuer_serial(signer_info, entry):
        matches.append('issuer_and_serial_number')
    if _signer_matches_subject_key_identifier(signer_info, entry):
        matches.append('subject_key_identifier')

    return {
        'layer': layer['layer'],
        'layer_id': layer['layer_id'],
        'depth': layer['depth'],
        'layer_path': list(layer['layer_path']),
        'signer_index': signer_index,
        'signer_info_index': signer_index,
        'signer_info': signer_info,
        'sid_type': sid.name,
        'sid': sid.native,
        'match': sid.name,
        'match_type': sid.name,
        'matches': matches,
        'issuer_and_serial_number_match': 'issuer_and_serial_number' in matches,
        'subject_key_identifier_match': 'subject_key_identifier' in matches,
        'issuer_serial_match': 'issuer_and_serial_number' in matches,
        'certificate': entry['certificate'],
        'certificate_index': entry['certificate_index'],
        'certificate_sha256': entry['certificate_sha256'],
        'certificate_der': entry['certificate_der'],
        'duplicate': entry['duplicate_count'] > 1,
        'duplicate_count': entry['duplicate_count'],
        'duplicate_occurrences': entry['duplicate_occurrences'],
        'conflict': (
            entry['issuer_serial_conflict'] or
            entry['subject_key_identifier_conflict']
        ),
        'status': status,
        'state': state,
    }


def _signer_record(layer, signer_index, signer_info):
    candidate_entries = [
        entry
        for entry in layer['certificates']
        if _signer_matches_certificate_entry(signer_info, entry)
    ]

    distinct_certificates = set([
        entry['certificate_der'] for entry in candidate_entries
    ])
    if len(candidate_entries) == 0:
        status = _CANDIDATE_STATUS_MISSING
        state = _CANDIDATE_STATE_MISSING
    elif len(distinct_certificates) > 1:
        status = _CANDIDATE_STATUS_CONFLICT
        state = _CANDIDATE_STATE_CONFLICT
    elif len(candidate_entries) > 1:
        status = _CANDIDATE_STATUS_DUPLICATE
        state = _CANDIDATE_STATE_DUPLICATE
    else:
        status = _CANDIDATE_STATUS_OK
        state = _CANDIDATE_STATE_MATCHED

    candidates = []
    for entry in candidate_entries:
        candidate_status = _CANDIDATE_STATUS_OK
        candidate_state = _CANDIDATE_STATE_MATCHED
        if len(distinct_certificates) > 1:
            candidate_status = _CANDIDATE_STATUS_CONFLICT
            candidate_state = _CANDIDATE_STATE_CONFLICT
        elif entry['duplicate_count'] > 1:
            candidate_status = _CANDIDATE_STATUS_DUPLICATE
            candidate_state = _CANDIDATE_STATE_DUPLICATE

        candidates.append(_candidate_record(
            signer_info,
            signer_index,
            entry,
            layer,
            candidate_status,
            candidate_state
        ))

    sid = signer_info['sid']
    return {
        'layer': layer['layer'],
        'layer_id': layer['layer_id'],
        'depth': layer['depth'],
        'layer_path': list(layer['layer_path']),
        'signer_index': signer_index,
        'signer_info_index': signer_index,
        'signer_info': signer_info,
        'declaration': 'signer_infos[%d]' % signer_index,
        'signer_id': '%s/signer_infos[%d]' % (layer['layer_id'], signer_index),
        'sid_type': sid.name,
        'sid': sid.native,
        'status': status,
        'state': state,
        'missing_certificate': state == _CANDIDATE_STATE_MISSING,
        'conflict': state == _CANDIDATE_STATE_CONFLICT,
        'duplicate': state == _CANDIDATE_STATE_DUPLICATE,
        'candidate_count': len(candidates),
        'unique_candidate_count': len(distinct_certificates),
        'candidates': candidates,
        'certificates': [candidate['certificate'] for candidate in candidates],
    }


def _collect_layers(signed_data, layer, layer_id, depth, layer_path, parent=None):
    certificates = []
    certificate_set = signed_data['certificates']
    if certificate_set is not None:
        for index, value in enumerate(certificate_set):
            entry = _certificate_entry(value, index)
            if entry is None:
                continue
            entry['layer'] = layer
            entry['layer_id'] = layer_id
            entry['depth'] = depth
            entry['layer_path'] = list(layer_path)
            certificates.append(entry)

    layer_record = {
        'layer': layer,
        'layer_id': layer_id,
        'depth': depth,
        'layer_path': list(layer_path),
        'parent': parent,
        'signed_data': signed_data,
        'certificates': certificates,
    }
    layers = [layer_record]

    for signer_index, signer_info in enumerate(signed_data['signer_infos']):
        unsigned_attrs = signer_info['unsigned_attrs']
        if unsigned_attrs is None:
            continue

        for attribute_index, attribute in enumerate(unsigned_attrs):
            if attribute['type'].native != 'microsoft_nested_signature':
                continue

            for value_index, content_info in enumerate(attribute['values']):
                try:
                    if content_info['content_type'].native != 'signed_data':
                        continue
                    nested_signed_data = content_info['content']
                except (ValueError, TypeError):
                    continue

                nested_path = list(layer_path) + [signer_index, value_index]
                nested_id = '%s/signer_infos[%d]/unsigned_attrs[%d]/microsoft_nested_signature[%d]' % (
                    layer_id,
                    signer_index,
                    attribute_index,
                    value_index
                )
                nested_parent = {
                    'layer_id': layer_id,
                    'signer_index': signer_index,
                    'attribute': 'microsoft_nested_signature',
                    'attribute_index': attribute_index,
                    'value_index': value_index,
                }
                layers.extend(_collect_layers(
                    nested_signed_data,
                    'nested',
                    nested_id,
                    depth + 1,
                    nested_path,
                    nested_parent
                ))

    return layers


def _build_certificate_candidate_report(signed_data):
    signed_data = _coerce_signed_data(signed_data)
    layers = _collect_layers(signed_data, 'outer', 'outer', 0, [])
    duplicates = _mark_duplicate_certificates(layers)
    conflicts = _mark_certificate_conflicts(layers)

    signer_records = []
    for layer in layers:
        layer['signers'] = []
        for signer_index, signer_info in enumerate(layer['signed_data']['signer_infos']):
            record = _signer_record(layer, signer_index, signer_info)
            layer['signers'].append(record)
            signer_records.append(record)

    report = SignerCertificateReport()
    report['outer'] = [
        record for record in signer_records
        if record['layer'] == 'outer'
    ]
    report['nested'] = [
        record for record in signer_records
        if record['layer'] == 'nested'
    ]
    report['signers'] = signer_records
    report['layers'] = layers
    report['duplicates'] = duplicates
    report['conflicts'] = conflicts
    report['missing'] = [
        record for record in signer_records
        if record['state'] == _CANDIDATE_STATE_MISSING
    ]
    report['missing_certificate'] = report['missing']
    return report


def signer_certificate_candidates(value):
    """
    Resolves certificate candidates for a SignedData, ContentInfo or DER byte
    string.

    :param value:
        A SignedData, ContentInfo containing SignedData, or DER byte string of
        either

    :return:
        A SignerCertificateReport with outer and nested signer evidence kept
        in separate lists
    """

    return _build_certificate_candidate_report(value)


def get_signer_certificate_candidates(value):
    """
    Alias for signer_certificate_candidates().
    """

    return signer_certificate_candidates(value)


def get_signer_certificates(value):
    """
    Alias for signer_certificate_candidates().
    """

    return signer_certificate_candidates(value)


def collect_signer_certificate_candidates(value):
    """
    Alias for signer_certificate_candidates().
    """

    return signer_certificate_candidates(value)


def collect_signer_certificates(value):
    """
    Alias for signer_certificate_candidates().
    """

    return signer_certificate_candidates(value)


def find_signer_certificate_candidates(value):
    """
    Alias for signer_certificate_candidates().
    """

    return signer_certificate_candidates(value)


def find_signer_certificates(value):
    """
    Alias for signer_certificate_candidates().
    """

    return signer_certificate_candidates(value)


def resolve_signer_certificates(value):
    """
    Alias for signer_certificate_candidates().
    """

    return signer_certificate_candidates(value)


def certificate_candidate_report(value):
    """
    Alias for signer_certificate_candidates().
    """

    return signer_certificate_candidates(value)


def get_certificate_candidates(value):
    """
    Alias for signer_certificate_candidates().
    """

    return signer_certificate_candidates(value)
