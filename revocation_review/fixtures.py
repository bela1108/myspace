from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from asn1crypto import cms, crl, pdf, x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# Deterministic seeds keep the generated DER fixtures byte-reproducible. These
# keys are test material for a local offline model, never for production use.
ISSUER_SEED = bytes(range(0x10, 0x30))
SEAL_SEED = bytes(range(0x40, 0x60))

ISSUER_NAME = {
    'country_name': 'CN',
    'organization_name': 'Offline Evidence Lab',
    'common_name': 'Offline Archive Issuer',
}
SEAL_NAME = {
    'country_name': 'CN',
    'organization_name': 'Offline Evidence Lab',
    'common_name': 'Offline Archive Seal',
}

RECEIPT_OID = '1.3.6.1.4.1.55555.1'
TARGET_SERIAL = 0x5A17C0DE
TAMPERED_SERIAL = 0xDEADBEEF
REVOCATION_DATE = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)
THIS_UPDATE = datetime(2026, 11, 20, 0, 0, 0, tzinfo=timezone.utc)
NEXT_UPDATE = datetime(2027, 11, 20, 0, 0, 0, tzinfo=timezone.utc)
ARCHIVE_PAYLOAD = b'offline archive payload: REV-001'


CITATIONS: Dict[str, Dict[str, Any]] = {
    'CIT-PDF-ARCH': {
        'path': 'asn1crypto/pdf.py',
        'line_start': 31,
        'line_end': 34,
        'snippets': ['class AdobeArchiveRevInfo(Sequence)', "('version', Integer)"],
        'claim': 'AdobeArchiveRevInfo carries only a version; it does not carry attachment bytes.',
    },
    'CIT-PDF-RIA': {
        'path': 'asn1crypto/pdf.py',
        'line_start': 64,
        'line_end': 69,
        'snippets': [
            'class RevocationInfoArchival(Sequence)',
            "('crl', SequenceOfCertificateList",
            "('ocsp', SequenceOfOCSPResponse",
            "('other_rev_info', SequenceOfOtherRevInfo",
        ],
        'claim': 'The archival revocation attribute has distinct crl, ocsp and other_rev_info branches.',
    },
    'CIT-PDF-OID': {
        'path': 'asn1crypto/pdf.py',
        'line_start': 82,
        'line_end': 84,
        'snippets': ['pdf_signing', 'adobe_revocation_info_archival', 'CMSAttribute._oid_specs'],
        'claim': 'The CMS attribute OID is mapped to SetOfRevocationInfoArchival.',
    },
    'CIT-PDF-DOC': {
        'path': 'asn1crypto/pdf.py',
        'line_start': 3,
        'line_end': 6,
        'snippets': ['ASN.1 type classes for PDF signature structures', 'CMSAttribute'],
        'claim': 'pdf.py is an ASN.1 type module, not a PDF byte-range parser.',
    },
    'CIT-CMS-SIGNER': {
        'path': 'asn1crypto/cms.py',
        'line_start': 605,
        'line_end': 614,
        'snippets': ['class SignerInfo(Sequence)', "('signed_attrs', CMSAttributes", "('signature', OctetString)"],
        'claim': 'SignerInfo separates signed attributes from the signature value.',
    },
    'CIT-CMS-SIGNEDDATA': {
        'path': 'asn1crypto/cms.py',
        'line_start': 621,
        'line_end': 629,
        'snippets': ['class SignedData(Sequence)', "('crls', RevocationInfoChoices", "('signer_infos', SignerInfos)"],
        'claim': 'SignedData keeps top-level CRLs and signer infos as separate fields.',
    },
    'CIT-CRL-LIST': {
        'path': 'asn1crypto/crl.py',
        'line_start': 286,
        'line_end': 291,
        'snippets': ['class CertificateList(Sequence)', "('tbs_cert_list', TbsCertList)", "('signature', OctetBitString)"],
        'claim': 'CertificateList separates the signed TBS bytes from algorithm and signature fields.',
    },
    'CIT-TSP-ATS': {
        'path': 'asn1crypto/tsp.py',
        'line_start': 202,
        'line_end': 212,
        'snippets': ['class ArchiveTimeStamp(Sequence)', "('time_stamp', ContentInfo)", 'class ArchiveTimeStampSequence(SequenceOf)'],
        'claim': 'Archive timestamp structures can chain preservation statements, but do not verify revocation status.',
    },
    'CIT-README-PARSE': {
        'path': 'readme.md',
        'line_start': 1,
        'line_end': 4,
        'snippets': ['parsing and serializing ASN.1 structures'],
        'claim': 'The package describes itself as a parser/serializer.',
    },
    'CIT-README-SIG': {
        'path': 'readme.md',
        'line_start': 90,
        'line_end': 95,
        'snippets': ['signatures are really byte strings', 'BitString'],
        'claim': 'Signatures are represented as byte strings; the package does not authenticate them.',
    },
}


ARCHIVE_ENTRIES: List[Dict[str, str]] = [
    {
        'id': 'IDX-001',
        'kind': 'archive',
        'claim': '外层 CMS 回执声明了一份吊销信息归档对象，并以 other_rev_info 摘要承诺其字节。',
        'baseline_tier': 'T1',
        'baseline_basis': '外层回执 SIG-OUTER；摘要本身不提供附件字节。',
    },
    {
        'id': 'REV-001',
        'kind': 'archive',
        'claim': '证书序列号 0x5A17C0DE 于 2026-11-18 12:00 UTC 被撤销，原因 key_compromise。',
        'baseline_tier': 'T1',
        'baseline_basis': '仅外层回执与目录索引；尚未读取实际 CRL 字节，也没有发行者验签。',
    },
    {
        'id': 'REV-002',
        'kind': 'archive',
        'claim': '归档政策要求在 2027-11-20 前重新封存同一条记录。',
        'baseline_tier': 'T1',
        'baseline_basis': '政策通知依据；不在本次 CRL 的 tbs_cert_list 签名覆盖范围。',
    },
]


CODE_ENTRIES: List[Dict[str, str]] = [
    {
        'id': 'CODE-001',
        'kind': 'code',
        'claim': 'AdobeArchiveRevInfo 只保存 version；实际附件类型由 RevocationInfoArchival 的 crl/ocsp/other_rev_info 分支承担。',
        'baseline_tier': 'S1',
        'baseline_basis': 'CIT-PDF-ARCH, CIT-PDF-RIA, CIT-PDF-OID',
    },
    {
        'id': 'CODE-002',
        'kind': 'code',
        'claim': 'CMS SignerInfo 将 signed_attrs 与 signature 分开；含 signed_attrs 的分支中，外层签名覆盖的是签名属性，而不是整个 ContentInfo。',
        'baseline_tier': 'S1',
        'baseline_basis': 'CIT-CMS-SIGNER, CIT-CMS-SIGNEDDATA',
    },
    {
        'id': 'CODE-003',
        'kind': 'code',
        'claim': 'CRL CertificateList 将 tbs_cert_list 与 signature_algorithm/signature 分开；内层签名只覆盖 TBS 字节。',
        'baseline_tier': 'S1',
        'baseline_basis': 'CIT-CRL-LIST',
    },
    {
        'id': 'CODE-004',
        'kind': 'code',
        'claim': 'ArchiveTimeStampSequence 可串联多份保全说明，但它本身不是撤销状态验签器。',
        'baseline_tier': 'S1',
        'baseline_basis': 'CIT-TSP-ATS',
    },
    {
        'id': 'CODE-005',
        'kind': 'code',
        'claim': 'asn1crypto 是解析/序列化库；签名在结构中表现为字节串，库内没有密码学 verify API。',
        'baseline_tier': 'S1',
        'baseline_basis': 'CIT-README-PARSE, CIT-README-SIG, ABS-NO-VERIFY',
    },
    {
        'id': 'CODE-006',
        'kind': 'code',
        'claim': 'asn1crypto/pdf.py 只提供 ASN.1 类型映射，不解析 PDF ByteRange，因此不能证明 PDF 文件级封存覆盖。',
        'baseline_tier': 'S1',
        'baseline_basis': 'CIT-PDF-DOC, ABS-NO-BYTERANGE',
    },
]

ALL_ENTRIES = [dict(item) for item in ARCHIVE_ENTRIES + CODE_ENTRIES]


def _private_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def key_id(public_raw: bytes) -> str:
    return 'KEY-' + hashlib.sha256(public_raw).hexdigest()[:16].upper()


def public_key_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def build_crl(issuer_key: Ed25519PrivateKey, serial: int = TARGET_SERIAL) -> crl.CertificateList:
    entry = crl.RevokedCertificate({
        'user_certificate': serial,
        'revocation_date': x509.Time({'utc_time': REVOCATION_DATE}),
        'crl_entry_extensions': [
            crl.CRLEntryExtension({
                'extn_id': 'crl_reason',
                'extn_value': crl.CRLReason('key_compromise'),
            }),
            crl.CRLEntryExtension({
                'extn_id': 'invalidity_date',
                'extn_value': crl.GeneralizedTime(REVOCATION_DATE),
            }),
        ],
    })
    tbs = crl.TbsCertList({
        'version': 'v2',
        'signature': {'algorithm': 'ed25519'},
        'issuer': x509.Name.build(ISSUER_NAME),
        'this_update': x509.Time({'utc_time': THIS_UPDATE}),
        'next_update': x509.Time({'utc_time': NEXT_UPDATE}),
        'revoked_certificates': [entry],
        'crl_extensions': [
            crl.TBSCertListExtension({
                'extn_id': 'crl_number',
                'critical': False,
                'extn_value': crl.Integer(7),
            }),
        ],
    })
    return crl.CertificateList({
        'tbs_cert_list': tbs,
        'signature_algorithm': {'algorithm': 'ed25519'},
        'signature': issuer_key.sign(tbs.dump()),
    })


def _archive_payload_digest() -> bytes:
    return hashlib.sha256(ARCHIVE_PAYLOAD).digest()


def build_outer_archive(
    seal_key: Ed25519PrivateKey,
    receipt_digest: bytes,
    crl_object: Optional[crl.CertificateList] = None,
) -> bytes:
    ria_fields: Dict[str, Any] = {
        'other_rev_info': [
            {'type': RECEIPT_OID, 'value': receipt_digest},
        ],
    }
    if crl_object is not None:
        ria_fields['crl'] = [crl_object]

    archival = pdf.RevocationInfoArchival(ria_fields)
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            'type': 'content_type',
            'values': [cms.ContentType('data')],
        }),
        cms.CMSAttribute({
            'type': 'message_digest',
            'values': [_archive_payload_digest()],
        }),
        cms.CMSAttribute({
            'type': 'adobe_revocation_info_archival',
            'values': [archival],
        }),
    ])

    signed_attrs_bytes = signed_attrs.untag().dump()
    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier((
            'issuer_and_serial_number',
            cms.IssuerAndSerialNumber({
                'issuer': x509.Name.build(SEAL_NAME),
                'serial_number': 1,
            }),
        )),
        'digest_algorithm': {'algorithm': 'sha256'},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'ed25519'},
        'signature': seal_key.sign(signed_attrs_bytes),
    })
    signed_data = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': 'sha256'}],
        'encap_content_info': {
            'content_type': 'data',
            'content': ARCHIVE_PAYLOAD,
        },
        'signer_infos': [signer_info],
    })
    return cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    }).dump()


def _entry_template() -> List[Dict[str, str]]:
    return [dict(item) for item in ALL_ENTRIES]


def _manifest(case: str, archive: str, issuer_key: Optional[str], attachment_refs: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        'case': case,
        'title': case,
        'archive': archive,
        'seal_key': 'seal-public.pem',
        'issuer_key': issuer_key,
        'attachment_refs': attachment_refs,
        'issuance_scope': ['REV-001'],
        'entries': _entry_template(),
        'citations': CITATIONS,
    }


def build_fixtures(destination: Path) -> Dict[str, Any]:
    """Create deterministic keys, ASN.1 archives and scenario manifests."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)

    issuer_key = _private_key(ISSUER_SEED)
    seal_key = _private_key(SEAL_SEED)
    issuer_public = _public_raw(issuer_key)
    seal_public = _public_raw(seal_key)

    (destination / 'issuer-public.pem').write_bytes(public_key_pem(issuer_key))
    (destination / 'seal-public.pem').write_bytes(public_key_pem(seal_key))

    valid_crl = build_crl(issuer_key, TARGET_SERIAL)
    valid_crl_bytes = valid_crl.dump()
    receipt_digest = hashlib.sha256(valid_crl_bytes).digest()

    # Outer seal around the real CRL attachment.
    (destination / 'archive-with-crl.der').write_bytes(
        build_outer_archive(seal_key, receipt_digest, valid_crl)
    )

    # Outer receipt that only commits to a digest; the attachment is absent.
    (destination / 'archive-outer-only.der').write_bytes(
        build_outer_archive(seal_key, receipt_digest, None)
    )

    # A CRL whose TBS was changed after the issuer signature was produced. The
    # outer seal signs the altered bytes, so an outer-only review would miss it.
    tampered_crl = build_crl(issuer_key, TAMPERED_SERIAL)
    tampered_crl = crl.CertificateList({
        'tbs_cert_list': tampered_crl['tbs_cert_list'],
        'signature_algorithm': {'algorithm': 'ed25519'},
        'signature': valid_crl['signature'].native,
    })
    (destination / 'archive-tampered-crl.der').write_bytes(
        build_outer_archive(seal_key, receipt_digest, tampered_crl)
    )

    # Keep a copy of the actual CRL for external-attachment experiments.
    (destination / 'revocation.crl.der').write_bytes(valid_crl_bytes)

    manifests = {
        'outer-only': _manifest('outer-only', 'archive-outer-only.der', None, []),
        'missing-attachment': _manifest(
            'missing-attachment',
            'archive-outer-only.der',
            None,
            [{
                'id': 'ATT-REV-001',
                'kind': 'crl',
                'path': 'attachments/revocation.crl.der',
                'sha256': receipt_digest.hex(),
            }],
        ),
        'attachment-unverified': _manifest(
            'attachment-unverified', 'archive-with-crl.der', None, []
        ),
        'issuance-verified': _manifest(
            'issuance-verified', 'archive-with-crl.der', 'issuer-public.pem', []
        ),
        'tampered-attachment': _manifest(
            'tampered-attachment', 'archive-tampered-crl.der', 'issuer-public.pem', []
        ),
    }
    for name, manifest in manifests.items():
        (destination / ('manifest-%s.json' % name)).write_text(
            json.dumps(manifest, indent=2, sort_keys=False) + '\n',
            encoding='utf-8',
        )

    return {
        'destination': str(destination),
        'issuer_key_id': key_id(issuer_public),
        'seal_key_id': key_id(seal_public),
        'issuer_public_sha256': hashlib.sha256(issuer_public).hexdigest(),
        'seal_public_sha256': hashlib.sha256(seal_public).hexdigest(),
        'crl_sha256': hashlib.sha256(valid_crl_bytes).hexdigest(),
        'crl_size': len(valid_crl_bytes),
        'receipt_digest': receipt_digest.hex(),
        'manifests': {
            name: str(destination / ('manifest-%s.json' % name))
            for name in manifests
        },
    }
