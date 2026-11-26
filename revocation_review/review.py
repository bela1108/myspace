from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from asn1crypto import __version__ as ASN1CRYPTO_VERSION
from asn1crypto import cms, crl, pdf
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .fixtures import build_fixtures


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURES = Path(__file__).resolve().parent / 'fixtures'
DEFAULT_OUT = Path(__file__).resolve().parent / 'out'

SCENARIO_ORDER = [
    'outer-only',
    'missing-attachment',
    'attachment-unverified',
    'tampered-attachment',
    'issuance-verified',
]

TIERS = {
    'T0': '无有效字节：没有可用外层回执，也没有附件字节。',
    'T1': '外层回执：外层签名/回执有效，但没有实际对象字节；只能证明曾提交过某个摘要承诺。',
    'T2': '附件字节：实际对象字节存在，且与回执摘要一致；外层封存覆盖这些字节，但尚未完成原发行验签。',
    'T3': '原发行证明：对象字节存在，并由独立发行者密钥验证了对象自身签名。',
    'S1': '源码引用：命题关于代码结构，引用行已离线核对；不改写也不升级归档层级。',
    'S0': '源码引用失配：引用的文件或行片段无法核对。',
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _der_header_len(tlv: bytes) -> int:
    if len(tlv) < 2:
        raise ValueError('truncated DER value')
    first_length = tlv[1]
    if first_length < 0x80:
        return 2
    count = first_length & 0x7F
    if count == 0:
        raise ValueError('indefinite-length DER is not supported by this review model')
    return 2 + count


def _der_content(tlv: bytes) -> bytes:
    header_len = _der_header_len(tlv)
    return tlv[header_len:]


def _find_unique(data: bytes, needle: bytes, label: str) -> Tuple[int, int]:
    if not needle:
        raise ValueError('%s: empty needle' % label)
    first = data.find(needle)
    if first < 0:
        raise ValueError('%s: byte sequence not found in archive' % label)
    second = data.find(needle, first + 1)
    if second >= 0:
        raise ValueError('%s: byte sequence occurs more than once' % label)
    return first, first + len(needle)


def _load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError('expected an Ed25519 public key: %s' % path)
    return key


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return 'KEY-' + hashlib.sha256(raw).hexdigest()[:16].upper()


def key_fingerprint(public_key: Ed25519PublicKey) -> str:
    return sha256(public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ))


def verify_signature(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> Tuple[bool, Optional[str]]:
    try:
        public_key.verify(signature, data)
        return True, None
    except Exception as exc:
        return False, '%s: %s' % (type(exc).__name__, exc)


def audit_citations(citations: Dict[str, Dict[str, Any]], repo_root: Path = REPO_ROOT) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    for citation_id, citation in citations.items():
        path = repo_root / citation['path']
        start = int(citation['line_start'])
        end = int(citation['line_end'])
        result: Dict[str, Any] = {
            'id': citation_id,
            'path': citation['path'],
            'line_start': start,
            'line_end': end,
            'claim': citation.get('claim', ''),
            'status': 'OK',
            'missing_snippets': [],
        }
        if not path.is_file():
            result['status'] = 'MISSING_FILE'
            result['missing_snippets'] = list(citation.get('snippets', []))
            results[citation_id] = result
            continue
        all_lines = path.read_text(encoding='utf-8').splitlines()
        if start < 1 or end < start or end > len(all_lines):
            result['status'] = 'BAD_RANGE'
            result['missing_snippets'] = list(citation.get('snippets', []))
            results[citation_id] = result
            continue
        selected = '\n'.join(all_lines[start - 1:end])
        missing = [snippet for snippet in citation.get('snippets', []) if snippet not in selected]
        if missing:
            result['status'] = 'MISMATCH'
            result['missing_snippets'] = missing
        results[citation_id] = result
    return results


ABSENCE_CHECKS = [
    {
        'id': 'ABS-NO-VERIFY',
        'description': 'asn1crypto 内没有签名验证 API（只搜索 def verify/check_signature）',
        'pattern': r'def (?:verify|verify_signature|check_signature)\b',
        'root': 'asn1crypto',
    },
    {
        'id': 'ABS-NO-BYTERANGE',
        'description': 'asn1crypto 内没有 PDF ByteRange 解析代码',
        'pattern': r'ByteRange',
        'root': 'asn1crypto',
    },
]


def audit_absences(repo_root: Path = REPO_ROOT) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    for check in ABSENCE_CHECKS:
        root = repo_root / check['root']
        matches: List[Dict[str, Any]] = []
        if root.is_dir():
            pattern = re.compile(check['pattern'])
            for path in sorted(root.rglob('*.py')):
                for line_number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                    if pattern.search(line):
                        matches.append({
                            'path': str(path.relative_to(repo_root)),
                            'line': line_number,
                            'text': line.strip(),
                        })
        results[check['id']] = {
            'id': check['id'],
            'description': check['description'],
            'pattern': check['pattern'],
            'status': 'OK' if not matches else 'FOUND',
            'matches': matches,
        }
    return results


def _signature_algorithm(obj: Any, field: str) -> Optional[str]:
    try:
        return obj[field]['algorithm'].native
    except Exception:
        return None


def _archival_value(signed_attrs: cms.CMSAttributes) -> Tuple[Optional[Any], Optional[cms.CMSAttribute]]:
    for attr in signed_attrs:
        if attr['type'].native == 'adobe_revocation_info_archival':
            return attr['values'][0], attr
    return None, None


def _message_digest(signed_attrs: cms.CMSAttributes) -> Optional[bytes]:
    for attr in signed_attrs:
        if attr['type'].native == 'message_digest':
            return attr['values'][0].native
    return None


def _attachment_refs(manifest: Dict[str, Any], fixtures_dir: Path) -> List[Dict[str, Any]]:
    result = []
    for ref in manifest.get('attachment_refs') or []:
        path = fixtures_dir / ref['path']
        exists = path.is_file()
        record = {
            'id': ref.get('id'),
            'kind': ref.get('kind'),
            'path': ref.get('path'),
            'expected_sha256': ref.get('sha256'),
            'exists': exists,
            'sha256': None,
            'size': None,
        }
        if exists:
            data = path.read_bytes()
            record['sha256'] = sha256(data)
            record['size'] = len(data)
        result.append(record)
    return result


def _coverage_object(
    object_id: str,
    label: str,
    logical_bytes: bytes,
    archive_span: Optional[Tuple[int, int]],
    outer_direct: bool,
    inner_direct: bool,
    note: str,
    outer_digest: bool = False,
) -> Dict[str, Any]:
    return {
        'id': object_id,
        'label': label,
        'sha256': sha256(logical_bytes),
        'length': len(logical_bytes),
        'archive_span': list(archive_span) if archive_span else None,
        'outer_direct': outer_direct,
        'outer_digest': outer_digest,
        'inner_direct': inner_direct,
        'note': note,
    }


def _scope_tier(
    outer_status: str,
    attachment: Dict[str, Any],
    inner: Dict[str, Any],
) -> Tuple[str, str]:
    outer_valid = outer_status == 'VALID'
    present = bool(attachment.get('present'))
    digest_match = attachment.get('digest_match')
    inner_valid = inner.get('status') == 'VALID'

    if outer_valid and present and digest_match and inner_valid:
        return 'T3', 'SIG-INNER（发行者密钥）+ SIG-OUTER + 附件摘要一致；字段读取自已验签的 tbs_cert_list。'
    if outer_valid and present and digest_match:
        reason = inner.get('status')
        if reason == 'MISSING_KEY':
            detail = '发行者公钥缺失，未做原发行验签。'
        elif reason == 'INVALID':
            detail = '原发行验签失败，不能提升到 T3。'
        elif reason == 'UNSUPPORTED':
            detail = '本审阅器未实现该发行签名算法。'
        else:
            detail = '尚未执行原发行验签。'
        return 'T2', 'SIG-OUTER + 实际附件字节且摘要一致；' + detail
    if outer_valid:
        state = attachment.get('state')
        if state == 'outer_receipt_only':
            detail = '只有外层回执，没有附件字节。'
        elif state == 'missing':
            detail = '声明的附件路径缺失；不能把外层回执等同于附件。'
        elif digest_match is False:
            detail = '外层封存有效，但附件摘要与外层承诺不一致。'
        else:
            detail = '没有可由本审阅器确认的附件字节。'
        return 'T1', 'SIG-OUTER 有效；' + detail
    return 'T0', '外层回执无效或缺失，且没有独立可验的附件字节。'


def analyze_manifest(manifest_path: Path, repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    fixtures_dir = manifest_path.parent
    archive_name = manifest['archive']
    archive_path = fixtures_dir / archive_name
    archive_bytes = archive_path.read_bytes()

    content_info = cms.ContentInfo.load(archive_bytes)
    if content_info['content_type'].native != 'signed_data':
        raise ValueError('archive is not CMS SignedData')
    signed_data = content_info['content']
    signer_info = signed_data['signer_infos'][0]

    signed_attrs = signer_info['signed_attrs']
    signed_attrs_set_bytes = signed_attrs.untag().dump()
    signed_attrs_content = _der_content(signed_attrs_set_bytes)
    signed_content_span = _find_unique(archive_bytes, signed_attrs_content, 'signed_attrs content')
    header_len = _der_header_len(signed_attrs_set_bytes)
    attrs_archive_start = signed_content_span[0] - header_len
    if archive_bytes[attrs_archive_start] != 0xA0:
        raise ValueError('signed_attrs archive wrapper is not the expected [0] implicit tag')
    signed_attrs_archive_span = (attrs_archive_start, signed_content_span[1])

    outer_signature_bytes = signer_info['signature'].native
    outer_signature_span = _find_unique(archive_bytes, outer_signature_bytes, 'outer signature value')

    seal_key_path = fixtures_dir / manifest['seal_key']
    if seal_key_path.is_file():
        seal_key = _load_public_key(seal_key_path)
        seal_key_id = key_id(seal_key)
        seal_fingerprint = key_fingerprint(seal_key)
        outer_valid, outer_error = verify_signature(seal_key, outer_signature_bytes, signed_attrs_set_bytes)
    else:
        seal_key = None
        seal_key_id = None
        seal_fingerprint = None
        outer_valid, outer_error = False, 'seal public key missing'

    outer_algorithm = _signature_algorithm(signer_info, 'signature_algorithm')
    if outer_algorithm != 'ed25519':
        outer_status = 'UNSUPPORTED'
        outer_error = 'review model only verifies Ed25519 seals; found %r' % outer_algorithm
    else:
        outer_status = 'VALID' if outer_valid else 'INVALID'

    payload = signed_data['encap_content_info']['content'].native
    if not isinstance(payload, bytes):
        payload = b''
    payload_span = _find_unique(archive_bytes, payload, 'payload') if payload else None
    digest_value = _message_digest(signed_attrs)
    digest_match_payload = digest_value == hashlib.sha256(payload).digest() if digest_value is not None else None

    archival_value, archival_attr = _archival_value(signed_attrs)
    archival_span = None
    archival_sha = None
    if archival_value is not None:
        archival_bytes = archival_value.dump()
        archival_span = _find_unique(archive_bytes, archival_bytes, 'revocation info archival attribute')
        archival_sha = sha256(archival_bytes)
        if not (signed_attrs_archive_span[0] <= archival_span[0] and archival_span[1] <= signed_attrs_archive_span[1]):
            raise ValueError('archival attribute is not inside signed_attrs')

    embedded_crls: List[crl.CertificateList] = []
    if archival_value is not None and archival_value['crl'].native is not None:
        embedded_crls = [item for item in archival_value['crl']]

    receipt_digests: List[bytes] = []
    if archival_value is not None and archival_value['other_rev_info'].native is not None:
        receipt_digests = [item['value'].native for item in archival_value['other_rev_info']]
    expected_digest = receipt_digests[0] if receipt_digests else None

    refs = _attachment_refs(manifest, fixtures_dir)
    crl_object: Optional[crl.CertificateList] = None
    crl_bytes: Optional[bytes] = None
    attachment_source = 'none'
    attachment_state = 'outer_receipt_only'
    attachment_present = False
    attachment_digest_match: Optional[bool] = None

    if embedded_crls:
        crl_object = embedded_crls[0]
        crl_bytes = crl_object.dump()
        attachment_source = 'embedded'
        attachment_state = 'present'
        attachment_present = True
    else:
        existing_refs = [ref for ref in refs if ref['exists']]
        if existing_refs:
            external_path = fixtures_dir / existing_refs[0]['path']
            external_bytes = external_path.read_bytes()
            crl_object = crl.CertificateList.load(external_bytes)
            crl_bytes = external_bytes
            attachment_source = 'external'
            attachment_state = 'present'
            attachment_present = True
        elif refs:
            attachment_state = 'missing'
            attachment_present = False
        else:
            attachment_state = 'outer_receipt_only'
            attachment_present = False

    if attachment_present and expected_digest is not None:
        attachment_digest_match = sha256(crl_bytes) == expected_digest.hex()
    elif attachment_present:
        attachment_digest_match = None

    attachment = {
        'state': attachment_state,
        'source': attachment_source,
        'present': attachment_present,
        'declared_refs': refs,
        'sha256': sha256(crl_bytes) if crl_bytes is not None else None,
        'size': len(crl_bytes) if crl_bytes is not None else None,
        'expected_sha256': expected_digest.hex() if expected_digest is not None else None,
        'digest_match': attachment_digest_match,
    }

    inner: Dict[str, Any] = {
        'status': 'NOT_ATTEMPTED',
        'algorithm': None,
        'signed_object': 'CertificateList.tbs_cert_list',
        'signed_sha256': None,
        'signed_len': None,
        'archive_span': None,
        'signature_sha256': None,
        'signature_span': None,
        'key_id': None,
        'key_fingerprint': None,
        'error': None,
    }
    coverage_objects: List[Dict[str, Any]] = [
        _coverage_object(
            'outer_signed_attrs',
            'CMS SignedAttrs（逻辑 SET 编码；归档内为 [0] 隐式包装）',
            signed_attrs_set_bytes,
            signed_attrs_archive_span,
            True,
            False,
            '外层签名的直接输入；归档中的 0xA0 标签被还原为 SET(0x31) 后验签。',
        ),
        _coverage_object(
            'outer_signature_value',
            '外层 CMS signature OCTET STRING 内容',
            outer_signature_bytes,
            outer_signature_span,
            False,
            False,
            '签名值自身不被任一签名覆盖。',
        ),
        _coverage_object(
            'payload',
            'encap_content_info 内容',
            payload,
            payload_span,
            False,
            False,
            '外层签名不直接覆盖 payload；只通过 message_digest 间接绑定。',
            outer_digest=bool(digest_match_payload),
        ),
    ]

    if archival_value is not None:
        coverage_objects.append(_coverage_object(
            'archival_attribute',
            'adobe_revocation_info_archival 值',
            archival_value.dump(),
            archival_span,
            True,
            False,
            '位于 signed_attrs 内，因此外层签名直接覆盖其字节；内层 CRL 签名不覆盖。',
        ))

    if crl_object is not None and crl_bytes is not None:
        tbs = crl_object['tbs_cert_list']
        tbs_bytes = tbs.dump()
        tbs_span = _find_unique(archive_bytes, tbs_bytes, 'CRL tbs_cert_list')
        crl_span = _find_unique(archive_bytes, crl_bytes, 'CRL CertificateList')
        crl_signature_bytes = crl_object['signature'].native
        crl_signature_span = _find_unique(archive_bytes, crl_signature_bytes, 'CRL signature value')
        entries = tbs['revoked_certificates']
        entry_bytes = entries[0].dump() if entries.native is not None else None
        entry_span = _find_unique(archive_bytes, entry_bytes, 'first revoked certificate') if entry_bytes else None

        coverage_objects.extend([
            _coverage_object(
                'crl_certificate_list',
                '内层 CertificateList（完整 CRL，含自身签名字段）',
                crl_bytes,
                crl_span,
                True,
                False,
                '外层封存覆盖完整 CRL 字节，但不因此验证 CRL 签名。',
            ),
            _coverage_object(
                'crl_tbs_cert_list',
                'CRL tbs_cert_list（被发行者签名的字节）',
                tbs_bytes,
                tbs_span,
                True,
                True,
                '内层签名的直接输入；是完整 CRL 的真子集。',
            ),
            _coverage_object(
                'revoked_certificate_entry',
                'revoked_certificates[0]（第一条吊销记录）',
                entry_bytes or b'',
                entry_span,
                True,
                True,
                '吊销记录内容位于 tbs_cert_list 内，因此两层都覆盖其字节；但只有内层签名证明其发行来源。',
            ),
            _coverage_object(
                'crl_signature_value',
                'CRL signature BIT STRING 内容',
                crl_signature_bytes,
                crl_signature_span,
                True,
                False,
                '外层封存把它当作附件字节覆盖；内层签名本身不覆盖自己的签名值。',
            ),
        ])

        inner['algorithm'] = _signature_algorithm(crl_object, 'signature_algorithm')
        inner['signed_sha256'] = sha256(tbs_bytes)
        inner['signed_len'] = len(tbs_bytes)
        inner['archive_span'] = list(tbs_span)
        inner['signature_sha256'] = sha256(crl_signature_bytes)
        inner['signature_span'] = list(crl_signature_span)
        if inner['algorithm'] != 'ed25519':
            inner['status'] = 'UNSUPPORTED'
            inner['error'] = 'review model only verifies Ed25519 CRLs; found %r' % inner['algorithm']
        elif not manifest.get('issuer_key'):
            inner['status'] = 'MISSING_KEY'
            inner['error'] = 'no independent issuer public key was supplied'
        else:
            issuer_key_path = fixtures_dir / manifest['issuer_key']
            if not issuer_key_path.is_file():
                inner['status'] = 'MISSING_KEY'
                inner['error'] = 'issuer public key file missing: %s' % manifest['issuer_key']
            else:
                issuer_key = _load_public_key(issuer_key_path)
                inner['key_id'] = key_id(issuer_key)
                inner['key_fingerprint'] = key_fingerprint(issuer_key)
                valid, error = verify_signature(issuer_key, crl_signature_bytes, tbs_bytes)
                inner['status'] = 'VALID' if valid else 'INVALID'
                inner['error'] = error

    outer_basis = {
        'status': outer_status,
        'algorithm': outer_algorithm,
        'signed_object': 'CMS SignedAttrs (untagged SET OF)',
        'signed_sha256': sha256(signed_attrs_set_bytes),
        'signed_len': len(signed_attrs_set_bytes),
        'archive_span': list(signed_attrs_archive_span),
        'signature_sha256': sha256(outer_signature_bytes),
        'signature_span': list(outer_signature_span),
        'key_id': seal_key_id,
        'key_fingerprint': seal_fingerprint,
        'error': outer_error,
        'message_digest_expected': hashlib.sha256(payload).hexdigest(),
        'message_digest_attr': digest_value.hex() if digest_value is not None else None,
        'message_digest_match': digest_match_payload,
        'archival_attr_present': archival_attr is not None,
    }

    citation_results = audit_citations(manifest.get('citations', {}), repo_root)
    absence_results = audit_absences(repo_root)
    scope = set(manifest.get('issuance_scope') or [])
    entries: List[Dict[str, Any]] = []
    for entry in manifest['entries']:
        record = dict(entry)
        record['tier'] = record.pop('baseline_tier')
        record['basis'] = record.pop('baseline_basis')
        record['changed'] = False
        if record['kind'] == 'code':
            cited = [part.strip() for part in record['basis'].split(',') if part.strip().startswith('CIT-')]
            bad = [cid for cid in cited if citation_results.get(cid, {}).get('status') != 'OK']
            absence_ids = [part.strip() for part in record['basis'].split(',') if part.strip().startswith('ABS-')]
            bad_absence = [aid for aid in absence_ids if absence_results.get(aid, {}).get('status') != 'OK']
            if bad or bad_absence:
                record['tier'] = 'S0'
                detail = ', '.join(bad + bad_absence)
                record['basis'] = record['basis'] + '; 失配引用/缺席检查: ' + detail
            record['citation_ids'] = cited
            record['absence_ids'] = absence_ids
            record['citation_status'] = 'OK' if not (bad or bad_absence) else 'MISMATCH'
        elif record['id'] in scope:
            old_tier = record['tier']
            old_basis = record['basis']
            tier, basis = _scope_tier(outer_status, attachment, inner)
            record['tier_changed'] = tier != old_tier
            record['basis_changed'] = basis != old_basis
            record['changed'] = record['tier_changed']
            record['tier'] = tier
            record['basis'] = basis
        entries.append(record)

    changed_ids = [entry['id'] for entry in entries if entry['changed']]

    return {
        'case': manifest['case'],
        'manifest': manifest_path.name,
        'archive': {
            'name': archive_name,
            'size': len(archive_bytes),
            'sha256': sha256(archive_bytes),
        },
        'outer': outer_basis,
        'attachment': attachment,
        'inner': inner,
        'archival_present': archival_value is not None,
        'embedded_crl_count': len(embedded_crls),
        'coverage': coverage_objects,
        'entries': entries,
        'changed_ids': changed_ids,
        'citation_audit': citation_results,
        'absence_audit': absence_results,
    }


def analyze_corpus_crl(path: Path = REPO_ROOT / 'tests' / 'fixtures' / 'eid2011.crl') -> Dict[str, Any]:
    data = path.read_bytes()
    cert_list = crl.CertificateList.load(data)
    tbs = cert_list['tbs_cert_list']
    revoked = tbs['revoked_certificates']
    count = 0 if revoked.native is None else len(revoked)
    return {
        'path': str(path.relative_to(REPO_ROOT)),
        'size': len(data),
        'sha256': sha256(data),
        'issuer': tbs['issuer'].human_friendly,
        'this_update': tbs['this_update'].native.isoformat() if tbs['this_update'].native else None,
        'revoked_count': count,
        'signature_algorithm': _signature_algorithm(cert_list, 'signature_algorithm'),
        'tbs_sha256': sha256(tbs.dump()),
        'tbs_len': len(tbs.dump()),
        'signature_len': len(cert_list['signature'].native),
        'issuer_key_available': False,
        'status': 'MISSING_KEY',
        'note': '本仓库没有该 CRL 的发行者公钥/证书，只能核对结构与 TBS 字节边界，不能提升到 T3。',
    }


def build_ledger(analyses: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    cases: Dict[str, Any] = {}
    keys: Dict[str, Any] = {}
    for case, analysis in analyses.items():
        outer = analysis['outer']
        inner = analysis['inner']
        if outer.get('key_id'):
            keys[outer['key_id']] = {
                'role': 'outer_seal',
                'fingerprint_sha256': outer.get('key_fingerprint'),
                'source': 'seal-public.pem',
            }
        if inner.get('key_id'):
            keys[inner['key_id']] = {
                'role': 'issuer',
                'fingerprint_sha256': inner.get('key_fingerprint'),
                'source': 'issuer-public.pem',
            }
        cases[case] = {
            'manifest': analysis['manifest'],
            'archive': analysis['archive'],
            'signatures': [
                {
                    'id': 'SIG-OUTER',
                    'layer': 'outer_cms_seal',
                    'algorithm': outer['algorithm'],
                    'status': outer['status'],
                    'signed_object': outer['signed_object'],
                    'signed_sha256': outer['signed_sha256'],
                    'signed_len': outer['signed_len'],
                    'archive_span': outer['archive_span'],
                    'signature_sha256': outer['signature_sha256'],
                    'signature_span': outer['signature_span'],
                    'key_id': outer['key_id'],
                    'error': outer['error'],
                },
                {
                    'id': 'SIG-INNER',
                    'layer': 'issuer_crl',
                    'algorithm': inner['algorithm'],
                    'status': inner['status'],
                    'signed_object': inner['signed_object'],
                    'signed_sha256': inner['signed_sha256'],
                    'signed_len': inner['signed_len'],
                    'archive_span': inner['archive_span'],
                    'signature_sha256': inner['signature_sha256'],
                    'signature_span': inner['signature_span'],
                    'key_id': inner['key_id'],
                    'error': inner['error'],
                },
            ],
            'attachment': {
                'state': analysis['attachment']['state'],
                'source': analysis['attachment']['source'],
                'sha256': analysis['attachment']['sha256'],
                'expected_sha256': analysis['attachment']['expected_sha256'],
                'digest_match': analysis['attachment']['digest_match'],
            },
            'coverage': analysis['coverage'],
        }
    return {
        'ledger_id': 'VL-REV-001',
        'generated_by': 'revocation_review/review.py',
        'target': {'package': 'asn1crypto', 'version': ASN1CRYPTO_VERSION},
        'keys': keys,
        'cases': cases,
    }


def _md_escape(value: Any) -> str:
    return str(value).replace('|', '\\|').replace('\n', ' ')


def _md_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> List[str]:
    lines = [
        '| ' + ' | '.join(_md_escape(header) for header in headers) + ' |',
        '| ' + ' | '.join('---' for _ in headers) + ' |',
    ]
    for row in rows:
        lines.append('| ' + ' | '.join(_md_escape(cell) for cell in row) + ' |')
    return lines


def _span_text(span: Optional[Sequence[int]]) -> str:
    if not span:
        return '—'
    return '[%d, %d) (%d B)' % (span[0], span[1], span[1] - span[0])


def _case_entry(analysis: Dict[str, Any], entry_id: str) -> Dict[str, Any]:
    for entry in analysis['entries']:
        if entry['id'] == entry_id:
            return entry
    raise KeyError(entry_id)


def _scenario_note(analysis: Dict[str, Any]) -> str:
    state = analysis['attachment']['state']
    outer = analysis['outer']['status']
    inner = analysis['inner']['status']
    if state == 'outer_receipt_only':
        return '只有外层回执/摘要承诺，没有对象字节。'
    if state == 'missing':
        return '声明了附件路径但文件缺失；与“只有外层回执”是不同状态。'
    if state == 'present' and analysis['attachment']['digest_match'] is False:
        return '外层封存仍有效，但附件摘要与外层承诺不一致，内层签名也失败。'
    if state == 'present' and inner == 'MISSING_KEY':
        return '附件字节在归档内且摘要一致；缺少独立发行者公钥，未做原发行验签。'
    if state == 'present' and inner == 'VALID':
        return '附件字节 + 外层封存 + 原发行验签全部通过；仅提升范围条目。'
    return '外层=%s，内层=%s。' % (outer, inner)


def _coverage_rows(analysis: Dict[str, Any]) -> List[List[str]]:
    rows: List[List[str]] = []
    for obj in analysis['coverage']:
        outer = '是' if obj['outer_direct'] else ('仅摘要' if obj['outer_digest'] else '否')
        inner = '是' if obj['inner_direct'] else '否'
        rows.append([
            obj['label'],
            _span_text(obj['archive_span']),
            outer,
            inner,
            '`%s` (%d B, sha256 `%s`)' % (obj['id'], obj['length'], obj['sha256'][:16] + '…'),
        ])
    return rows


def write_report(
    analyses: Dict[str, Dict[str, Any]],
    fixture_meta: Dict[str, Any],
    out_dir: Path,
) -> Tuple[Path, Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    fixture_meta = dict(fixture_meta)
    fixture_meta.pop('destination', None)
    if fixture_meta.get('manifests'):
        fixture_meta['manifests'] = {
            name: Path(path).name
            for name, path in fixture_meta['manifests'].items()
        }

    baseline = analyses['outer-only']
    verified = analyses['issuance-verified']
    corpus = analyze_corpus_crl()
    ledger = build_ledger(analyses)

    report_json = {
        'report_id': 'REVIEW-REV-001',
        'target': {'package': 'asn1crypto', 'version': ASN1CRYPTO_VERSION},
        'tiers': TIERS,
        'fixture_meta': fixture_meta,
        'scenario_order': SCENARIO_ORDER,
        'scenarios': {
            case: {
                'case': analysis['case'],
                'manifest': analysis['manifest'],
                'archive': analysis['archive'],
                'outer': analysis['outer'],
                'attachment': analysis['attachment'],
                'inner': analysis['inner'],
                'entries': analysis['entries'],
                'changed_ids': analysis['changed_ids'],
                'coverage': analysis['coverage'],
                'citation_audit': analysis['citation_audit'],
            }
            for case, analysis in analyses.items()
        },
        'baseline': {
            'case': baseline['case'],
            'entries': baseline['entries'],
        },
        'issuance_verified': {
            'case': verified['case'],
            'entries': verified['entries'],
            'changed_ids': verified['changed_ids'],
        },
        'absence_audit': verified['absence_audit'],
        'corpus': corpus,
    }

    report_json_path = out_dir / 'report.json'
    report_json_path.write_text(
        json.dumps(report_json, indent=2, ensure_ascii=False, sort_keys=False) + '\n',
        encoding='utf-8',
    )
    ledger_path = out_dir / 'verification_ledger.json'
    ledger_path.write_text(
        json.dumps(ledger, indent=2, ensure_ascii=False, sort_keys=False) + '\n',
        encoding='utf-8',
    )

    lines: List[str] = []
    lines.append('# asn1crypto %s 离线引用审阅：吊销记录的多层封存' % ASN1CRYPTO_VERSION)
    lines.append('')
    lines.append('本报告只基于本地仓库源码、生成的小型 ASN.1 夹具和独立验签账，不联网、不执行夹具中的任何程序。')
    lines.append('')
    lines.append('## 结论')
    lines.append('')
    lines.append('- 外层 CMS 封存的签名输入是 `SignerInfo.signed_attrs` 的去标记 SET 编码；归档中的 `[0]` 隐式包装在验签前被还原为 `SET(0x31)`。')
    lines.append('- 嵌入 `adobe_revocation_info_archival` 的完整 CRL 字节直接落在外层签名范围内；但外层签名只冻结字节，不证明 CRL 的发行来源。')
    lines.append('- 内层 CRL 签名只覆盖 `CertificateList.tbs_cert_list`，不覆盖 `signature_algorithm`、自身 `signature` 值、外层 CMS 包装，也不自动证明外层 payload 或 PDF `/ByteRange`。')
    lines.append('- 只有外层回执（`outer_receipt_only`）时，`REV-001` 保持 `T1`；声明了附件但文件缺失（`missing`）是另一个状态，不能被改写成“仅有外层回执”。')
    lines.append('- 本地夹具补上实际 CRL 字节、发行者公钥和原 CRL 签名后，只有 `REV-001` 从 `T1` 升到 `T3`；其他归档条目和源码引用条目保持原层级/原依据。')
    lines.append('- asn1crypto `pdf.py` 只定义 ASN.1 类型，不解析 PDF 文件结构，也不执行密码学验签；本报告的“外层封存”是 CMS 层签名模型。')
    lines.append('')
    lines.append('## 证据层级')
    lines.append('')
    lines.extend(_md_table(['层级', '含义'], [[key, value] for key, value in TIERS.items()]))
    lines.append('')
    lines.append('`T` 是归档字节的可证层级；`S` 是源码引用域，二者不能互相替代。`T1` 的外层回执只能证明“提交过某个摘要承诺”，不能把摘要当作内容。')
    lines.append('')
    lines.append('## 场景对照')
    lines.append('')
    scenario_rows = []
    for case in SCENARIO_ORDER:
        analysis = analyses[case]
        entry = _case_entry(analysis, 'REV-001')
        scenario_rows.append([
            case,
            analysis['attachment']['state'],
            analysis['outer']['status'],
            analysis['inner']['status'],
            entry['tier'],
            _scenario_note(analysis),
        ])
    lines.extend(_md_table(['场景', '附件状态', '外层验签', '原发行验签', 'REV-001 层级', '判定'], scenario_rows))
    lines.append('')
    lines.append('关键区别：`outer-only` 没有声明具体附件路径；`missing-attachment` 声明了 `attachments/revocation.crl.der`，但该文件不存在。两者的 `REV-001` 都在 `T1`，但报告依据和缺件说明不同；不能把后者写成“外层回执已确认附件”。')
    lines.append('')
    lines.append('## 字节覆盖（issuance-verified 夹具）')
    lines.append('')
    lines.append('逻辑字节与归档偏移并列，因为 CMS 签名输入是去标记后的 SET 编码，而归档内实际存放的是 `[0]` 隐式标签包装；两者内容相同，标签不同。偏移均为 `[start, end)`。')
    lines.append('')
    lines.extend(_md_table(
        ['对象', '归档偏移', '外层封存直接覆盖', '内层 CRL 签名直接覆盖', '逻辑字节'],
        _coverage_rows(verified),
    ))
    lines.append('')
    lines.append('由此可核：`crl_tbs_cert_list` 的偏移区间严格位于 `crl_certificate_list` 内；`revoked_certificate_entry` 又严格位于 `tbs_cert_list` 内；`outer_signed_attrs` 的范围包含 `archival_attribute` 和完整 CRL。')
    lines.append('')
    lines.append('## 补件前后：只有对应条目升级')
    lines.append('')
    lines.append('基线取 `outer-only` 场景，补件取 `issuance-verified` 场景。补件把实际 CRL 字节、本地发行者公钥和原 CRL 签名加入归档，不改变其他条目的命题或依据。')
    lines.append('')
    before_by_id = {entry['id']: entry for entry in baseline['entries']}
    after_by_id = {entry['id']: entry for entry in verified['entries']}
    diff_rows = []
    for entry_id in before_by_id:
        before = before_by_id[entry_id]
        after = after_by_id[entry_id]
        diff_rows.append([
            entry_id,
            before['tier'],
            after['tier'],
            '是' if (before['tier'] != after['tier'] or before['basis'] != after['basis']) else '保持',
            after['basis'],
        ])
    lines.extend(_md_table(['条目', '补件前', '补件后', '是否变化', '补件后依据'], diff_rows))
    lines.append('')
    lines.append('实际变化条目：`%s`。其余 %d 个条目保持原依据；没有因 `REV-001` 的附件出现而整体抬高。' % (
        ', '.join(verified['changed_ids']),
        len(before_by_id) - len(verified['changed_ids']),
    ))
    lines.append('')
    lines.append('## 独立验签账')
    lines.append('')
    lines.append('验签账单独写入 `out/verification_ledger.json`，记录每次签名使用的对象、输入 SHA-256、归档偏移、密钥 ID/指纹和结果；报告不把外层回执自己的文字当作“已验证”。')
    lines.append('')
    lines.append('主场景（`issuance-verified`）的签名记录：')
    lines.append('')
    ledger_rows = [
        ['SIG-OUTER', verified['outer']['signed_object'], verified['outer']['algorithm'], verified['outer']['key_id'], verified['outer']['status'], verified['outer']['signed_sha256']],
        ['SIG-INNER', verified['inner']['signed_object'], verified['inner']['algorithm'], verified['inner']['key_id'], verified['inner']['status'], verified['inner']['signed_sha256']],
    ]
    lines.extend(_md_table(['签名', '覆盖对象', '算法', '密钥', '结果', '输入 SHA-256'], ledger_rows))
    lines.append('')
    lines.append('外层密钥 `%s`，指纹 `%s`；内层发行者密钥 `%s`，指纹 `%s`。内层密钥来自本地夹具 `issuer-public.pem`，不是归档自带的证书字段。' % (
        verified['outer']['key_id'],
        (verified['outer']['key_fingerprint'] or '')[:32] + '…',
        verified['inner']['key_id'],
        (verified['inner']['key_fingerprint'] or '')[:32] + '…',
    ))
    lines.append('')
    lines.append('## 引用审阅')
    lines.append('')
    lines.append('引用逐条回到源码行核对片段；任何一行失配都会把对应代码条目降为 `S0`，但不会影响归档条目。')
    lines.append('')
    citation_rows = []
    for citation_id, result in sorted(verified['citation_audit'].items()):
        citation_rows.append([
            citation_id,
            '`%s:%d-%d`' % (result['path'], result['line_start'], result['line_end']),
            result['status'],
            result['claim'],
        ])
    lines.extend(_md_table(['引用', '位置', '核对', '说明'], citation_rows))
    lines.append('')
    lines.append('代码条目 `CODE-001`…`CODE-006` 的 `S1` 只表示“源码行与命题相符”，不表示运行时已验签；`CODE-005` 明确区分了解析库与密码学验证器。')
    lines.append('')
    lines.append('引用注记：`pdf.py:5` 的文档串写作 `asn1crypto.xms.CMSAttribute()`，而同文件实际从 `.cms` 导入；这是文档笔误，不影响 OID 映射与字节覆盖结论。')
    lines.append('')
    lines.append('## 缺席检查')
    lines.append('')
    lines.append('除“某行有什么”之外，还检查“库中没有什么”，避免把未实现的能力误读为已验证：')
    lines.append('')
    absence_rows = []
    for check_id, result in sorted(verified['absence_audit'].items()):
        absence_rows.append([
            check_id,
            result['description'],
            '`%s`' % result['pattern'],
            result['status'],
            '%d 处命中' % len(result['matches']),
        ])
    lines.extend(_md_table(['检查', '说明', '模式', '结果', '命中'], absence_rows))
    lines.append('')
    lines.append('`ABS-NO-VERIFY` 在 `asn1crypto/` 下没有命中 `def verify`/`check_signature`；`ABS-NO-BYTERANGE` 没有命中 PDF `ByteRange`。因此 `CODE-005` 与 `CODE-006` 的 `S1` 仍只是源码事实，不替代本报告外部的 Ed25519 验签。')
    lines.append('')
    lines.append('## 现有语料复核')
    lines.append('')
    lines.append('仓库内真实 CRL 语料 `%s`（%d B，sha256 `%s`）可作为结构对照：' % (
        corpus['path'], corpus['size'], corpus['sha256'][:32] + '…'
    ))
    lines.append('')
    lines.append('- 发行者：`%s`；`this_update`：`%s`；吊销条目数：`%d`。' % (
        corpus['issuer'], corpus['this_update'], corpus['revoked_count']
    ))
    lines.append('- TBS 长度 `%d B`，TBS SHA-256 `%s`；签名算法 `%s`，签名长度 `%d B`。' % (
        corpus['tbs_len'], corpus['tbs_sha256'], corpus['signature_algorithm'], corpus['signature_len']
    ))
    lines.append('- 仓库没有该 CRL 的发行者公钥/证书，因此状态为 `MISSING_KEY`；只能核对结构边界，不能提升到 `T3`，也不能用外层摘要代替发行者签名。')
    lines.append('')
    lines.append('## 边界与不能证明的事')
    lines.append('')
    lines.append('- 本模型的外层封存是 CMS `SignedData`；`pdf.py` 不解析 PDF `/ByteRange`，所以本报告不能证明某个 PDF 文件级签名的字节范围。若真实档案只有 PDF 外层回执而无附件，应保持 `T1`。')
    lines.append('- 外层签名覆盖嵌入的 CRL 字节，但“覆盖”不等于“验证 CRL 发行”。`tampered-attachment` 场景中外层签名仍有效，而内层发行签名失败，证明外层封存可以冻结被篡改的字节。')
    lines.append('- 外层对 payload 只有 `message_digest` 的间接绑定；payload 字节本身不在签名输入内。')
    lines.append('- 本夹具的 `SignerInfo` 含 `signed_attrs`；若真实 CMS 采用无 signedAttrs 的分支，外层签名输入会变为 eContent，本模型不覆盖该分支，应另行核对。')
    lines.append('- `AdobeArchiveRevInfo` 扩展只有 `version`，不能承载附件；如果档案只出现该扩展而没有 `RevocationInfoArchival` 的 `crl`/`ocsp`/`other_rev_info` 字节，仍应停在 `T1`。')
    lines.append('- 本审阅器只实现 Ed25519 夹具验签；遇到其他算法标记 `UNSUPPORTED`，不擅自提升层级。')
    lines.append('- `REV-002` 是政策通知，不在本次 CRL 签名覆盖范围；即使 `REV-001` 已升到 `T3`，它仍保持 `T1`。')
    lines.append('')
    lines.append('## 复跑')
    lines.append('')
    lines.append('```sh')
    lines.append('python -m revocation_review.review build-fixtures')
    lines.append('python -m revocation_review.review report')
    lines.append('python -m revocation_review.review verify-ledger')
    lines.append('python -m unittest tests.test_revocation_review')
    lines.append('```')
    lines.append('')
    lines.append('机器可读详情：`out/report.json`；独立验签账：`out/verification_ledger.json`。')

    report_md_path = out_dir / 'REVIEW_REPORT.md'
    report_md_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return report_md_path, report_json_path, ledger_path


def read_fixture_meta(fixtures_dir: Path) -> Dict[str, Any]:
    fixtures_dir = Path(fixtures_dir)
    issuer_key = _load_public_key(fixtures_dir / 'issuer-public.pem')
    seal_key = _load_public_key(fixtures_dir / 'seal-public.pem')
    crl_bytes = (fixtures_dir / 'revocation.crl.der').read_bytes()
    outer_only = cms.ContentInfo.load((fixtures_dir / 'archive-outer-only.der').read_bytes())
    signer = outer_only['content']['signer_infos'][0]
    archival, _ = _archival_value(signer['signed_attrs'])
    digest = archival['other_rev_info'][0]['value'].native if archival is not None else b''
    return {
        'issuer_key_id': key_id(issuer_key),
        'seal_key_id': key_id(seal_key),
        'issuer_public_sha256': key_fingerprint(issuer_key),
        'seal_public_sha256': key_fingerprint(seal_key),
        'crl_sha256': sha256(crl_bytes),
        'crl_size': len(crl_bytes),
        'receipt_digest': digest.hex(),
        'manifests': {
            name: 'manifest-%s.json' % name
            for name in SCENARIO_ORDER
        },
    }


def analyze_all(fixtures_dir: Path) -> Dict[str, Dict[str, Any]]:
    analyses: Dict[str, Dict[str, Any]] = {}
    for name in SCENARIO_ORDER:
        analyses[name] = analyze_manifest(Path(fixtures_dir) / ('manifest-%s.json' % name))
    return analyses


def verify_ledger(ledger_path: Path, fixtures_dir: Path) -> List[str]:
    errors: List[str] = []
    ledger = json.loads(Path(ledger_path).read_text(encoding='utf-8'))
    if ledger.get('target', {}).get('version') != ASN1CRYPTO_VERSION:
        errors.append('target asn1crypto version does not match')
    for case, recorded in ledger.get('cases', {}).items():
        manifest = Path(fixtures_dir) / recorded['manifest']
        try:
            actual = analyze_manifest(manifest)
        except Exception as exc:
            errors.append('%s: re-analysis failed: %s' % (case, exc))
            continue
        if actual['archive']['sha256'] != recorded['archive']['sha256']:
            errors.append('%s: archive sha256 mismatch' % case)
        for sig in recorded['signatures']:
            if sig['id'] == 'SIG-OUTER':
                observed = actual['outer']
            else:
                observed = actual['inner']
            for key in ('status', 'signed_sha256', 'archive_span', 'signature_sha256', 'signature_span'):
                if observed.get(key) != sig.get(key):
                    errors.append('%s/%s: %s mismatch' % (case, sig['id'], key))
        for field in ('state', 'sha256', 'expected_sha256', 'digest_match'):
            if actual['attachment'].get(field) != recorded['attachment'].get(field):
                errors.append('%s: attachment.%s mismatch' % (case, field))
        for obj in recorded['coverage']:
            actual_obj = next((item for item in actual['coverage'] if item['id'] == obj['id']), None)
            if actual_obj is None:
                errors.append('%s: coverage object missing: %s' % (case, obj['id']))
                continue
            if actual_obj['sha256'] != obj['sha256'] or actual_obj['archive_span'] != obj['archive_span']:
                errors.append('%s: coverage object mismatch: %s' % (case, obj['id']))
    return errors


def _cmd_build(args: argparse.Namespace) -> int:
    meta = build_fixtures(Path(args.fixtures))
    print(json.dumps({key: value for key, value in meta.items() if key != 'destination'}, indent=2))
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    fixtures = Path(args.fixtures)
    if not args.no_build:
        meta = build_fixtures(fixtures)
    else:
        meta = read_fixture_meta(fixtures)
    meta.pop('destination', None)
    if meta.get('manifests'):
        meta['manifests'] = {
            name: Path(path).name
            for name, path in meta['manifests'].items()
        }
    analyses = analyze_all(fixtures)
    paths = write_report(analyses, meta, Path(args.out))
    for path in paths:
        print(path)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    errors = verify_ledger(Path(args.ledger), Path(args.fixtures))
    if errors:
        for error in errors:
            print('ERROR:', error, file=sys.stderr)
        return 1
    print('verification ledger matches %d case(s)' % len(json.loads(Path(args.ledger).read_text(encoding='utf-8'))['cases']))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='Offline review of layered revocation evidence in asn1crypto.')
    sub = parser.add_subparsers(dest='command')

    build_parser = sub.add_parser('build-fixtures', help='Generate deterministic local ASN.1 fixtures.')
    build_parser.add_argument('--fixtures', default=str(DEFAULT_FIXTURES))
    build_parser.set_defaults(func=_cmd_build)

    report_parser = sub.add_parser('report', help='Analyze scenarios and write report + verification ledger.')
    report_parser.add_argument('--fixtures', default=str(DEFAULT_FIXTURES))
    report_parser.add_argument('--out', default=str(DEFAULT_OUT))
    report_parser.add_argument('--no-build', action='store_true', help='Use existing fixtures instead of rebuilding them.')
    report_parser.set_defaults(func=_cmd_report)

    verify_parser = sub.add_parser('verify-ledger', help='Recompute and compare the independent verification ledger.')
    verify_parser.add_argument('--fixtures', default=str(DEFAULT_FIXTURES))
    verify_parser.add_argument('--ledger', default=str(DEFAULT_OUT / 'verification_ledger.json'))
    verify_parser.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    if not getattr(args, 'func', None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
