# coding: utf-8

"""
Read-only inventory of BER/DER-encoded evidence bundles.

The inventory walks encoded values without modifying the caller's byte string.
It is intended for situations where CMS and PKCS#12 wrappers are mixed in one
bundle and the caller needs a bounded, auditable list of:

 - structural nodes that could be identified
 - layers that are understood but can not be opened without more information,
   such as encrypted or compressed payloads
 - the exact byte range (provenance) of each item in the supplied bundle

Budgets are expressed as a maximum number of structural nodes and a maximum
number of reviewed bytes. Parents are recorded before their children, so a
parent that was confirmed before the budget was exhausted is always retained.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._errors import unwrap
from ._types import byte_cls, int_types, type_name
from . import parser
from . import pem
from .core import ObjectIdentifier


__all__ = [
    'Inventory',
    'Manifest',
    'InventoryNode',
    'Entry',
    'Item',
    'build_inventory',
    'inventory',
    'manifest',
    'scan',
    'review',
    'audit',
]


_CLASS_NAMES = {
    0: 'universal',
    1: 'application',
    2: 'context',
    3: 'private',
}

_METHOD_NAMES = {
    0: 'primitive',
    1: 'constructed',
}

_UNIVERSAL_KINDS = {
    1: 'asn1.Boolean',
    2: 'asn1.Integer',
    3: 'asn1.BitString',
    4: 'asn1.OctetString',
    5: 'asn1.Null',
    6: 'asn1.ObjectIdentifier',
    9: 'asn1.Real',
    10: 'asn1.Enumerated',
    12: 'asn1.UTF8String',
    13: 'asn1.RelativeOid',
    16: 'asn1.Sequence',
    17: 'asn1.Set',
    18: 'asn1.NumericString',
    19: 'asn1.PrintableString',
    20: 'asn1.TeletexString',
    21: 'asn1.VideotexString',
    22: 'asn1.IA5String',
    23: 'asn1.UTCTime',
    24: 'asn1.GeneralizedTime',
    25: 'asn1.GraphicString',
    26: 'asn1.VisibleString',
    27: 'asn1.GeneralString',
    28: 'asn1.UniversalString',
    30: 'asn1.BMPString',
}

_CMS_CONTENT_TYPES = {
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

_CMS_INNER_KINDS = {
    'data': 'asn1.OctetString',
    'signed_data': 'cms.SignedData',
    'enveloped_data': 'cms.EnvelopedData',
    'signed_and_enveloped_data': 'cms.SignedAndEnvelopedData',
    'digested_data': 'cms.DigestedData',
    'encrypted_data': 'cms.EncryptedData',
    'authenticated_data': 'cms.AuthenticatedData',
    'compressed_data': 'cms.CompressedData',
    'authenticated_enveloped_data': 'cms.AuthEnvelopedData',
}

_PKCS12_BAG_TYPES = {
    '1.2.840.113549.1.12.10.1.1': 'key_bag',
    '1.2.840.113549.1.12.10.1.2': 'pkcs8_shrouded_key_bag',
    '1.2.840.113549.1.12.10.1.3': 'cert_bag',
    '1.2.840.113549.1.12.10.1.4': 'crl_bag',
    '1.2.840.113549.1.12.10.1.5': 'secret_bag',
    '1.2.840.113549.1.12.10.1.6': 'safe_contents',
}

_PKCS12_CERT_IDS = {
    '1.2.840.113549.1.9.22.1': 'x509',
    '1.2.840.113549.1.9.22.2': 'sdsi',
}

_PKCS12_BAG_INNER_KINDS = {
    'key_bag': 'keys.PrivateKeyInfo',
    'pkcs8_shrouded_key_bag': 'keys.EncryptedPrivateKeyInfo',
    'cert_bag': 'pkcs12.CertBag',
    'crl_bag': 'pkcs12.CrlBag',
    'secret_bag': 'pkcs12.SecretBag',
    'safe_contents': 'pkcs12.SafeContents',
}

_SEMANTIC_PREFIXES = (
    'algos.',
    'cms.',
    'crl.',
    'keys.',
    'ocsp.',
    'pkcs12.',
    'tsp.',
    'x509.',
)

_OPAQUE_KINDS = {
    'cms.encrypted_content': 'encrypted',
    'cms.compressed_content': 'compressed',
    'cms.raw_content': 'raw',
    'keys.encrypted_key': 'encrypted',
}


class _Record(dict):
    """
    A dict with attribute access, so callers may use either style and the
    result can still be serialized with json.dumps().
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            pass
        raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value

    def to_dict(self):
        return _plain(self)


def _plain(value):
    if isinstance(value, dict):
        output = {}
        for key in value.keys():
            output[key] = _plain(value[key])
        return output
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


class InventoryNode(_Record):
    """
    One structural node in an inventory.

    Important keys include path, kind, status, classification, openable,
    offset, total_length, source, parent, children, complete and
    unvisited_children.
    """

    _computed = {
        'class': 'classification',
        'category': 'classification',
        'origin': 'source',
        'child_paths': 'children',
        'is_opaque': 'opaque',
        'is_classified': 'status',
        'has_more_children': 'has_unvisited_children',
        'has_unvisited': 'has_unvisited_children',
        'unreviewed_children': 'has_unvisited_children',
        'children_pending': 'has_unvisited_children',
        'children_unvisited': 'has_unvisited_children',
        'children_truncated': 'has_unvisited_children',
        'unvisited_child_items': 'has_unvisited_children',
        'child_items_unvisited': 'has_unvisited_children',
        'siblings_independent': 'can_continue_siblings',
        'sibling_review_possible': 'can_continue_siblings',
        'children_complete': 'complete',
        'fully_reviewed': 'complete',
        'truncated': 'complete',
    }

    def __getitem__(self, key):
        if key not in self and key in self._computed:
            source_key = self._computed[key]
            value = self.get(source_key)
            if key == 'is_classified':
                return value == 'classified'
            if key == 'truncated':
                return not value
            if key == 'is_opaque':
                return bool(value)
            return value
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


class Inventory(_Record):
    """
    Result of :func:`inventory()`.

    entries is a flat list in depth-first order. Each entry has a stable
    ``path``; ``parent`` refers to the parent path. ``source`` contains the
    absolute offset and length of the node's TLV in the supplied bundle.

    It may be constructed either from an already-built result dict (internal)
    or directly from bytes: ``Inventory(data, max_nodes=10)``.
    """

    def __init__(self, data=None, max_nodes=None, max_bytes=None, max_depth=None, pem_mode=None):
        if data is None:
            dict.__init__(self)
        elif isinstance(data, dict):
            dict.__init__(self, data)
        elif isinstance(data, byte_cls):
            result = _Scanner(data, max_nodes, max_bytes, max_depth, pem_mode).scan()
            dict.__init__(self, result)
        else:
            raise TypeError(unwrap(
                'Inventory data must be a byte string or a result dict, not %s',
                type_name(data)
            ))

    @classmethod
    def from_bytes(cls, data, max_nodes=None, max_bytes=None, max_depth=None, pem_mode=None):
        return cls(data, max_nodes, max_bytes, max_depth, pem_mode)

    def __getitem__(self, key):
        if isinstance(key, int_types):
            return dict.__getitem__(self, 'entries')[key]
        if isinstance(key, slice):
            return dict.__getitem__(self, 'entries')[key]
        return dict.__getitem__(self, key)


# Common names for one inventory entry.
Entry = InventoryNode
Item = InventoryNode
Manifest = Inventory


class _Tlv(object):
    __slots__ = (
        'class_',
        'method',
        'tag',
        'header',
        'content',
        'trailer',
        'offset',
        'header_length',
        'content_length',
        'trailer_length',
        'total_length',
        'content_offset',
        'content_end',
        'end',
    )

    def __init__(self, info, offset, end):
        class_, method, tag, header, content, trailer = info
        self.class_ = class_
        self.method = method
        self.tag = tag
        self.header = header
        self.content = content
        self.trailer = trailer
        self.offset = offset
        self.header_length = len(header)
        self.content_length = len(content)
        self.trailer_length = len(trailer)
        self.total_length = end - offset
        self.content_offset = offset + self.header_length
        self.content_end = self.content_offset + self.content_length
        self.end = end


def _read_tlv(data, offset, limit):
    if offset >= limit:
        raise ValueError(unwrap(
            'Insufficient data - expected an ASN.1 value at offset %s',
            offset
        ))
    info, end = parser._parse(data, limit, pointer=offset)
    if end > limit:
        raise ValueError(unwrap(
            'ASN.1 value at offset %s extends past the enclosing value',
            offset
        ))
    return _Tlv(info, offset, end)


def _child_tlvs(data, tlv):
    children = []
    offset = tlv.content_offset
    while offset < tlv.content_end:
        child = _read_tlv(data, offset, tlv.content_end)
        children.append(child)
        offset = child.end
    return children


def _oid_from_tlv(tlv):
    if tlv.class_ != 0 or tlv.tag != 6:
        return None
    try:
        return ObjectIdentifier.load(tlv.header + tlv.content + tlv.trailer).native
    except (ValueError, TypeError):
        return None


def _first_oid(data, children):
    if not children:
        return None
    return _oid_from_tlv(children[0])


def _is_context(tlv, tag):
    return tlv.class_ == 2 and tlv.tag == tag


def _is_universal(tlv, tag):
    return tlv.class_ == 0 and tlv.tag == tag


def _looks_like_content_info(data, children):
    if len(children) < 2:
        return False
    oid = _oid_from_tlv(children[0])
    if oid is None or oid in _PKCS12_BAG_TYPES:
        return False
    return _is_context(children[1], 0) and children[1].method == 1


def _looks_like_safe_bag(data, children):
    if len(children) < 2:
        return False
    oid = _oid_from_tlv(children[0])
    if oid not in _PKCS12_BAG_TYPES:
        return False
    return _is_context(children[1], 0) and children[1].method == 1


def _sequence_kind(data, tlv, children):
    if not children:
        return 'asn1.Sequence'

    first = children[0]
    first_oid = _oid_from_tlv(first)

    if first_oid is not None:
        if first_oid in _PKCS12_BAG_TYPES and _looks_like_safe_bag(data, children):
            return 'pkcs12.SafeBag'
        if first_oid in _PKCS12_CERT_IDS and len(children) >= 2 and _is_context(children[1], 0):
            return 'pkcs12.CertBag'
        if _looks_like_content_info(data, children):
            return 'cms.ContentInfo'

    # PKCS#12 PFX: SEQUENCE { version INTEGER, auth_safe ContentInfo, macData OPTIONAL }
    if _is_universal(first, 2) and len(children) >= 2 and _is_universal(children[1], 16):
        try:
            nested = _child_tlvs(data, children[1])
        except ValueError:
            nested = []
        if _looks_like_content_info(data, nested):
            return 'pkcs12.Pfx'

    # AuthenticatedSafe is a SEQUENCE OF ContentInfo.
    if len(children) and all(_is_universal(child, 16) for child in children):
        all_content_info = True
        all_safe_bag = True
        for child in children:
            try:
                nested = _child_tlvs(data, child)
            except ValueError:
                all_content_info = False
                all_safe_bag = False
                break
            if not _looks_like_content_info(data, nested):
                all_content_info = False
            if not _looks_like_safe_bag(data, nested):
                all_safe_bag = False
        if all_content_info:
            return 'pkcs12.AuthenticatedSafe'
        if all_safe_bag:
            return 'pkcs12.SafeContents'

    # X.509 Certificate / CRL have a distinctive three-field outer sequence.
    if len(children) >= 3 and _is_universal(children[0], 16) and \
            _is_universal(children[1], 16) and _is_universal(children[2], 3):
        try:
            tbs = _child_tlvs(data, children[0])
        except ValueError:
            tbs = []
        # Certificate TBSCertificate has validity (SEQUENCE) at index 3;
        # CertificateList has thisUpdate (UTCTime/GeneralizedTime).
        if len(tbs) >= 4 and tbs[3].class_ == 0 and tbs[3].tag in (23, 24):
            return 'crl.CertificateList'
        if len(tbs) >= 3 and _is_universal(tbs[1], 16) and _is_universal(tbs[2], 16):
            return 'x509.Certificate'

    return 'asn1.Sequence'


def _detect_kind(data, tlv, hint, parent):
    if hint is not None and hint.get('kind'):
        return hint['kind']

    if tlv.class_ == 0:
        if tlv.tag == 16:
            try:
                children = _child_tlvs(data, tlv)
            except ValueError:
                children = []
            return _sequence_kind(data, tlv, children)
        if tlv.tag in _UNIVERSAL_KINDS:
            return _UNIVERSAL_KINDS[tlv.tag]
        return 'asn1.Universal'

    if tlv.class_ == 2:
        return 'asn1.ContextSpecific'
    if tlv.class_ == 1:
        return 'asn1.Application'
    return 'asn1.Private'


def _is_semantic(kind):
    if kind is None:
        return False
    for prefix in _SEMANTIC_PREFIXES:
        if kind.startswith(prefix):
            return True
    return False


def _make_source(tlv, path, parent_path, embedded, pem_info):
    source = {
        'offset': tlv.offset,
        'end_offset': tlv.end,
        'length': tlv.total_length,
        'header_length': tlv.header_length,
        'content_offset': tlv.content_offset,
        'content_length': tlv.content_length,
        'path': path,
        'parent': parent_path,
        'embedded': embedded,
        'offset_basis': 'pem_decoded' if pem_info is not None else 'bundle',
    }
    if pem_info is not None:
        source['pem_type'] = pem_info.get('type')
        source['pem_index'] = pem_info.get('index')
        source['decoded_offset'] = tlv.offset
    return source


def _child_hints(record, children):
    """
    Assign structural expectations to direct children based on the parent's
    identified kind. This is deliberately schema-light: it uses the stable
    shapes of CMS and PKCS#12 rather than materializing the whole object graph.
    """

    count = len(children)
    hints = [None] * count

    def set_hint(index, **kwargs):
        if index < 0:
            index = count + index
        if 0 <= index < count:
            hints[index] = kwargs

    kind = record.get('kind')
    content_type = record.get('content_type')
    bag_type = record.get('bag_type')
    payload_kind = record.get('_payload_kind')
    parent_kind = record.get('parent_kind')

    if kind == 'pkcs12.Pfx':
        set_hint(0, kind='pkcs12.version')
        set_hint(1, kind='cms.ContentInfo', field='auth_safe')
        set_hint(2, kind='pkcs12.MacData')

    elif kind == 'cms.ContentInfo':
        set_hint(0, kind='cms.content_type')
        if count > 1:
            inner_kind = _CMS_INNER_KINDS.get(content_type)
            hint = {
                'kind': 'asn1.Explicit',
                'field': 'content',
                'inner_kind': inner_kind,
            }
            if record.get('field') == 'auth_safe':
                if content_type == 'data':
                    hint['inner_kind'] = 'asn1.OctetString'
                    hint['embedded_kind'] = 'pkcs12.AuthenticatedSafe'
                    hint['embedded_expected'] = True
                else:
                    hint['inner_kind'] = _CMS_INNER_KINDS.get(content_type)
                    hint['_payload_kind'] = 'pkcs12.AuthenticatedSafe'
            elif parent_kind == 'pkcs12.AuthenticatedSafe':
                if content_type == 'data':
                    hint['inner_kind'] = 'asn1.OctetString'
                    hint['embedded_kind'] = 'pkcs12.SafeContents'
                    hint['embedded_expected'] = True
                elif content_type == 'signed_data':
                    hint['_payload_kind'] = 'pkcs12.AuthenticatedSafe'
            elif payload_kind is not None:
                hint['embedded_kind'] = payload_kind
                hint['embedded_expected'] = True
            set_hint(1, **hint)

    elif kind == 'cms.EncapsulatedContentInfo':
        set_hint(0, kind='cms.content_type')
        if count > 1:
            hint = {
                'kind': 'asn1.Explicit',
                'field': 'content',
                'inner_kind': 'asn1.OctetString',
            }
            if record.get('_payload_kind') == 'compressed' or parent_kind == 'cms.CompressedData':
                hint['_payload_kind'] = 'compressed'
            elif record.get('_payload_kind') is not None:
                hint['embedded_kind'] = record.get('_payload_kind')
                hint['embedded_expected'] = True
            elif content_type == 'data' and parent_kind in (
                    'cms.SignedData', 'cms.SignedAndEnvelopedData', 'cms.DigestedData',
                    'cms.AuthenticatedData', 'cms.CompressedData'):
                hint['embedded_try'] = True
            elif content_type in _CMS_INNER_KINDS and content_type != 'data':
                hint['embedded_kind'] = 'cms.ContentInfo'
                hint['embedded_expected'] = True
            set_hint(1, **hint)

    elif kind == 'cms.SignedData':
        set_hint(0, kind='cms.version')
        set_hint(1, kind='cms.DigestAlgorithms')
        set_hint(2, kind='cms.EncapsulatedContentInfo', _payload_kind=payload_kind)
        for index in range(3, count):
            child = children[index]
            if _is_context(child, 0):
                set_hint(index, kind='cms.CertificateSet')
            elif _is_context(child, 1):
                set_hint(index, kind='cms.RevocationInfoChoices')
            else:
                set_hint(index, kind='cms.SignerInfos')

    elif kind == 'cms.DigestedData':
        set_hint(0, kind='cms.version')
        set_hint(1, kind='algos.DigestAlgorithm')
        set_hint(2, kind='cms.EncapsulatedContentInfo')
        set_hint(3, kind='asn1.OctetString')

    elif kind == 'cms.EnvelopedData':
        set_hint(0, kind='cms.version')
        for index in range(1, count):
            child = children[index]
            if _is_context(child, 0):
                set_hint(index, kind='cms.OriginatorInfo')
            elif _is_universal(child, 17):
                set_hint(index, kind='cms.RecipientInfos')
            elif _is_universal(child, 16):
                set_hint(index, kind='cms.EncryptedContentInfo')
            elif _is_context(child, 1):
                set_hint(index, kind='cms.CMSAttributes')

    elif kind == 'cms.EncryptedData':
        set_hint(0, kind='cms.version')
        set_hint(1, kind='cms.EncryptedContentInfo')
        set_hint(2, kind='cms.CMSAttributes')

    elif kind == 'cms.AuthEnvelopedData':
        set_hint(0, kind='cms.version')
        for index in range(1, count):
            child = children[index]
            if _is_context(child, 0):
                set_hint(index, kind='cms.OriginatorInfo')
            elif _is_universal(child, 17):
                set_hint(index, kind='cms.RecipientInfos')
            elif _is_universal(child, 16):
                set_hint(index, kind='cms.EncryptedContentInfo')
            elif _is_context(child, 1):
                set_hint(index, kind='cms.CMSAttributes')
            elif _is_universal(child, 4):
                set_hint(index, kind='asn1.OctetString')

    elif kind == 'cms.SignedAndEnvelopedData':
        set_hint(0, kind='cms.version')
        set_hint(1, kind='cms.RecipientInfos')
        set_hint(2, kind='cms.DigestAlgorithms')
        set_hint(3, kind='cms.EncryptedContentInfo')
        for index in range(4, count):
            child = children[index]
            if _is_context(child, 0):
                set_hint(index, kind='cms.CertificateSet')
            elif _is_context(child, 1):
                set_hint(index, kind='cms.RevocationInfoChoices')
            else:
                set_hint(index, kind='cms.SignerInfos')

    elif kind == 'cms.AuthenticatedData':
        set_hint(0, kind='cms.version')
        index = 1
        if index < count and _is_context(children[index], 0):
            set_hint(index, kind='cms.OriginatorInfo')
            index += 1
        if index < count and _is_universal(children[index], 17):
            set_hint(index, kind='cms.RecipientInfos')
            index += 1
        if index < count and _is_universal(children[index], 16):
            set_hint(index, kind='algos.HmacAlgorithm')
            index += 1
        if index < count and _is_context(children[index], 1):
            set_hint(index, kind='algos.DigestAlgorithm')
            index += 1
        if index < count and _is_universal(children[index], 16):
            set_hint(index, kind='cms.EncapsulatedContentInfo')
            index += 1
        if index < count and _is_context(children[index], 2):
            set_hint(index, kind='cms.CMSAttributes')
            index += 1
        if index < count and _is_universal(children[index], 4):
            set_hint(index, kind='asn1.OctetString')
            index += 1
        if index < count and _is_context(children[index], 3):
            set_hint(index, kind='cms.CMSAttributes')

    elif kind == 'cms.CompressedData':
        set_hint(0, kind='cms.version')
        set_hint(1, kind='algos.CompressionAlgorithm')
        set_hint(2, kind='cms.EncapsulatedContentInfo', _payload_kind='compressed')

    elif kind == 'cms.EncryptedContentInfo':
        set_hint(0, kind='cms.content_type')
        set_hint(1, kind='algos.EncryptionAlgorithm')
        if count > 2:
            set_hint(2, kind='cms.encrypted_content', opaque_reason='encrypted')

    elif kind == 'cms.DigestAlgorithms':
        for index in range(count):
            set_hint(index, kind='algos.DigestAlgorithm')

    elif kind == 'cms.CertificateSet':
        for index in range(count):
            if _is_universal(children[index], 16):
                set_hint(index, kind='x509.Certificate')
            else:
                set_hint(index, kind='cms.CertificateChoice', opaque_reason=None)

    elif kind == 'cms.RevocationInfoChoices':
        for index in range(count):
            if _is_universal(children[index], 16):
                set_hint(index, kind='crl.CertificateList')
            else:
                set_hint(index, kind='cms.RevocationInfoChoice')

    elif kind == 'cms.SignerInfos':
        for index in range(count):
            set_hint(index, kind='cms.SignerInfo')

    elif kind == 'pkcs12.AuthenticatedSafe':
        for index in range(count):
            set_hint(index, kind='cms.ContentInfo', field='content_info')

    elif kind == 'pkcs12.SafeContents':
        for index in range(count):
            set_hint(index, kind='pkcs12.SafeBag')

    elif kind == 'pkcs12.SafeBag':
        set_hint(0, kind='pkcs12.bag_id')
        inner_kind = _PKCS12_BAG_INNER_KINDS.get(bag_type)
        if count > 1:
            hint = {
                'kind': 'asn1.Explicit',
                'field': 'bag_value',
                'inner_kind': inner_kind,
            }
            set_hint(1, **hint)
        set_hint(2, kind='pkcs12.Attributes')

    elif kind == 'pkcs12.CertBag':
        set_hint(0, kind='pkcs12.cert_id')
        if count > 1:
            set_hint(1, kind='asn1.Explicit', field='cert_value',
                     inner_kind='asn1.OctetString', embedded_kind='x509.Certificate',
                     embedded_expected=True)

    elif kind == 'pkcs12.CrlBag':
        set_hint(0, kind='pkcs12.crl_id')
        if count > 1:
            set_hint(1, kind='asn1.Explicit', field='crl_value',
                     inner_kind='asn1.OctetString', embedded_kind='crl.CertificateList',
                     embedded_expected=True)

    elif kind == 'pkcs12.SecretBag':
        set_hint(0, kind='pkcs12.secret_type_id')
        if count > 1:
            set_hint(1, kind='asn1.Explicit', field='secret_value',
                     inner_kind='asn1.OctetString', next_opaque_reason='secret')

    elif kind == 'keys.EncryptedPrivateKeyInfo':
        set_hint(0, kind='algos.EncryptionAlgorithm')
        if count > 1:
            set_hint(1, kind='keys.encrypted_key', opaque_reason='encrypted')

    elif kind == 'asn1.Explicit':
        inner_kind = record.get('_inner_kind')
        if count:
            hint = {'kind': inner_kind}
            for key in ('embedded_kind', 'embedded_expected', 'embedded_try', 'opaque_reason',
                        '_payload_kind'):
                if key in record:
                    hint[key] = record[key]
            if record.get('next_opaque_reason') is not None:
                hint['opaque_reason'] = record['next_opaque_reason']
            set_hint(0, **hint)

    return hints


class _Scanner(object):

    def __init__(self, data, max_nodes=None, max_bytes=None, max_depth=None, pem_mode=None):
        if not isinstance(data, byte_cls):
            raise TypeError(unwrap(
                'data must be a byte string, not %s',
                type_name(data)
            ))
        if max_nodes is not None and not isinstance(max_nodes, int_types):
            raise TypeError(unwrap(
                'max_nodes must be an integer, not %s',
                type_name(max_nodes)
            ))
        if max_nodes is not None and max_nodes < 0:
            raise ValueError('max_nodes must be greater than or equal to zero')
        if max_bytes is not None and not isinstance(max_bytes, int_types):
            raise TypeError(unwrap(
                'max_bytes must be an integer, not %s',
                type_name(max_bytes)
            ))
        if max_bytes is not None and max_bytes < 0:
            raise ValueError('max_bytes must be greater than or equal to zero')
        if max_depth is not None and not isinstance(max_depth, int_types):
            raise TypeError(unwrap(
                'max_depth must be an integer, not %s',
                type_name(max_depth)
            ))
        if max_depth is not None and max_depth < 0:
            raise ValueError('max_depth must be greater than or equal to zero')

        self.data = data
        self.max_nodes = max_nodes
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self.pem_mode = pem_mode

        self.entries = []
        self.by_path = {}
        self.bytes_read = 0
        self.nodes_read = 0
        self.errors = []
        self.pending = []
        self.stop_reason = None
        self.stop_detail = None
        self.stop_path = None
        self.stop_offset = None
        self.stop_next_path = None
        self.budget_stopped = False
        self.hit_depth = False
        self._pem_info = None
        self._root_counter = 0
        self._active_pem = None

    def scan(self):
        data = self.data
        if self.pem_mode is None:
            self.pem_mode = pem.detect(data)

        if self.pem_mode:
            self._scan_pem()
        else:
            self._scan_der(data, self._pem_info)

        return self._result()

    def _scan_pem(self):
        index = 0
        try:
            blocks = pem.unarmor(self.data, multiple=True)
        except ValueError as e:
            self._add_error(0, None, 'not_pem', str(e))
            return

        for object_type, headers, der_bytes in blocks:
            if self.budget_stopped:
                break
            info = {'type': object_type, 'index': index, 'headers': headers}
            self._scan_der(der_bytes, info)
            index += 1

    def _scan_der(self, data, pem_info):
        self._active_pem = pem_info
        offset = 0
        data_len = len(data)
        while offset < data_len:
            if self.budget_stopped:
                break
            while offset < data_len and data[offset:offset + 1] in (b' ', b'\t', b'\r', b'\n'):
                offset += 1
            if offset >= data_len:
                break
            try:
                tlv = _read_tlv(data, offset, data_len)
            except (ValueError, TypeError) as e:
                self._add_error(offset, str(self._root_counter), 'malformed', str(e), pem_info)
                break

            path = str(self._root_counter)
            result = self._visit(data, tlv, path, None, 0, None, False, pem_info)
            if result is False:
                visited_root = path in self.by_path
                remaining = data_len - (tlv.end if visited_root else tlv.offset)
                if remaining > 0:
                    next_root = self._root_counter + 1 if visited_root else self._root_counter
                    self.pending.append({
                        'parent': None,
                        'next_index': next_root,
                        'remaining_bytes': remaining,
                        'independent': True,
                        'kind': 'roots',
                        'visited_children': self._root_counter if not visited_root else self._root_counter + 1,
                        'reason': 'remaining top-level items are independent of the reviewed roots',
                    })
                break
            offset = tlv.end
            self._root_counter += 1

    def _add_error(self, offset, path, reason, detail, pem_info=None, parent=None, depth=0):
        error = InventoryNode({
            'path': path,
            'index': len(self.entries),
            'parent': parent,
            'depth': depth,
            'kind': None,
            'type': None,
            'classification': 'unreadable',
            'status': 'error',
            'state': 'error',
            'openable': False,
            'opaque': False,
            'reason': reason,
            'opaque_reason': reason,
            'detail': detail,
            'offset': offset,
            'end_offset': None,
            'total_length': None,
            'source': {
                'offset': offset,
                'end_offset': None,
                'length': None,
                'path': path,
                'parent': parent,
                'embedded': False,
            },
            'children': [],
            'child_count': None,
            'complete': False,
            'unvisited_children': False,
            'has_unvisited_children': False,
            'budget': None,
        })
        self.errors.append(error)

    def _stop(self, reason, path, offset, detail, next_path=None):
        self.budget_stopped = True
        if self.stop_reason is None:
            self.stop_reason = reason
            self.stop_path = path
            self.stop_offset = offset
            self.stop_next_path = next_path
            self.stop_detail = detail

    def _visit(self, data, tlv, path, parent, depth, hint, embedded, pem_info):
        if self.budget_stopped:
            return False

        if self.max_depth is not None and depth > self.max_depth:
            self.hit_depth = True
            self._stop(
                'max_depth',
                parent.get('path') if parent is not None else path,
                tlv.offset,
                unwrap(
                    'Maximum depth of %s reached at %s; child items were not visited',
                    self.max_depth,
                    parent.get('path') if parent is not None else path
                ),
                path
            )
            return False

        children_meta = None
        kind = _detect_kind(data, tlv, hint, parent)
        if hint is not None and hint.get('_payload_kind') == 'compressed' and \
                kind == 'asn1.OctetString':
            kind = 'cms.compressed_content'
        embedded_like = hint is not None and (
            hint.get('embedded_kind') is not None or
            hint.get('embedded_expected') or
            hint.get('embedded_try')
        )
        # Any constructed value is traversed structurally. Opaque layers are
        # handled separately and charged as a single payload.
        is_container = tlv.method == 1
        opaque_reason = None
        if hint is not None:
            opaque_reason = hint.get('opaque_reason')
        if opaque_reason is None:
            opaque_reason = _OPAQUE_KINDS.get(kind)

        # An opaque layer is confirmed from its header and surrounding context;
        # its payload is deliberately not opened.
        # Containers and embedded-value wrappers are charged their header; the
        # child TLVs are charged as they are reviewed, avoiding double-counting
        # the same bytes. Opaque payloads (including compressed content) are
        # charged as a whole because they are treated as a single layer.
        if embedded_like and kind != 'cms.compressed_content':
            cost = tlv.header_length
        elif is_container:
            cost = tlv.header_length
        else:
            cost = tlv.total_length
        if self.max_nodes is not None and self.nodes_read >= self.max_nodes:
            self._stop(
                'node_budget',
                parent.get('path') if parent is not None else path,
                tlv.offset,
                unwrap(
                    'Node budget of %s reached before %s; confirmed parents were retained',
                    self.max_nodes,
                    path
                ),
                path
            )
            return False
        if self.max_bytes is not None and self.bytes_read + cost > self.max_bytes:
            self._stop(
                'byte_budget',
                parent.get('path') if parent is not None else path,
                tlv.offset,
                unwrap(
                    'Byte budget of %s reached before %s; confirmed parents were retained',
                    self.max_bytes,
                    path
                ),
                path
            )
            return False

        parent_path = parent.get('path') if parent is not None else None
        record = InventoryNode({
            'path': path,
            'index': len(self.entries),
            'parent': parent_path,
            'depth': depth,
            'kind': kind,
            'type': kind,
            'classification': None,
            'status': None,
            'state': None,
            'openable': False,
            'opaque': False,
            'reason': opaque_reason,
            'oid': None,
            'content_type': None,
            'content_type_oid': None,
            'bag_type': None,
            'parent_kind': parent.get('kind') if parent is not None else None,
            'field': hint.get('field') if hint is not None else None,
            'tag': (tlv.class_, tlv.method, tlv.tag),
            'tag_name': _CLASS_NAMES.get(tlv.class_, 'unknown'),
            'method': _METHOD_NAMES.get(tlv.method, 'unknown'),
            'offset': tlv.offset,
            'content_offset': tlv.content_offset,
            'end_offset': tlv.end,
            'header_length': tlv.header_length,
            'content_length': tlv.content_length,
            'trailer_length': tlv.trailer_length,
            'total_length': tlv.total_length,
            'reviewed_bytes': cost,
            'source': _make_source(tlv, path, parent_path, embedded, pem_info),
            'source_path': path,
            'children': [],
            'child_count': None,
            'complete': True,
            'unvisited_children': False,
            'has_unvisited_children': False,
            'pending_children': False,
            'next_child_index': None,
            'boundary': False,
            'sibling_continuation': None,
            'can_continue_siblings': False,
            'embedded': embedded,
            'error': None,
            'opaque_reason': opaque_reason,
        })

        if hint is not None:
            for key in ('embedded_kind', 'embedded_expected', 'embedded_try', '_payload_kind',
                        'next_opaque_reason'):
                if key in hint:
                    record[key] = hint[key]
            if hint.get('inner_kind') is not None:
                record['_inner_kind'] = hint['inner_kind']

        # Decode enough context to label the node, but never materialize or
        # mutate the underlying object.
        try:
            if kind in (
                    'cms.ContentInfo', 'cms.EncapsulatedContentInfo', 'pkcs12.SafeBag',
                    'pkcs12.CertBag', 'pkcs12.CrlBag', 'pkcs12.SecretBag'):
                children_meta = _child_tlvs(data, tlv)
                oid = _first_oid(data, children_meta)
                if oid is not None:
                    if kind == 'cms.ContentInfo' or kind == 'cms.EncapsulatedContentInfo':
                        record['content_type_oid'] = oid
                        record['content_type'] = _CMS_CONTENT_TYPES.get(oid)
                    elif kind == 'pkcs12.SafeBag':
                        record['content_type_oid'] = oid
                        record['bag_type'] = _PKCS12_BAG_TYPES.get(oid)
                    else:
                        record['content_type_oid'] = oid
            if tlv.class_ == 0 and tlv.tag == 6:
                record['oid'] = _oid_from_tlv(tlv)
        except (ValueError, TypeError):
            children_meta = None

        if opaque_reason is not None:
            record['classification'] = 'opaque'
            record['status'] = 'opaque'
            record['state'] = 'opaque'
            record['openable'] = False
            record['opaque'] = True
            record['boundary'] = True
            record['reason'] = opaque_reason
            record['complete'] = True
            record['sibling_continuation'] = {
                'possible': True,
                'reason': 'sibling items do not require opening this layer',
            }
            record['can_continue_siblings'] = True
        else:
            if _is_semantic(kind):
                record['classification'] = 'known'
            elif kind.startswith('asn1.'):
                record['classification'] = 'structural'
            else:
                record['classification'] = 'unknown'
            record['status'] = 'classified'
            record['state'] = 'classified'
            record['openable'] = tlv.method == 1

        self.entries.append(record)
        self.by_path[path] = record
        self.nodes_read += 1
        self.bytes_read += cost

        if opaque_reason is not None:
            return True

        if tlv.method == 1:
            if children_meta is None:
                try:
                    children_meta = _child_tlvs(data, tlv)
                except (ValueError, TypeError) as e:
                    record['complete'] = False
                    record['error'] = 'malformed_children'
                    record['detail'] = str(e)
                    self._add_error(
                        tlv.content_offset,
                        path,
                        'malformed_children',
                        str(e),
                        pem_info,
                        parent_path,
                        depth
                    )
                    return 'error'

            hints = _child_hints(record, children_meta)
            record['openable'] = True
            for index, child in enumerate(children_meta):
                child_path = path + '.' + str(index)
                child_hint = hints[index] if index < len(hints) else None
                result = self._visit(
                    data, child, child_path, record, depth + 1, child_hint, False, pem_info
                )
                if result is False:
                    record['complete'] = False
                    record['unvisited_children'] = True
                    record['has_unvisited_children'] = True
                    record['pending_children'] = True
                    record['next_child_index'] = index
                    record['sibling_continuation'] = {
                        'possible': True,
                        'reason': 'the budget boundary is local; unvisited sibling items are independent',
                    }
                    record['can_continue_siblings'] = True
                    self._record_pending(record, child, index)
                    return False
                if result == 'error':
                    record['complete'] = False
                    record['error'] = 'unreadable_child'
                    # The child's TLV boundary is known even when its contents
                    # were malformed, so independent siblings can still be
                    # reviewed. The enclosing parent is marked incomplete.
                    if child_path in self.by_path:
                        record['children'].append(child_path)
                    continue
                record['children'].append(child_path)

            record['child_count'] = len(children_meta)
            if record.get('error') is None:
                record['complete'] = True
            else:
                record['complete'] = False
                return 'error'
            return True

        # A primitive OCTET STRING/BIT STRING can still be a wrapper around an
        # encoded value. Only open it when the surrounding structure says that
        # is expected, or when a data payload can be parsed cleanly as ASN.1.
        embedded_kind = record.get('embedded_kind')
        embedded_expected = record.get('embedded_expected', False)
        embedded_try = record.get('embedded_try', False)
        if embedded_kind is not None or embedded_expected or embedded_try:
            result = self._visit_embedded(
                data, tlv, record, hint, depth, pem_info, embedded_kind, embedded_expected
            )
            return result

        return True

    def _visit_embedded(self, data, tlv, record, hint, depth, pem_info, embedded_kind, embedded_expected):
        if tlv.content_length == 0:
            if embedded_expected:
                record['classification'] = 'opaque'
                record['status'] = 'opaque'
                record['state'] = 'opaque'
                record['reason'] = 'empty_content'
                record['opaque_reason'] = 'empty_content'
                record['openable'] = False
                record['complete'] = False
                record['boundary'] = True
            return True

        embedded_path = record['path'] + '.content'
        try:
            child = _read_tlv(data, tlv.content_offset, tlv.content_end)
        except (ValueError, TypeError) as e:
            self._charge_extra(record, tlv.content_length)
            if embedded_expected:
                record['classification'] = 'opaque'
                record['status'] = 'opaque'
                record['state'] = 'opaque'
                record['reason'] = 'unreadable'
                record['opaque_reason'] = 'unreadable'
                record['openable'] = False
                record['complete'] = False
                record['error'] = str(e)
                record['boundary'] = True
            else:
                record['classification'] = 'opaque'
                record['status'] = 'opaque'
                record['state'] = 'opaque'
                record['kind'] = 'cms.raw_content'
                record['type'] = 'cms.raw_content'
                record['reason'] = 'raw'
                record['opaque_reason'] = 'raw'
                record['openable'] = False
                record['boundary'] = True
                record['sibling_continuation'] = {
                    'possible': True,
                    'reason': 'sibling items do not require opening this layer',
                }
                record['can_continue_siblings'] = True
            return True

        if child.end != tlv.content_end and not embedded_expected:
            # A best-effort parse that leaves trailing data is too ambiguous to
            # call classified. Keep the layer opaque instead of guessing.
            self._charge_extra(record, tlv.content_length)
            record['classification'] = 'opaque'
            record['status'] = 'opaque'
            record['state'] = 'opaque'
            record['kind'] = 'cms.raw_content'
            record['type'] = 'cms.raw_content'
            record['reason'] = 'raw'
            record['opaque_reason'] = 'raw'
            record['openable'] = False
            record['boundary'] = True
            record['sibling_continuation'] = {
                'possible': True,
                'reason': 'sibling items do not require opening this layer',
            }
            record['can_continue_siblings'] = True
            return True

        child_hint = None
        if embedded_kind is not None:
            child_hint = {'kind': embedded_kind}
        result = self._visit(
            data, child, embedded_path, record, depth + 1, child_hint, True, pem_info
        )
        if result is False:
            record['complete'] = False
            record['unvisited_children'] = True
            record['has_unvisited_children'] = True
            record['pending_children'] = True
            record['next_child_index'] = 0
            return False
        if result == 'error':
            record['complete'] = False
            record['unvisited_children'] = True
            record['has_unvisited_children'] = True
            record['error'] = 'unreadable_child'
            return 'error'

        record['children'].append(embedded_path)
        record['child_count'] = 1
        record['openable'] = True
        record['complete'] = True

        # If there are multiple encoded values in a body that is expected to
        # contain exactly one, retain the first and note the trailing bytes.
        if embedded_expected and child.end < tlv.content_end:
            record['trailing_bytes'] = tlv.content_end - child.end
        return True

    def _charge_extra(self, record, amount):
        """
        Charges a primitive payload after a failed embedded parse. The charge
        is clamped to the remaining byte budget so bytes_read never exceeds the
        caller's limit, even though the confirmed layer is retained.
        """

        if amount <= 0:
            return
        if self.max_bytes is not None:
            remaining = self.max_bytes - self.bytes_read
            if remaining < 0:
                remaining = 0
            if amount > remaining:
                amount = remaining
        self.bytes_read += amount
        record['reviewed_bytes'] = record.get('reviewed_bytes', 0) + amount

    def _record_pending(self, record, child, index):
        remaining = record['content_offset'] + record['content_length'] - child.offset
        if remaining <= 0:
            return
        visited = len(record.get('children', []))
        pending_kind = 'siblings' if visited > 0 else 'children'
        self.pending.append({
            'parent': record['path'],
            'next_index': index,
            'remaining_bytes': remaining,
            'independent': True,
            'kind': pending_kind,
            'visited_children': visited,
            'reason': 'unvisited sibling items are independent of the reviewed child' if visited > 0
                      else 'unvisited child items are independent of one another',
        })

    def _result(self):
        truncated = self.budget_stopped or self.hit_depth or len(self.errors) > 0
        incomplete = []
        for entry in self.entries:
            if not entry.get('complete', True):
                incomplete.append(entry['path'])

        independent_siblings = []
        for pending in self.pending:
            if pending.get('independent'):
                independent_siblings.append(pending)

        if self.stop_reason is None and self.errors:
            self.stop_reason = 'error'
            self.stop_path = self.errors[0].get('path')
            self.stop_offset = self.errors[0].get('offset')
            self.stop_detail = self.errors[0].get('detail')

        if self.stop_detail is None:
            if self.stop_reason == 'node_budget':
                self.stop_detail = unwrap(
                    'Node budget of %s reached; confirmed parent objects and their sources were retained',
                    self.max_nodes
                )
            elif self.stop_reason == 'byte_budget':
                self.stop_detail = unwrap(
                    'Byte budget of %s reached; confirmed parent objects and their sources were retained',
                    self.max_bytes
                )
            elif self.stop_reason == 'max_depth':
                self.stop_detail = unwrap(
                    'Maximum depth of %s reached; confirmed parent objects and their sources were retained',
                    self.max_depth
                )
            elif self.stop_reason == 'error':
                self.stop_detail = 'The bundle contains an unreadable value'
            else:
                self.stop_detail = 'The complete bundle was reviewed'

        if self.stop_reason in ('node_budget', 'byte_budget', 'max_depth'):
            unvisited = []
            for entry in self.entries:
                if entry.get('has_unvisited_children'):
                    unvisited.append(entry)
            if unvisited:
                deepest = unvisited[0]
                for entry in unvisited[1:]:
                    if entry['depth'] > deepest['depth']:
                        deepest = entry
                self.stop_detail += unwrap(
                    '; confirmed parent %s (%s) was retained with its source and has unvisited child items',
                    deepest['path'],
                    deepest.get('kind')
                )
                if len(unvisited) > 1:
                    self.stop_detail += '; %s enclosing parent(s) also have unvisited children' % \
                        (len(unvisited) - 1)
            if independent_siblings:
                self.stop_detail += '; %s independent sibling boundary item(s) were noted' % \
                    len(independent_siblings)

        result = Inventory({
            'entries': self.entries,
            'items': self.entries,
            'nodes': self.entries,
            'roots': [entry['path'] for entry in self.entries if entry['parent'] is None],
            'nodes_read': self.nodes_read,
            'node_count': self.nodes_read,
            'nodes_used': self.nodes_read,
            'nodes_seen': self.nodes_read,
            'bytes_read': self.bytes_read,
            'bytes_used': self.bytes_read,
            'bytes_seen': self.bytes_read,
            'max_nodes': self.max_nodes,
            'max_bytes': self.max_bytes,
            'node_budget': self.max_nodes,
            'byte_budget': self.max_bytes,
            'max_depth': self.max_depth,
            'truncated': truncated,
            'partial': truncated,
            'budget_exceeded': self.budget_stopped,
            'complete': not truncated,
            'incomplete': incomplete,
            'is_incomplete': bool(incomplete) or truncated,
            'has_unvisited_children': any(e.get('has_unvisited_children') for e in self.entries),
            'unvisited': [
                {
                    'path': e['path'],
                    'kind': e.get('kind'),
                    'next_child_index': e.get('next_child_index'),
                    'visited_children': len(e.get('children', [])),
                }
                for e in self.entries if e.get('has_unvisited_children')
            ],
            'stop_reason': self.stop_reason,
            'stop_detail': self.stop_detail,
            'stop_path': self.stop_path,
            'stop_offset': self.stop_offset,
            'stop_next_path': self.stop_next_path,
            'stop': {
                'reason': self.stop_reason,
                'detail': self.stop_detail,
                'path': self.stop_path,
                'offset': self.stop_offset,
                'next_path': self.stop_next_path,
            },
            'pending': self.pending,
            'independent_siblings': independent_siblings,
            'siblings_remaining': bool(independent_siblings),
            'errors': self.errors,
            'classified': [e for e in self.entries if e.get('status') == 'classified'],
            'opaque': [e for e in self.entries if e.get('opaque')],
            'opaque_nodes': [e for e in self.entries if e.get('opaque')],
            'unreadable': self.errors,
            'budget': {
                'nodes': self.max_nodes,
                'bytes': self.max_bytes,
                'depth': self.max_depth,
                'nodes_used': self.nodes_read,
                'bytes_used': self.bytes_read,
            },
            'by_path': self.by_path,
        })
        return result


def inventory(data, max_nodes=None, max_bytes=None, max_depth=None, pem_mode=None,
              budget=None, node_budget=None, byte_budget=None, node_limit=None, byte_limit=None):
    """
    Builds a read-only inventory of an ASN.1 evidence bundle.

    The bundle may contain one or more concatenated BER/DER values, or PEM
    blocks. CMS ContentInfo, SignedData, EnvelopedData, EncryptedData,
    CompressedData and PKCS#12 PFX/AuthenticatedSafe/SafeContents/SafeBag
    structures are recognized where their shape is unambiguous. Encrypted,
    compressed, secret and otherwise unreadable layers are retained as opaque
    nodes with a reason, instead of being dropped or guessed at.

    :param data:
        A byte string containing the evidence bundle

    :param max_nodes:
        An optional integer maximum number of structural nodes to review. A
        parent that was confirmed before the limit is retained even when its
        children can not be visited.

    :param max_bytes:
        An optional integer maximum number of raw bytes to review. Container
        headers and leaf/opaque payloads count toward the budget; the children
        of a container are charged separately as they are visited.

    :param max_depth:
        An optional integer maximum nesting depth

    :param pem_mode:
        None to auto-detect PEM, True to force PEM handling, or False to treat
        the input as concatenated DER.

    :param budget:
        An optional 2-element tuple or dict with equivalent node/byte limits,
        e.g. {"nodes": 10, "bytes": 4096}

    :param node_budget:
        An alias for max_nodes

    :param byte_budget:
        An alias for max_bytes

    :raises:
        TypeError - when data or a budget is the wrong type
        ValueError - when a budget is negative

    :return:
        An Inventory object (a dict subclass with attribute access)
    """

    if budget is not None:
        if isinstance(budget, dict):
            if max_nodes is None:
                max_nodes = budget.get('nodes', budget.get('max_nodes'))
            if max_bytes is None:
                max_bytes = budget.get('bytes', budget.get('max_bytes'))
        elif isinstance(budget, (tuple, list)) and len(budget) == 2:
            if max_nodes is None:
                max_nodes = budget[0]
            if max_bytes is None:
                max_bytes = budget[1]
        else:
            raise TypeError('budget must be a dict or a 2-element tuple')
    if max_nodes is None:
        max_nodes = node_budget if node_budget is not None else node_limit
    if max_bytes is None:
        max_bytes = byte_budget if byte_budget is not None else byte_limit

    return _Scanner(data, max_nodes, max_bytes, max_depth, pem_mode).scan()


# Friendly aliases for callers that use different terminology for a read-only
# review manifest.
build_inventory = inventory
manifest = inventory
scan = inventory
review = inventory
audit = inventory
