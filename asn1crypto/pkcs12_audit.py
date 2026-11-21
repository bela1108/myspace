# coding: utf-8

"""
Read-only, layer-aware inventory support for PKCS#12 archives.

The functions in this module never attempt to decrypt data and never validate
passwords or MACs. They only expose information that is present in the clear
ASN.1 structure. Content below a password-protected layer is reported as
unobservable instead of being guessed at or treated as compliant.

Exports the following items:

 - Pkcs12AuditError()
 - Pkcs12GovernanceReport()
 - Pkcs12Inventory()
 - Pkcs12Policy()
 - governance_report()
 - inventory()
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import json
import os
from binascii import hexlify
from collections import OrderedDict

from .cms import SignedData
from .core import Void
from .keys import EncryptedPrivateKeyInfo, PrivateKeyInfo
from .pem import detect as pem_detect, unarmor as pem_unarmor
from .pkcs12 import AuthenticatedSafe, CertBag, Pfx, SafeContents


try:
    string_types = (basestring,)  # noqa
    integer_types = (int, long)  # noqa
except NameError:
    string_types = (str,)
    integer_types = (int,)


byte_types = (bytes, bytearray)


_SEVERITY_RANK = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'unknown': 1,
    'none': 0,
}


_SAFE_CIPHERS = set([
    'aes128_cbc',
    'aes192_cbc',
    'aes256_cbc',
    'aes128_cfb',
    'aes192_cfb',
    'aes256_cfb',
    'aes128_ofb',
    'aes192_ofb',
    'aes256_ofb',
    'aes128_gcm',
    'aes192_gcm',
    'aes256_gcm',
    'aes128_ccm',
    'aes192_ccm',
    'aes256_ccm',
])


_WEAK_CIPHERS = set([
    'des',
    'tripledes_2key',
    'tripledes_3key',
    'rc2',
    'rc2_40',
    'rc2_128',
    'rc4',
    'rc4_40',
    'rc4_128',
    'rc5',
])


_SAFE_MACS = set([
    'sha224',
    'sha256',
    'sha384',
    'sha512',
    'sha512_224',
    'sha512_256',
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512',
])


_WEAK_MACS = set([
    'md2',
    'md4',
    'md5',
    'sha1',
    'des_mac',
])


_PBE_NAME_PARTS = {
    'pkcs12_sha1_rc4_128': ('pkcs12', 'rc4_128', 'sha1'),
    'pkcs12_sha1_rc4_40': ('pkcs12', 'rc4_40', 'sha1'),
    'pkcs12_sha1_tripledes_3key': ('pkcs12', 'tripledes_3key', 'sha1'),
    'pkcs12_sha1_tripledes_2key': ('pkcs12', 'tripledes_2key', 'sha1'),
    'pkcs12_sha1_rc2_128': ('pkcs12', 'rc2_128', 'sha1'),
    'pkcs12_sha1_rc2_40': ('pkcs12', 'rc2_40', 'sha1'),
    'pbes1_md2_des': ('pbes1', 'des', 'md2'),
    'pbes1_md5_des': ('pbes1', 'des', 'md5'),
    'pbes1_md2_rc2': ('pbes1', 'rc2', 'md2'),
    'pbes1_md5_rc2': ('pbes1', 'rc2', 'md5'),
    'pbes1_sha1_des': ('pbes1', 'des', 'sha1'),
    'pbes1_sha1_rc2': ('pbes1', 'rc2', 'sha1'),
}


_PROTECTION_ATTRIBUTE_TYPES = set([
    'local_key_id',
    'trusted_key_usage',
    'microsoft_local_machine_keyset',
    'microsoft_csp_name',
])


DEFAULT_POLICY = {
    'allowed_ciphers': sorted(_SAFE_CIPHERS),
    'weak_ciphers': sorted(_WEAK_CIPHERS),
    'allowed_mac_algorithms': sorted(_SAFE_MACS),
    'weak_mac_algorithms': sorted(_WEAK_MACS),
    'allowed_prfs': ['sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_384', 'sha3_512'],
    'min_pbkdf2_iterations': 100000,
    'require_integrity': True,
    'require_encrypted_private_keys': True,
    'unobservable_action': 'review',
    'unknown_action': 'review',
}


_POLICY_KEYS = set(DEFAULT_POLICY.keys())


class Pkcs12GovernanceReport(OrderedDict):
    """
    A batch report. Keys are also available as attributes and the report can
    be serialized with to_dict()/to_json().
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    @property
    def native(self):
        return self.to_dict()

    def to_dict(self):
        return _plain_value(self)

    def to_json(self, **kwargs):
        kwargs.setdefault('indent', 2)
        kwargs.setdefault('sort_keys', False)
        return json.dumps(_json_value(self), **kwargs)


class Pkcs12AuditError(ValueError):
    """
    Raised when the input can not be interpreted as a PKCS#12 archive.
    """

    pass


class Pkcs12Policy(OrderedDict):
    """
    A normalized audit policy. Unknown keys are retained, but only the keys
    documented in DEFAULT_POLICY affect the built-in checks.
    """

    def __init__(self, value=None, **kwargs):
        if value is None:
            value = {}
        if not isinstance(value, dict):
            raise TypeError('policy must be a dict')
        policy = dict(DEFAULT_POLICY)
        policy.update(value)
        policy.update(kwargs)
        for key in (
            'allowed_ciphers',
            'weak_ciphers',
            'allowed_mac_algorithms',
            'weak_mac_algorithms',
            'allowed_prfs',
        ):
            policy[key] = sorted(set(policy[key]))
        OrderedDict.__init__(self, sorted(policy.items()))

    def to_dict(self):
        return OrderedDict((key, _json_value(value)) for key, value in self.items())


class Pkcs12Inventory(OrderedDict):
    """
    A read-only inventory of a single PKCS#12 archive.

    Keys are also available as attributes, e.g. inventory.safe_bags.
    """

    _aliases = {
        'bags': 'safe_bags',
        'mac': 'integrity',
        'policy_findings': 'findings',
        'sealed': 'unobservable',
        'unsupported': 'unknown',
    }

    def __getattr__(self, name):
        if name in self._aliases:
            return self[self._aliases[name]]
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, key):
        return OrderedDict.__getitem__(self, self._aliases.get(key, key))

    def __contains__(self, key):
        return OrderedDict.__contains__(self, self._aliases.get(key, key))

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    @property
    def native(self):
        return self.to_dict()

    def to_dict(self):
        return _plain_value(self)

    def to_json(self, **kwargs):
        kwargs.setdefault('indent', 2)
        kwargs.setdefault('sort_keys', False)
        return json.dumps(_json_value(self), **kwargs)


def inventory(value, policy=None):
    """
    Builds a read-only protection inventory for a PKCS#12 archive.

    :param value:
        A Pfx object, DER/PEM bytes, a file-like object or a filesystem path

    :param policy:
        None for DEFAULT_POLICY, or a dict/Pkcs12Policy of audit thresholds

    :return:
        A Pkcs12Inventory instance
    """

    return inventory_pfx(_load_pfx(value), policy=policy)


def inventory_pfx(pfx, policy=None):
    """
    Builds a read-only protection inventory for a parsed Pfx object.

    :param pfx:
        A Pfx object

    :param policy:
        None for DEFAULT_POLICY, or a dict/Pkcs12Policy of audit thresholds

    :return:
        A Pkcs12Inventory instance
    """

    if not isinstance(pfx, Pfx):
        raise TypeError('pfx must be an asn1crypto.pkcs12.Pfx object')

    normalized_policy = _normalize_policy(policy)

    result = Pkcs12Inventory()
    result['kind'] = 'pkcs12_inventory'
    result['format'] = 'PKCS#12'
    result['version'] = _safe_native(pfx['version'])
    result['observable'] = True
    result['encapsulation'] = []
    result['safe_bags'] = []
    result['integrities'] = []
    result['unobservable'] = []
    result['unknown'] = []
    result['entries'] = []
    result['checks'] = []
    result['findings'] = []
    result['policy'] = normalized_policy

    entries = result['entries']
    encapsulation = result['encapsulation']
    bag_entries = result['safe_bags']
    integrities = result['integrities']
    unobservable = result['unobservable']
    unknown = result['unknown']

    _collect_integrity(pfx, integrities, unobservable, unknown)

    auth_safe = pfx['auth_safe']
    outer_entry = _describe_content_info(
        auth_safe,
        'pfx.auth_safe',
        'pfx.auth_safe',
        unobservable,
        unknown,
        integrities
    )
    encapsulation.append(outer_entry)
    entries.append(outer_entry)

    raw_authenticated_safe = _read_content_info_bytes(auth_safe, outer_entry, unobservable, unknown)
    authenticated_safe = None
    if raw_authenticated_safe is not None:
        try:
            authenticated_safe = AuthenticatedSafe.load(raw_authenticated_safe)
        except Exception:
            _mark_unknown(
                outer_entry,
                unknown,
                'malformed_authenticated_safe',
                'The authSafe content is readable but is not a valid AuthenticatedSafe'
            )

    if authenticated_safe is not None:
        for index, content_info in enumerate(authenticated_safe):
            layer = 'pfx.authenticated_safe[%d]' % index
            entry = _describe_content_info(
                content_info,
                layer,
                layer,
                unobservable,
                unknown,
                integrities
            )
            entry['index'] = index
            encapsulation.append(entry)
            entries.append(entry)

            raw = _read_content_info_bytes(content_info, entry, unobservable, unknown)
            if raw is None:
                continue

            content_type = entry['content_type']
            if content_type == 'data':
                _describe_safe_contents(raw, layer + '.safe_contents', bag_entries, entries, unobservable, unknown)
            elif content_type == 'signed_data':
                _describe_safe_contents(raw, layer + '.safe_contents', bag_entries, entries, unobservable, unknown)

    result['integrity'] = integrities[0] if len(integrities) > 0 else OrderedDict([
        ('kind', 'integrity'),
        ('type', 'mac'),
        ('layer', 'pfx.mac_data'),
        ('scope_layer', 'pfx'),
        ('present', False),
        ('observable', True),
        ('algorithm', None),
        ('algorithm_oid', None),
        ('status', 'fail'),
        ('severity', 'high'),
        ('reasons', ['missing_integrity']),
    ])

    for integrity in integrities:
        if not any(item is integrity for item in entries):
            entries.append(integrity)
    if not any(item is result['integrity'] for item in entries):
        entries.append(result['integrity'])

    result['auth_safe'] = outer_entry
    result['authenticated_safe'] = encapsulation[1:]
    result['layers'] = entries

    _assess(result, normalized_policy)
    return result


def assess_inventory(value, policy=None):
    """
    Re-runs policy checks against an existing inventory without re-reading the
    archive. This is useful when the same observations are evaluated under
    multiple governance policies.

    :param value:
        A Pkcs12Inventory instance

    :param policy:
        None for DEFAULT_POLICY, or a dict/Pkcs12Policy of audit thresholds

    :return:
        A new Pkcs12Inventory instance
    """

    if not isinstance(value, Pkcs12Inventory):
        if isinstance(value, dict) and value.get('kind') == 'pkcs12_inventory':
            value = Pkcs12Inventory(value)
        else:
            raise TypeError('value must be a Pkcs12Inventory')

    result = Pkcs12Inventory()
    memo = {}
    for key, item in value.items():
        if key in ('checks', 'findings', 'summary', 'policy', 'layers'):
            continue
        result[key] = _copy_plain(item, memo)
    normalized_policy = _normalize_policy(policy if policy is not None else value.get('policy'))
    result['layers'] = result['entries']
    result['policy'] = normalized_policy
    result['checks'] = []
    result['findings'] = []
    _assess(result, normalized_policy)
    return result


def governance_report(archives, *extra, **kwargs):
    """
    Produces a batch governance report from one or more archives or
    inventories.

    :param archives:
        A Pfx, bytes, path, Pkcs12Inventory, or a list/tuple of those values.
        A list of (name, value) tuples may be used to label archives.

    :param extra:
        Additional archives. A single dict containing policy keys in this
        position is treated as the policy for backwards-friendly calls.

    :param kwargs:
        policy - None for DEFAULT_POLICY, or a dict/Pkcs12Policy
        names - an optional list of archive names

    :return:
        An OrderedDict containing findings, layers_to_change and summary
    """

    policy = kwargs.pop('policy', None)
    names = kwargs.pop('names', None)
    if kwargs:
        raise TypeError('unexpected keyword arguments: %s' % ', '.join(sorted(kwargs.keys())))

    if policy is None:
        for index, item in enumerate(extra):
            if _looks_like_policy(item):
                policy = item
                extra = extra[:index] + extra[index + 1:]
                break

    values = [archives]
    values.extend(extra)

    normalized_policy = _normalize_policy(policy)
    archive_items = _normalize_archive_items(values, names)

    report = Pkcs12GovernanceReport()
    report['kind'] = 'pkcs12_governance_report'
    report['format'] = 'PKCS#12'
    report['policy'] = normalized_policy
    report['archives'] = []
    report['findings'] = []
    report['layers_to_change'] = []
    report['review_required'] = []

    for name, value in archive_items:
        if isinstance(value, Pkcs12Inventory):
            inventory_value = assess_inventory(value, normalized_policy)
        elif isinstance(value, dict) and value.get('kind') == 'pkcs12_inventory':
            inventory_value = assess_inventory(Pkcs12Inventory(value), normalized_policy)
        else:
            inventory_value = inventory(value, policy=normalized_policy)

        archive_findings = []
        for finding in inventory_value['findings']:
            item = OrderedDict(finding)
            item['archive'] = name
            archive_findings.append(item)
            report['findings'].append(item)

            if item['status'] == 'fail':
                report['layers_to_change'].append(item)
            elif item['status'] in ('unobservable', 'unknown'):
                report['review_required'].append(item)

        report['archives'].append(OrderedDict([
            ('name', name),
            ('status', inventory_value['summary']['status']),
            ('inventory', inventory_value),
        ]))

    report['layers_to_change'] = _dedupe_findings(report['layers_to_change'])
    report['review_required'] = _dedupe_findings(report['review_required'])
    report['layers_to_change'].sort(key=_finding_sort_key)
    report['review_required'].sort(key=_finding_sort_key)

    fail_count = len(report['layers_to_change'])
    review_count = len(report['review_required'])

    if fail_count > 0:
        conclusion = 'change_required'
    elif review_count > 0:
        conclusion = 'review_required'
    else:
        conclusion = 'pass'

    recommended_layers = []
    seen_layers = set()
    for item in report['layers_to_change']:
        layer = item['layer']
        if layer not in seen_layers:
            seen_layers.add(layer)
            recommended_layers.append(layer)
    report['recommended_layers'] = recommended_layers
    report['recommended_layer'] = recommended_layers[0] if len(recommended_layers) > 0 else None
    report['recommended_finding'] = report['layers_to_change'][0] if fail_count > 0 else None
    report['summary'] = OrderedDict([
        ('archives', len(archive_items)),
        ('findings', len(report['findings'])),
        ('failures', fail_count),
        ('review_required', review_count),
        ('compliant', conclusion == 'pass'),
        ('conclusion', conclusion),
    ])
    return report


def _normalize_policy(policy):
    if isinstance(policy, Pkcs12Policy):
        return Pkcs12Policy(policy.to_dict())
    if policy is None:
        return Pkcs12Policy()
    return Pkcs12Policy(policy)


def _looks_like_policy(value):
    return isinstance(value, dict) and value.get('kind') not in ('pkcs12_inventory', 'pkcs12_governance_report') and (
        len(set(value.keys()) & _POLICY_KEYS) > 0
    )


def _normalize_archive_items(values, names):
    items = []
    flat = []
    for value in values:
        if _is_archive_sequence(value):
            for item in value:
                if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], string_types):
                    flat.append((item[0], item[1]))
                else:
                    flat.append((None, item))
        else:
            flat.append((None, value))

    if names is not None and len(names) != len(flat):
        raise ValueError('names must contain exactly one name per archive')

    for index, item in enumerate(flat):
        name = item[0]
        if name is None and names is not None:
            name = names[index]
        if name is None:
            name = 'archive[%d]' % index
        items.append((name, item[1]))
    return items


def _is_archive_sequence(value):
    if not isinstance(value, (list, tuple)):
        return False
    if len(value) == 0:
        return False
    return True


def _load_pfx(value):
    if isinstance(value, Pfx):
        return value
    if hasattr(value, 'read') and not isinstance(value, string_types):
        return Pfx.load(value.read())
    if isinstance(value, bytearray):
        value = bytes(value)
    if isinstance(value, byte_types):
        if pem_detect(value):
            _, _, value = pem_unarmor(value)
        return Pfx.load(value)
    if isinstance(value, string_types):
        if os.path.exists(value):
            with open(value, 'rb') as f:
                return Pfx.load(f.read())
        if not isinstance(value, bytes):
            value = value.encode('latin-1')
        return Pfx.load(value)
    raise Pkcs12AuditError('value must be DER/PEM bytes, a path, a file-like object or a Pfx')


def _describe_content_info(content_info, layer, scope_layer, unobservable, unknown, integrities):
    entry = OrderedDict([
        ('kind', 'encapsulation'),
        ('layer', layer),
        ('scope_layer', scope_layer),
        ('path', layer),
        ('content_type', None),
        ('content_type_oid', None),
        ('observable', True),
        ('content_state', 'unknown'),
        ('unobservable_reason', None),
        ('encrypted', False),
        ('algorithm', None),
        ('algorithm_oid', None),
        ('family', None),
        ('cipher', None),
        ('cipher_oid', None),
        ('kdf', None),
        ('kdf_oid', None),
        ('prf', None),
        ('iterations', None),
        ('salt_length', None),
        ('iv_length', None),
        ('parameters', OrderedDict()),
        ('protection_layer', None),
    ])

    try:
        content_type = content_info['content_type'].native
        content_type_oid = content_info['content_type'].dotted
    except Exception as exc:
        entry['observable'] = False
        entry['unobservable_reason'] = _exception_message(exc)
        _mark_unknown(entry, unknown, 'unreadable_content_type', 'The ContentInfo content type is not readable')
        return entry

    entry['content_type'] = content_type
    entry['content_type_oid'] = content_type_oid

    if content_type == 'data':
        entry['content_state'] = 'observable'
        return entry

    if content_type in ('encrypted_data', 'enveloped_data'):
        encrypted_content_info = None
        try:
            content = content_info['content']
            if content_type == 'encrypted_data':
                encrypted_content_info = content['encrypted_content_info']
            else:
                encrypted_content_info = content['encrypted_content_info']
            algorithm = encrypted_content_info['content_encryption_algorithm']
        except Exception as exc:
            entry['observable'] = False
            entry['unobservable_reason'] = _exception_message(exc)
            _mark_unknown(entry, unknown, 'unreadable_encryption_headers', 'Encryption headers are not readable')
            return entry

        protection_layer = layer + '.encrypted_content_info'
        encryption = _describe_encryption(algorithm, protection_layer, scope_layer)
        _merge_encryption(entry, encryption)
        entry['encrypted'] = True
        entry['content_state'] = 'unobservable'
        entry['unobservable_reason'] = content_type
        entry['protection_layer'] = protection_layer
        _add_unobservable(
            unobservable,
            protection_layer,
            scope_layer,
            content_type,
            encryption
        )
        return entry

    if content_type == 'signed_data':
        try:
            signed_data = content_info['content']
            if isinstance(signed_data, SignedData):
                _collect_signed_integrity(signed_data, layer, integrities, unknown)
        except Exception as exc:
            entry['observable'] = False
            entry['unobservable_reason'] = _exception_message(exc)
            _mark_unknown(entry, unknown, 'unreadable_signed_data', 'SignedData headers are not readable')
            return entry
        entry['content_state'] = 'observable'
        return entry

    entry['observable'] = True
    entry['content_state'] = 'unknown'
    entry['unobservable_reason'] = 'unsupported_content_type'
    _mark_unknown(
        entry,
        unknown,
        'unsupported_content_type',
        'Content type %s can not be inventoried without decrypting or interpreting another format' % content_type
    )
    return entry


def _read_content_info_bytes(content_info, entry, unobservable, unknown):
    content_type = entry['content_type']

    if content_type == 'data':
        try:
            return content_info['content'].native
        except Exception as exc:
            _mark_unknown(
                entry,
                unknown,
                'unreadable_data_content',
                'The data content is not readable: %s' % _exception_message(exc)
            )
            return None

    if content_type != 'signed_data':
        return None

    try:
        signed_data = content_info['content']
        encap_content_info = signed_data['encap_content_info']
        content = encap_content_info['content']
        if isinstance(content, Void):
            return None
        value = content.native
        if isinstance(value, bytearray):
            value = bytes(value)
        return value
    except Exception as exc:
        _mark_unknown(
            entry,
            unknown,
            'unreadable_signed_content',
            'The signed content is not readable: %s' % _exception_message(exc)
        )
        return None


def _describe_encryption(algorithm, layer, scope_layer):
    result = OrderedDict([
        ('kind', 'encryption'),
        ('layer', layer),
        ('scope_layer', scope_layer),
        ('path', layer),
        ('observable', True),
        ('algorithm', None),
        ('algorithm_oid', None),
        ('family', None),
        ('cipher', None),
        ('cipher_oid', None),
        ('kdf', None),
        ('kdf_oid', None),
        ('prf', None),
        ('prf_oid', None),
        ('iterations', None),
        ('salt_length', None),
        ('iv_length', None),
        ('key_length', None),
        ('parameters', OrderedDict()),
    ])

    try:
        result['algorithm'] = algorithm['algorithm'].native
        result['algorithm_oid'] = algorithm['algorithm'].dotted
    except Exception as exc:
        result['observable'] = False
        result['error'] = _exception_message(exc)
        return result

    name = result['algorithm']
    result['cipher'] = name
    result['cipher_oid'] = result['algorithm_oid']

    try:
        result['parameters'] = _parameters_native(algorithm['parameters'])
    except Exception:
        result['parameters'] = OrderedDict()

    try:
        if name == 'pbes2':
            result['family'] = 'pbes2'
            params = algorithm['parameters']
            kdf = params['key_derivation_func']
            result['kdf'] = kdf['algorithm'].native
            result['kdf_oid'] = kdf['algorithm'].dotted
            kdf_params = kdf['parameters']

            if result['kdf'] == 'pbkdf2':
                result['iterations'] = _safe_native(kdf_params['iteration_count'])
                result['salt_length'] = _salt_length(kdf_params['salt'])
                prf = kdf_params['prf']
                result['prf'] = _safe_native(prf['algorithm'])
                result['prf_oid'] = _safe_oid(prf['algorithm'])
                result['key_length'] = _safe_native(kdf_params['key_length'])
            elif result['kdf'] == 'scrypt':
                result['salt_length'] = _octet_length(kdf_params['salt'])
                result['parameters']['cost_parameter'] = _safe_native(kdf_params['cost_parameter'])
                result['parameters']['block_size'] = _safe_native(kdf_params['block_size'])
                result['parameters']['parallelization_parameter'] = _safe_native(
                    kdf_params['parallelization_parameter']
                )
                result['key_length'] = _safe_native(kdf_params['key_length'])

            scheme = params['encryption_scheme']
            result['cipher'] = scheme['algorithm'].native
            result['cipher_oid'] = scheme['algorithm'].dotted
            result['iv_length'] = _cipher_iv_length(scheme)

        elif name in _PBE_NAME_PARTS:
            family, cipher, prf = _PBE_NAME_PARTS[name]
            result['family'] = family
            result['cipher'] = cipher
            result['kdf'] = family
            result['prf'] = prf
            params = algorithm['parameters']
            result['salt_length'] = _octet_length(params['salt'])
            result['iterations'] = _safe_native(params['iterations'])

        else:
            result['family'] = 'direct'
            result['iv_length'] = _cipher_iv_length(algorithm)

    except Exception as exc:
        result['observable'] = False
        result['error'] = _exception_message(exc)

    return result


def _merge_encryption(entry, encryption):
    for key in (
        'observable',
        'algorithm',
        'algorithm_oid',
        'family',
        'cipher',
        'cipher_oid',
        'kdf',
        'kdf_oid',
        'prf',
        'prf_oid',
        'iterations',
        'salt_length',
        'iv_length',
        'parameters',
    ):
        if key in encryption:
            entry[key] = encryption[key]
    if 'key_length' in encryption:
        entry['key_length'] = encryption['key_length']
    if 'error' in encryption:
        entry['error'] = encryption['error']


def _describe_safe_contents(raw, base_layer, bag_entries, entries, unobservable, unknown, depth=0):
    if depth > 32:
        dummy = OrderedDict([
            ('kind', 'safe_bag'),
            ('layer', base_layer),
            ('scope_layer', base_layer),
            ('path', base_layer),
            ('observable', True),
            ('content_state', 'unknown'),
            ('encrypted', False),
            ('algorithm', None),
        ])
        _mark_unknown(dummy, unknown, 'nesting_limit', 'SafeBag nesting exceeds the audit limit')
        entries.append(dummy)
        return

    try:
        safe_contents = SafeContents.load(raw)
    except Exception:
        dummy = OrderedDict([
            ('kind', 'safe_contents'),
            ('layer', base_layer),
            ('scope_layer', base_layer),
            ('path', base_layer),
            ('observable', True),
            ('content_state', 'unknown'),
            ('encrypted', False),
            ('algorithm', None),
        ])
        _mark_unknown(dummy, unknown, 'malformed_safe_contents', 'SafeContents is not a valid sequence of SafeBag')
        entries.append(dummy)
        return

    for index, bag in enumerate(safe_contents):
        layer = '%s[%d]' % (base_layer, index)
        entry = _describe_safe_bag(
            bag,
            layer,
            bag_entries,
            entries,
            unobservable,
            unknown,
            depth
        )
        if entry is not None:
            bag_entries.append(entry)
            entries.append(entry)


def _describe_safe_bag(bag, layer, bag_entries, entries, unobservable, unknown, depth):
    entry = OrderedDict([
        ('kind', 'safe_bag'),
        ('layer', layer),
        ('scope_layer', layer),
        ('path', layer),
        ('bag_id', None),
        ('bag_oid', None),
        ('observable', True),
        ('content_state', 'observable'),
        ('encrypted', False),
        ('algorithm', None),
        ('algorithm_oid', None),
        ('family', None),
        ('cipher', None),
        ('cipher_oid', None),
        ('kdf', None),
        ('kdf_oid', None),
        ('prf', None),
        ('prf_oid', None),
        ('iterations', None),
        ('salt_length', None),
        ('iv_length', None),
        ('parameters', OrderedDict()),
        ('protection_layer', None),
        ('key_algorithm', None),
        ('key_algorithm_oid', None),
        ('certificate_algorithm', None),
        ('attributes', []),
        ('visible_attributes', []),
        ('protection_attributes', []),
    ])

    try:
        entry['bag_id'] = bag['bag_id'].native
        entry['bag_oid'] = bag['bag_id'].dotted
    except Exception as exc:
        entry['observable'] = False
        _mark_unknown(
            entry,
            unknown,
            'unreadable_bag_id',
            'The SafeBag id is not readable: %s' % _exception_message(exc)
        )
        return entry

    attributes = _describe_attributes(bag)
    entry['attributes'] = attributes
    entry['visible_attributes'] = attributes
    entry['protection_attributes'] = [
        attribute for attribute in attributes
        if attribute['type'] in _PROTECTION_ATTRIBUTE_TYPES
    ]

    try:
        bag_value = bag['bag_value']
    except Exception as exc:
        _mark_unknown(
            entry,
            unknown,
            'unreadable_bag_value',
            'The SafeBag value is not readable: %s' % _exception_message(exc)
        )
        return entry

    if isinstance(bag_value, Void):
        _mark_unknown(
            entry,
            unknown,
            'missing_bag_value',
            'The SafeBag has no value at this layer'
        )
        return entry

    if isinstance(bag_value, EncryptedPrivateKeyInfo):
        protection_layer = layer + '.bag_value'
        encryption = _describe_encryption(
            bag_value['encryption_algorithm'],
            protection_layer + '.encryption_algorithm',
            protection_layer
        )
        _merge_encryption(entry, encryption)
        entry['encrypted'] = True
        entry['content_state'] = 'unobservable'
        entry['unobservable_reason'] = 'encrypted_private_key_info'
        entry['protection_layer'] = protection_layer
        _add_unobservable(
            unobservable,
            protection_layer,
            layer,
            'encrypted_private_key_info',
            encryption
        )
        return entry

    if isinstance(bag_value, PrivateKeyInfo):
        entry['key_algorithm'], entry['key_algorithm_oid'] = _describe_private_key_info(bag_value)
        entry['content_state'] = 'observable'
        entry['protection_layer'] = layer + '.bag_value'
        return entry

    if isinstance(bag_value, CertBag):
        entry['certificate_algorithm'] = _describe_cert_bag(bag_value)
        entry['content_state'] = 'observable'
        return entry

    if entry['bag_id'] == 'crl_bag':
        entry['content_state'] = 'observable'
        return entry

    if entry['bag_id'] == 'secret_bag':
        try:
            entry['secret_type_id'] = bag_value['secret_type_id'].native
            entry['secret_type_oid'] = bag_value['secret_type_id'].dotted
        except Exception:
            pass
        entry['content_state'] = 'unknown'
        entry['unobservable_reason'] = 'opaque_secret_bag'
        _mark_unknown(
            entry,
            unknown,
            'opaque_secret_bag',
            'SecretBag content is opaque and is not assessed by this inventory'
        )
        return entry

    if entry['bag_id'] == 'safe_contents':
        nested = bag_value
        if isinstance(nested, SafeContents):
            nested_layer = layer + '.bag_value.safe_contents'
            for index, nested_bag in enumerate(nested):
                child_layer = '%s[%d]' % (nested_layer, index)
                child = _describe_safe_bag(
                    nested_bag,
                    child_layer,
                    bag_entries,
                    entries,
                    unobservable,
                    unknown,
                    depth + 1
                )
                if child is not None:
                    bag_entries.append(child)
                    entries.append(child)
            entry['content_state'] = 'observable'
            return entry
        return entry

    if entry['bag_id'] == 'key_bag':
        entry['content_state'] = 'observable'
        return entry

    entry['content_state'] = 'unknown'
    entry['unobservable_reason'] = 'unrecognized_bag_id'
    _mark_unknown(
        entry,
        unknown,
        'unrecognized_bag_id',
        'The SafeBag type %s is not understood by this inventory' % entry['bag_id']
    )
    return entry


def _describe_attributes(bag):
    attributes = []
    try:
        if 'bag_attributes' not in bag:
            return attributes
        bag_attributes = bag['bag_attributes']
    except Exception:
        return attributes

    for attribute in bag_attributes:
        try:
            attribute_type = attribute['type'].native
            attribute_oid = attribute['type'].dotted
        except Exception:
            attribute_type = None
            attribute_oid = None

        try:
            values = attribute['values'].native
        except Exception as exc:
            values = _exception_message(exc)

        attributes.append(OrderedDict([
            ('type', attribute_type),
            ('type_oid', attribute_oid),
            ('values', _json_value(values)),
            ('observable', True),
        ]))
    return attributes


def _describe_private_key_info(private_key_info):
    try:
        algorithm = private_key_info['private_key_algorithm']['algorithm']
        return algorithm.native, algorithm.dotted
    except Exception:
        return None, None


def _describe_cert_bag(cert_bag):
    try:
        cert_value = cert_bag['cert_value']
        certificate = cert_value.parsed
        if certificate is None:
            certificate = cert_value
        signature_algorithm = certificate['signature_algorithm']['algorithm'].native
        return signature_algorithm
    except Exception:
        return None


def _collect_integrity(pfx, integrities, unobservable, unknown):
    try:
        mac_data = pfx['mac_data']
        if isinstance(mac_data, Void):
            return
        digest_info = mac_data['mac']
        digest_algorithm = digest_info['digest_algorithm']
        algorithm = digest_algorithm['algorithm'].native
        algorithm_oid = digest_algorithm['algorithm'].dotted
        digest_length = None
        mac_length = None
        salt_length = None
        iterations = None
        try:
            digest_length = len(digest_info['digest'].native)
        except Exception:
            pass
        try:
            mac_length = digest_length
            salt_length = len(mac_data['mac_salt'].native)
            iterations = _safe_native(mac_data['iterations'])
        except Exception:
            pass
        integrities.append(OrderedDict([
            ('kind', 'integrity'),
            ('type', 'mac'),
            ('layer', 'pfx.mac_data'),
            ('scope_layer', 'pfx'),
            ('present', True),
            ('observable', True),
            ('algorithm', algorithm),
            ('algorithm_oid', algorithm_oid),
            ('digest_length', digest_length),
            ('mac_length', mac_length),
            ('salt_length', salt_length),
            ('iterations', iterations),
            ('parameters', OrderedDict()),
        ]))
    except Exception as exc:
        dummy = OrderedDict([
            ('kind', 'integrity'),
            ('type', 'mac'),
            ('layer', 'pfx.mac_data'),
            ('scope_layer', 'pfx'),
            ('present', True),
            ('observable', False),
            ('algorithm', None),
            ('algorithm_oid', None),
        ])
        _mark_unknown(
            dummy,
            unknown,
            'unreadable_integrity',
            'MacData is present but not readable: %s' % _exception_message(exc)
        )
        integrities.append(dummy)


def _collect_signed_integrity(signed_data, layer, integrities, unknown):
    try:
        digest_algorithms = signed_data["digest_algorithms"]
    except Exception:
        digest_algorithms = []

    digests = []
    for digest_algorithm in digest_algorithms:
        try:
            digests.append(OrderedDict([
                ("algorithm", digest_algorithm["algorithm"].native),
                ("algorithm_oid", digest_algorithm["algorithm"].dotted),
            ]))
        except Exception:
            digests.append(OrderedDict([
                ("algorithm", None),
                ("algorithm_oid", None),
            ]))

    try:
        signer_infos = signed_data["signer_infos"]
    except Exception:
        signer_infos = []

    signatures = []
    for index, signer_info in enumerate(signer_infos):
        try:
            digest = signer_info["digest_algorithm"]["algorithm"].native
            signature = signer_info["signature_algorithm"]["algorithm"].native
        except Exception:
            digest = None
            signature = None
        signatures.append(OrderedDict([
            ("index", index),
            ("digest_algorithm", digest),
            ("signature_algorithm", signature),
            ("layer", "%s.signer_infos[%d]" % (layer, index)),
        ]))

    for index, digest in enumerate(digests):
        integrities.append(OrderedDict([
            ("kind", "integrity"),
            ("type", "signed_data_digest"),
            ("layer", "%s.digest_algorithms[%d]" % (layer, index)),
            ("scope_layer", layer),
            ("present", True),
            ("observable", digest["algorithm"] is not None),
            ("algorithm", digest["algorithm"]),
            ("algorithm_oid", digest["algorithm_oid"]),
            ("digest_algorithms", [_copy_plain(item) for item in digests]),
            ("signatures", [_copy_plain(item) for item in signatures]),
            ("parameters", OrderedDict()),
        ]))


def _assess(result, policy):
    checks = result['checks']
    findings = result['findings']

    for entry in result['entries']:
        if entry.get('kind') == 'encapsulation' and entry.get('algorithm') is not None:
            _assess_encryption(entry, policy, checks, findings)
        elif entry.get('kind') == 'safe_bag' and entry.get('algorithm') is not None:
            _assess_encryption(entry, policy, checks, findings)

    for entry in result['entries']:
        if entry.get('kind') == 'safe_bag' and entry.get('bag_id') == 'key_bag':
            if entry.get('content_state') == 'observable' and not entry.get('encrypted', False):
                _assess_unprotected_key_bag(entry, policy, checks, findings)

    for integrity in result['integrities']:
        _assess_integrity(integrity, policy, checks, findings)

    if result['integrity'].get('present') is False and result['integrity'].get('status') == 'fail':
        _assess_integrity(result['integrity'], policy, checks, findings)

    for item in result['unobservable']:
        status = 'unobservable'
        action = policy.get('unobservable_action', 'review')
        if action == 'ignore':
            status = 'pass'
        elif action == 'fail':
            status = 'fail'
        check = OrderedDict([
            ('kind', 'observability'),
            ('layer', item['layer']),
            ('scope_layer', item['scope_layer']),
            ('status', status),
            ('severity', 'unknown' if status != 'pass' else 'none'),
            ('reason', item['reason']),
        ])
        checks.append(check)
        if status != 'pass':
            findings.append(OrderedDict([
                ('code', 'unobservable_content'),
                ('layer', item['layer']),
                ('scope_layer', item['scope_layer']),
                ('algorithm', item.get('algorithm')),
                ('status', status),
                ('severity', 'unknown'),
                ('message', 'Content below this layer is sealed; its inner protections can not be assessed'),
            ]))

    for item in result['unknown']:
        status = 'unknown'
        action = policy.get('unknown_action', 'review')
        if action == 'review':
            status = 'unknown'
        elif action == 'ignore':
            status = 'pass'
        elif action == 'fail':
            status = 'fail'
        check = OrderedDict([
            ('kind', 'observability'),
            ('layer', item['layer']),
            ('scope_layer', item['scope_layer']),
            ('status', status),
            ('severity', 'unknown' if status != 'pass' else 'none'),
            ('reason', item['reason']),
        ])
        checks.append(check)
        if status != 'pass':
            findings.append(OrderedDict([
                ('code', item['reason']),
                ('layer', item['layer']),
                ('scope_layer', item['scope_layer']),
                ('algorithm', item.get('algorithm')),
                ('status', status),
                ('severity', 'unknown'),
                ('message', item['message']),
            ]))

    counts = OrderedDict([
        ('pass', 0),
        ('fail', 0),
        ('unobservable', 0),
        ('unknown', 0),
    ])
    for check in checks:
        status = check['status']
        if status not in counts:
            counts[status] = 0
        counts[status] += 1

    if counts.get('fail', 0) > 0:
        status = 'fail'
    elif counts.get('unknown', 0) > 0:
        status = 'unknown'
    elif counts.get('unobservable', 0) > 0:
        status = 'review_required'
    else:
        status = 'pass'

    sealed_layers = len(result['unobservable'])
    unknown_layers = len(result['unknown'])
    result['summary'] = OrderedDict([
        ('status', status),
        ('compliant', status == 'pass'),
        ('coverage', 'partial' if sealed_layers > 0 or unknown_layers > 0 else 'complete'),
        ('layers_total', len(result['entries'])),
        ('observable_layers', len([
            entry for entry in result['entries']
            if entry.get('observable') is True and entry.get('content_state') not in ('unobservable', 'unknown')
        ])),
        ('sealed_layers', sealed_layers),
        ('unknown_layers', unknown_layers),
        ('pass_count', counts.get('pass', 0)),
        ('fail_count', counts.get('fail', 0)),
        ('unobservable_count', counts.get('unobservable', 0)),
        ('unknown_count', counts.get('unknown', 0)),
        ('checks', counts),
    ])


def _assess_encryption(entry, policy, checks, findings):
    status, severity, reasons = _classify_encryption(entry, policy)
    entry['status'] = status
    entry['severity'] = severity
    entry['reasons'] = reasons
    check = OrderedDict([
        ('kind', 'encryption'),
        ('layer', entry.get('protection_layer') or entry['layer']),
        ('scope_layer', entry.get('scope_layer') or entry['layer']),
        ('status', status),
        ('severity', severity),
        ('algorithm', entry.get('algorithm')),
        ('cipher', entry.get('cipher')),
        ('kdf', entry.get('kdf')),
        ('reasons', reasons),
    ])
    checks.append(check)
    if status != 'pass':
        findings.append(OrderedDict([
            ('code', _encryption_code(reasons)),
            ('layer', check['layer']),
            ('scope_layer', check['scope_layer']),
            ('algorithm', entry.get('algorithm')),
            ('cipher', entry.get('cipher')),
            ('kdf', entry.get('kdf')),
            ('iterations', entry.get('iterations')),
            ('status', status),
            ('severity', severity),
            ('message', _encryption_message(entry, reasons)),
        ]))


def _classify_encryption(entry, policy):
    reasons = []
    severity = 'none'
    status = 'pass'

    if not entry.get('observable', False):
        return 'unknown', 'unknown', ['encryption_parameters_unreadable']

    cipher = entry.get('cipher') or entry.get('algorithm')
    family = entry.get('family')

    if cipher is None:
        return 'unknown', 'unknown', ['encryption_algorithm_missing']

    allowed_ciphers = set(policy.get('allowed_ciphers', []))
    weak_ciphers = set(policy.get('weak_ciphers', []))

    if family in ('pkcs12', 'pbes1'):
        reasons.append('legacy_password_based_encryption')
        severity = _max_severity(severity, 'high')
        status = 'fail'
    elif cipher in weak_ciphers:
        reasons.append('weak_cipher')
        severity = _max_severity(severity, 'critical' if cipher in ('rc4_40', 'rc2_40') else 'high')
        status = 'fail'
    elif cipher not in allowed_ciphers:
        reasons.append('unrecognized_cipher')
        severity = _max_severity(severity, 'unknown')
        status = 'unknown'

    if family == 'pbes2':
        kdf = entry.get('kdf')
        if kdf == 'pbkdf2':
            iterations = entry.get('iterations')
            minimum = policy.get('min_pbkdf2_iterations', 100000)
            if not isinstance(iterations, integer_types):
                reasons.append('pbkdf2_iterations_unknown')
                severity = _max_severity(severity, 'unknown')
                status = _worst_status(status, 'unknown')
            elif iterations < minimum:
                reasons.append('pbkdf2_iterations_low')
                severity = _max_severity(severity, 'medium')
                status = 'fail'

            prf = entry.get('prf')
            if prf is None:
                reasons.append('pbkdf2_prf_unknown')
                severity = _max_severity(severity, 'unknown')
                status = _worst_status(status, 'unknown')
            elif prf not in set(policy.get('allowed_prfs', [])):
                reasons.append('weak_pbkdf2_prf')
                severity = _max_severity(severity, 'medium')
                status = 'fail'
        elif kdf == 'scrypt':
            pass
        else:
            reasons.append('unrecognized_kdf')
            severity = _max_severity(severity, 'unknown')
            status = _worst_status(status, 'unknown')

    return status, severity, reasons


def _assess_unprotected_key_bag(entry, policy, checks, findings):
    if not policy.get('require_encrypted_private_keys', True):
        return

    layer = entry.get('protection_layer') or (entry['layer'] + '.bag_value')
    entry['status'] = 'fail'
    entry['severity'] = 'high'
    entry['reasons'] = ['unencrypted_private_key']
    checks.append(OrderedDict([
        ('kind', 'encryption'),
        ('layer', layer),
        ('scope_layer', entry['layer']),
        ('status', 'fail'),
        ('severity', 'high'),
        ('algorithm', None),
        ('cipher', None),
        ('kdf', None),
        ('reasons', ['unencrypted_private_key']),
    ]))
    findings.append(OrderedDict([
        ('code', 'unencrypted_private_key'),
        ('layer', layer),
        ('scope_layer', entry['layer']),
        ('algorithm', None),
        ('cipher', None),
        ('kdf', None),
        ('iterations', None),
        ('status', 'fail'),
        ('severity', 'high'),
        ('message', 'The private key bag is stored without encryption at this layer'),
    ]))


def _assess_integrity(entry, policy, checks, findings):
    status, severity, reasons = _classify_integrity(entry, policy)
    entry['status'] = status
    entry['severity'] = severity
    entry['reasons'] = reasons
    check = OrderedDict([
        ('kind', 'integrity'),
        ('layer', entry['layer']),
        ('scope_layer', entry.get('scope_layer', entry['layer'])),
        ('status', status),
        ('severity', severity),
        ('algorithm', entry.get('algorithm')),
        ('reasons', reasons),
    ])
    checks.append(check)
    if status != 'pass':
        findings.append(OrderedDict([
            ('code', _integrity_code(reasons)),
            ('layer', entry['layer']),
            ('scope_layer', entry.get('scope_layer', entry['layer'])),
            ('algorithm', entry.get('algorithm')),
            ('status', status),
            ('severity', severity),
            ('message', _integrity_message(entry, reasons)),
        ]))


def _classify_integrity(entry, policy):
    reasons = []
    severity = 'none'
    status = 'pass'

    if not entry.get('present', False):
        if policy.get('require_integrity', True):
            return 'fail', 'high', ['missing_integrity']
        return 'pass', 'none', []

    if not entry.get('observable', False):
        return 'unknown', 'unknown', ['integrity_parameters_unreadable']

    algorithm = entry.get('algorithm')
    if algorithm is None:
        return 'unknown', 'unknown', ['integrity_algorithm_missing']

    if algorithm in set(policy.get('weak_mac_algorithms', [])):
        reasons.append('weak_integrity_algorithm')
        severity = _max_severity(severity, 'critical' if algorithm in ('md2', 'md5') else 'high')
        status = 'fail'
    elif algorithm not in set(policy.get('allowed_mac_algorithms', [])):
        reasons.append('unrecognized_integrity_algorithm')
        severity = _max_severity(severity, 'unknown')
        status = 'unknown'

    return status, severity, reasons


def _add_unobservable(items, layer, scope_layer, reason, encryption):
    items.append(OrderedDict([
        ('layer', layer),
        ('scope_layer', scope_layer),
        ('path', layer),
        ('reason', reason),
        ('algorithm', encryption.get('algorithm')),
        ('cipher', encryption.get('cipher')),
        ('kdf', encryption.get('kdf')),
        ('content_state', 'unobservable'),
        ('observable', False),
    ]))


def _mark_unknown(entry, items, reason, message):
    entry['content_state'] = 'unknown'
    items.append(OrderedDict([
        ('layer', entry['layer']),
        ('scope_layer', entry.get('scope_layer', entry['layer'])),
        ('path', entry['layer']),
        ('reason', reason),
        ('algorithm', entry.get('algorithm')),
        ('content_state', 'unknown'),
        ('observable', False),
        ('message', message),
    ]))


def _encryption_code(reasons):
    for reason in (
        'weak_cipher',
        'legacy_password_based_encryption',
        'pbkdf2_iterations_low',
        'weak_pbkdf2_prf',
    ):
        if reason in reasons:
            return reason
    if 'unrecognized_cipher' in reasons or 'unrecognized_kdf' in reasons:
        return 'unrecognized_encryption'
    return 'encryption_policy'


def _encryption_message(entry, reasons):
    if 'weak_cipher' in reasons:
        return 'The %s protection uses a weak cipher and should be replaced at this layer' % entry.get('cipher')
    if 'legacy_password_based_encryption' in reasons:
        return 'The %s protection uses a legacy password-based scheme at this layer' % entry.get('algorithm')
    if 'pbkdf2_iterations_low' in reasons:
        return 'PBKDF2 iterations are below policy at this layer'
    if 'weak_pbkdf2_prf' in reasons:
        return 'The PBKDF2 PRF is below policy at this layer'
    if 'unrecognized_cipher' in reasons or 'unrecognized_kdf' in reasons:
        return 'The protection algorithm at this layer is not recognized by policy'
    return 'The protection at this layer does not satisfy policy'


def _integrity_code(reasons):
    if 'missing_integrity' in reasons:
        return 'missing_integrity'
    if 'weak_integrity_algorithm' in reasons:
        return 'weak_integrity_algorithm'
    if 'unrecognized_integrity_algorithm' in reasons:
        return 'unrecognized_integrity_algorithm'
    return 'integrity_policy'


def _integrity_message(entry, reasons):
    if 'missing_integrity' in reasons:
        return 'No PKCS#12 integrity MAC is present'
    if 'weak_integrity_algorithm' in reasons:
        return 'The integrity MAC uses %s, which is below policy' % entry.get('algorithm')
    if 'unrecognized_integrity_algorithm' in reasons:
        return 'The integrity MAC algorithm %s is not recognized by policy' % entry.get('algorithm')
    return 'The integrity protection does not satisfy policy'


def _dedupe_findings(findings):
    seen = set()
    result = []
    for item in findings:
        key = (item.get('archive'), item.get('layer'), item.get('code'))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _finding_sort_key(item):
    return (
        -_SEVERITY_RANK.get(item.get('severity', 'none'), 0),
        item.get('archive') or '',
        item.get('layer') or '',
    )


def _worst_status(left, right):
    order = {'pass': 0, 'unobservable': 1, 'unknown': 2, 'fail': 3}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _max_severity(left, right):
    return left if _SEVERITY_RANK.get(left, 0) >= _SEVERITY_RANK.get(right, 0) else right


def _salt_length(salt):
    try:
        if salt.__class__.__name__ == 'Pbkdf2Salt':
            if salt.name == 'specified':
                return len(salt.chosen.native)
            return None
        return len(salt.native)
    except Exception:
        return None


def _octet_length(value):
    try:
        native = value.native
        if isinstance(native, byte_types):
            return len(native)
    except Exception:
        pass
    return None


def _cipher_iv_length(algorithm):
    try:
        parameters = algorithm['parameters']
        if isinstance(parameters, Void):
            return None
        if _octet_length(parameters) is not None:
            return _octet_length(parameters)
        return _octet_length(parameters['iv'])
    except Exception:
        return None


def _parameters_native(parameters):
    if isinstance(parameters, Void):
        return OrderedDict()
    try:
        native = parameters.native
    except Exception:
        return OrderedDict()
    if native is None:
        return OrderedDict()
    if isinstance(native, dict):
        return _json_value(native)
    return OrderedDict([('value', _json_value(native))])


def _safe_native(value):
    try:
        return value.native
    except Exception:
        return None


def _safe_oid(value):
    try:
        return value.dotted
    except Exception:
        return None


def _exception_message(exc):
    return str(exc) or exc.__class__.__name__


def _plain_value(value):
    if isinstance(value, (Pkcs12Inventory, Pkcs12GovernanceReport, Pkcs12Policy)):
        return OrderedDict((key, _plain_value(item)) for key, item in value.items())
    if isinstance(value, dict):
        return OrderedDict((key, _plain_value(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return [_plain_value(item) for item in value]
    if isinstance(value, set):
        return sorted(_plain_value(item) for item in value)
    return value


def _json_value(value):
    if isinstance(value, bytearray):
        value = bytes(value)
    if isinstance(value, bytes):
        return hexlify(value).decode('ascii')
    if isinstance(value, (Pkcs12Inventory, Pkcs12GovernanceReport, Pkcs12Policy, dict)):
        return OrderedDict((key, _json_value(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, set):
        return sorted(_json_value(item) for item in value)
    if isinstance(value, integer_types) or isinstance(value, float) or value is None or isinstance(value, bool):
        return value
    if isinstance(value, string_types):
        return value
    if hasattr(value, 'native'):
        return _json_value(value.native)
    return str(value)


def _copy_plain(value, memo=None):
    if memo is None:
        memo = {}
    if isinstance(value, dict):
        identity = id(value)
        if identity in memo:
            return memo[identity]
        result = OrderedDict()
        memo[identity] = result
        for key, item in value.items():
            result[key] = _copy_plain(item, memo)
        return result
    if isinstance(value, list):
        identity = id(value)
        if identity in memo:
            return memo[identity]
        result = []
        memo[identity] = result
        for item in value:
            result.append(_copy_plain(item, memo))
        return result
    return value


# Friendly aliases for callers that use audit/inventory terminology.
audit = inventory
analyze = inventory
inspect = inventory
protection_inventory = inventory
audit_pfx = inventory_pfx
inspect_pfx = inventory_pfx
