# coding: utf-8
"""
Offline review of the RFC 6211 CMSAlgorithmProtection attribute.

The functions in this module compare the algorithm identifiers carried in a
CMSAlgorithmProtection signed/authenticated attribute with the identifiers
actually used by a SignerInfo or AuthenticatedData structure.  They do not
verify signatures or MACs.  Signature and MAC verification remains the
responsibility of the caller.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import collections
import binascii

from . import algos, cms, core, parser, pem
from ._types import str_cls


OID_CMS_ALGORITHM_PROTECTION = '1.2.840.113549.1.9.52'

STATUS_PROTECTED = 'protected'
STATUS_UNPROTECTED = 'unprotected'
STATUS_UNAUTHENTICATED = 'unauthenticated'
STATUS_DUPLICATE = 'duplicate'
STATUS_ALGORITHM_MISMATCH = 'algorithm_mismatch'
STATUS_PARAMETER_MISMATCH = 'parameter_mismatch'
STATUS_INDETERMINATE = 'indeterminate'
STATUS_MALFORMED = 'malformed'
STATUS_UNEXPECTED_COMPONENT = 'unexpected_component'
STATUS_UNSUPPORTED_CONTENT = 'unsupported_content'
STATUS_ERROR = 'error'

VERDICT_MIGRATE = 'migrate'
VERDICT_SUPPLEMENT = 'supplement'
VERDICT_MANUAL_REVIEW = 'manual_review'

ROLE_DIGEST = 'digest'
ROLE_SIGNATURE = 'signature'
ROLE_MAC = 'mac'

_NIL_PARAMETER_KINDS = ('absent', 'null')


def _byte_hex(value):
    if value is None:
        return None
    if hasattr(value, 'hex'):
        return value.hex()
    return binascii.hexlify(value).decode('ascii')


def _safe_native(value):
    try:
        return value.native
    except Exception:
        return None


def _asn1_error_text(exc):
    text = str(exc).strip().splitlines()[0]
    if len(text) > 300:
        text = text[:297] + '...'
    return text


def _parse_tlv(data, pointer=0):
    parts, consumed = parser._parse(data, len(data), pointer)
    return parts, consumed


def _raw_algorithm_parts(algorithm):
    """
    Extracts the OID and raw parameter TLV from an AlgorithmIdentifier
    without asking asn1crypto to interpret the parameters.  This is used as
    a fallback when the parameters contain a value that the installed
    algorithm model can not parse.
    """

    encoded = algorithm.dump()
    outer, _ = _parse_tlv(encoded)
    contents = outer[4]
    child, used = _parse_tlv(contents)
    oid_der = child[3] + child[4] + child[5]
    oid = core.ObjectIdentifier.load(oid_der)
    return oid, contents[used:]


def _parameter_state(algorithm):
    """
    Returns a small, JSON-friendly description of an AlgorithmIdentifier's
    parameters.  The private ``_object`` key is used internally for semantic
    comparison and is stripped from public output.
    """

    state = collections.OrderedDict()
    state['kind'] = 'absent'
    state['der'] = None
    state['native'] = None
    state['parse_error'] = None
    state['_object'] = None

    try:
        params = algorithm['parameters']
    except Exception as exc:
        state['kind'] = 'unreadable'
        state['parse_error'] = _asn1_error_text(exc)
        try:
            _, raw = _raw_algorithm_parts(algorithm)
            if raw:
                state['der'] = _byte_hex(raw)
        except Exception:
            pass
        return state

    state['_object'] = params

    if isinstance(params, core.Void):
        return state

    try:
        state['der'] = _byte_hex(params.dump())
    except Exception as exc:
        state['kind'] = 'unreadable'
        state['parse_error'] = _asn1_error_text(exc)
        return state

    if isinstance(params, core.Null):
        state['kind'] = 'null'
        return state

    # Some AlgorithmIdentifier definitions leave ``parameters`` as an Any, so
    # an explicit NULL arrives as an Any wrapping 05 00 instead of core.Null.
    if state['der'] == '0500':
        state['kind'] = 'null'
        return state

    state['kind'] = 'value'
    state['native'] = _safe_native(params)
    return state


def _algorithm_info(algorithm):
    """
    Returns a JSON-friendly description of an AlgorithmIdentifier, or None
    when the field is absent/void.
    """

    if algorithm is None or isinstance(algorithm, core.Void):
        return None

    info = collections.OrderedDict()
    info['oid'] = None
    info['name'] = None
    info['parameters'] = None
    info['error'] = None

    try:
        oid_obj = algorithm['algorithm']
        info['oid'] = oid_obj.dotted
        info['name'] = oid_obj.native
    except Exception as exc:
        info['error'] = _asn1_error_text(exc)
        try:
            oid_obj, _ = _raw_algorithm_parts(algorithm)
            info['oid'] = oid_obj.dotted
            info['name'] = oid_obj.native
        except Exception:
            pass

    info['parameters'] = _parameter_state(algorithm)
    return info


def _public_algorithm_info(info):
    if info is None:
        return None
    out = collections.OrderedDict()
    out['oid'] = info.get('oid')
    out['name'] = info.get('name')
    out['error'] = info.get('error')
    params = info.get('parameters')
    if params is None:
        out['parameters'] = None
    else:
        out['parameters'] = collections.OrderedDict([
            ('kind', params.get('kind')),
            ('der', params.get('der')),
            ('native', params.get('native')),
            ('parse_error', params.get('parse_error')),
        ])
    return out


def _signature_family(name):
    if name == 'rsassa_pss':
        return 'pss'
    if name in ('ed25519', 'ed448'):
        return 'eddsa'
    if name in ('dsa', 'ecdsa'):
        return 'dsa_ecdsa'
    if name is not None and (name.endswith('_dsa') or name.endswith('_ecdsa') or name.endswith('_ecdsa_plain')):
        return 'dsa_ecdsa'
    if name == 'rsassa_pkcs1v15' or (name is not None and name.endswith('_rsa')):
        return 'rsa_pkcs1'
    return 'unknown'


def _generic_signature_alias(attribute_name, structure_name, digest_name):
    """
    Returns an explanation when one identifier uses the generic CMS key type
    (e.g. rsaEncryption) and the other uses the digest-specific signature OID
    (e.g. sha256_rsa) for the same digest.  This pattern is common in older
    CMS/PKCS#7 producers.
    """

    pairs = [
        ('rsassa_pkcs1v15', '_rsa', 'RSA PKCS#1 v1.5'),
        ('dsa', '_dsa', 'DSA'),
        ('ecdsa', '_ecdsa', 'ECDSA'),
        ('ecdsa', '_ecdsa_plain', 'ECDSA plain'),
    ]
    for generic_name, suffix, label in pairs:
        if attribute_name == generic_name and structure_name and structure_name.endswith(suffix):
            specific_name = structure_name
        elif structure_name == generic_name and attribute_name and attribute_name.endswith(suffix):
            specific_name = attribute_name
        else:
            continue
        prefix = specific_name[:-len(suffix)]
        if digest_name is None or prefix == digest_name:
            return (
                'One identifier uses the generic %s OID and the other uses the digest-specific %s OID; '
                'the digest is independently compared, so these are treated as the same signature algorithm.'
                % (label, specific_name)
            )
    return None


def _nil_parameter_reason(role, family):
    if role == ROLE_DIGEST:
        return (
            'Digest algorithm identifiers carry no parameters; explicit NULL and absent parameters '
            'are equivalent for this comparison.'
        )
    if role == ROLE_MAC:
        return (
            'HMAC algorithm identifiers as used by CMS AuthenticatedData carry no parameters; '
            'explicit NULL and absent parameters are equivalent for this comparison.'
        )
    if family == 'rsa_pkcs1':
        return (
            'RSA PKCS#1 v1.5 signature algorithms use NULL parameters (RFC 4055/RFC 8017); '
            'an absent parameters field is tolerated as the same meaning for legacy CMS files.'
        )
    if family == 'dsa_ecdsa':
        return (
            'DSA/ECDSA signature algorithms require absent parameters (RFC 5758/RFC 5480); '
            'a legacy explicit NULL is tolerated as equivalent because it conveys no digest or curve data.'
        )
    if family == 'eddsa':
        return (
            'Ed25519/Ed448 require absent parameters (RFC 8410); a legacy explicit NULL is tolerated '
            'as equivalent because it conveys no algorithm information.'
        )
    return 'Both identifiers omit algorithm parameters (absent or NULL); there is no parameter information to compare.'


def _simple_parameter_semantics(role, family, state):
    kind = state.get('kind')
    if kind in _NIL_PARAMETER_KINDS:
        return collections.OrderedDict([('kind', 'nil')]), None
    if kind == 'unreadable':
        return None, (
            'The parameters could not be decoded by the installed asn1crypto model: %s'
            % state.get('parse_error')
        )
    return None, (
        'This %s algorithm does not define parameters that the installed implementation can interpret '
        '(parameter TLV: %s).' % (role, state.get('der'))
    )


_PSS_DEFAULT_HASH = 'sha1'
_PSS_DEFAULT_MGF_HASH = 'sha1'
_PSS_DEFAULT_SALT_LENGTH = 20
_PSS_DEFAULT_TRAILER = 'trailer_field_bc'
_DIGEST_NAMES = set(algos.DigestAlgorithmId._map.values())


def _pss_semantics(algorithm, state):
    kind = state.get('kind')
    explicit = kind == 'value'
    if kind in _NIL_PARAMETER_KINDS:
        value = collections.OrderedDict([
            ('hash', _PSS_DEFAULT_HASH),
            ('mgf', 'mgf1'),
            ('mgf_hash', _PSS_DEFAULT_MGF_HASH),
            ('salt_length', _PSS_DEFAULT_SALT_LENGTH),
            ('trailer_field', _PSS_DEFAULT_TRAILER),
        ])
        note = None
        if kind == 'absent':
            note = (
                'RSASSA-PSS parameters are absent; for review they are interpreted using the '
                'ASN.1 defaults SHA-1/MGF1-SHA-1/saltLength=20/trailerField=BC.'
            )
        else:
            note = (
                'RSASSA-PSS has NULL parameters, which is not a defined encoding; for review it is '
                'interpreted using the ASN.1 defaults SHA-1/MGF1-SHA-1/saltLength=20/trailerField=BC.'
            )
        return value, note, None

    if kind == 'unreadable':
        return None, None, (
            'RSASSA-PSS parameters could not be decoded: %s' % state.get('parse_error')
        )

    params = state.get('_object')
    try:
        hash_algorithm = params['hash_algorithm']
        hash_name = hash_algorithm['algorithm'].native
        if not isinstance(hash_name, str_cls) or hash_name not in _DIGEST_NAMES:
            raise ValueError('unknown RSASSA-PSS hash algorithm OID')

        mgf = params['mask_gen_algorithm']
        mgf_name = mgf['algorithm'].native
        if mgf_name != 'mgf1':
            raise ValueError('unsupported RSASSA-PSS mask generation algorithm')

        mgf_hash_algorithm = mgf['parameters']
        mgf_hash_name = mgf_hash_algorithm['algorithm'].native
        if not isinstance(mgf_hash_name, str_cls) or mgf_hash_name not in _DIGEST_NAMES:
            raise ValueError('unknown RSASSA-PSS MGF1 hash algorithm OID')

        salt_length = params['salt_length'].native
        trailer_field = params['trailer_field'].native
    except Exception as exc:
        return None, None, (
            'RSASSA-PSS parameters could not be interpreted by the installed implementation: %s'
            % _asn1_error_text(exc)
        )

    value = collections.OrderedDict([
        ('hash', hash_name),
        ('mgf', mgf_name),
        ('mgf_hash', mgf_hash_name),
        ('salt_length', salt_length),
        ('trailer_field', trailer_field),
    ])
    note = None
    if not explicit:
        note = 'RSASSA-PSS parameters were defaulted from an empty parameter sequence.'
    elif value['hash'] == _PSS_DEFAULT_HASH and value['mgf_hash'] == _PSS_DEFAULT_MGF_HASH \
            and value['salt_length'] == _PSS_DEFAULT_SALT_LENGTH \
            and value['trailer_field'] == _PSS_DEFAULT_TRAILER:
        note = 'The explicit RSASSA-PSS parameters equal the ASN.1 defaults.'
    return value, note, None


def _compare_parameters(role, name, left, right):
    """
    Compares two parameter states semantically.  Returns a tuple of
    (status, reason, details, notes).
    """

    notes = []
    details = collections.OrderedDict()
    details['left'] = collections.OrderedDict([
        ('kind', left.get('kind')),
        ('der', left.get('der')),
        ('native', left.get('native')),
    ])
    details['right'] = collections.OrderedDict([
        ('kind', right.get('kind')),
        ('der', right.get('der')),
        ('native', right.get('native')),
    ])

    if left.get('kind') == 'unreadable' or right.get('kind') == 'unreadable':
        errors = [s.get('parse_error') for s in (left, right) if s.get('kind') == 'unreadable']
        return (
            'unsupported',
            'At least one parameter encoding could not be interpreted: %s' % '; '.join(errors),
            details,
            notes,
        )

    if role == ROLE_DIGEST or role == ROLE_MAC:
        left_value, left_error = _simple_parameter_semantics(role, 'unknown', left)
        right_value, right_error = _simple_parameter_semantics(role, 'unknown', right)
    elif role == ROLE_SIGNATURE:
        family = _signature_family(name)
        if family == 'pss':
            left_value, left_note, left_error = _pss_semantics(None, left)
            right_value, right_note, right_error = _pss_semantics(None, right)
            if left_note:
                notes.append('left: ' + left_note)
            if right_note:
                notes.append('right: ' + right_note)
        else:
            left_value, left_error = _simple_parameter_semantics(role, family, left)
            right_value, right_error = _simple_parameter_semantics(role, family, right)
    else:
        left_value = None
        right_value = None
        left_error = 'Unsupported algorithm role: %s' % role
        right_error = left_error

    if left_error or right_error:
        errors = [e for e in (left_error, right_error) if e]
        return 'unsupported', '; '.join(errors), details, notes

    if left_value == right_value:
        left_kind = left.get('kind')
        right_kind = right.get('kind')
        if left_kind == right_kind:
            return 'match', 'Algorithm identifiers and parameters match.', details, notes
        if role == ROLE_SIGNATURE:
            family = _signature_family(name)
        else:
            family = 'unknown'
        if role == ROLE_SIGNATURE and family == 'pss':
            return (
                'equivalent',
                'RSASSA-PSS parameters are semantically equal after applying the ASN.1 defaults '
                '(SHA-1/MGF1-SHA-1/saltLength=20/trailerField=BC).',
                details,
                notes,
            )
        return 'equivalent', _nil_parameter_reason(role, family), details, notes

    if role == ROLE_SIGNATURE and _signature_family(name) == 'pss':
        differences = []
        for key in ('hash', 'mgf', 'mgf_hash', 'salt_length', 'trailer_field'):
            if left_value.get(key) != right_value.get(key):
                differences.append('%s: %s != %s' % (key, left_value.get(key), right_value.get(key)))
        reason = 'RSASSA-PSS parameters are not equivalent (%s).' % ', '.join(differences)
    else:
        reason = 'The parameter encodings differ and no permitted equivalence applies.'
    return 'parameter_mismatch', reason, details, notes


class AlgorithmComparison(object):
    """The conclusion for one digest, signature or MAC identifier pair."""

    def __init__(self, role, status, reason, attribute, structure, details=None, notes=None):
        self.role = role
        self.status = status
        self.reason = reason
        self.attribute = attribute
        self.structure = structure
        self.details = details or collections.OrderedDict()
        self.notes = notes or []

    @property
    def equivalent(self):
        return self.status in ('match', 'equivalent')

    @property
    def native(self):
        return collections.OrderedDict([
            ('role', self.role),
            ('status', self.status),
            ('equivalent', self.equivalent),
            ('reason', self.reason),
            ('attribute', _public_algorithm_info(self.attribute)),
            ('structure', _public_algorithm_info(self.structure)),
            ('details', self.details),
            ('notes', self.notes),
        ])


def compare_algorithm_identifiers(attribute_algorithm, structure_algorithm, role=None, digest_name=None):
    """
    Compares one RFC 6211 attribute algorithm identifier with the identifier
    used by the containing CMS structure.

    :param attribute_algorithm:
        An asn1crypto AlgorithmIdentifier from CMSAlgorithmProtection

    :param structure_algorithm:
        An asn1crypto AlgorithmIdentifier from SignerInfo or AuthenticatedData

    :param role:
        A unicode string of "digest", "signature" or "mac"; used to select
        the permitted parameter equivalences

    :param digest_name:
        An optional unicode string of the digest algorithm name from the
        containing SignerInfo; used to recognise the generic RSA/DSA/ECDSA
        signature OID versus its digest-specific equivalent

    :return:
        An AlgorithmComparison object
    """

    if attribute_algorithm is None or isinstance(attribute_algorithm, core.Void):
        return AlgorithmComparison(
            role,
            'missing',
            'The CMSAlgorithmProtection attribute does not contain this algorithm identifier.',
            None,
            _algorithm_info(structure_algorithm) if structure_algorithm is not None else None,
        )

    if structure_algorithm is None or isinstance(structure_algorithm, core.Void):
        return AlgorithmComparison(
            role,
            'missing',
            'The containing CMS structure does not contain this algorithm identifier.',
            _algorithm_info(attribute_algorithm),
            None,
        )

    attribute_info = _algorithm_info(attribute_algorithm)
    structure_info = _algorithm_info(structure_algorithm)

    if attribute_info.get('error') or structure_info.get('error'):
        reason = 'The algorithm identifier could not be decoded: %s' % ', '.join(
            [e for e in (attribute_info.get('error'), structure_info.get('error')) if e]
        )
        return AlgorithmComparison(role, 'unsupported', reason, attribute_info, structure_info)

    attribute_oid = attribute_info.get('oid')
    structure_oid = structure_info.get('oid')
    attribute_name = attribute_info.get('name')
    structure_name = structure_info.get('name')

    notes = []
    comparison_name = attribute_name
    if attribute_oid != structure_oid:
        if attribute_name == structure_name and attribute_name and not attribute_name[0].isdigit():
            notes.append(
                'The OIDs differ (%s vs %s) but both map to the same asn1crypto algorithm name "%s"; '
                'this is treated as an OID alias for the same algorithm.'
                % (attribute_oid, structure_oid, attribute_name)
            )
        else:
            alias_reason = None
            if role == ROLE_SIGNATURE:
                alias_reason = _generic_signature_alias(attribute_name, structure_name, digest_name)
            if alias_reason is None:
                return AlgorithmComparison(
                    role,
                    'algorithm_mismatch',
                    'The attribute algorithm OID %s does not match the structure algorithm OID %s.'
                    % (attribute_oid, structure_oid),
                    attribute_info,
                    structure_info,
                    notes=notes,
                )

    if attribute_name != structure_name:
        alias_reason = None
        if role == ROLE_SIGNATURE:
            alias_reason = _generic_signature_alias(attribute_name, structure_name, digest_name)
        if alias_reason is None:
            return AlgorithmComparison(
                role,
                'algorithm_mismatch',
                'The attribute algorithm %s does not match the structure algorithm %s.'
                % (attribute_name, structure_name),
                attribute_info,
                structure_info,
                notes=notes,
            )
        notes.append(alias_reason)
        # The OIDs name the same signature algorithm with the digest supplied
        # by SignerInfo.digest_algorithm, so continue to compare parameters.
        if attribute_name in ('rsassa_pkcs1v15', 'dsa', 'ecdsa'):
            comparison_name = structure_name
        else:
            comparison_name = attribute_name

    status, reason, details, parameter_notes = _compare_parameters(
        role,
        comparison_name,
        attribute_info['parameters'],
        structure_info['parameters'],
    )
    notes.extend(parameter_notes)
    return AlgorithmComparison(role, status, reason, attribute_info, structure_info, details, notes)


def _identity_for_signer(signer_info):
    try:
        sid = signer_info['sid']
    except Exception as exc:
        return collections.OrderedDict([
            ('type', 'unavailable'),
            ('error', _asn1_error_text(exc)),
        ])

    try:
        choice = sid.name
    except Exception:
        choice = None

    if choice == 'issuer_and_serial_number':
        chosen = sid.chosen
        return collections.OrderedDict([
            ('type', 'issuer_and_serial_number'),
            ('issuer', _safe_native(chosen['issuer'])),
            ('serial_number', _safe_native(chosen['serial_number'])),
        ])

    if choice == 'subject_key_identifier':
        ski = _safe_native(sid.chosen)
        return collections.OrderedDict([
            ('type', 'subject_key_identifier'),
            ('subject_key_identifier', _byte_hex(ski) if isinstance(ski, bytes) else ski),
        ])

    return collections.OrderedDict([
        ('type', choice or 'unknown'),
        ('native', _safe_native(sid)),
    ])


def _identity_text(identity):
    if not identity:
        return '-'
    kind = identity.get('type')
    if kind == 'issuer_and_serial_number':
        issuer = identity.get('issuer')
        if isinstance(issuer, dict):
            parts = []
            for key, value in issuer.items():
                parts.append('%s=%s' % (key, value))
            issuer_text = ','.join(parts)
        else:
            issuer_text = str(issuer)
        return 'issuer=%s serial=%s' % (issuer_text, identity.get('serial_number'))
    if kind == 'subject_key_identifier':
        return 'SKI=%s' % identity.get('subject_key_identifier')
    if kind == 'authenticated_data':
        return 'AuthenticatedData'
    return str(identity.get('native') or kind)


class AlgorithmProtectionResult(object):
    """The independent RFC 6211 conclusion for one signer or AuthenticatedData."""

    def __init__(self, kind, index, path, identity):
        self.kind = kind
        self.index = index
        self.path = path
        self.identity = identity
        self.status = STATUS_ERROR
        self.verdict = VERDICT_MANUAL_REVIEW
        self.summary = ''
        self.attribute_locations = []
        self.checks = []
        self.issues = []
        self.notes = []

    @property
    def migratable(self):
        return self.verdict == VERDICT_MIGRATE

    @property
    def needs_materials(self):
        return self.verdict == VERDICT_SUPPLEMENT

    @property
    def requires_manual_review(self):
        return self.verdict == VERDICT_MANUAL_REVIEW

    @property
    def protected(self):
        return self.status == STATUS_PROTECTED

    @property
    def declares_protection(self):
        return bool(self.attribute_locations)

    @property
    def ledger_claim_supported(self):
        return self.protected

    @property
    def code(self):
        """A stable, finer-grained code for the first detected issue."""
        if self.issues:
            return self.issues[0]['code']
        return self.status

    @property
    def recommendation(self):
        if self.verdict == VERDICT_MIGRATE:
            return 'migrate'
        if self.verdict == VERDICT_SUPPLEMENT:
            return 'return_for_materials'
        return 'manual_review'

    @property
    def classification(self):
        return self.status

    @property
    def reason_code(self):
        return self.code

    @property
    def disposition(self):
        return self.recommendation

    @property
    def verdict_text(self):
        return self.recommendation

    @property
    def checks_by_role(self):
        return collections.OrderedDict((check.role, check) for check in self.checks)

    @property
    def attribute_path(self):
        for location in self.attribute_locations:
            if location.get('authenticated'):
                return location.get('path')
        if self.attribute_locations:
            return self.attribute_locations[0].get('path')
        return None

    def _add_issue(self, code, message, path=None, role=None, attribute_index=None, value_index=None):
        issue = collections.OrderedDict([
            ('code', code),
            ('message', message),
            ('path', path),
            ('role', role),
            ('attribute_index', attribute_index),
            ('value_index', value_index),
        ])
        self.issues.append(issue)

    @property
    def native(self):
        return collections.OrderedDict([
            ('kind', self.kind),
            ('index', self.index),
            ('path', self.path),
            ('identity', self.identity),
            ('status', self.status),
            ('classification', self.classification),
            ('code', self.code),
            ('status_detail', self.code),
            ('reason_code', self.reason_code),
            ('verdict', self.verdict),
            ('verdict_text', self.verdict_text),
            ('recommendation', self.recommendation),
            ('disposition', self.disposition),
            ('protected', self.protected),
            ('declares_protection', self.declares_protection),
            ('ledger_claim_supported', self.ledger_claim_supported),
            ('migratable', self.migratable),
            ('needs_materials', self.needs_materials),
            ('requires_manual_review', self.requires_manual_review),
            ('summary', self.summary),
            ('attribute_path', self.attribute_path),
            ('attribute_locations', self.attribute_locations),
            ('checks', [check.native for check in self.checks]),
            ('checks_by_role', collections.OrderedDict(
                (role, check.native) for role, check in self.checks_by_role.items()
            )),
            ('algorithm_status', collections.OrderedDict(
                (check.role, check.status) for check in self.checks
            )),
            ('issues', self.issues),
            ('notes', self.notes),
            ('signature_verified', False),
            ('verification', 'not_performed'),
        ])

    def to_native(self):
        return self.native

    def as_native(self):
        return self.native

    def as_dict(self):
        return self.native

    def __getitem__(self, key):
        if isinstance(key, str_cls):
            return self.native[key]
        return self.checks[key]

    def format_line(self):
        return '%-18s %-34s %-20s %-13s %s' % (
            self.path,
            _identity_text(self.identity)[:34],
            self.status,
            self.verdict,
            self.summary,
        )


class CMSAlgorithmProtectionReview(object):
    """The complete review of a ContentInfo containing CMS data."""

    def __init__(self, content_type):
        self.content_type = content_type
        self.results = []
        self.digest_algorithms = []
        self.notes = []
        self.errors = []

    @property
    def signers(self):
        return [result for result in self.results if result.kind == 'signer']

    @property
    def authenticated_data(self):
        return [result for result in self.results if result.kind == 'authenticated_data']

    @property
    def summary(self):
        counts = collections.OrderedDict([
            (VERDICT_MIGRATE, 0),
            (VERDICT_SUPPLEMENT, 0),
            (VERDICT_MANUAL_REVIEW, 0),
        ])
        for result in self.results:
            if result.verdict in counts:
                counts[result.verdict] += 1
        return counts

    @property
    def recommendations(self):
        counts = collections.OrderedDict([
            ('migrate', 0),
            ('return_for_materials', 0),
            ('manual_review', 0),
        ])
        for result in self.results:
            counts[result.recommendation] += 1
        return counts

    @property
    def ledger_claim_supported(self):
        return bool(self.results) and all(result.protected for result in self.results)

    @property
    def native(self):
        return collections.OrderedDict([
            ('content_type', self.content_type),
            ('ledger_claim_supported', self.ledger_claim_supported),
            ('summary', self.summary),
            ('recommendations', self.recommendations),
            ('results', [result.native for result in self.results]),
            ('signers', [result.native for result in self.signers]),
            ('authenticated_data', [result.native for result in self.authenticated_data]),
            ('digest_algorithms', self.digest_algorithms),
            ('notes', self.notes),
            ('errors', self.errors),
            ('signature_verified', False),
            ('verification', 'not_performed'),
        ])

    def to_native(self):
        return self.native

    def as_native(self):
        return self.native

    def as_dict(self):
        return self.native

    def __iter__(self):
        return iter(self.results)

    def __len__(self):
        return len(self.results)

    def __getitem__(self, index):
        if isinstance(index, str_cls):
            return self.native[index]
        return self.results[index]

    def format_text(self):
        lines = []
        lines.append('CMS Algorithm Protection Review (RFC 6211)')
        lines.append('Content type: %s' % self.content_type)
        lines.append('Ledger claim supported: %s' % ('yes' if self.ledger_claim_supported else 'no'))
        lines.append('Verification: not performed (signature/MAC verification is the caller\'s responsibility)')
        lines.append('')
        lines.append('%-18s %-34s %-20s %-13s %s' % ('SUBJECT', 'SIGNER IDENTITY', 'STATUS', 'VERDICT', 'DETAIL'))
        lines.append('-' * 132)
        for result in self.results:
            lines.append(result.format_line())
        lines.append('')
        lines.append('Summary: %s migrate, %s supplement, %s manual review' % (
            self.summary[VERDICT_MIGRATE],
            self.summary[VERDICT_SUPPLEMENT],
            self.summary[VERDICT_MANUAL_REVIEW],
        ))
        return '\n'.join(lines)

    def __str__(self):
        return self.format_text()


def _collect_protection_attributes(container, field_name, subject_path):
    """
    Returns a list of dicts describing every CMSAlgorithmProtection attribute
    in a CMSAttributes field.
    """

    found = []
    try:
        attributes = container[field_name]
    except Exception:
        attributes = None

    if attributes is None or isinstance(attributes, core.Void):
        return found

    try:
        attribute_iterator = list(attributes)
    except Exception as exc:
        found.append(collections.OrderedDict([
            ('location', field_name),
            ('path', '%s.%s' % (subject_path, field_name)),
            ('attribute_index', None),
            ('oid', None),
            ('values', []),
            ('error', _asn1_error_text(exc)),
        ]))
        return found

    for attribute_index, attribute in enumerate(attribute_iterator):
        try:
            type_obj = attribute['type']
            oid = type_obj.dotted
            name = type_obj.native
        except Exception as exc:
            found.append(collections.OrderedDict([
                ('location', field_name),
                ('path', '%s.%s[%d]' % (subject_path, field_name, attribute_index)),
                ('attribute_index', attribute_index),
                ('oid', None),
                ('values', []),
                ('error', _asn1_error_text(exc)),
            ]))
            continue

        if oid != OID_CMS_ALGORITHM_PROTECTION and name != 'cms_algorithm_protection':
            continue

        record = collections.OrderedDict([
            ('location', field_name),
            ('path', '%s.%s[%d]' % (subject_path, field_name, attribute_index)),
            ('attribute_index', attribute_index),
            ('oid', oid),
            ('values', []),
            ('error', None),
        ])

        try:
            values = list(attribute['values'])
        except Exception as exc:
            record['error'] = _asn1_error_text(exc)
            found.append(record)
            continue

        for value_index, value in enumerate(values):
            record['values'].append(collections.OrderedDict([
                ('value_index', value_index),
                ('path', '%s.values[%d]' % (record['path'], value_index)),
                ('value', value),
            ]))
        found.append(record)

    return found


def _compare_component(protection_value, field, structure_algorithm, role, digest_name=None):
    try:
        attribute_algorithm = protection_value[field]
    except Exception as exc:
        return AlgorithmComparison(
            role,
            'malformed',
            'The %s field of CMSAlgorithmProtection could not be decoded: %s'
            % (field, _asn1_error_text(exc)),
            None,
            _algorithm_info(structure_algorithm) if structure_algorithm is not None else None,
        )
    return compare_algorithm_identifiers(attribute_algorithm, structure_algorithm, role, digest_name=digest_name)


def _apply_check_outcome(result, check, attribute_path, attribute_index, value_index):
    result.checks.append(check)
    if check.status == 'algorithm_mismatch':
        result._add_issue(
            '%s_algorithm_mismatch' % check.role,
            check.reason,
            path=attribute_path,
            role=check.role,
            attribute_index=attribute_index,
            value_index=value_index,
        )
    elif check.status == 'parameter_mismatch':
        result._add_issue(
            '%s_parameter_mismatch' % check.role,
            check.reason,
            path=attribute_path,
            role=check.role,
            attribute_index=attribute_index,
            value_index=value_index,
        )
    elif check.status == 'unsupported':
        result._add_issue(
            '%s_parameters_uninterpretable' % check.role,
            check.reason,
            path=attribute_path,
            role=check.role,
            attribute_index=attribute_index,
            value_index=value_index,
        )
    elif check.status == 'missing':
        result._add_issue(
            '%s_algorithm_missing' % check.role,
            check.reason,
            path=attribute_path,
            role=check.role,
            attribute_index=attribute_index,
            value_index=value_index,
        )
    elif check.status == 'malformed':
        result._add_issue(
            '%s_algorithm_malformed' % check.role,
            check.reason,
            path=attribute_path,
            role=check.role,
            attribute_index=attribute_index,
            value_index=value_index,
        )
    elif check.status == 'equivalent':
        result.notes.append('%s: %s' % (check.role, check.reason))
    for note in check.notes:
        result.notes.append('%s: %s' % (check.role, note))


def _set_verdict(result):
    statuses = [check.status for check in result.checks]
    issue_codes = [issue['code'] for issue in result.issues]

    if result.status == STATUS_PROTECTED:
        malformed = any(
            code.endswith('_algorithm_malformed') or code.endswith('_algorithm_missing')
            for code in issue_codes
        )
        if 'algorithm_mismatch' in statuses:
            result.status = STATUS_ALGORITHM_MISMATCH
        elif 'parameter_mismatch' in statuses:
            result.status = STATUS_PARAMETER_MISMATCH
        elif 'unsupported' in statuses:
            result.status = STATUS_INDETERMINATE
        elif 'missing' in statuses or malformed:
            result.status = STATUS_MALFORMED
        elif any(code.startswith('unexpected_') for code in issue_codes):
            result.status = STATUS_UNEXPECTED_COMPONENT

    if result.status == STATUS_PROTECTED:
        result.verdict = VERDICT_MIGRATE
        equivalent_notes = [check for check in result.checks if check.status == 'equivalent']
        if equivalent_notes:
            result.summary = 'Protected; algorithm identifiers match with permitted parameter equivalence.'
        else:
            result.summary = 'Protected; digest and signature/MAC identifiers match the protected attribute.'
    elif result.status in (STATUS_UNPROTECTED,):
        result.verdict = VERDICT_SUPPLEMENT
        result.summary = (
            'No CMSAlgorithmProtection declaration; the ledger claim is unsupported. '
            'Return for supplementary materials.'
        )
    elif result.status == STATUS_UNAUTHENTICATED:
        result.verdict = VERDICT_SUPPLEMENT
        result.summary = (
            'CMSAlgorithmProtection appears only in an unauthenticated attribute location; '
            'it can not support the protection claim. Return for supplementary materials.'
        )
    elif result.status == STATUS_DUPLICATE:
        result.verdict = VERDICT_SUPPLEMENT
        result.summary = (
            'More than one CMSAlgorithmProtection attribute or value is present; '
            'the authoritative declaration is ambiguous. Return for supplementary materials.'
        )
    elif result.status == STATUS_ALGORITHM_MISMATCH:
        result.verdict = VERDICT_SUPPLEMENT
        result.summary = (
            'The protected algorithm identifier does not match the signer/AuthenticatedData structure. '
            'Return for supplementary materials.'
        )
    elif result.status == STATUS_PARAMETER_MISMATCH:
        result.verdict = VERDICT_SUPPLEMENT
        result.summary = (
            'The algorithm name matches but the parameters are not equivalent. '
            'Return for supplementary materials.'
        )
    elif result.status == STATUS_UNEXPECTED_COMPONENT:
        result.verdict = VERDICT_SUPPLEMENT
        result.summary = (
            'CMSAlgorithmProtection contains a component that does not apply to this structure. '
            'Return for supplementary materials.'
        )
    elif result.status == STATUS_MALFORMED:
        result.verdict = VERDICT_SUPPLEMENT
        result.summary = (
            'The CMSAlgorithmProtection attribute is malformed. Return for supplementary materials.'
        )
    elif result.status == STATUS_INDETERMINATE:
        result.verdict = VERDICT_MANUAL_REVIEW
        result.summary = (
            'The installed implementation can not interpret some protected parameters. Manual review required.'
        )
    else:
        result.verdict = VERDICT_MANUAL_REVIEW
        result.summary = 'The CMS structure could not be reviewed automatically. Manual review required.'


def _review_signer(signer_info, signer_index, digest_algorithms):
    path = 'signer_infos[%d]' % signer_index
    result = AlgorithmProtectionResult('signer', signer_index, path, _identity_for_signer(signer_info))

    authenticated = _collect_protection_attributes(signer_info, 'signed_attrs', path)
    unauthenticated = _collect_protection_attributes(signer_info, 'unsigned_attrs', path)

    for record in authenticated:
        result.attribute_locations.append(collections.OrderedDict([
            ('location', 'signed_attrs'),
            ('path', record['path']),
            ('attribute_index', record['attribute_index']),
            ('authenticated', True),
            ('value_count', len(record['values']) if record.get('values') is not None else None),
        ]))
    for record in unauthenticated:
        result.attribute_locations.append(collections.OrderedDict([
            ('location', 'unsigned_attrs'),
            ('path', record['path']),
            ('attribute_index', record['attribute_index']),
            ('authenticated', False),
            ('value_count', len(record['values']) if record.get('values') is not None else None),
        ]))

    if not authenticated and not unauthenticated:
        result.status = STATUS_UNPROTECTED
        result._add_issue(
            'missing_protection_attribute',
            'No CMSAlgorithmProtection attribute is present in signedAttrs or unsignedAttrs.',
            path=path,
        )
        _set_verdict(result)
        return result

    if not authenticated:
        result.status = STATUS_UNAUTHENTICATED
        for record in unauthenticated:
            result._add_issue(
                'unauthenticated_location',
                'CMSAlgorithmProtection is present only in unsignedAttrs, which is not protected by the signature.',
                path=record['path'],
                attribute_index=record['attribute_index'],
            )
        _set_verdict(result)
        return result

    if len(authenticated) > 1 or len(unauthenticated) > 0:
        result.status = STATUS_DUPLICATE
        if len(authenticated) > 1:
            result._add_issue(
                'duplicate_attribute',
                'Multiple CMSAlgorithmProtection attributes are present in signedAttrs.',
                path=path,
            )
        for record in unauthenticated:
            result._add_issue(
                'unauthenticated_copy',
                'An additional CMSAlgorithmProtection attribute is present in unsignedAttrs.',
                path=record['path'],
                attribute_index=record['attribute_index'],
            )
        # Still inspect the signed attribute so the report is locatable, but
        # the duplicate/ambiguous condition controls the verdict.

    record = authenticated[0]
    if record.get('error'):
        result.status = STATUS_MALFORMED
        result._add_issue(
            'attribute_unparseable',
            'The CMSAlgorithmProtection attribute could not be decoded: %s' % record['error'],
            path=record['path'],
            attribute_index=record['attribute_index'],
        )
        _set_verdict(result)
        return result

    if len(record['values']) == 0:
        if result.status != STATUS_DUPLICATE:
            result.status = STATUS_MALFORMED
        result._add_issue(
            'missing_attribute_value',
            'CMSAlgorithmProtection must have exactly one value; none was found.',
            path=record['path'],
            attribute_index=record['attribute_index'],
        )
        _set_verdict(result)
        return result

    if len(record['values']) != 1:
        if result.status != STATUS_DUPLICATE:
            result.status = STATUS_DUPLICATE
        result._add_issue(
            'duplicate_attribute_value',
            'CMSAlgorithmProtection must have exactly one value; found %d.' % len(record['values']),
            path=record['path'],
            attribute_index=record['attribute_index'],
        )
        _set_verdict(result)
        return result

    value_record = record['values'][0]
    protection_value = value_record['value']
    if not isinstance(protection_value, cms.CMSAlgorithmProtection):
        try:
            protection_value = protection_value.parsed
        except Exception:
            pass

    if not isinstance(protection_value, cms.CMSAlgorithmProtection):
        result.status = STATUS_MALFORMED
        result._add_issue(
            'attribute_value_malformed',
            'The CMSAlgorithmProtection value does not decode to a CMSAlgorithmProtection structure.',
            path=value_record['path'],
            attribute_index=record['attribute_index'],
            value_index=value_record['value_index'],
        )
        _set_verdict(result)
        return result

    try:
        signer_digest = signer_info['digest_algorithm']
        signer_signature = signer_info['signature_algorithm']
    except Exception as exc:
        result.status = STATUS_MALFORMED
        result._add_issue(
            'signer_algorithm_unparseable',
            'The SignerInfo algorithm identifiers could not be decoded: %s' % _asn1_error_text(exc),
            path=path,
        )
        _set_verdict(result)
        return result

    # A SignedData protects a signature, not a MAC.
    try:
        unexpected_mac = protection_value['mac_algorithm']
    except Exception:
        unexpected_mac = None
    if unexpected_mac is not None and not isinstance(unexpected_mac, core.Void):
        result._add_issue(
            'unexpected_mac_algorithm',
            'CMSAlgorithmProtection for a SignedData signer must not contain macAlgorithm.',
            path=value_record['path'],
            role=ROLE_MAC,
            attribute_index=record['attribute_index'],
            value_index=value_record['value_index'],
        )

    digest_check = _compare_component(protection_value, 'digest_algorithm', signer_digest, ROLE_DIGEST)
    signer_digest_name = _algorithm_info(signer_digest).get('name')
    signature_check = _compare_component(
        protection_value,
        'signature_algorithm',
        signer_signature,
        ROLE_SIGNATURE,
        digest_name=signer_digest_name,
    )

    for check in (digest_check, signature_check):
        _apply_check_outcome(
            result,
            check,
            value_record['path'],
            record['attribute_index'],
            value_record['value_index'],
        )

    digest_membership_issue = False
    if signer_digest is not None and digest_algorithms:
        signer_digest_oid = _algorithm_info(signer_digest).get('oid')
        digest_oids = set(_algorithm_info(algorithm).get('oid') for algorithm in digest_algorithms)
        if signer_digest_oid and signer_digest_oid not in digest_oids:
            digest_membership_issue = True
            result._add_issue(
                'digest_not_in_digest_algorithms',
                'The SignerInfo digest algorithm is not listed in SignedData.digestAlgorithms.',
                path=path,
                role=ROLE_DIGEST,
            )

    if result.status != STATUS_DUPLICATE and result.status != STATUS_MALFORMED:
        result.status = STATUS_MALFORMED if digest_membership_issue else STATUS_PROTECTED
    _set_verdict(result)

    return result


def _review_authenticated_data(authenticated_data, digest_algorithms):
    path = 'authenticated_data'
    result = AlgorithmProtectionResult(
        'authenticated_data',
        0,
        path,
        collections.OrderedDict([('type', 'authenticated_data')]),
    )

    authenticated = _collect_protection_attributes(authenticated_data, 'auth_attrs', path)
    unauthenticated = _collect_protection_attributes(authenticated_data, 'unauth_attrs', path)

    for record in authenticated:
        result.attribute_locations.append(collections.OrderedDict([
            ('location', 'auth_attrs'),
            ('path', record['path']),
            ('attribute_index', record['attribute_index']),
            ('authenticated', True),
            ('value_count', len(record['values']) if record.get('values') is not None else None),
        ]))
    for record in unauthenticated:
        result.attribute_locations.append(collections.OrderedDict([
            ('location', 'unauth_attrs'),
            ('path', record['path']),
            ('attribute_index', record['attribute_index']),
            ('authenticated', False),
            ('value_count', len(record['values']) if record.get('values') is not None else None),
        ]))

    if not authenticated and not unauthenticated:
        result.status = STATUS_UNPROTECTED
        result._add_issue(
            'missing_protection_attribute',
            'No CMSAlgorithmProtection attribute is present in authAttrs or unauthAttrs.',
            path=path,
        )
        _set_verdict(result)
        return result

    if not authenticated:
        result.status = STATUS_UNAUTHENTICATED
        for record in unauthenticated:
            result._add_issue(
                'unauthenticated_location',
                'CMSAlgorithmProtection is present only in unauthAttrs, which is not covered by the MAC.',
                path=record['path'],
                attribute_index=record['attribute_index'],
            )
        _set_verdict(result)
        return result

    if len(authenticated) > 1 or len(unauthenticated) > 0:
        result.status = STATUS_DUPLICATE
        if len(authenticated) > 1:
            result._add_issue(
                'duplicate_attribute',
                'Multiple CMSAlgorithmProtection attributes are present in authAttrs.',
                path=path,
            )
        for record in unauthenticated:
            result._add_issue(
                'unauthenticated_copy',
                'An additional CMSAlgorithmProtection attribute is present in unauthAttrs.',
                path=record['path'],
                attribute_index=record['attribute_index'],
            )

    record = authenticated[0]
    if record.get('error'):
        result.status = STATUS_MALFORMED
        result._add_issue(
            'attribute_unparseable',
            'The CMSAlgorithmProtection attribute could not be decoded: %s' % record['error'],
            path=record['path'],
            attribute_index=record['attribute_index'],
        )
        _set_verdict(result)
        return result

    if len(record['values']) == 0:
        if result.status != STATUS_DUPLICATE:
            result.status = STATUS_MALFORMED
        result._add_issue(
            'missing_attribute_value',
            'CMSAlgorithmProtection must have exactly one value; none was found.',
            path=record['path'],
            attribute_index=record['attribute_index'],
        )
        _set_verdict(result)
        return result

    if len(record['values']) != 1:
        if result.status != STATUS_DUPLICATE:
            result.status = STATUS_DUPLICATE
        result._add_issue(
            'duplicate_attribute_value',
            'CMSAlgorithmProtection must have exactly one value; found %d.' % len(record['values']),
            path=record['path'],
            attribute_index=record['attribute_index'],
        )
        _set_verdict(result)
        return result

    value_record = record['values'][0]
    protection_value = value_record['value']
    if not isinstance(protection_value, cms.CMSAlgorithmProtection):
        try:
            protection_value = protection_value.parsed
        except Exception:
            pass

    if not isinstance(protection_value, cms.CMSAlgorithmProtection):
        result.status = STATUS_MALFORMED
        result._add_issue(
            'attribute_value_malformed',
            'The CMSAlgorithmProtection value does not decode to a CMSAlgorithmProtection structure.',
            path=value_record['path'],
            attribute_index=record['attribute_index'],
            value_index=value_record['value_index'],
        )
        _set_verdict(result)
        return result

    try:
        ad_digest = authenticated_data['digest_algorithm']
        ad_mac = authenticated_data['mac_algorithm']
    except Exception as exc:
        result.status = STATUS_MALFORMED
        result._add_issue(
            'authenticated_data_algorithm_unparseable',
            'The AuthenticatedData algorithm identifiers could not be decoded: %s' % _asn1_error_text(exc),
            path=path,
        )
        _set_verdict(result)
        return result

    # AuthenticatedData protects a MAC, not a signature.
    try:
        unexpected_signature = protection_value['signature_algorithm']
    except Exception:
        unexpected_signature = None
    if unexpected_signature is not None and not isinstance(unexpected_signature, core.Void):
        result._add_issue(
            'unexpected_signature_algorithm',
            'CMSAlgorithmProtection for AuthenticatedData must not contain signatureAlgorithm.',
            path=value_record['path'],
            role=ROLE_SIGNATURE,
            attribute_index=record['attribute_index'],
            value_index=value_record['value_index'],
        )

    digest_check = _compare_component(protection_value, 'digest_algorithm', ad_digest, ROLE_DIGEST)
    mac_check = _compare_component(protection_value, 'mac_algorithm', ad_mac, ROLE_MAC)

    for check in (digest_check, mac_check):
        _apply_check_outcome(
            result,
            check,
            value_record['path'],
            record['attribute_index'],
            value_record['value_index'],
        )

    if result.status != STATUS_DUPLICATE and result.status != STATUS_MALFORMED:
        result.status = STATUS_PROTECTED
    _set_verdict(result)

    if ad_digest is not None and digest_algorithms:
        ad_digest_oid = _algorithm_info(ad_digest).get('oid')
        digest_oids = set(_algorithm_info(algorithm).get('oid') for algorithm in digest_algorithms)
        if ad_digest_oid and ad_digest_oid not in digest_oids:
            result._add_issue(
                'digest_not_in_digest_algorithms',
                'The AuthenticatedData digest algorithm is not present in the expected set.',
                path=path,
                role=ROLE_DIGEST,
            )

    return result


def _load_content_info(value):
    if isinstance(value, cms.ContentInfo):
        return value
    if isinstance(value, (cms.SignedData, cms.SignerInfo, cms.AuthenticatedData)):
        return value

    if isinstance(value, bytearray):
        value = bytes(value)

    if isinstance(value, bytes):
        data = value
        if data.lstrip().startswith(b'-----BEGIN'):
            _, _, der = pem.unarmor(data)
            data = der
        try:
            return cms.ContentInfo.load(data)
        except Exception as content_info_error:
            try:
                return cms.SignedData.load(data)
            except Exception:
                try:
                    return cms.AuthenticatedData.load(data)
                except Exception:
                    try:
                        return cms.SignerInfo.load(data)
                    except Exception:
                        raise content_info_error

    raise TypeError('value must be a CMS ContentInfo/SignedData/AuthenticatedData object or DER/PEM bytes')


def review(value):
    """
    Reviews the RFC 6211 CMSAlgorithmProtection declarations in a CMS
    ContentInfo, SignedData or AuthenticatedData structure.

    The returned object contains one independent result per SignerInfo and
    one for AuthenticatedData.  No signature or MAC verification is
    performed.

    :param value:
        A cms.ContentInfo, cms.SignedData, cms.AuthenticatedData, or DER/PEM
        byte string

    :return:
        A CMSAlgorithmProtectionReview object
    """

    loaded = _load_content_info(value)

    if isinstance(loaded, cms.SignerInfo):
        review_obj = CMSAlgorithmProtectionReview('signer_info')
        review_obj.results.append(_review_signer(loaded, 0, []))
        return review_obj
    elif isinstance(loaded, cms.SignedData):
        signed_data = loaded
        content_type = 'signed_data'
        authenticated_data = None
    elif isinstance(loaded, cms.AuthenticatedData):
        signed_data = None
        content_type = 'authenticated_data'
        authenticated_data = loaded
    elif isinstance(loaded, cms.ContentInfo):
        try:
            content_type = loaded['content_type'].native
        except Exception as exc:
            review_obj = CMSAlgorithmProtectionReview('unknown')
            review_obj.errors.append('Could not decode ContentInfo.contentType: %s' % _asn1_error_text(exc))
            return review_obj
        if content_type not in ('signed_data', 'authenticated_data'):
            review_obj = CMSAlgorithmProtectionReview(content_type)
            review_obj.errors.append(
                'Content type %s does not contain SignerInfo or AuthenticatedData subjects.' % content_type
            )
            return review_obj
        try:
            content = loaded['content']
        except Exception as exc:
            review_obj = CMSAlgorithmProtectionReview(content_type)
            review_obj.errors.append('Could not decode ContentInfo.content: %s' % _asn1_error_text(exc))
            return review_obj
        if content_type == 'signed_data':
            signed_data = content
            authenticated_data = None
        else:
            signed_data = None
            authenticated_data = content
    else:
        raise TypeError('Unsupported CMS value type')

    review_obj = CMSAlgorithmProtectionReview(content_type)

    if signed_data is not None:
        try:
            digest_algorithms = list(signed_data['digest_algorithms'])
        except Exception as exc:
            digest_algorithms = []
            review_obj.errors.append('Could not decode SignedData.digestAlgorithms: %s' % _asn1_error_text(exc))
        for algorithm in digest_algorithms:
            review_obj.digest_algorithms.append(_public_algorithm_info(_algorithm_info(algorithm)))

        try:
            signer_infos = list(signed_data['signer_infos'])
        except Exception as exc:
            review_obj.errors.append('Could not decode SignedData.signerInfos: %s' % _asn1_error_text(exc))
            signer_infos = []

        for signer_index, signer_info in enumerate(signer_infos):
            review_obj.results.append(_review_signer(signer_info, signer_index, digest_algorithms))

    if authenticated_data is not None:
        try:
            ad_digest = authenticated_data['digest_algorithm']
            if ad_digest is not None and not isinstance(ad_digest, core.Void):
                review_obj.digest_algorithms.append(_public_algorithm_info(_algorithm_info(ad_digest)))
        except Exception:
            pass
        review_obj.results.append(_review_authenticated_data(authenticated_data, []))

    return review_obj


def analyze(value):
    """Alias for :func:`review`."""
    return review(value)


def review_algorithm_protection(value):
    """Alias for :func:`review`."""
    return review(value)


def analyze_algorithm_protection(value):
    """Alias for :func:`review`."""
    return review(value)


def check_algorithm_protection(value):
    """Alias for :func:`review`."""
    return review(value)


def review_results(value):
    """Reviews a CMS value and returns only the list of per-subject results."""
    return review(value).results


def review_native(value):
    """Reviews a CMS value and returns a JSON-friendly native dictionary."""
    return review(value).native


def review_signer_info(signer_info):
    """Reviews one cms.SignerInfo object independently."""
    return _review_signer(signer_info, 0, [])


def review_authenticated_data(authenticated_data):
    """Reviews one cms.AuthenticatedData object independently."""
    return _review_authenticated_data(authenticated_data, [])


__all__ = [
    'OID_CMS_ALGORITHM_PROTECTION',
    'STATUS_PROTECTED',
    'STATUS_UNPROTECTED',
    'STATUS_UNAUTHENTICATED',
    'STATUS_DUPLICATE',
    'STATUS_ALGORITHM_MISMATCH',
    'STATUS_PARAMETER_MISMATCH',
    'STATUS_INDETERMINATE',
    'STATUS_MALFORMED',
    'STATUS_UNEXPECTED_COMPONENT',
    'STATUS_UNSUPPORTED_CONTENT',
    'STATUS_ERROR',
    'VERDICT_MIGRATE',
    'VERDICT_SUPPLEMENT',
    'VERDICT_MANUAL_REVIEW',
    'ROLE_DIGEST',
    'ROLE_SIGNATURE',
    'ROLE_MAC',
    'AlgorithmComparison',
    'AlgorithmProtectionResult',
    'CMSAlgorithmProtectionReview',
    'compare_algorithm_identifiers',
    'review',
    'analyze',
    'review_algorithm_protection',
    'analyze_algorithm_protection',
    'check_algorithm_protection',
    'review_results',
    'review_native',
    'review_signer_info',
    'review_authenticated_data',
]
