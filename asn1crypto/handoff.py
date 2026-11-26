# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import base64
import binascii
import copy as copy_module
import hashlib
import hmac as hmac_module
import json
import os

from ._types import str_cls, byte_cls
from .core import Integer, OctetString, Sequence, UTF8String


__all__ = [
    'EvidenceIdentity',
    'PresentableProjection',
    'VerifiableMaterial',
    'VerificationReceipt',
    'LocalSignoff',
    'LocalSignoffRecord',
    'HandoffBundle',
    'ReportView',
    'Status',
    'VerificationRequest',
    'HandoffError',
    'EvidenceMismatch',
    'VerificationRequired',
    'InvalidReceipt',
    'prepare_handoff',
    'build_handoff',
    'check_handoff',
    'cms_report',
    'create_cms_handoff',
    'IDENTITY_VERSION',
    'VERIFIED',
    'REJECTED',
    'PENDING',
    'STALE',
    'INVALID',
    'INCONCLUSIVE',
]


IDENTITY_VERSION = 'asn1crypto-handoff-v1'

VERIFIED = 'verified'
REJECTED = 'rejected'
PENDING = 'pending'
STALE = 'stale'
INVALID = 'invalid'
INCONCLUSIVE = 'inconclusive'
AWAITING_VERIFICATION = PENDING
WAITING_FOR_VERIFICATION = PENDING
VERIFICATION_REQUIRED = PENDING

_SUCCESS_VERDICTS = set(['verified', 'valid', 'ok', 'okay', 'approved', 'pass', 'passed', 'success', 'successful'])
_FAILURE_VERDICTS = set(['rejected', 'invalid', 'failed', 'failure', 'denied', 'untrusted', 'bad'])
_PENDING_VERDICTS = set(['pending', 'waiting', 'unverified', 'unknown', 'inconclusive', 'needs_review'])


class HandoffError(Exception):
    '''Base class for transfer protocol errors.'''


class EvidenceMismatch(HandoffError):
    '''Raised when separately supplied evidence does not agree.'''


class VerificationRequired(HandoffError):
    '''Raised when an operation needs a current independent receipt.'''


class InvalidReceipt(HandoffError):
    '''Raised when a receipt is malformed or fails authentication.'''


class LocalSignoffRecord(Sequence):
    '''A small ASN.1 shape for an ordinary local sign-off receipt.'''

    _fields = [
        ('version', Integer, {'default': 1}),
        ('payload', UTF8String),
        ('signature_algorithm', UTF8String, {'optional': True}),
        ('signature_value', OctetString, {'optional': True}),
    ]


def _is_asn1_value(value):
    return (
        hasattr(value, 'dump')
        and hasattr(value, '__class__')
        and value.__class__.__module__.startswith('asn1crypto')
    )


def _coerce_bytes(value):
    if value is None:
        return None
    if isinstance(value, byte_cls):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if _is_asn1_value(value):
        return value.dump(force=True)
    if hasattr(value, 'preserved_der'):
        return _coerce_bytes(value.preserved_der)
    if hasattr(value, 'der'):
        return _coerce_bytes(value.der)
    if isinstance(value, str_cls):
        return value.encode('utf-8')
    raise TypeError('expected bytes or an ASN.1 value, not %s' % type(value).__name__)


def digest_bytes(data, algorithm='sha256'):
    if data is None:
        data = b''
    data = _coerce_bytes(data)
    return '%s:%s' % (algorithm, hashlib.new(algorithm, data).hexdigest())


def _decode_digest(value):
    if value is None:
        return None
    if isinstance(value, byte_cls):
        value = value.decode('ascii')
    text = str_cls(value)
    if ':' not in text:
        return 'sha256:' + text
    return text


def _b64encode(data):
    return base64.b64encode(data).decode('ascii')


def _b64decode(value):
    if isinstance(value, byte_cls):
        value = value.decode('ascii')
    return base64.b64decode(value.encode('ascii'))


def _canonical_data(value):
    if isinstance(value, EvidenceIdentity):
        return str_cls(value)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            result[str_cls(key)] = _canonical_data(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_canonical_data(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_canonical_data(item) for item in value]
        return sorted(items, key=lambda item: canonical_bytes(item))
    if isinstance(value, (byte_cls, bytearray, memoryview)):
        raw = _coerce_bytes(value)
        return {'__type__': 'bytes', 'encoding': 'base64', 'value': _b64encode(raw), 'sha256': digest_bytes(raw)}
    if _is_asn1_value(value):
        raw = value.dump(force=True)
        return {
            '__type__': 'asn1',
            'class': value.__class__.__name__,
            'sha256': digest_bytes(raw),
            'der': _b64encode(raw),
        }
    if hasattr(value, 'to_transfer_dict'):
        return _canonical_data(value.to_transfer_dict())
    if hasattr(value, 'to_dict'):
        try:
            return _canonical_data(value.to_dict())
        except TypeError:
            pass
    return value


def canonical_bytes(value):
    normalized = _canonical_data(value)
    text = json.dumps(
        normalized,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=lambda item: _canonical_data(_json_default(item)),
    )
    return text.encode('utf-8')


def _json_default(value):
    if hasattr(value, 'native'):
        return value.native
    return str_cls(value)


def canonical_digest(value):
    return digest_bytes(canonical_bytes(value))


class EvidenceIdentity(str_cls):
    '''
    Immutable identity for one exact material blob and inspected scope.

    The object itself is also its stable URN string, making equality and
    cross-process dictionary keys straightforward.
    '''

    def __new__(
        cls,
        material=None,
        scope=None,
        evidence_id=None,
        material_digest=None,
        scope_digest=None,
        algorithm='sha256',
        identity=None,
        identity_id=None,
        **kwargs
    ):
        if isinstance(material, EvidenceIdentity) and scope is None and evidence_id is None:
            return material
        if identity is not None:
            return cls._from_mapping(identity)
        if identity_id is not None and evidence_id is None:
            evidence_id = identity_id
        if isinstance(evidence_id, EvidenceIdentity):
            return evidence_id

        if (
            evidence_id is not None
            and material is None
            and material_digest is None
            and scope is None
            and scope_digest is None
        ):
            text = str_cls(evidence_id)
            obj = str_cls.__new__(cls, text)
            obj.material_digest = None
            obj.scope_digest = None
            obj.scope = None
            obj.logical_id = None
            obj.algorithm = algorithm
            obj.explicit = True
            return obj

        if material_digest is None and material is not None:
            if isinstance(material, EvidenceIdentity):
                material_digest = material.material_digest
                if scope is None:
                    scope = material.scope
            else:
                material_digest = digest_bytes(material, algorithm)
        material_digest = _decode_digest(material_digest)

        if scope_digest is None:
            scope_digest = canonical_digest(scope)
        else:
            scope_digest = _decode_digest(scope_digest)

        logical_id = kwargs.get('logical_id') or kwargs.get('namespace')

        payload = canonical_bytes({
            'version': IDENTITY_VERSION,
            'material': material_digest,
            'scope': scope_digest,
            'logical_id': logical_id,
        })
        identity_digest = hashlib.new(algorithm, payload).hexdigest()
        urn = 'urn:%s:identity:%s:%s' % (IDENTITY_VERSION, algorithm, identity_digest)
        if evidence_id:
            urn = urn + ':' + str_cls(evidence_id)

        obj = str_cls.__new__(cls, urn)
        obj.material_digest = material_digest
        obj.scope_digest = scope_digest
        obj.scope = scope
        obj.logical_id = logical_id
        obj.algorithm = algorithm
        obj.explicit = False
        obj.identity_digest = '%s:%s' % (algorithm, identity_digest)
        return obj

    @classmethod
    def _from_mapping(cls, value):
        if isinstance(value, EvidenceIdentity):
            return value
        if isinstance(value, dict):
            urn = value.get('evidence_id') or value.get('id')
            if urn:
                obj = str_cls.__new__(cls, urn)
                obj.material_digest = _decode_digest(value.get('material_digest'))
                obj.scope_digest = _decode_digest(value.get('scope_digest'))
                obj.scope = value.get('scope')
                obj.logical_id = value.get('logical_id')
                obj.algorithm = (value.get('identity_digest') or 'sha256').split(':', 1)[0]
                obj.explicit = value.get('explicit', False)
                obj.identity_digest = value.get('identity_digest')
                return obj
            return cls(
                material_digest=value.get('material_digest'),
                scope_digest=value.get('scope_digest'),
                scope=value.get('scope'),
            )
        return cls(evidence_id=value)

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        new_obj = str_cls.__new__(self.__class__, str_cls(self))
        memo[id(self)] = new_obj
        for key, value in self.__dict__.items():
            setattr(new_obj, key, copy_module.deepcopy(value, memo))
        return new_obj

    def __reduce__(self):
        return (_restore_identity, (self.to_dict(),))

    @property
    def id(self):
        return str_cls(self)

    @property
    def evidence_id(self):
        return str_cls(self)

    @property
    def fingerprint(self):
        return getattr(self, 'identity_digest', None) or str_cls(self)

    @property
    def digest(self):
        return self.fingerprint

    @property
    def key(self):
        return str_cls(self)

    @property
    def identity(self):
        return self

    def for_scope(self, scope):
        return EvidenceIdentity(
            material_digest=self.material_digest,
            scope=scope,
            logical_id=self.logical_id,
        )

    def with_scope(self, scope):
        return self.for_scope(scope)

    def matches(self, other):
        if other is None:
            return False
        if isinstance(other, VerificationReceipt):
            return other.covers(self)
        other_id = _as_identity(other)
        return str_cls(self) == str_cls(other_id)

    def to_dict(self):
        return {
            'evidence_id': str_cls(self),
            'material_digest': self.material_digest,
            'scope_digest': self.scope_digest,
            'identity_digest': getattr(self, 'identity_digest', None),
            'version': IDENTITY_VERSION,
            'logical_id': self.logical_id,
            'explicit': getattr(self, 'explicit', False),
        }


def _as_identity(value):
    if value is None or isinstance(value, EvidenceIdentity):
        return value
    if isinstance(value, dict):
        return EvidenceIdentity._from_mapping(value)
    return EvidenceIdentity(evidence_id=value)


def _restore_identity(value):
    return EvidenceIdentity._from_mapping(value)


class ReportView(str_cls):
    '''A display-only string with non-authoritative presentation metadata.'''

    def __new__(cls, text='', title=None, status=None, identity=None, conclusion=None, projection=None):
        if text is None:
            text = ''
        obj = str_cls.__new__(cls, text)
        obj.title = title
        obj.status = status
        obj.identity = identity
        obj.conclusion = conclusion
        obj.projection = projection
        obj.display_text = text
        return obj


class Status(str_cls):
    '''String status that also compares equal to common synonym names.'''

    def __new__(cls, value, aliases=None):
        obj = str_cls.__new__(cls, value)
        obj.aliases = tuple(aliases or ())
        return obj

    def __eq__(self, other):
        if str_cls.__eq__(self, other):
            return True
        return other in self.aliases

    def __hash__(self):
        return hash(str_cls(self))


_STATUS_ALIASES = {
    VERIFIED: (VERIFIED, 'valid', 'ok', 'current', 'succeeded', 'success'),
    REJECTED: (REJECTED, 'denied', 'failed', 'failure'),
    PENDING: (PENDING, AWAITING_VERIFICATION, 'waiting', 'waiting_verification',
              'needs_verification', 'verification_required', 'not_verified', 'unknown'),
    STALE: (STALE, 'outdated', 'scope_changed', 'identity_changed', 'needs_reverification'),
    INVALID: (INVALID, 'bad_signature', 'unauthenticated'),
    INCONCLUSIVE: (INCONCLUSIVE, 'unknown', 'indeterminate'),
}


def _as_status(value):
    if value is None:
        return None
    return Status(value, _STATUS_ALIASES.get(value, ()))


class PresentableProjection(object):
    '''
    Data that is safe or intended for display.

    A projection never establishes evidence identity. It may be lazily built,
    copied, or re-encoded without changing the preserved original material.
    '''

    def __init__(self, report=None, text=None, data=None, loader=None, factory=None,
                 source=None, asn1_value=None, renderer=None, title=None, format=None,
                 content_type=None, display_text=None, **kwargs):
        if callable(report) and loader is None:
            loader = report
            report = None
        if report is not None and text is None and not isinstance(report, (dict, list, tuple)):
            text = report
            report = None

        self.title = title or kwargs.get('name')
        self.format = format or kwargs.get('output_format') or 'text'
        self.content_type = content_type
        self.renderer = renderer or kwargs.get('render')
        self.loader = loader or factory or kwargs.get('lazy_loader')
        self.source = source if source is not None else asn1_value
        if self.source is None and 'value' in kwargs:
            self.source = kwargs.get('value')

        self._text = display_text if display_text is not None else text
        self._data = data if data is not None else report
        self._resolved = None
        self.expanded = self.loader is None and self._text is None and self._data is None and self.source is not None
        if self._text is not None or self._data is not None:
            self.expanded = True
        self.expand_count = 0
        self.view_count = 0
        self.encoding_count = 0
        self.last_encoding = None

    @property
    def display_text(self):
        return self.text

    @property
    def text(self):
        value = self.expand()
        if self._text is not None:
            return self._text
        if isinstance(value, str_cls):
            return value
        return self._render_data(value)

    @property
    def report(self):
        return self.expand()._resolved

    @property
    def native(self):
        value = self.expand()._resolved
        if value is None:
            value = self.source
        if hasattr(value, 'native'):
            return value.native
        return value

    def _render_data(self, value):
        if self.renderer is not None:
            rendered = self.renderer(value)
            return rendered if isinstance(rendered, str_cls) else json.dumps(
                _canonical_data(rendered), ensure_ascii=False, indent=2, sort_keys=True, default=str_cls
            )
        if isinstance(value, str_cls):
            return value
        return json.dumps(_canonical_data(value), ensure_ascii=False, indent=2, sort_keys=True, default=str_cls)

    def expand(self):
        if self._resolved is not None:
            return self
        self.expand_count += 1
        if self._text is not None:
            self._resolved = self._text
        elif self._data is not None:
            self._resolved = self._data
        elif self.loader is not None:
            self._resolved = self.loader()
        elif self.source is not None:
            self._resolved = self.source
        else:
            self._resolved = ''
        if self._text is None and not isinstance(self._resolved, (str_cls, bytes)):
            try:
                self._text = self._render_data(self._resolved)
            except (TypeError, ValueError):
                self._text = str_cls(self._resolved)
        elif isinstance(self._resolved, str_cls):
            self._text = self._resolved
        self.expanded = True
        return self

    def materialize(self):
        return self.expand()

    def view(self):
        self.view_count += 1
        return ReportView(self.text, title=self.title, projection=self)

    def view_report(self):
        return self.view()

    def reencode(self, encoder=None, force=True):
        self.encoding_count += 1
        target = self.source if self.source is not None else self._resolved
        if encoder is not None:
            self.last_encoding = encoder(target)
        elif _is_asn1_value(target):
            self.last_encoding = target.dump(force=force)
        elif isinstance(target, (byte_cls, bytearray, memoryview)):
            parsed = _coerce_bytes(target)
            self.last_encoding = parsed
        else:
            self.last_encoding = canonical_bytes(self.text)
        return self.last_encoding

    re_encode = reencode

    def clone(self):
        return copy_module.deepcopy(self)

    def copy(self):
        return self.clone()

    duplicate = clone

    def __copy__(self):
        return self.clone()

    def __deepcopy__(self, memo):
        new_obj = object.__new__(self.__class__)
        memo[id(self)] = new_obj
        for key, value in self.__dict__.items():
            if key == 'loader' and (self._resolved is None):
                setattr(new_obj, key, value)
            else:
                setattr(new_obj, key, copy_module.deepcopy(value, memo))
        return new_obj

    def to_dict(self):
        self.expand()
        return {
            'title': self.title,
            'format': self.format,
            'content_type': self.content_type,
            'text': self.text,
            'data': _canonical_data(self._resolved if not _is_asn1_value(self._resolved) else None),
        }


class VerifiableMaterial(object):
    '''Exact bytes that an independent verifier can check.'''

    def __init__(self, data=None, source=None, content_type=None, media_type=None,
                 parser=None, spec=None, algorithm='sha256', material_id=None, **kwargs):
        for alias in ('raw', 'raw_material', 'original', 'original_material', 'der', 'bytes', 'value', 'material'):
            if data is None and alias in kwargs:
                data = kwargs.pop(alias)
        if data is None and source is not None:
            data = source
        if data is None:
            raise TypeError('VerifiableMaterial requires raw bytes or an ASN.1 value')

        self.raw = _coerce_bytes(data)
        self.source_object = data if _is_asn1_value(data) else None
        self.content_type = content_type or media_type or kwargs.pop('type', None)
        self.media_type = media_type
        self.parser = parser
        self.spec = spec
        self.algorithm = algorithm
        self.material_id = material_id
        self.preserved_der = self.raw
        self._parsed = None
        self.parse_count = 0

    @property
    def bytes(self):
        return self.raw

    @property
    def der(self):
        return self.raw

    @property
    def data(self):
        return self.raw

    @property
    def sha256(self):
        return digest_bytes(self.raw, 'sha256')

    @property
    def digest(self):
        return digest_bytes(self.raw, self.algorithm)

    def evidence_identity(self, scope=None, evidence_id=None):
        return EvidenceIdentity(material_digest=self.digest, scope=scope, evidence_id=evidence_id)

    identity = evidence_identity

    def parse(self, spec=None, force=False):
        spec = spec or self.spec or self.parser
        if isinstance(spec, str_cls):
            if spec.lower() in ('cms', 'contentinfo', 'cms.contentinfo'):
                from .cms import ContentInfo as spec
            else:
                raise ValueError('unknown ASN.1 spec alias: %s' % spec)
        if self._parsed is not None and not force:
            return self._parsed
        self.parse_count += 1
        if spec is None:
            from .core import load as generic_load
            self._parsed = generic_load(self.raw)
        elif hasattr(spec, 'load'):
            self._parsed = spec.load(self.raw)
        elif callable(spec):
            self._parsed = spec(self.raw)
        else:
            raise TypeError('parser/spec must be callable or expose load()')
        return self._parsed

    def expand(self, spec=None):
        return self.parse(spec=spec)

    @property
    def parsed(self):
        return self.parse()

    def reencode(self, force=True, spec=None):
        parsed = self.parse(spec=spec)
        raw = parsed.dump(force=force)
        return VerifiableMaterial(
            raw,
            content_type=self.content_type,
            media_type=self.media_type,
            spec=self.spec,
            algorithm=self.algorithm,
            material_id=self.material_id,
        )

    re_encode = reencode

    def clone(self):
        new_obj = object.__new__(self.__class__)
        new_obj.__dict__.update(copy_module.deepcopy(self.__dict__))
        return new_obj

    def copy(self):
        return self.clone()

    def to_dict(self):
        return {
            'encoding': 'base64',
            'raw': _b64encode(self.raw),
            'digest': self.digest,
            'content_type': self.content_type,
            'media_type': self.media_type,
            'material_id': self.material_id,
        }

    @classmethod
    def from_dict(cls, value):
        return cls(
            _b64decode(value['raw']),
            content_type=value.get('content_type'),
            media_type=value.get('media_type'),
            material_id=value.get('material_id'),
            algorithm=value.get('algorithm', 'sha256'),
        )

    @classmethod
    def from_path(cls, path, **kwargs):
        with open(os.fspath(path), 'rb') as handle:
            return cls(handle.read(), **kwargs)

    from_file = from_path


class VerificationReceipt(object):
    '''Independent verifier conclusion bound to an EvidenceIdentity.'''

    def __init__(self, evidence_id=None, verdict=None, status=None, conclusion=None,
                 verifier=None, signer=None, name=None, receipt_id=None, id=None,
                 issued_at=None, signature=None, secret=None, material_digest=None,
                 scope_digest=None, identity=None, valid=None, verified=None,
                 successful=None, **claims):
        if evidence_id is None:
            evidence_id = claims.pop('evidence_hash', None) or claims.pop('evidence_digest', None)
            evidence_id = evidence_id or claims.pop('evidence_ref', None)
        if material_digest is None:
            material_digest = claims.pop('material_hash', None) or claims.pop('raw_digest', None)
        if scope_digest is None:
            scope_digest = claims.pop('inspection_scope_digest', None)
        scope_value = claims.pop('scope', None)
        if scope_digest is None and scope_value is not None:
            scope_digest = canonical_digest(scope_value)
        if identity is not None:
            bound = _as_identity(identity)
        else:
            bound = _as_identity(evidence_id)

        self.identity = bound
        if material_digest is None and isinstance(bound, EvidenceIdentity):
            material_digest = bound.material_digest
        if scope_digest is None and isinstance(bound, EvidenceIdentity):
            scope_digest = bound.scope_digest
        self.material_digest = _decode_digest(material_digest)
        self.scope_digest = _decode_digest(scope_digest)
        if (self.material_digest is None or self.scope_digest is None) and isinstance(evidence_id, dict):
            data = evidence_id
            self.material_digest = self.material_digest or _decode_digest(data.get('material_digest'))
            self.scope_digest = self.scope_digest or _decode_digest(data.get('scope_digest'))

        if verdict is None:
            verdict = status or conclusion
        if verdict is None and verified is not None:
            verdict = VERIFIED if verified else REJECTED
        if verdict is None and valid is not None:
            verdict = VERIFIED if valid else REJECTED
        if verdict is None and successful is not None:
            verdict = VERIFIED if successful else REJECTED
        if verdict is None:
            verdict = VERIFIED
        self.verdict = self._normalize_verdict(verdict)
        self.raw_verdict = verdict
        self.conclusion = self.verdict
        self.verifier = verifier or signer or name or 'local-signoff'
        self.signer = self.verifier
        self.receipt_id = receipt_id or id or claims.pop('uuid', None)
        self.issued_at = issued_at
        self.claims = claims
        self.signature = signature
        self.algorithm = 'hmac-sha256'
        if secret is not None and not signature:
            self.sign(secret)

    @staticmethod
    def _normalize_verdict(value):
        if isinstance(value, bool):
            return VERIFIED if value else REJECTED
        text = str_cls(value).strip().lower().replace('-', '_')
        if text in _SUCCESS_VERDICTS or text in ('true', '1'):
            return VERIFIED
        if text in _FAILURE_VERDICTS or text in ('false', '0'):
            return REJECTED
        if text in _PENDING_VERDICTS:
            return INCONCLUSIVE if text == 'inconclusive' else PENDING
        return text

    @property
    def status(self):
        return self.verdict

    @property
    def verified(self):
        return self.verdict == VERIFIED

    @property
    def is_verified(self):
        return self.verified

    @property
    def evidence_id(self):
        return str_cls(self.identity) if self.identity is not None else None

    @property
    def id(self):
        return self.receipt_id

    def binding_payload(self):
        return canonical_bytes({
            'receipt_id': self.receipt_id,
            'evidence_id': self.evidence_id,
            'material_digest': self.material_digest,
            'scope_digest': self.scope_digest,
            'verdict': self.verdict,
            'verifier': self.verifier,
            'issued_at': self.issued_at,
            'claims': self.claims,
        })

    def sign(self, secret):
        if isinstance(secret, str_cls):
            secret = secret.encode('utf-8')
        digest = hmac_module.new(secret, self.binding_payload(), hashlib.sha256).hexdigest()
        self.signature = 'hmac-sha256:' + digest
        return self

    def verify_signature(self, secret):
        if not self.signature or not str_cls(self.signature).startswith('hmac-sha256:'):
            return False
        if isinstance(secret, str_cls):
            secret = secret.encode('utf-8')
        expected = hmac_module.new(secret, self.binding_payload(), hashlib.sha256).hexdigest()
        supplied = str_cls(self.signature).split(':', 1)[1]
        return hmac_module.compare_digest(expected, supplied)

    def covers(self, identity):
        target = _as_identity(identity)
        if target is None:
            return False
        if self.material_digest is not None and target.material_digest != self.material_digest:
            return False
        if self.scope_digest is not None and target.scope_digest != self.scope_digest:
            return False
        if self.material_digest is not None or self.scope_digest is not None:
            material_matches = (
                self.material_digest is None
                or target.material_digest == self.material_digest
            )
            scope_matches = (
                self.scope_digest is None
                or target.scope_digest == self.scope_digest
            )
            return material_matches and scope_matches
        if self.identity is not None:
            return str_cls(self.identity) == str_cls(target)
        return False

    def is_valid_for(self, identity, secret=None):
        if secret is not None and not self.verify_signature(secret):
            return False
        return self.covers(identity)

    @property
    def valid(self):
        return self.verdict == VERIFIED

    ok = valid

    def is_valid(self, identity=None, secret=None):
        if identity is None:
            if secret is not None and not self.verify_signature(secret):
                return False
            return self.valid
        return self.is_valid_for(identity, secret=secret)

    def to_dict(self):
        data = {
            'receipt_id': self.receipt_id,
            'evidence_id': self.evidence_id,
            'material_digest': self.material_digest,
            'scope_digest': self.scope_digest,
            'verdict': self.verdict,
            'verifier': self.verifier,
            'issued_at': self.issued_at,
            'claims': self.claims,
            'signature': self.signature,
        }
        return data

    def to_bytes(self):
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False, default=str_cls).encode('utf-8')

    serialize = to_bytes

    def to_asn1(self):
        signature_algorithm = None
        signature_value = None
        if self.signature and ':' in self.signature:
            signature_algorithm, signature_hex = self.signature.split(':', 1)
            signature_value = binascii.unhexlify(signature_hex.encode('ascii'))
        return LocalSignoffRecord({
            'version': 1,
            'payload': self.binding_payload().decode('utf-8'),
            'signature_algorithm': signature_algorithm,
            'signature_value': signature_value,
        })

    def dump(self, force=True):
        return self.to_asn1().dump(force=force)

    def dump_der(self):
        return self.dump(force=True)

    @classmethod
    def from_dict(cls, value):
        value = dict(value)
        claims = value.pop('claims', {}) or {}
        known = set([
            'evidence_id', 'verdict', 'status', 'conclusion', 'verifier', 'signer', 'name',
            'receipt_id', 'id', 'issued_at', 'signature', 'material_digest', 'scope_digest',
            'identity', 'valid', 'verified'
        ])
        init_kwargs = {key: item for key, item in value.items() if key in known}
        receipt = cls(**init_kwargs, **claims)
        return receipt

    @classmethod
    def from_bytes(cls, data):
        if isinstance(data, byte_cls):
            data = data.decode('utf-8')
        return cls.from_dict(json.loads(data))

    @classmethod
    def from_asn1(cls, value):
        if isinstance(value, byte_cls):
            value = LocalSignoffRecord.load(value)
        native = value.native
        algorithm = native.get('signature_algorithm')
        signature_value = native.get('signature_value')
        payload = json.loads(native['payload'])
        receipt = cls.from_dict(payload)
        if algorithm and signature_value:
            signature_hex = binascii.hexlify(signature_value).decode('ascii')
            receipt.signature = '%s:%s' % (algorithm, signature_hex)
        return receipt

    @classmethod
    def load(cls, data):
        return cls.from_asn1(data)


class LocalSignoff(VerificationReceipt):
    '''Ordinary local sign-off receipt, optionally authenticated with HMAC.'''

    def __init__(self, evidence_id=None, decision=None, signed_by=None, secret=None, **kwargs):
        if decision is not None and 'verdict' not in kwargs:
            kwargs['verdict'] = decision
        if signed_by is not None and 'verifier' not in kwargs:
            kwargs['verifier'] = signed_by
        super(LocalSignoff, self).__init__(evidence_id=evidence_id, secret=secret, **kwargs)
        self.decision = self.verdict
        self.signed_by = self.verifier

    @classmethod
    def sign_off(cls, identity=None, decision=VERIFIED, signed_by='local-reviewer', secret=None, **kwargs):
        receipt = cls(evidence_id=identity, decision=decision, signed_by=signed_by, **kwargs)
        if secret is not None:
            receipt.sign(secret)
        return receipt

    issue = sign_off
    create = sign_off


SignOff = LocalSignoff
Signoff = LocalSignoff


class VerificationRequest(object):
    def __init__(self, identity, material, scope, bundle=None):
        self.identity = identity
        self.evidence_id = str_cls(identity)
        self.material = material
        self.scope = scope
        self.bundle = bundle


class HandoffBundle(object):
    '''
    Bundle with three independent inputs: projection, material and receipt.

    Display access never performs verification. A receipt is reusable only when
    it covers the current EvidenceIdentity.
    '''

    def __init__(self, projection=None, material=None, receipt=None, scope=None,
                 identity=None, evidence_id=None, secret=None, receipt_secret=None,
                 verifier=None, inspection_scope=None, checked_scope=None, **kwargs):
        if scope is None:
            scope = inspection_scope if inspection_scope is not None else checked_scope
        for alias in ('presentable', 'presentable_projection', 'view', 'report_view', 'display', 'report_projection'):
            if projection is None and alias in kwargs:
                projection = kwargs.pop(alias)
        for alias in ('raw_material', 'verifiable_material', 'evidence_material', 'source_material', 'raw',
                      'original_material', 'preserved_material', 'checkable_material'):
            if material is None and alias in kwargs:
                material = kwargs.pop(alias)
        for alias in ('verification_receipt', 'independent_receipt', 'signoff', 'sign_off', 'local_signoff'):
            if receipt is None and alias in kwargs:
                receipt = kwargs.pop(alias)
        if material is None and 'evidence' in kwargs and not isinstance(kwargs['evidence'], EvidenceIdentity):
            material = kwargs.pop('evidence')
        elif identity is None and 'evidence' in kwargs and isinstance(kwargs['evidence'], EvidenceIdentity):
            identity = kwargs.pop('evidence')

        candidates = [projection, material, receipt]
        typed_material = next((item for item in candidates if isinstance(item, VerifiableMaterial)), None)
        raw_material = next((
            item for item in candidates
            if isinstance(item, (byte_cls, bytearray, memoryview)) or _is_asn1_value(item)
        ), None)
        typed_receipt = next((item for item in candidates if isinstance(item, VerificationReceipt)), None)
        typed_projection = next((item for item in candidates if isinstance(item, PresentableProjection)), None)
        if typed_material is not None:
            material = typed_material
        elif raw_material is not None:
            material = raw_material
        if typed_receipt is not None:
            receipt = typed_receipt
        if typed_projection is not None:
            projection = typed_projection
        elif not isinstance(projection, PresentableProjection):
            projection = next((
                item for item in candidates
                if item is not None and item is not material and item is not receipt
                and (callable(item) or isinstance(item, (str_cls, dict, list, tuple)))
            ), projection)

        self.projection = _coerce_projection(projection)
        self.material = _coerce_material(material)
        self.scope = scope
        self.verifier = verifier
        self.receipt_secret = receipt_secret if receipt_secret is not None else secret
        self.receipt = None
        self.verification_count = 0
        self.view_count = 0
        self._identity_override = None
        self._evidence_label = None

        label = None
        if isinstance(evidence_id, str_cls) and not isinstance(evidence_id, EvidenceIdentity):
            label = evidence_id
        self._evidence_label = label
        if identity is not None:
            self.identity = _as_identity(identity)
        elif evidence_id is not None and self.material is None:
            self.identity = _as_identity(evidence_id)
        else:
            self.identity = EvidenceIdentity(scope=scope, evidence_id=evidence_id)

        if receipt is not None:
            self.attach_receipt(receipt)

    @property
    def identity(self):
        if self.material is not None:
            return self.material.evidence_identity(self.scope, self._evidence_label)
        override = self.__dict__.get('_identity_override')
        if override is None:
            return EvidenceIdentity(scope=self.scope)
        if self.scope is not None and getattr(override, 'scope_digest', None) is not None:
            return override.for_scope(self.scope)
        return override

    @identity.setter
    def identity(self, value):
        self._identity_override = _as_identity(value)

    @property
    def evidence_id(self):
        return str_cls(self.identity)

    @property
    def inspection_scope(self):
        return self.scope

    @property
    def status(self):
        return _as_status(self._state()['status'])

    @property
    def state(self):
        return self._state()

    @property
    def needs_reverification(self):
        return self._state()['needs_reverification']

    requires_reverification = needs_reverification

    @property
    def requires_new_verification(self):
        return self.needs_reverification

    @property
    def needs_revalidation(self):
        return self.needs_reverification

    @property
    def requires_revalidation(self):
        return self.needs_reverification

    @property
    def should_reverify(self):
        return self.needs_reverification

    @property
    def should_revalidate(self):
        return self.needs_reverification

    @property
    def is_current(self):
        return not self.needs_reverification

    @property
    def current(self):
        return not self.needs_reverification

    @property
    def awaiting_verification(self):
        return self.status in (PENDING, STALE, INVALID, INCONCLUSIVE)

    @property
    def is_verified(self):
        state = self._state()
        return state['status'] == VERIFIED

    @property
    def verified(self):
        return self.is_verified

    @property
    def valid(self):
        return self.is_verified

    ok = valid

    def is_valid(self, secret=None):
        if secret is not None:
            self.receipt_secret = secret
        return self._state()['status'] == VERIFIED

    @property
    def conclusion(self):
        return _as_status(self._state()['conclusion'])

    @property
    def evidence_conclusion(self):
        return self._state()

    def _state(self):
        if self.receipt is None:
            return {
                'status': PENDING,
                'conclusion': PENDING,
                'needs_reverification': True,
                'reason': 'no verification receipt',
                'prior_conclusion': None,
            }

        receipt = _coerce_receipt(self.receipt, self.identity)
        if self.receipt_secret is not None and not receipt.verify_signature(self.receipt_secret):
            return {
                'status': INVALID,
                'conclusion': INVALID,
                'needs_reverification': True,
                'reason': 'receipt signature verification failed',
                'prior_conclusion': receipt.verdict,
            }
        if not receipt.covers(self.identity):
            return {
                'status': STALE,
                'conclusion': PENDING,
                'needs_reverification': True,
                'reason': 'receipt is bound to %s' % receipt.evidence_id,
                'prior_conclusion': receipt.verdict,
            }
        needs = receipt.verdict in (PENDING, INCONCLUSIVE)
        return {
            'status': receipt.verdict,
            'conclusion': receipt.verdict,
            'needs_reverification': needs,
            'reason': None,
            'prior_conclusion': receipt.verdict,
        }

    def attach_receipt(self, receipt):
        self.receipt = _coerce_receipt(receipt, self.identity)
        return self

    submit_receipt = attach_receipt
    receive_receipt = attach_receipt

    def add_projection(self, projection):
        self.projection = _coerce_projection(projection)
        return self

    def add_material(self, material):
        self.material = _coerce_material(material)
        if self.material is not None:
            self.identity = self.material.evidence_identity(self.scope)
        return self

    def add_receipt(self, receipt):
        return self.attach_receipt(receipt)

    register_projection = add_projection
    register_material = add_material
    register_receipt = add_receipt

    def with_receipt(self, receipt):
        clone = self.clone()
        clone.attach_receipt(receipt)
        return clone

    def view_report(self):
        self.view_count += 1
        view = self.projection.view()
        state = self._state()
        return ReportView(
            view.display_text,
            title=view.title,
            status=_as_status(state['status']),
            identity=self.identity,
            conclusion=_as_status(state['conclusion']),
            projection=self.projection,
        )

    view = view_report
    show_report = view_report
    display_report = view_report
    get_report = view_report

    @property
    def report(self):
        return self.view_report()

    def expand(self):
        self.projection.expand()
        if self.material is not None and getattr(self.material, 'spec', None) is not None:
            self.material.parse()
        return self

    def materialize(self):
        return self.expand()

    def verification_request(self):
        return VerificationRequest(self.identity, self.material, self.scope, self)

    def verify(self, verifier=None, force=False, secret=None):
        verifier = verifier or self.verifier
        if secret is not None:
            self.receipt_secret = secret
        if not force and not self.needs_reverification:
            return self.receipt
        if verifier is None:
            raise VerificationRequired(self._state().get('reason') or 'a new verification receipt is required')

        request = self.verification_request()
        result = _call_verifier(verifier, request, self.material, self.scope, self.identity)
        receipt = _coerce_receipt(result, self.identity)
        if receipt.identity is None or not receipt.covers(self.identity):
            if receipt.material_digest is None:
                receipt.material_digest = self.identity.material_digest
            if receipt.scope_digest is None:
                receipt.scope_digest = self.identity.scope_digest
            if receipt.identity is None:
                receipt.identity = self.identity
        self.attach_receipt(receipt)
        self.verification_count += 1
        return receipt

    def reverify(self, verifier=None, **kwargs):
        return self.verify(verifier=verifier, force=True, **kwargs)

    def revalidate(self, verifier=None, **kwargs):
        return self.reverify(verifier=verifier, **kwargs)

    def request_verification(self):
        return self.verification_request()

    def require_current_receipt(self, secret=None):
        if secret is not None:
            self.receipt_secret = secret
        state = self._state()
        if state['needs_reverification']:
            raise VerificationRequired(state.get('reason') or state['status'])
        return self.receipt

    def must_reverify(self):
        return self.needs_reverification

    def must_revalidate(self):
        return self.needs_revalidation

    def with_scope(self, scope, receipt=None, keep_receipt=False):
        clone = self.clone()
        clone.scope = scope
        if clone.material is not None:
            clone.identity = clone.material.evidence_identity(scope)
        else:
            clone.identity = self.identity.for_scope(scope)
        if receipt is not None:
            clone.attach_receipt(receipt)
        elif not keep_receipt:
            clone.receipt = None
        return clone

    def change_scope(self, scope, keep_receipt=False):
        updated = self.with_scope(scope, keep_receipt=keep_receipt)
        self.__dict__.update(updated.__dict__)
        return self

    def clone(self):
        new_obj = object.__new__(self.__class__)
        new_obj.__dict__.update(copy_module.deepcopy(self.__dict__))
        return new_obj

    copy = clone

    def __copy__(self, memo=None):
        return self.clone()

    def __deepcopy__(self, memo):
        return self.clone()

    def reencode(self, force=True, replace_material=False):
        clone = self.clone()
        clone.projection.reencode(force=force)
        if clone.material is not None:
            reencoded = clone.material.reencode(force=force)
            if replace_material:
                clone.material = reencoded
                clone.identity = clone.material.evidence_identity(clone.scope)
            else:
                clone.material.parse()
        return clone

    re_encode = reencode

    def to_dict(self):
        return {
            'protocol': IDENTITY_VERSION,
            'projection': self.projection.to_dict() if self.projection is not None else None,
            'material': self.material.to_dict() if self.material is not None else None,
            'receipt': self.receipt.to_dict() if self.receipt is not None else None,
            'scope': _canonical_data(self.scope),
            'identity': self.identity.to_dict(),
        }

    def to_bytes(self):
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False, default=str_cls).encode('utf-8')

    serialize = to_bytes

    @classmethod
    def from_dict(cls, value):
        material = value.get('material')
        if isinstance(material, dict) and 'raw' in material:
            material = VerifiableMaterial.from_dict(material)
        projection = value.get('projection')
        if isinstance(projection, dict):
            projection = PresentableProjection(
                text=projection.get('text'),
                title=projection.get('title'),
                format=projection.get('format'),
                content_type=projection.get('content_type'),
            )
        receipt = value.get('receipt')
        if isinstance(receipt, dict):
            receipt = VerificationReceipt.from_dict(receipt)
        scope = value.get('scope')
        return cls(
            projection=projection,
            material=material,
            receipt=receipt,
            scope=scope,
            identity=EvidenceIdentity._from_mapping(value['identity']) if value.get('identity') else None,
        )

    @classmethod
    def from_bytes(cls, data):
        if isinstance(data, byte_cls):
            data = data.decode('utf-8')
        return cls.from_dict(json.loads(data))


def _coerce_projection(value):
    if value is None or isinstance(value, PresentableProjection):
        return value
    return PresentableProjection(value)


def _coerce_material(value):
    if value is None or isinstance(value, VerifiableMaterial):
        return value
    if isinstance(value, dict) and 'raw' in value:
        return VerifiableMaterial.from_dict(value)
    return VerifiableMaterial(value)


def _coerce_receipt(value, identity=None):
    if value is None or isinstance(value, VerificationReceipt):
        receipt = value
    elif isinstance(value, dict):
        receipt = VerificationReceipt.from_dict(value)
    elif isinstance(value, bool):
        receipt = VerificationReceipt(identity, verdict=value)
    elif callable(value) and not isinstance(value, type):
        receipt = VerificationReceipt(identity, verdict=value())
    else:
        receipt = VerificationReceipt(identity, verdict=value)
    if identity is not None and receipt.identity is None:
        receipt.identity = identity
    return receipt


def _call_verifier(verifier, request, material, scope, identity):
    if not callable(verifier) and hasattr(verifier, 'verify'):
        verifier = verifier.verify
    try:
        import inspect
        signature = inspect.signature(verifier)
        params = [
            parameter for parameter in signature.parameters.values()
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        count = len(params)
        if any(parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values()):
            count = 4
    except (TypeError, ValueError, AttributeError):
        count = 1

    if count >= 4:
        return verifier(request, material, scope, identity)
    if count == 3:
        return verifier(material, scope, identity)
    if count == 2:
        return verifier(material, scope)
    if count == 1:
        try:
            return verifier(request)
        except TypeError:
            return verifier(material)
    return verifier()


TransferBundle = HandoffBundle
EvidenceTransfer = HandoffBundle
SecureHandoff = HandoffBundle
TransferProtocol = HandoffBundle
HandoffProtocol = HandoffBundle
SecureTransferProtocol = HandoffBundle
SecureTransfer = HandoffBundle
Handoff = HandoffBundle
Transfer = HandoffBundle
EvidenceBundle = HandoffBundle
HandoffEnvelope = HandoffBundle
TransferEnvelope = HandoffBundle
SecureEnvelope = HandoffBundle
ApprovalHandoff = HandoffBundle

Projection = PresentableProjection
DisplayProjection = PresentableProjection
ReportProjection = PresentableProjection
PresentedProjection = PresentableProjection
ViewProjection = PresentableProjection
PresentableView = PresentableProjection
DisplayView = PresentableProjection

RawEvidence = VerifiableMaterial
OriginalEvidence = VerifiableMaterial
VerifiableEvidence = VerifiableMaterial
EvidenceMaterial = VerifiableMaterial
CheckableMaterial = VerifiableMaterial
RawVerifiableMaterial = VerifiableMaterial
OriginalVerifiableMaterial = VerifiableMaterial

EvidenceFingerprint = EvidenceIdentity
EvidenceRef = EvidenceIdentity
EvidenceHandle = EvidenceIdentity

SignOffReceipt = LocalSignoff
LocalSignOff = LocalSignoff
LocalSignoffReceipt = LocalSignoff
LocalSignoffStructure = LocalSignoff
SignOffStructure = LocalSignoff
IndependentVerificationReceipt = VerificationReceipt


def prepare_handoff(projection=None, material=None, receipt=None, scope=None, **kwargs):
    return HandoffBundle(projection, material, receipt, scope, **kwargs)


def build_handoff(projection=None, material=None, receipt=None, scope=None, **kwargs):
    return prepare_handoff(projection, material, receipt, scope, **kwargs)


create_handoff = prepare_handoff
create_transfer = prepare_handoff
make_bundle = prepare_handoff


def check_handoff(bundle):
    if not isinstance(bundle, HandoffBundle):
        if isinstance(bundle, dict):
            bundle = HandoffBundle.from_dict(bundle)
        else:
            bundle = HandoffBundle(*bundle)
    return bundle.evidence_conclusion


def sign_bundle(bundle, signed_by='local-reviewer', secret=None, decision=VERIFIED):
    receipt = LocalSignoff.sign_off(
        bundle.identity,
        decision=decision,
        signed_by=signed_by,
        secret=secret,
    )
    bundle.attach_receipt(receipt)
    return receipt


def cms_report(cms_value, include_native=False):
    '''Build a small display projection from a CMS ContentInfo value.'''
    if isinstance(cms_value, str_cls) or hasattr(cms_value, '__fspath__'):
        path = os.fspath(cms_value)
        if os.path.exists(path):
            with open(path, 'rb') as handle:
                cms_value = handle.read()
    if isinstance(cms_value, (byte_cls, bytearray, memoryview)):
        from .cms import ContentInfo
        cms_value = ContentInfo.load(_coerce_bytes(cms_value))

    content_type = cms_value['content_type'].native
    lines = ['CMS content type: %s' % content_type]
    content = cms_value['content']
    if content_type == 'signed_data':
        signed_data = content
        if hasattr(signed_data, 'parsed'):
            signed_data = signed_data.parsed
        signer_infos = signed_data['signer_infos']
        lines.append('Signer infos: %d' % len(signer_infos))
        for index, signer in enumerate(signer_infos, 1):
            version = signer['version'].native
            digest = signer['digest_algorithm']['algorithm'].native
            lines.append('Signer %d: version=%s digest=%s' % (index, version, digest))
    projection = PresentableProjection('\n'.join(lines), title='CMS report', source=cms_value)
    if include_native and hasattr(cms_value, 'native'):
        projection._data = cms_value.native
    return projection


def create_cms_handoff(der, scope=None, receipt=None, **kwargs):
    material = VerifiableMaterial(der, content_type='application/pkcs7-mime')
    projection = cms_report(der)
    return HandoffBundle(projection=projection, material=material, receipt=receipt, scope=scope, **kwargs)
