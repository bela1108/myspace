# -*- coding: utf-8 -*-

"""
Versioned handler capabilities and offline change-impact auditing.

The helpers in this module deliberately work on *saved* determinations
(MIME, extension, handler identity and an optional header sample).  They
never open a path or otherwise read an attachment body.
"""

from __future__ import absolute_import

import binascii
from collections import OrderedDict

try:
    from collections.abc import Mapping, Sequence
except ImportError:  # Python 2
    from collections import Mapping, Sequence

from .types import TYPES, Type
from .utils import signature


DEFAULT_VERSION = 1

CAPABILITY_ACTIVE = 'active'
CAPABILITY_DEGRADED = 'degraded'
CAPABILITY_RETIRED = 'retired'
CAPABILITY_UNAVAILABLE = 'unavailable'

AUDIT_UNCHANGED = 'unchanged'
AUDIT_CHANGED = 'changed'
AUDIT_DEGRADED = 'degraded'
AUDIT_UNAVAILABLE = 'unavailable'
AUDIT_AMBIGUOUS = 'ambiguous'
AUDIT_INVALID = 'invalid'

_UNAVAILABLE_STATUSES = frozenset((
    CAPABILITY_RETIRED,
    CAPABILITY_UNAVAILABLE,
    'disabled',
    'removed',
    'offline',
    'decommissioned',
    'inactive',
))

_CAPABILITY_FIELDS = (
    'handler',
    'version',
    'handler_id',
    'key',
    'mime',
    'extension',
    'available',
    'checkable',
    'inspectable',
    'status',
    'read_only',
    'category',
)

_AUDIT_FIELDS = (
    'record',
    'previous',
    'current',
    'status',
    'checkable',
    'verified',
    'changed',
    'degraded',
    'retired',
    'unavailable',
    'inspectable',
    'ok',
    'impact',
    'claimed_checkable',
    'stale',
    'ambiguous',
    'available',
    'reason',
    'candidates',
    'evidence',
    'previous_evidence',
    'current_evidence',
    'handler',
    'version',
    'handler_id',
    'mime',
    'extension',
)

_RECORD_ALIASES = {
    'handler': ('handler', 'matcher', 'checker', 'processor'),
    'version': (
        'version',
        'handler_version',
        'matcher_version',
        'processor_version',
    ),
    'handler_id': ('handler_id', 'capability_id'),
    'mime': ('mime', 'mime_type', 'media_type'),
    'extension': (
        'extension',
        'ext',
        'type',
        'file_type',
        'suffix',
    ),
    'evidence': (
        'evidence',
        'old_evidence',
        'previous_evidence',
        'proof',
        'sample_evidence',
    ),
    'header': (
        'header',
        'header_bytes',
        'sample',
        'sample_bytes',
        'signature',
        'magic',
        'magic_bytes',
    ),
    'header_hex': ('header_hex', 'sample_hex', 'signature_hex'),
    'claimed_available': (
        'claimed_available',
        'claimed_checkable',
        'checkable',
        'inspectable',
        'available',
    ),
}


def _text(value):
    if value is None:
        return None
    return str(value)


def _as_bool(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip().lower() in (
            '1', 'true', 'yes', 'y', 'available', 'active', 'ok')
    return bool(value)


def _version_text(value):
    return None if value is None else str(value)


def _version_value(value):
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def _default_category(matcher):
    module = getattr(type(matcher), '__module__', '')
    category = module.rsplit('.', 1)[-1] if module else None
    return getattr(type(matcher), 'CATEGORY', category)


def _status_for(available, status):
    if status is not None:
        if (not available and
                _text(status).lower() == CAPABILITY_ACTIVE):
            return CAPABILITY_RETIRED
        return status
    return CAPABILITY_ACTIVE if available else CAPABILITY_RETIRED


def _infer_available(status, available):
    if status is not None and _text(status).lower() in _UNAVAILABLE_STATUSES:
        return False
    if available is not None:
        return bool(_as_bool(available))
    return True


class Capability(Mapping):
    """
    Describes what one handler version can inspect.

    A capability is intentionally independent of an attachment.  It carries
    the handler identity/version, the MIME and extension it can produce and
    whether the handler is still able to inspect content.
    """

    def __init__(self, handler, version=DEFAULT_VERSION, mime=None,
                 extension=None, available=None, status=None,
                 read_only=False, category=None, matcher=None):
        self.handler = _text(handler)
        self.version = _version_value(version)
        self.mime = mime
        self.extension = extension
        self.status = _status_for(True, status)
        available = _infer_available(self.status, available)
        self.available = bool(available)
        self.status = _status_for(self.available, status)
        self.read_only = bool(read_only)
        self.category = category
        self.matcher = matcher

    @property
    def handler_id(self):
        return '{0}@{1}'.format(self.handler, self.version)

    @property
    def key(self):
        return self.handler_id

    @property
    def checkable(self):
        return self.available

    @property
    def inspectable(self):
        return self.checkable

    def as_dict(self):
        return OrderedDict((
            ('handler', self.handler),
            ('version', self.version),
            ('handler_id', self.handler_id),
            ('key', self.key),
            ('mime', self.mime),
            ('extension', self.extension),
            ('available', self.available),
            ('checkable', self.checkable),
            ('inspectable', self.inspectable),
            ('status', self.status),
            ('read_only', self.read_only),
            ('category', self.category),
        ))

    to_dict = as_dict

    def __getitem__(self, key):
        if key not in _CAPABILITY_FIELDS:
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self):
        return iter(_CAPABILITY_FIELDS)

    def __len__(self):
        return len(_CAPABILITY_FIELDS)

    def __repr__(self):
        return '<Capability {0} {1}/{2} available={3}>'.format(
            self.handler_id, self.mime, self.extension, self.available)


class CapabilityManifest(Mapping):
    """
    Ordered collection of capabilities keyed by ``handler@version``.

    Several formats can share a MIME type, so the manifest keeps every entry
    and exposes MIME/extension indexes instead of collapsing them.
    """

    def __init__(self, entries=None):
        self.entries = tuple(entries or ())
        self._by_key = OrderedDict()
        for capability in self.entries:
            base = capability.key
            key = base
            suffix = 2
            while key in self._by_key:
                key = '{0}#{1}'.format(base, suffix)
                suffix += 1
            self._by_key[key] = capability

    @property
    def by_key(self):
        return self._by_key

    @property
    def by_mime(self):
        index = OrderedDict()
        for capability in self.entries:
            index.setdefault(capability.mime, []).append(capability)
        return index

    @property
    def by_extension(self):
        index = OrderedDict()
        for capability in self.entries:
            index.setdefault(capability.extension, []).append(capability)
        return index

    @property
    def by_handler(self):
        index = OrderedDict()
        for capability in self.entries:
            index.setdefault(capability.handler, []).append(capability)
        return index

    @property
    def by_version(self):
        index = OrderedDict()
        for capability in self.entries:
            index.setdefault(capability.version, []).append(capability)
        return index

    @property
    def versions(self):
        return list(self.by_version)

    @property
    def available(self):
        return [c for c in self.entries if c.available]

    @property
    def unavailable(self):
        return [c for c in self.entries if not c.available]

    retired = unavailable

    @property
    def checkable(self):
        return self.available

    def lookup(self, handler=None, version=None, mime=None,
               extension=None, available=None):
        """Return every capability matching all supplied criteria."""
        matches = list(self.entries)
        if handler is not None:
            matches = [c for c in matches if c.handler == handler]
        if version is not None:
            matches = [
                c for c in matches
                if _version_text(c.version) == _version_text(version)
            ]
        if mime is not None:
            matches = [c for c in matches if c.mime == mime]
        if extension is not None:
            matches = [c for c in matches if c.extension == extension]
        if available is not None:
            matches = [c for c in matches if c.available == bool(available)]
        return matches

    find = lookup

    def to_dict(self):
        return OrderedDict(
            (key, capability.as_dict())
            for key, capability in self._by_key.items()
        )

    def __getitem__(self, key):
        if isinstance(key, slice):
            return self.entries[key]
        if isinstance(key, int):
            return self.entries[key]
        if key in self._by_key:
            return self._by_key[key]
        matches = [c for c in self.entries if c.handler == key]
        if len(matches) == 1:
            return matches[0]
        raise KeyError(key)

    def __iter__(self):
        return iter(self._by_key)

    def __len__(self):
        return len(self._by_key)

    def __repr__(self):
        return '<CapabilityManifest entries={0}>'.format(len(self.entries))


def _capability_from_matcher(matcher, category=None):
    if isinstance(matcher, Capability):
        return matcher
    if not isinstance(matcher, Type):
        return None

    available = getattr(matcher, 'available', True)
    status = getattr(matcher, 'status', None)
    return Capability(
        handler=getattr(matcher, 'handler', type(matcher).__name__),
        version=getattr(matcher, 'version', DEFAULT_VERSION),
        mime=getattr(matcher, 'mime', None),
        extension=getattr(matcher, 'extension', None),
        available=available,
        status=status,
        read_only=getattr(matcher, 'read_only', False),
        category=category or _default_category(matcher),
        matcher=matcher,
    )


def _parse_capability_key(key):
    parsed = {
        'handler': None,
        'version': None,
        'mime': None,
        'extension': None,
    }
    if not isinstance(key, str):
        return parsed
    for separator in ('@', ':'):
        if separator in key:
            handler, version = key.rsplit(separator, 1)
            parsed['handler'] = handler
            parsed['version'] = version
            return parsed
    if '/' in key:
        parsed['mime'] = key
    elif key:
        parsed['extension'] = key
    return parsed


def _capability_from_mapping(spec, key=None):
    parsed = _parse_capability_key(key)
    handler = (
        spec.get('handler') or
        spec.get('name') or
        parsed['handler']
    )
    version = spec.get('version', parsed['version'])
    if version is None:
        version = DEFAULT_VERSION
    mime = spec.get('mime') or spec.get('mime_type') or parsed['mime']
    extension = (
        spec.get('extension') or
        spec.get('ext') or
        parsed['extension']
    )
    status = spec.get('status')
    available = spec.get('available')
    if available is None:
        available = spec.get('enabled')
    if available is None:
        available = spec.get('checkable')
    available = _as_bool(available)
    return Capability(
        handler=handler or 'unknown',
        version=version,
        mime=mime,
        extension=extension,
        available=available,
        status=status,
        read_only=spec.get('read_only', spec.get('readonly', False)),
        category=spec.get('category'),
    )


def _capabilities_from_spec(spec, key=None):
    if isinstance(spec, (list, tuple)):
        result = []
        for item in spec:
            result.extend(_capabilities_from_spec(item, key))
        return result
    if isinstance(spec, Capability):
        return [spec]
    if isinstance(spec, Type):
        capability = _capability_from_matcher(spec)
        return [capability] if capability is not None else []
    if isinstance(spec, Mapping):
        return [_capability_from_mapping(spec, key)]
    if isinstance(spec, bool):
        parsed = _parse_capability_key(key)
        return [Capability(
            handler=parsed['handler'] or 'unknown',
            version=parsed['version'] or DEFAULT_VERSION,
            mime=parsed['mime'],
            extension=parsed['extension'],
            available=spec,
        )]
    if isinstance(spec, str):
        if key is None:
            parsed = _parse_capability_key(spec)
            status = None
        else:
            parsed = _parse_capability_key(key)
            status = spec
        return [Capability(
            handler=parsed['handler'] or 'unknown',
            version=parsed['version'] or DEFAULT_VERSION,
            mime=parsed['mime'],
            extension=parsed['extension'],
            status=status,
        )]
    return []


def _entries_from_mapping(mapping):
    entries = []
    for key, spec in mapping.items():
        entries.extend(_capabilities_from_spec(spec, key))
    return entries


def _matches_override_key(capability, key):
    if not isinstance(key, str):
        return False
    candidates = (
        capability.key,
        capability.handler_id,
        capability.handler,
        capability.mime,
        capability.extension,
    )
    if key in candidates:
        return True
    if capability.mime and capability.extension:
        if key == '{0}:{1}'.format(capability.mime, capability.extension):
            return True
    return False


def _apply_override(capability, override):
    values = {
        'handler': capability.handler,
        'version': capability.version,
        'mime': capability.mime,
        'extension': capability.extension,
        'available': capability.available,
        'status': capability.status,
        'read_only': capability.read_only,
        'category': capability.category,
        'matcher': capability.matcher,
    }
    if isinstance(override, bool):
        values['available'] = override
        values['status'] = _status_for(override, None)
    elif isinstance(override, str):
        values['status'] = override
        values['available'] = _infer_available(override, None)
    elif isinstance(override, Mapping):
        for field in (
            'handler', 'version', 'mime', 'extension', 'available',
            'status', 'read_only', 'category',
        ):
            if field in override:
                values[field] = override[field]
        if 'available' in override:
            values['available'] = bool(_as_bool(override['available']))
            if 'status' not in override:
                values['status'] = _status_for(values['available'], None)
        elif 'status' in override:
            values['available'] = _infer_available(
                override['status'], None)
    return Capability(**values)


def _build_manifest(matchers=None, overrides=None,
                    include_unavailable=True, category=None):
    if matchers is None:
        matchers = TYPES
    if isinstance(matchers, (Type, Capability)):
        matchers = [matchers]

    entries = []
    for matcher in matchers:
        capability = _capability_from_matcher(matcher, category=category)
        if capability is None:
            continue
        if overrides:
            for key, override in overrides.items():
                if _matches_override_key(capability, key):
                    capability = _apply_override(capability, override)
        entries.append(capability)

    if not include_unavailable:
        entries = [c for c in entries if c.available]
    return CapabilityManifest(entries)


def capabilities(matchers=None, overrides=None, include_unavailable=True):
    """
    Return a capability manifest for the current handler registry.

    Args:
        matchers: iterable of ``Type`` instances. Defaults to ``TYPES``.
        overrides: optional mapping keyed by ``handler@version`` (handler,
            MIME or extension also work) used to change lifecycle metadata.
        include_unavailable: keep retired/disabled handlers in the manifest.

    Returns:
        A :class:`CapabilityManifest`.
    """
    return _build_manifest(
        matchers=matchers,
        overrides=overrides,
        include_unavailable=include_unavailable,
    )


get_capabilities = capabilities
capability_manifest = capabilities
manifest = capabilities


def get_capability(handler=None, version=None, mime=None, extension=None,
                   matchers=None):
    """Return the first capability matching the supplied identity fields."""
    matches = _build_manifest(matchers=matchers).lookup(
        handler=handler,
        version=version,
        mime=mime,
        extension=extension,
    )
    return matches[0] if matches else None


capability_for = get_capability


def _coerce_manifest(value, matchers=None):
    if value is None:
        return _build_manifest(matchers=matchers)
    if isinstance(value, CapabilityManifest):
        return value
    if isinstance(value, Mapping):
        for wrapper in ('handlers', 'capabilities', 'types', 'matchers'):
            nested = value.get(wrapper)
            if isinstance(nested, Mapping):
                return CapabilityManifest(_entries_from_mapping(nested))
        return CapabilityManifest(_entries_from_mapping(value))
    if isinstance(value, (list, tuple, set)):
        if all(isinstance(item, (Type, Capability)) for item in value):
            return _build_manifest(matchers=value)
        entries = []
        for item in value:
            entries.extend(_capabilities_from_spec(item))
        return CapabilityManifest(entries)
    if isinstance(value, (Type, Capability)):
        return _build_manifest(matchers=[value])
    raise TypeError(
        'capabilities must be a CapabilityManifest, mapping or iterable')


def _field(data, names):
    for name in names:
        if isinstance(data, Mapping):
            if name in data:
                return data[name]
        elif hasattr(data, name):
            return getattr(data, name)
    return None


def _evidence_header(evidence):
    if isinstance(evidence, Mapping):
        header = _coerce_header(_field(evidence, _RECORD_ALIASES['header']))
        if header is not None:
            return header
        header_hex = _field(evidence, _RECORD_ALIASES['header_hex'])
        return _decode_hex_header(header_hex)
    return None


def _coerce_header(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return signature(bytearray(value))
        except ValueError:
            return None
    if isinstance(value, (list, tuple)):
        if all(isinstance(item, int) for item in value):
            try:
                return signature(bytearray(value))
            except ValueError:
                return None
    return None


def _decode_hex_header(value):
    if not isinstance(value, str):
        return None
    try:
        return signature(bytearray(binascii.unhexlify(value)))
    except (TypeError, ValueError, binascii.Error):
        return None


def _parse_handler_id(value):
    if not isinstance(value, str):
        return None, None
    for separator in ('@', ':'):
        if separator in value:
            handler, version = value.rsplit(separator, 1)
            return handler, version
    return None, None


def _nested_record(data, names):
    if not isinstance(data, Mapping):
        return None
    for name in names:
        value = data.get(name)
        if isinstance(value, Mapping):
            return value
        if isinstance(value, Type):
            return {
                'handler': value.handler,
                'version': value.version,
                'mime': value.mime,
                'extension': value.extension,
            }
        if isinstance(value, Capability):
            return {
                'handler': value.handler,
                'version': value.version,
                'mime': value.mime,
                'extension': value.extension,
            }
    return None


def _normalise_record(record):
    if isinstance(record, Type):
        data = {
            'handler': record.handler,
            'version': record.version,
            'mime': record.mime,
            'extension': record.extension,
        }
    elif isinstance(record, Capability):
        data = {
            'handler': record.handler,
            'version': record.version,
            'mime': record.mime,
            'extension': record.extension,
        }
    elif isinstance(record, str):
        if '/' in record:
            data = {'mime': record}
        else:
            data = {'extension': record}
    elif isinstance(record, (tuple, list)):
        data = {}
        if len(record) >= 1:
            first = record[0]
            if '/' in str(first):
                data['mime'] = first
            else:
                data['extension'] = first
        if len(record) >= 2:
            data['extension'] = record[1]
        if len(record) >= 3:
            data['version'] = record[2]
    elif isinstance(record, Mapping):
        data = dict(record)
    else:
        data = {}
        for alias in _RECORD_ALIASES.values():
            for name in alias:
                if hasattr(record, name):
                    data[name] = getattr(record, name)
                    break

    nested = data.get('type')
    if isinstance(nested, (Type, Capability, Mapping)) and not isinstance(
            nested, str):
        nested_data = _normalise_record(nested)
        merged = dict(nested_data)
        merged.update(
            (key, value) for key, value in data.items() if key != 'type')
        data = merged

    capability = data.get('capability')
    if isinstance(capability, (Type, Capability, Mapping)):
        cap_data = _normalise_record(capability)
        for key, value in cap_data.items():
            data.setdefault(key, value)
    elif isinstance(capability, str):
        data.setdefault('handler_id', capability)

    current_source = _nested_record(
        data, ('current', 'new', 'latest', 'recheck', 'after'))
    previous_source = _nested_record(
        data, ('previous', 'old', 'saved', 'prior', 'before', 'original'))
    if previous_source:
        for key, value in previous_source.items():
            data.setdefault(key, value)

    handler = _field(data, _RECORD_ALIASES['handler'])
    version = _field(data, _RECORD_ALIASES['version'])
    handler_id = _field(data, _RECORD_ALIASES['handler_id'])
    if (handler is None or version is None) and handler_id:
        parsed_handler, parsed_version = _parse_handler_id(handler_id)
        if handler is None:
            handler = parsed_handler
        if version is None:
            version = parsed_version
    if handler and '@' in str(handler) and version is None:
        parsed_handler, parsed_version = _parse_handler_id(str(handler))
        handler = parsed_handler
        version = parsed_version

    mime = _field(data, _RECORD_ALIASES['mime'])
    extension = _field(data, _RECORD_ALIASES['extension'])
    evidence = _field(data, _RECORD_ALIASES['evidence'])
    header = _coerce_header(_field(data, _RECORD_ALIASES['header']))
    if header is None:
        header = _decode_hex_header(
            _field(data, _RECORD_ALIASES['header_hex']))
    if header is None:
        header = _evidence_header(evidence)

    if handler_id is None and handler is not None and version is not None:
        handler_id = '{0}@{1}'.format(handler, version)

    claimed_available = _as_bool(
        _field(data, _RECORD_ALIASES['claimed_available']))

    current_record = None
    if current_source:
        current_record = _normalise_record(current_source)

    return {
        'handler': _text(handler),
        'version': version,
        'handler_id': _text(handler_id),
        'mime': _text(mime),
        'extension': _text(extension),
        'evidence': evidence,
        'header': header,
        'current_record': current_record,
        'claimed_available': claimed_available,
        'raw': record,
    }


def _select_capabilities(manifest, record):
    candidates = list(manifest.entries)
    if record['handler'] is not None:
        matches = [
            c for c in candidates if c.handler == record['handler']
        ]
        if matches:
            candidates = matches
    if record['extension'] is not None:
        matches = [
            c for c in candidates
            if c.extension == record['extension']
        ]
        candidates = matches
    if record['mime'] is not None:
        matches = [
            c for c in candidates if c.mime == record['mime']
        ]
        candidates = matches
    if record['version'] is not None and candidates:
        matches = [
            c for c in candidates
            if _version_text(c.version) == _version_text(record['version'])
        ]
        if matches:
            candidates = matches
    return candidates


def _select_one(candidates, record):
    if len(candidates) == 1:
        return candidates[0]
    signatures = set((c.mime, c.extension) for c in candidates)
    if len(signatures) == 1:
        available = [c for c in candidates if c.available]
        return (available or candidates)[0]
    if record['extension'] is not None:
        matches = [
            c for c in candidates
            if c.extension == record['extension']
        ]
        if len(matches) == 1:
            return matches[0]
    if record['handler'] is not None and record['version'] is not None:
        matches = [
            c for c in candidates
            if _version_text(c.version) == _version_text(record['version'])
        ]
        if len(matches) == 1:
            return matches[0]
    return None


def _capability_for_matcher(manifest, matcher):
    for capability in manifest.entries:
        if capability.matcher is matcher:
            return capability
    matches = manifest.lookup(
        handler=getattr(matcher, 'handler', type(matcher).__name__),
        version=getattr(matcher, 'version', DEFAULT_VERSION),
    )
    if matches:
        available = [c for c in matches if c.available]
        return (available or matches)[0]
    return None


def _detect(sample, matchers, manifest):
    for matcher in matchers:
        capability = _capability_for_matcher(manifest, matcher)
        if capability is not None and not capability.available:
            continue
        try:
            matched = matcher.match(sample)
        except Exception:
            continue
        if matched:
            return matcher, capability
    return None, None


def _previous_determination(record):
    evidence = record['evidence']
    if evidence is None and record['header'] is not None:
        evidence = {
            'handler': record['handler'],
            'version': record['version'],
            'header': record['header'],
        }
    return OrderedDict((
        ('handler', record['handler']),
        ('version', record['version']),
        ('handler_id', record['handler_id']),
        ('mime', record['mime']),
        ('extension', record['extension']),
        ('evidence', evidence),
        ('header', record['header']),
    ))


def _current_determination(matcher, capability, sample):
    evidence = OrderedDict((
        ('handler', getattr(matcher, 'handler', type(matcher).__name__)),
        ('version', getattr(matcher, 'version', DEFAULT_VERSION)),
        ('header', sample),
    ))
    if capability is not None:
        evidence['capability'] = capability.as_dict()
    return OrderedDict((
        ('handler', getattr(matcher, 'handler', type(matcher).__name__)),
        ('version', getattr(matcher, 'version', DEFAULT_VERSION)),
        ('handler_id', '{0}@{1}'.format(
            getattr(matcher, 'handler', type(matcher).__name__),
            getattr(matcher, 'version', DEFAULT_VERSION))),
        ('mime', getattr(matcher, 'mime', None)),
        ('extension', getattr(matcher, 'extension', None)),
        ('evidence', evidence),
        ('header', sample),
    ))


def _determination_changed(previous, current):
    if current is None:
        return True
    for field in ('mime', 'extension'):
        old = previous.get(field)
        new = current.get(field)
        if old is not None and new is not None and old != new:
            return True
    old_handler = previous.get('handler')
    new_handler = current.get('handler')
    if old_handler is not None and new_handler is not None:
        if old_handler != new_handler:
            return True
    old_id = previous.get('handler_id')
    new_id = current.get('handler_id')
    if old_id is not None and new_id is not None and old_id != new_id:
        return True
    return False


def _is_empty(record):
    return not any((
        record['handler'],
        record['handler_id'],
        record['mime'],
        record['extension'],
    ))


class AuditResult(Mapping):
    """Outcome of auditing one saved determination."""

    def __init__(self, record, previous, current, status, checkable,
                 verified, candidates, reason=None, evidence=None):
        self.record = record
        self.previous = previous
        self.current = current
        self.status = status
        self.checkable = bool(checkable)
        self.verified = bool(verified)
        self.candidates = tuple(candidates)
        self.reason = reason
        self.changed = status == AUDIT_CHANGED
        self.degraded = status == AUDIT_DEGRADED
        self.retired = any(not c.available for c in self.candidates)
        self.unavailable = status == AUDIT_UNAVAILABLE
        self.inspectable = self.checkable
        self.ok = status == AUDIT_UNCHANGED
        self.impact = status
        self.claimed_checkable = record.get('claimed_available')
        self.stale = bool(self.claimed_checkable) and not self.checkable
        self.ambiguous = status == AUDIT_AMBIGUOUS
        self.available = (
            any(c.available for c in self.candidates) or self.checkable
        )
        self.evidence = evidence or OrderedDict()
        self.previous_evidence = self.evidence.get('previous')
        self.current_evidence = self.evidence.get('current')
        self.handler = previous.get('handler')
        self.version = previous.get('version')
        self.handler_id = previous.get('handler_id')
        self.mime = previous.get('mime')
        self.extension = previous.get('extension')

    def to_dict(self):
        return OrderedDict((
            ('status', self.status),
            ('impact', self.impact),
            ('checkable', self.checkable),
            ('inspectable', self.inspectable),
            ('verified', self.verified),
            ('changed', self.changed),
            ('degraded', self.degraded),
            ('retired', self.retired),
            ('unavailable', self.unavailable),
            ('ok', self.ok),
            ('claimed_checkable', self.claimed_checkable),
            ('stale', self.stale),
            ('ambiguous', self.ambiguous),
            ('available', self.available),
            ('reason', self.reason),
            ('handler', self.handler),
            ('version', self.version),
            ('handler_id', self.handler_id),
            ('mime', self.mime),
            ('extension', self.extension),
            ('previous', _json_safe(self.previous)),
            ('current', _json_safe(self.current)),
            ('candidates', [c.as_dict() for c in self.candidates]),
            ('evidence', _json_safe(self.evidence)),
        ))

    def __getitem__(self, key):
        if key not in _AUDIT_FIELDS:
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self):
        return iter(_AUDIT_FIELDS)

    def __len__(self):
        return len(_AUDIT_FIELDS)

    def __repr__(self):
        return '<AuditResult {0} status={1} checkable={2}>'.format(
            self.handler_id or self.extension or self.mime,
            self.status,
            self.checkable,
        )


class AuditReport(Sequence):
    """Collection of :class:`AuditResult` objects with status indexes."""

    def __init__(self, results):
        self.results = list(results)

    def __getitem__(self, key):
        if isinstance(key, str):
            if key == 'results':
                return list(self.results)
            if key == 'summary':
                return self.summary()
            return [r for r in self.results if r.status == key]
        return self.results[key]

    def __iter__(self):
        return iter(self.results)

    def __len__(self):
        return len(self.results)

    def by_status(self, status):
        return [r for r in self.results if r.status == status]

    @property
    def changed(self):
        return self.by_status(AUDIT_CHANGED)

    @property
    def degraded(self):
        return self.by_status(AUDIT_DEGRADED)

    @property
    def unchanged(self):
        return self.by_status(AUDIT_UNCHANGED)

    @property
    def unavailable(self):
        return self.by_status(AUDIT_UNAVAILABLE)

    @property
    def ambiguous(self):
        return self.by_status(AUDIT_AMBIGUOUS)

    @property
    def invalid(self):
        return self.by_status(AUDIT_INVALID)

    @property
    def stale(self):
        return [r for r in self.results if r.stale]

    @property
    def checkable(self):
        return [r for r in self.results if r.checkable]

    @property
    def uncheckable(self):
        return [r for r in self.results if not r.checkable]

    def summary(self):
        summary = OrderedDict()
        for status in (
            AUDIT_UNCHANGED,
            AUDIT_CHANGED,
            AUDIT_DEGRADED,
            AUDIT_UNAVAILABLE,
            AUDIT_AMBIGUOUS,
            AUDIT_INVALID,
        ):
            summary[status] = len(self.by_status(status))
        summary['total'] = len(self.results)
        summary['checkable'] = len(self.checkable)
        summary['uncheckable'] = len(self.uncheckable)
        summary['stale'] = len(self.stale)
        return summary

    def to_dict(self):
        return OrderedDict((
            ('summary', self.summary()),
            ('results', [result.to_dict() for result in self.results]),
        ))

    def __repr__(self):
        return '<AuditReport total={0}>'.format(len(self.results))


def _json_safe(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return binascii.hexlify(bytes(value)).decode('ascii')
    if isinstance(value, Mapping):
        return OrderedDict(
            (key, _json_safe(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _audit_record(record, manifest, matchers):
    normalised = _normalise_record(record)
    previous = _previous_determination(normalised)
    candidates = _select_capabilities(manifest, normalised)
    selected = _select_one(candidates, normalised)
    available_candidates = [c for c in candidates if c.available]
    sample = normalised['header']

    stored_current = normalised.get('current_record')
    has_stored_current = (
        stored_current is not None and not _is_empty(stored_current))
    current = None
    current_candidates = []
    current_available = []
    matched_capability = None
    if has_stored_current:
        current = _previous_determination(stored_current)
        verified = (
            stored_current['evidence'] is not None or
            stored_current['header'] is not None or
            sample is not None)
        current_candidates = _select_capabilities(
            manifest, stored_current)
        current_available = [
            c for c in current_candidates if c.available
        ]
    else:
        verified = sample is not None
        if verified:
            matcher, matched_capability = _detect(
                sample, matchers, manifest)
            if matcher is not None:
                current = _current_determination(
                    matcher, matched_capability, sample)

    previous_evidence = previous.get('evidence')
    current_evidence = current.get('evidence') if current else None
    evidence = OrderedDict((
        ('previous', previous_evidence),
        ('current', current_evidence),
    ))

    version_changed = (
        selected is not None
        and normalised['version'] is not None
        and _version_text(selected.version) != _version_text(
            normalised['version'])
    )
    handler_changed = (
        selected is not None
        and normalised['handler'] is not None
        and selected.handler != normalised['handler']
    )
    selected_available = (
        selected.available if selected is not None
        else bool(available_candidates)
    )

    if _is_empty(normalised):
        status = AUDIT_INVALID
        checkable = False
        reason = 'record contains no recognisable determination'
    elif has_stored_current:
        if not current_candidates:
            status = AUDIT_DEGRADED
            checkable = False
            reason = (
                'current determination has no matching deployed handler'
            )
        elif not current_available:
            status = AUDIT_DEGRADED
            checkable = False
            reason = 'current determination handler is retired or disabled'
        elif (_select_one(current_candidates, stored_current) is None and
              len(set((c.mime, c.extension)
                      for c in current_candidates)) > 1):
            status = AUDIT_AMBIGUOUS
            checkable = bool(current_available)
            reason = 'current determination has multiple candidate formats'
        else:
            changed = _determination_changed(previous, current)
            status = AUDIT_CHANGED if changed else AUDIT_UNCHANGED
            checkable = True
            if changed:
                reason = (
                    'current detector disagrees with the saved determination'
                )
            else:
                reason = 'saved determination is still supported'
    elif verified:
        if current is None:
            if candidates and not available_candidates:
                status = AUDIT_DEGRADED
                reason = 'matching handler is retired; header is unreadable'
            else:
                status = AUDIT_UNAVAILABLE
                reason = 'no current handler can inspect the header sample'
            checkable = False
        else:
            changed = (
                _determination_changed(previous, current)
                or version_changed
                or handler_changed
            )
            if selected is not None and not selected.available:
                changed = True
                reason = (
                    'saved handler is retired; replacement handler matched '
                    'the header sample'
                )
            elif version_changed:
                reason = 'handler version changed for the saved determination'
            elif changed:
                reason = (
                    'current detector disagrees with the saved determination'
                )
            else:
                reason = 'saved determination is still supported'
            status = AUDIT_CHANGED if changed else AUDIT_UNCHANGED
            checkable = True
    else:
        if not candidates:
            status = AUDIT_UNAVAILABLE
            checkable = False
            reason = 'no handler matches the saved determination'
        elif selected is None:
            status = AUDIT_AMBIGUOUS
            checkable = bool(available_candidates)
            reason = (
                'MIME maps to multiple formats; extension or header sample '
                'is required'
            )
        elif not selected.available:
            status = AUDIT_DEGRADED
            checkable = False
            reason = 'matching handler is retired or disabled'
        elif version_changed or handler_changed:
            status = AUDIT_CHANGED
            checkable = selected_available
            reason = 'handler version changed for the saved determination'
        else:
            status = AUDIT_UNCHANGED
            checkable = selected_available
            reason = 'saved determination is still supported'

    return AuditResult(
        record=normalised,
        previous=previous,
        current=current,
        status=status,
        checkable=checkable,
        verified=verified,
        candidates=candidates,
        reason=reason,
        evidence=evidence,
    )


def _normalise_records(records):
    if isinstance(records, Mapping):
        saved = records.get('records')
        if isinstance(saved, (list, tuple)):
            return list(saved)
        if _looks_like_record(records):
            return [records]
        return list(records.values())
    if isinstance(records, (Type, Capability, str)):
        return [records]
    if (isinstance(records, tuple) and len(records) in (2, 3) and
            isinstance(records[0], str) and isinstance(records[1], str)):
        return [records]
    return list(records)


def _looks_like_record(value):
    if not isinstance(value, Mapping):
        return False
    names = set()
    for aliases in _RECORD_ALIASES.values():
        names.update(aliases)
    return any(name in value for name in names)


def audit(records, capabilities=None, manifest=None, matchers=None,
          capability_manifest=None):
    """
    Check saved determinations for handler-version change impact.

    ``records`` may contain mappings, objects, ``Type`` instances or
    ``(mime, extension)`` tuples.  A record may carry a small header sample
    (``header`` / ``sample`` bytes) and evidence captured by the old detector.
    Only that stored sample is inspected; attachment paths are never opened.

    Args:
        records: one saved record or an iterable of records.
        capabilities: optional capability manifest (or a mapping describing
            one) representing the currently deployed handlers.
        manifest: alias for ``capabilities``.
        capability_manifest: alias for ``capabilities``.
        matchers: optional iterable of current ``Type`` matchers. Defaults to
            the registry described by the manifest, falling back to ``TYPES``.

    Returns:
        An :class:`AuditReport`.
    """
    if capability_manifest is not None:
        if capabilities is not None or manifest is not None:
            raise TypeError(
                'pass only one of capabilities, manifest and '
                'capability_manifest')
        capabilities = capability_manifest
    if capabilities is not None and manifest is not None:
        raise TypeError('pass either capabilities or manifest, not both')
    supplied = capabilities if capabilities is not None else manifest

    if supplied is None:
        capability_manifest_ = _build_manifest(matchers=matchers)
    else:
        capability_manifest_ = _coerce_manifest(supplied, matchers=matchers)

    if matchers is not None:
        if isinstance(matchers, Type):
            matchers = [matchers]
        detect_matchers = list(matchers)
    elif supplied is None:
        detect_matchers = list(TYPES)
    else:
        detect_matchers = [
            c.matcher for c in capability_manifest_.entries
            if c.matcher is not None
        ]
        if not detect_matchers:
            detect_matchers = list(TYPES)

    results = [
        _audit_record(record, capability_manifest_, detect_matchers)
        for record in _normalise_records(records)
    ]
    return AuditReport(results)


check_impact = audit
change_impact = audit


__all__ = [
    'DEFAULT_VERSION',
    'CAPABILITY_ACTIVE',
    'CAPABILITY_DEGRADED',
    'CAPABILITY_RETIRED',
    'CAPABILITY_UNAVAILABLE',
    'AUDIT_UNCHANGED',
    'AUDIT_CHANGED',
    'AUDIT_DEGRADED',
    'AUDIT_UNAVAILABLE',
    'AUDIT_AMBIGUOUS',
    'AUDIT_INVALID',
    'Capability',
    'CapabilityManifest',
    'AuditResult',
    'AuditReport',
    'capabilities',
    'get_capabilities',
    'capability_manifest',
    'capability_for',
    'manifest',
    'get_capability',
    'audit',
    'check_impact',
    'change_impact',
]
