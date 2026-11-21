"""Injectable parsing contexts for extension-aware STIX imports.

A :class:`ParsingContext` carries the extension definitions a caller has
approved for a particular import batch.  Passing one to ``stix2.parse()``
(or ``dict_to_stix2()`` / ``parse_observable()``) makes the parser resolve
extension references against those approved definitions instead of only the
process-global registry.  This allows two partners to ship different
definitions under the same extension name and have each batch interpreted
with its own definitions, without mutating global state or affecting other
batches parsed in the same process.
"""

import contextlib
import contextvars
import copy
from collections import OrderedDict

import simplejson as json

from .exceptions import ParseError
from .registry import class_for_type

_active_context = contextvars.ContextVar("stix2_parsing_context", default=None)


def get_active_context():
    """Return the :class:`ParsingContext` active for the current parse, or
    None if parsing is proceeding with the process-global registry."""
    return _active_context.get()


@contextlib.contextmanager
def use_context(context):
    """Make ``context`` the active parsing context for the enclosed block.

    A None context is a no-op, so nested parses (e.g. of bundle contents)
    transparently inherit whatever context the outer import established.
    """
    if context is None:
        yield None
        return
    token = _active_context.set(context)
    try:
        yield context
    finally:
        _active_context.reset(token)


def _globally_registered(extension_key):
    """Check whether an extension key is registered in the process-global
    registry for any supported STIX version."""
    return any(
        class_for_type(extension_key, version, "extensions") is not None
        for version in ("2.0", "2.1")
    )


class ExtensionConflict:
    """Record of an object whose extension references could not be
    reconciled with the approved definitions of a :class:`ParsingContext`.

    The original content of the conflicting object is preserved verbatim in
    ``raw`` so it can be reviewed or reprocessed later.
    """

    def __init__(self, extension_key, raw, reason=""):
        self.extension_key = extension_key
        self.raw = raw
        self.reason = reason

    @property
    def object_type(self):
        if isinstance(self.raw, dict):
            return self.raw.get("type")
        return None

    @property
    def object_id(self):
        if isinstance(self.raw, dict):
            return self.raw.get("id")
        return None

    @property
    def raw_bytes(self):
        """The preserved object content as bytes, for audit/review."""
        if isinstance(self.raw, bytes):
            return self.raw
        if isinstance(self.raw, str):
            return self.raw.encode("utf-8")
        return json.dumps(self.raw, sort_keys=True).encode("utf-8")

    def __repr__(self):
        return "ExtensionConflict(extension_key=%r, object_id=%r, reason=%r)" % (
            self.extension_key, self.object_id, self.reason,
        )


class ParsingContext:
    """A set of caller-approved extension definitions used while parsing.

    Args:
        extensions: An iterable of extension classes (keyed by their
            ``_type``), or a mapping of extension key to extension class.
            These definitions take precedence over the process-global
            registry while the context is active.
        strict (bool): If True, raise :class:`ParseError` as soon as parsed
            content references an extension which is neither approved by
            this context nor registered globally.  If False (the default),
            the reference is left as raw content and an
            :class:`ExtensionConflict` is recorded on ``conflicts`` instead.

    Attributes:
        conflicts: List of :class:`ExtensionConflict` records collected
            while parsing with this context.
        missing_definitions: Extension keys referenced by the most recently
            parsed input which this context does not approve (and which are
            not globally registered).
        unreferenced_definitions: Extension keys approved by this context
            which the most recently parsed input never referenced.
    """

    def __init__(self, extensions=(), strict=False):
        self.strict = strict
        self._definitions = OrderedDict()
        self._used_definitions = OrderedDict()
        self.conflicts = []
        self.missing_definitions = []
        self.unreferenced_definitions = []

        if hasattr(extensions, "items"):
            for key, ext_cls in extensions.items():
                self.register(ext_cls, key=key)
        else:
            for ext_cls in extensions:
                self.register(ext_cls)

    def register(self, ext_cls, key=None):
        """Approve an extension definition for this context.

        Args:
            ext_cls: The extension class to approve.
            key: The extension key (e.g. an ``extension-definition--`` ID or
                an ``*-ext`` type name).  Defaults to the class's ``_type``.
        """
        if key is None:
            key = getattr(ext_cls, "_type", None)
        if not key:
            raise ValueError(
                "Extension definitions need a key: either pass 'key' or use "
                "a class with a '_type' attribute.",
            )
        self._definitions[key] = ext_cls

    @property
    def definitions(self):
        """Mapping of approved extension keys to their classes."""
        return OrderedDict(self._definitions)

    @property
    def used_definitions(self):
        """Mapping of the approved definitions actually consulted so far,
        in order of first use.  Useful for finding out which definitions a
        batch of previously parsed objects relied on."""
        return OrderedDict(self._used_definitions)

    def class_for_extension(self, extension_key):
        """Look up the approved class for an extension key, recording the
        use.  Returns None if this context does not approve the key."""
        ext_cls = self._definitions.get(extension_key)
        if ext_cls is not None:
            self._used_definitions.setdefault(extension_key, ext_cls)
        return ext_cls

    def check_object(self, stix_dict):
        """Check one (unparsed) object's extension references against this
        context.  Unapproved, globally-unknown references are recorded as
        conflicts with the object's original content preserved."""
        extensions = stix_dict.get("extensions")
        if not isinstance(extensions, dict):
            return
        for key in extensions:
            if key in self._definitions or _globally_registered(key):
                continue
            if self.strict:
                raise ParseError(
                    "Object references extension '%s', which is not approved "
                    "by this parsing context." % key,
                )
            self.conflicts.append(
                ExtensionConflict(
                    key,
                    copy.deepcopy(stix_dict),
                    reason="extension not approved by parsing context",
                ),
            )

    def finalize(self, stix_dict):
        """Cross-check approved definitions against the references found in
        a fully parsed input (a single object or a bundle).  Populates
        ``missing_definitions`` and ``unreferenced_definitions``."""
        if stix_dict.get("type") == "bundle":
            objects = stix_dict.get("objects") or []
        else:
            objects = [stix_dict]

        referenced = set()
        for obj in objects:
            if isinstance(obj, dict):
                referenced.update((obj.get("extensions") or {}).keys())

        self.missing_definitions = sorted(
            key for key in referenced
            if key not in self._definitions and not _globally_registered(key)
        )
        self.unreferenced_definitions = sorted(
            key for key in self._definitions if key not in referenced
        )

        if self.strict and self.missing_definitions:
            raise ParseError(
                "Input references extensions not approved by this parsing "
                "context: %s" % ", ".join(self.missing_definitions),
            )

    def derive(self):
        """Create a new context approving exactly the definitions which were
        actually used under this one.  This lets a later batch re-parse old
        objects with the same definitions they were originally read with."""
        derived = ParsingContext(strict=self.strict)
        for key, ext_cls in self._used_definitions.items():
            derived.register(ext_cls, key=key)
        return derived

    def __enter__(self):
        self._token = _active_context.set(self)
        return self

    def __exit__(self, *exc_info):
        _active_context.reset(self._token)
        self._token = None
        return False
