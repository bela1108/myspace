"""Evidence records for artifact resolution.

An ``EvidenceReport`` captures, for every resolved artifact, the digest that
was recorded, the source that was read, and source identities observed before
and after the read.  Resolvers that can observe the underlying resource use the
identities to prove that the digest describes one stable snapshot.  Legacy
resolvers that only implement ``hash_artifacts`` still produce useful entries,
but those entries are marked as ``unverified``.
"""

from collections import OrderedDict
from collections.abc import Mapping

CONSISTENT = "consistent"
CHANGED = "changed"
UNVERIFIED = "unverified"

_CONSISTENT_ALIASES = {
    True,
    "consistent",
    "unchanged",
    "stable",
    "same",
    "ok",
    "match",
}
_CHANGED_ALIASES = {
    False,
    "changed",
    "inconsistent",
    "mixed",
    "replaced",
    "modified",
    "mismatch",
}
_UNVERIFIED_ALIASES = {
    None,
    "unverified",
    "unknown",
    "unproven",
    "legacy",
    "not_checked",
}


def _normalize_status(value):
    """Return one of ``consistent``, ``changed`` or ``unverified``."""
    if isinstance(value, str):
        value = value.strip().lower().replace("-", "_")

    if value in _CONSISTENT_ALIASES:
        return CONSISTENT
    if value in _CHANGED_ALIASES:
        return CHANGED
    return UNVERIFIED


def _identity_dict(value):  # noqa: PLR0911
    """Convert identity-like values to a plain dictionary."""
    if value is None:
        return None
    if isinstance(value, SourceIdentity):
        return value.to_dict()
    if isinstance(value, Mapping):
        return OrderedDict(
            (str(key), _plain_value(val)) for key, val in value.items()
        )
    if isinstance(value, (str, int, float, bool)):
        return {"value": value}
    if hasattr(value, "to_dict"):
        return _identity_dict(value.to_dict())
    if hasattr(value, "__dict__"):
        return OrderedDict(
            (key, _plain_value(val))
            for key, val in vars(value).items()
            if not key.startswith("_")
        )
    return {"value": str(value)}


def _plain_value(value):
    """Recursively convert helper objects into JSON-serializable values."""
    if isinstance(value, SourceIdentity):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): _plain_value(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain_value(item) for item in value]
    if hasattr(value, "to_dict") and not isinstance(value, type):
        return _plain_value(value.to_dict())
    return value


class SourceIdentity(Mapping):
    """Identity of a resource at a particular point in time.

    The object behaves like a read-only mapping, so a caller may use
    ``identity["inode"]`` as well as ``identity.inode`` (via ``get``).  It is
    also comparable to a plain dictionary, which keeps serialized evidence
    easy to inspect in tests and downstream tools.
    """

    __hash__ = None

    def __init__(self, data=None, **kwargs):
        if data is None:
            data = {}
        elif isinstance(data, SourceIdentity):
            data = data.to_dict()
        elif not isinstance(data, Mapping):
            data = {"value": data}

        merged = dict(data)
        merged.update(kwargs)
        self._data = OrderedDict(
            (str(key), _plain_value(value))
            for key, value in merged.items()
            if value is not None
        )

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __getattr__(self, name):
        try:
            return self._data[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __eq__(self, other):
        if isinstance(other, SourceIdentity):
            return self._data == other._data
        if isinstance(other, Mapping):
            return self._data == _identity_dict(other)
        return False

    def __repr__(self):
        return f"SourceIdentity({dict(self._data)!r})"

    def to_dict(self):
        return dict(self._data)

    @classmethod
    def from_dict(cls, data):
        if isinstance(data, cls):
            return data
        return cls(data or {})


class ArtifactSource(str):  # noqa: SLOT000
    """The source that was read, with optional identity metadata attached."""

    def __new__(cls, value="", **metadata):
        obj = super().__new__(cls, "" if value is None else str(value))
        obj._metadata = {
            key: _plain_value(val)
            for key, val in metadata.items()
            if val is not None
        }
        return obj

    @property
    def identity(self):
        return self._metadata.get("identity")

    @property
    def path(self):
        return self._metadata.get("path")

    @property
    def realpath(self):
        return self._metadata.get("realpath")

    @property
    def resolver(self):
        return self._metadata.get("resolver")

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return super().__getitem__(key)
        try:
            return self._metadata[key]
        except KeyError as exc:
            raise KeyError(key) from exc

    def get(self, key, default=None):
        return self._metadata.get(key, default)

    def to_dict(self):
        return {"uri": str(self), **self._metadata}

    @classmethod
    def from_value(cls, value, resolver=None):
        if isinstance(value, cls):
            if resolver and value.resolver is None:
                value._metadata["resolver"] = resolver  # noqa: SLF001
            return value
        if isinstance(value, Mapping):
            data = dict(value)
            uri = (
                data.pop("uri", None)
                or data.pop("source", None)
                or data.pop("path", None)
                or ""
            )
            if resolver is not None:
                data.setdefault("resolver", resolver)
            return cls(uri, **data)
        if hasattr(value, "to_dict"):
            return cls.from_value(value.to_dict(), resolver=resolver)
        if value is None:
            return cls("", resolver=resolver)
        return cls(str(value), resolver=resolver)


class EvidenceEntry(Mapping):
    """Evidence for one resolved artifact."""

    def __init__(  # noqa: C901, PLR0912, PLR0913, PLR0915
        self,
        name=None,
        hashes=None,
        source=None,
        resolver=None,
        before=None,
        after=None,
        status=None,
        consistent=None,
        reason=None,
        details=None,
        uri=None,
        source_identity=None,
        **kwargs,
    ):
        if hashes is None:
            hashes = kwargs.pop("digest", kwargs.pop("hash", None))
        if uri is None:
            uri = kwargs.pop("uri", None)
        if resolver is None:
            resolver = kwargs.pop("resolver_id", None)
        if source is None:
            source = kwargs.pop("source_at_read", None)
        if before is None:
            before = kwargs.pop(
                "before_identity", kwargs.pop("identity_before", None)
            )
        if after is None:
            after = kwargs.pop(
                "after_identity", kwargs.pop("identity_after", None)
            )

        if isinstance(name, Mapping):
            data = dict(name)
            data.update(kwargs)
            name = data.pop("name", None)
            hashes = data.pop(
                "hashes",
                data.pop("digest", data.pop("hash", None)),
            )
            source = data.pop("source", None)
            resolver = data.pop("resolver", None)
            before = data.pop(
                "before", data.pop("before_identity", data.pop("identity", None))
            )
            after = data.pop(
                "after", data.pop("after_identity", data.pop("identity_after", None))
            )
            status = data.pop("status", None)
            consistent = data.pop("consistent", None)
            reason = data.pop("reason", None)
            details = data.pop("details", None)
            uri = data.pop("uri", None)
            source_identity = data.pop("source_identity", None)
            hashes = hashes or {
                key: value
                for key, value in data.items()
                if isinstance(value, str)
                and key not in {"source", "uri", "resolver"}
            }

        self.name = name
        self.uri = uri if uri is not None else name

        if hashes is None:
            hashes = {}
        elif isinstance(hashes, str):
            hashes = {"sha256": hashes}
        elif isinstance(hashes, Mapping):
            hashes = dict(hashes)
        else:
            hashes = dict(hashes)
        self.hashes = hashes

        self.resolver = _resolver_name(resolver)
        self.source = ArtifactSource.from_value(source, self.resolver)
        if source_identity is not None:
            self.source_identity = SourceIdentity.from_dict(source_identity)
        else:
            self.source_identity = SourceIdentity(self.source.to_dict())

        self.before = (
            SourceIdentity.from_dict(_identity_dict(before))
            if before is not None
            else None
        )
        self.after = (
            SourceIdentity.from_dict(_identity_dict(after))
            if after is not None
            else None
        )

        if status is not None:
            self.status = _normalize_status(status)
        elif consistent is not None:
            self.status = _normalize_status(consistent)
        elif self.before is not None or self.after is not None:
            self.status = (
                CONSISTENT if self.before == self.after else CHANGED
            )
        else:
            self.status = UNVERIFIED

        self.reason = reason
        self.details = dict(details or {})
        self.details.update(kwargs)

    @property
    def digest(self):
        return self.hashes

    @property
    def hash(self):
        return self.hashes

    @property
    def sha256(self):
        return self.hashes.get("sha256")

    @property
    def resolver_id(self):
        return self.resolver

    @property
    def resolver_name(self):
        return self.resolver

    @property
    def source_at_read(self):
        return self.source

    @property
    def before_identity(self):
        return self.before

    @property
    def after_identity(self):
        return self.after

    @property
    def identity(self):
        return self.after or self.before or self.source_identity

    @property
    def consistent(self):
        if self.status == CONSISTENT:
            return True
        if self.status == CHANGED:
            return False
        return None

    @property
    def is_consistent(self):
        return self.status == CONSISTENT

    @property
    def is_unverified(self):
        return self.status == UNVERIFIED

    @property
    def affected(self):
        return self.status == CHANGED

    @property
    def inconsistent(self):
        return self.affected

    @property
    def mixed_snapshot(self):
        return self.affected

    @property
    def proven(self):
        return self.is_consistent

    def mark_changed(self, reason=None):
        self.status = CHANGED
        if reason is not None:
            self.reason = reason
        return self

    def __getitem__(self, key):  # noqa: C901, PLR0911, PLR0912
        if key in self._canonical_dict():
            return self._canonical_dict()[key]
        if key == "digest":
            return self.hashes
        if key == "hash":
            return self.hashes
        if key == "affected":
            return self.affected
        if key in {"inconsistent", "changed", "is_changed"}:
            return self.affected
        if key == "is_consistent":
            return self.is_consistent
        if key == "proven":
            return self.proven
        if key == "resolver_id":
            return self.resolver
        if key == "resolver_name":
            return self.resolver
        if key == "source_at_read":
            return self.source
        if key == "identity":
            return self.identity
        if key in self.hashes:
            return self.hashes[key]
        try:
            return self.details[key]
        except KeyError as exc:
            raise KeyError(key) from exc

    def __iter__(self):
        return iter(self._canonical_dict())

    def __len__(self):
        return len(self._canonical_dict())

    def __repr__(self):
        return f"EvidenceEntry({self._canonical_dict()!r})"

    def _canonical_dict(self):
        data = {
            "name": self.name,
            "uri": self.uri,
            "resolver": self.resolver,
            "hashes": self.hashes,
            "source": str(self.source),
            "source_identity": self.source_identity.to_dict(),
            "before": self.before.to_dict() if self.before is not None else None,
            "after": self.after.to_dict() if self.after is not None else None,
            "status": self.status,
            "consistent": self.consistent,
            "reason": self.reason,
        }
        if self.details:
            data["details"] = self.details
        return data

    def to_dict(self):
        return self._canonical_dict()

    @classmethod
    def from_dict(cls, data):
        if isinstance(data, cls):
            return data
        return cls(data or {})


def _resolver_name(resolver):
    if resolver is None:
        return None
    if isinstance(resolver, str):
        return resolver
    if isinstance(resolver, Mapping):
        for key in ("scheme", "name", "id", "resolver"):
            if key in resolver:
                return _resolver_name(resolver[key])
        return None
    for attr in ("scheme", "SCHEME", "resolver_id", "name"):
        value = getattr(resolver, attr, None)
        if value:
            return str(value)
    return resolver.__class__.__name__


class EvidenceEntries(list):
    """Ordered collection of entries with optional lookup by artifact name."""

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return super().__getitem__(key)
        for entry in self:
            if key in {entry.name, entry.uri}:
                return entry
        raise KeyError(key)

    def __contains__(self, key):
        if isinstance(key, EvidenceEntry):
            return super().__contains__(key)
        return any(key in {entry.name, entry.uri} for entry in self)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def by_name(self):
        return OrderedDict((entry.name, entry) for entry in self)

    def keys(self):
        return [entry.name for entry in self]

    def values(self):
        return list(self)

    def items(self):
        return [(entry.name, entry) for entry in self]


class _CallableList(list):
    """List that can also be called, for convenient property-like access."""

    def __call__(self):
        return self


class EvidenceReport(Mapping):
    """Consistency report for a set of resolved artifacts."""

    def __init__(  # noqa: C901
        self, entries=None, resolver=None, mixed_snapshot=None, **meta
    ):
        self.entries = EvidenceEntries()
        self.resolver = _resolver_name(resolver)
        self.meta = dict(meta)
        self._mixed_snapshot = mixed_snapshot

        if entries is None:
            return

        if isinstance(entries, EvidenceReport):
            for entry in entries.entries:
                self.add(entry)
            self.resolver = self.resolver or entries.resolver
            if mixed_snapshot is None:
                self._mixed_snapshot = entries._mixed_snapshot  # noqa: SLF001
            self.meta.update(entries.meta)
            return

        if isinstance(entries, Mapping):
            if _looks_like_report(entries):
                report = EvidenceReport.from_dict(entries)
                for entry in report.entries:
                    self.add(entry)
                self.resolver = self.resolver or report.resolver
                if mixed_snapshot is None:
                    self._mixed_snapshot = report._mixed_snapshot  # noqa: SLF001
                self.meta.update(report.meta)
                return

            if _looks_like_entry(entries):
                self.add(
                    _entry_from_value(
                        entries.get("name") or entries.get("uri"),
                        entries,
                        resolver,
                    )
                )
                return

            for name, value in entries.items():
                self.add(_entry_from_value(name, value, resolver))
            return

        for value in entries:
            self.add(_entry_from_value(None, value, resolver))

    def add(self, entry):
        if entry is None:
            return
        if not isinstance(entry, EvidenceEntry):
            entry = EvidenceEntry.from_dict(entry)
        if entry.resolver is None and self.resolver is not None:
            entry.resolver = self.resolver
            entry.source = ArtifactSource.from_value(
                entry.source, self.resolver
            )
        self.entries.append(entry)

    def extend(self, entries):
        if isinstance(entries, EvidenceReport):
            entries = entries.entries
        for entry in entries:
            self.add(entry)
        return self

    @property
    def by_name(self):
        return self.entries.by_name()

    @property
    def hashes(self):
        return {
            entry.name: dict(entry.hashes)
            for entry in self.entries
            if entry.name is not None and entry.hashes
        }

    @property
    def materials(self):
        return self.hashes

    @property
    def artifacts(self):
        return self.hashes

    @property
    def affected_entries(self):
        return [entry for entry in self.entries if entry.affected]

    @property
    def inconsistent_entries(self):
        return self.affected_entries

    @property
    def changed_entries(self):
        return self.affected_entries

    @property
    def unverified_entries(self):
        return [entry for entry in self.entries if entry.is_unverified]

    @property
    def consistent_entries(self):
        return [entry for entry in self.entries if entry.is_consistent]

    @property
    def affected_names(self):
        return [entry.name for entry in self.affected_entries]

    @property
    def affected_uris(self):
        return [entry.uri for entry in self.affected_entries]

    @property
    def affected_resolvers(self):
        resolvers = {
            entry.resolver
            for entry in self.affected_entries
            if entry.resolver is not None
        }
        return sorted(resolvers)

    @property
    def resolvers(self):
        return sorted(
            {
                entry.resolver
                for entry in self.entries
                if entry.resolver is not None
            }
        )

    @property
    def affected_with_resolvers(self):
        return [
            (entry, entry.resolver)
            for entry in self.affected_entries
        ]

    @property
    def mixed_snapshot(self):
        return bool(self._mixed_snapshot) or bool(self.affected_entries)

    @property
    def mixed(self):
        return self.mixed_snapshot

    @property
    def has_mixed_snapshot(self):
        return self.mixed_snapshot

    @property
    def ok(self):
        return not self.mixed_snapshot

    @property
    def consistent(self):
        if self.mixed_snapshot:
            return False
        return all(entry.is_consistent for entry in self.entries)

    @property
    def fully_consistent(self):
        return self.consistent

    @property
    def verified(self):
        return self.consistent

    @property
    def is_consistent(self):
        return self.consistent

    @property
    def is_mixed_snapshot(self):
        return self.mixed_snapshot

    def entries_for_resolver(self, resolver):
        resolver = _resolver_name(resolver)
        return [
            entry for entry in self.entries if entry.resolver == resolver
        ]

    def resolver_for(self, name):
        entry = self.entries.get(name)
        return entry.resolver if entry is not None else None

    def find(self, name):
        return self.entries.get(name)

    @property
    def affected(self):
        return _CallableList(self.affected_entries)

    def find_affected_entries(self):
        return self.affected_entries

    def get_affected_entries(self):
        return self.affected_entries

    def get_affected_resolvers(self):
        return self.affected_resolvers

    def affected_resolver_map(self):
        result = OrderedDict()
        for entry in self.affected_entries:
            result.setdefault(entry.resolver, []).append(entry)
        return result

    @property
    def affected_resolver_entries(self):
        return self.affected_resolver_map()

    def find_entries_for_resolver(self, resolver):
        return self.entries_for_resolver(resolver)

    def report_for(self, name):
        return self.entries.get(name)

    def to_dict(self):
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "materials": self.hashes,
            "consistent": self.consistent,
            "mixed_snapshot": self.mixed_snapshot,
            "resolvers": self.resolvers,
            "affected_resolvers": self.affected_resolvers,
        }

    @classmethod
    def from_dict(cls, data, resolver=None):  # noqa: C901, PLR0911
        if isinstance(data, cls):
            return data
        if data is None:
            return cls(resolver=resolver)
        if (
            isinstance(data, (tuple, list))
            and len(data) == 2
            and isinstance(data[0], Mapping)
            and isinstance(data[1], (list, tuple, Mapping, cls))
            and not isinstance(data[0].get("entries"), (list, Mapping))
            and any(
                _looks_like_entry(entry)
                for entry in (
                    data[1].entries
                    if isinstance(data[1], cls)
                    else data[1].values()
                    if isinstance(data[1], Mapping)
                    else data[1]
                )
            )
        ):
            hashes, evidence = data
            report = cls(entries=evidence, resolver=resolver)
            for name, hash_dict in hashes.items():
                entry = report.entries.get(name)
                if entry is None:
                    report.add(
                        EvidenceEntry(
                            name=name,
                            hashes=hash_dict,
                            source=name,
                            resolver=resolver,
                        )
                    )
                elif not entry.hashes:
                    entry.hashes = dict(hash_dict)
            return report
        if isinstance(data, Mapping):
            if "hashes" in data and "evidence" in data:
                report = cls(entries=data["evidence"], resolver=resolver)
                for name, hash_dict in data["hashes"].items():
                    entry = report.entries.get(name)
                    if entry is not None and not entry.hashes:
                        entry.hashes = dict(hash_dict)
                return report
            if "entries" in data:
                report = cls(
                    entries=data["entries"],
                    resolver=resolver or data.get("resolver"),
                    mixed_snapshot=data.get("mixed_snapshot"),
                )
                report.meta.update(
                    {
                        key: value
                        for key, value in data.items()
                        if key
                        not in {
                            "entries",
                            "resolver",
                            "mixed_snapshot",
                            "consistent",
                            "resolvers",
                        }
                    }
                )
                return report
            if _looks_like_entry(data):
                return cls(entries=[data], resolver=resolver)
            return cls(entries=data, resolver=resolver)
        return cls(entries=data, resolver=resolver)

    def __getitem__(self, key):  # noqa: PLR0911
        if key == "entries":
            return self.entries
        if key == "hashes":
            return self.hashes
        if key == "materials":
            return self.hashes
        if key == "consistent":
            return self.consistent
        if key == "mixed_snapshot":
            return self.mixed_snapshot
        if key == "resolvers":
            return self.resolvers
        return self.entries[key]

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)

    def __repr__(self):
        return f"EvidenceReport({self.to_dict()!r})"


def _looks_like_report(data):
    return "entries" in data


def _looks_like_entry(value):
    if isinstance(value, EvidenceEntry):
        return True
    if not isinstance(value, Mapping):
        return False
    return any(
        key in value
        for key in (
            "hashes",
            "digest",
            "hash",
            "source",
            "resolver",
            "before",
            "after",
            "status",
            "consistent",
            "source_identity",
        )
    )


def _looks_like_hashes(value):
    if not isinstance(value, Mapping):
        return False
    return bool(value) and all(
        isinstance(key, str) and isinstance(digest, str)
        for key, digest in value.items()
    )


def _entry_from_value(name, value, resolver=None):
    if isinstance(value, EvidenceEntry):
        entry = value
        if name is not None:
            entry.name = name
        return entry

    if isinstance(value, (tuple, list)):
        values = list(value)
        hashes = values[0] if values else {}
        source = values[1] if len(values) > 1 else None
        before = values[2] if len(values) > 2 else None
        after = values[3] if len(values) > 3 else None
        status = values[4] if len(values) > 4 else None
        return EvidenceEntry(
            name=name,
            hashes=hashes,
            source=source,
            resolver=resolver,
            before=before,
            after=after,
            status=status,
        )

    if _looks_like_entry(value):
        data = dict(value)
    elif _looks_like_hashes(value):
        data = {"hashes": dict(value)}
    else:
        data = {"hashes": dict(value) if isinstance(value, Mapping) else {}}

    data.setdefault("name", name)
    data.setdefault("uri", name)
    entry = EvidenceEntry.from_dict(data)
    if entry.resolver is None and resolver is not None:
        entry.resolver = _resolver_name(resolver)
        entry.source = ArtifactSource.from_value(entry.source, entry.resolver)
    return entry


def report_from_hashes(hashes, resolver=None, source=None):
    """Create an unverified report from a legacy artifact hash dictionary."""
    entries = []
    for name, hash_dict in hashes.items():
        entry_resolver = resolver(name) if callable(resolver) else resolver
        entry_source = source(name) if callable(source) else source
        if entry_source is None:
            entry_source = name
        entries.append(
            EvidenceEntry(
                name=name,
                hashes=hash_dict,
                source=entry_source,
                resolver=entry_resolver,
                status=UNVERIFIED,
            )
        )
    return EvidenceReport(
        entries=entries,
        resolver=None if callable(resolver) else resolver,
    )


def evidence_from_hashes(hashes, resolver=None, source=None):
    """Alias for :func:`report_from_hashes`."""
    return report_from_hashes(hashes, resolver=resolver, source=source)


def check_evidence_consistency(evidence):
    """Return ``True`` if the passed evidence proves a stable snapshot."""
    report = EvidenceReport.from_dict(evidence)
    return report.consistent


def verify_evidence_consistency(evidence):
    """Return the normalized report if it is consistent, else raise ValueError."""
    report = EvidenceReport.from_dict(evidence)
    if not report.consistent:
        raise ValueError(
            "artifact evidence is inconsistent for: "
            + ", ".join(
                f"{entry.name} ({entry.resolver})"
                for entry in report.affected_entries
            )
        )
    return report


def find_affected_entries(evidence):
    """Return entries whose source changed while the digest was recorded."""
    report = EvidenceReport.from_dict(evidence)
    return report.affected_entries


def affected_resolvers(evidence):
    """Return resolver identifiers responsible for affected entries."""
    report = EvidenceReport.from_dict(evidence)
    return report.affected_resolvers


def find_entries_for_resolver(evidence, resolver):
    """Return all entries produced by ``resolver``."""
    report = EvidenceReport.from_dict(evidence)
    return report.entries_for_resolver(resolver)


def resolver_for_entry(evidence, name):
    """Return the resolver identifier for an artifact entry."""
    report = EvidenceReport.from_dict(evidence)
    return report.resolver_for(name)


def consistency_report(evidence):
    """Return a normalized :class:`EvidenceReport`."""
    return EvidenceReport.from_dict(evidence)


def as_report(evidence, resolver=None):
    """Coerce arbitrary resolver output into an :class:`EvidenceReport`."""
    return EvidenceReport.from_dict(evidence, resolver=resolver)


# Public aliases kept intentionally close to the terminology used by callers.
Evidence = EvidenceEntry
ArtifactEvidence = EvidenceEntry
MaterialEvidence = EvidenceEntry
ResolverEvidence = EvidenceEntry
ResolutionEvidence = EvidenceEntry

MaterialReport = EvidenceReport
MaterialsReport = EvidenceReport
MaterialEvidenceReport = EvidenceReport
ResolutionReport = EvidenceReport
ConsistencyReport = EvidenceReport
EvidenceConsistencyReport = EvidenceReport
ArtifactEvidenceReport = EvidenceReport

SnapshotIdentity = SourceIdentity
ArtifactIdentity = SourceIdentity

CONSISTENT_STATUS = CONSISTENT
CHANGED_STATUS = CHANGED
UNVERIFIED_STATUS = UNVERIFIED
