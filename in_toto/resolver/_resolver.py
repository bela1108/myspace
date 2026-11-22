"""Resolver interface and implementations for files, OSTree, and directory
artifacts."""

import contextlib
import hashlib
import locale
import logging
import os
import stat
from abc import ABC, abstractmethod
from functools import cmp_to_key
from itertools import combinations
from os.path import exists, isdir, isfile, join, normpath

from pathspec import GitIgnoreSpec

from in_toto.exceptions import PrefixError
from in_toto.resolver.evidence import (
    CHANGED,
    CONSISTENT,
    ArtifactSource,
    EvidenceEntry,
    EvidenceReport,
    SourceIdentity,
)

logger = logging.getLogger(__name__)

_HASH_ALGORITHM = "sha256"

RESOLVER_FOR_URI_SCHEME = {}

# Compatibility aliases for callers that import evidence types with the
# resolver implementation module.
ArtifactEvidence = EvidenceEntry
MaterialEvidence = EvidenceEntry
ResolverEvidence = EvidenceEntry
MaterialsReport = EvidenceReport
ResolutionReport = EvidenceReport


class Resolver(ABC):
    """Resolver interface and factory."""

    SCHEME = None

    @classmethod
    def for_uri(cls, uri):
        """Return registered resolver instance for passed URI."""
        scheme, match, _ = uri.partition(":")

        if not match or scheme not in RESOLVER_FOR_URI_SCHEME:
            scheme = FileResolver.SCHEME

        return RESOLVER_FOR_URI_SCHEME[scheme]

    @abstractmethod
    def hash_artifacts(self, uris):
        """Return hash dictionary for passed list of artifact URIs."""
        raise NotImplementedError

    @property
    def scheme(self):
        """Return the URI scheme (or a stable fallback) for this resolver."""
        return self.SCHEME or self.__class__.__name__

    @property
    def resolver_id(self):
        """Alias for :attr:`scheme`, used in evidence reports."""
        return self.scheme

    def _has_custom_method(self, name):
        """Return True if the subclass replaced the base no-op hook."""
        return getattr(type(self), name, None) is not getattr(
            Resolver, name, None
        )

    def resolve_artifact(self, _uri):
        """Resolve a single artifact into evidence.

        Legacy resolvers only need to implement :meth:`hash_artifacts`.
        Resolvers that can describe the underlying resource may override this
        method and return an :class:`EvidenceEntry` or a dictionary with at
        least ``hashes`` and ``source``.
        """
        raise NotImplementedError

    def artifact_identity(self, _uri):
        """Return a resource identity for ``uri``, if observable.

        This is an optional hook for simple resolvers. The default evidence
        adapter snapshots the identity before and after hashing, and marks the
        record as consistent or changed based on the two observations.
        """
        return

    def artifact_source(self, _uri):
        """Return the source read for ``uri``, if observable."""
        return

    def _call_optional(self, names, uri):
        """Call the first overridden hook from ``names`` with ``uri``."""
        for name in names:
            method = getattr(self, name, None)
            if method is None or not callable(method):
                continue
            if not self._has_custom_method(name):
                continue
            try:
                return method(uri)
            except TypeError:
                continue
        return None

    def _observed_identity(self, uri):
        return self._call_optional(
            (
                "artifact_identity",
                "identity_before",
                "before_identity",
                "source_identity",
                "get_artifact_identity",
                "identity_for",
                "get_identity",
                "snapshot_identity",
                "snapshot",
            ),
            uri,
        )

    def _observed_source(self, uri):
        return self._call_optional(
            (
                "artifact_source",
                "source_before",
                "before_source",
                "get_artifact_source",
                "source_for",
                "get_source",
                "resolve_source",
            ),
            uri,
        )

    def _observed_identity_after(self, uri):
        return self._call_optional(
            (
                "artifact_identity_after",
                "identity_after",
                "after_identity",
                "artifact_identity",
                "snapshot_identity",
                "snapshot",
            ),
            uri,
        )

    def _observed_source_after(self, uri):
        return self._call_optional(
            (
                "artifact_source_after",
                "source_after",
                "after_source",
                "artifact_source",
                "get_source",
                "resolve_source",
            ),
            uri,
        )

    def hash_artifacts_with_evidence(self, uris):
        """Return an :class:`EvidenceReport` for passed artifact URIs.

        Resolvers with a native single-artifact interface can override
        :meth:`resolve_artifact`. Other resolvers are adapted from
        :meth:`hash_artifacts`; optional identity/source hooks are observed
        before and after hashing to detect replacement during the read.
        """
        uris = list(uris)

        if self._has_custom_method("resolve_artifact"):
            entries = []
            for uri in uris:
                value = self.resolve_artifact(uri)
                entries.append(
                    _entry_from_resolver_value(
                        uri, value, resolver=self.scheme
                    )
                )
            return EvidenceReport(entries=entries, resolver=self.scheme)

        source_before = {uri: self._observed_source(uri) for uri in uris}
        identity_before = {uri: self._observed_identity(uri) for uri in uris}

        hashes = self.hash_artifacts(uris)

        if isinstance(hashes, EvidenceReport):
            for entry in hashes.entries:
                if entry.resolver is None:
                    entry.resolver = self.scheme
            return hashes
        if (
            isinstance(hashes, (tuple, list))
            and len(hashes) == 2
            and isinstance(hashes[0], dict)
            and (isinstance(hashes, tuple) or not isinstance(hashes[1], dict))
        ):
            return EvidenceReport.from_dict(hashes, resolver=self.scheme)

        source_after = {
            uri: self._observed_source_after(uri) for uri in uris
        }
        identity_after = {
            uri: self._observed_identity_after(uri) for uri in uris
        }

        entries = []
        for name, value in _iter_resolver_hashes(hashes):
            uri = _uri_for_name(name, uris)
            before = identity_before.get(uri)
            after = identity_after.get(uri)
            source = (
                source_before.get(uri)
                or source_after.get(uri)
                or name
            )

            if before is not None or after is not None:
                status = CONSISTENT if before == after else CHANGED
            else:
                status = None

            entries.append(
                _entry_from_resolver_value(
                    name,
                    value,
                    resolver=self.scheme,
                    uri=uri,
                    source=source,
                    before=before,
                    after=after,
                    status=status,
                )
            )

        return EvidenceReport(entries=entries, resolver=self.scheme)

    def resolve(self, uris):
        """Alias for :meth:`hash_artifacts_with_evidence`."""
        return self.hash_artifacts_with_evidence(uris)

    def resolve_artifacts(self, uris):
        """Alias for :meth:`hash_artifacts_with_evidence`."""
        return self.hash_artifacts_with_evidence(uris)

    def hash_artifacts_evidence(self, uris):
        """Alias for :meth:`hash_artifacts_with_evidence`."""
        return self.hash_artifacts_with_evidence(uris)

    def hash_artifacts_with_provenance(self, uris):
        """Alias for :meth:`hash_artifacts_with_evidence`."""
        return self.hash_artifacts_with_evidence(uris)

    def resolve_with_evidence(self, uris):
        """Alias for :meth:`hash_artifacts_with_evidence`."""
        return self.hash_artifacts_with_evidence(uris)

    def hash_artifacts_and_evidence(self, uris):
        """Return a ``(hashes, report)`` pair for passed artifact URIs."""
        report = self.hash_artifacts_with_evidence(uris)
        return report.hashes, report


class FileResolver(Resolver):
    """File resolver implementation.

    Provides a ``hash_artifacts`` method to generate hashes for passed file
    paths. The resolver is configurable via its constructor.

    """

    SCHEME = "file"

    def __init__(
        self,
        exclude_patterns=None,
        base_path=None,
        follow_symlink_dirs=False,
        normalize_line_endings=False,
        lstrip_paths=None,
    ):
        if exclude_patterns is None:
            exclude_patterns = []

        if not lstrip_paths:
            lstrip_paths = []

        if base_path is not None and not isinstance(base_path, str):
            raise ValueError("'base_path' must be string")

        for name, val in [
            ("exclude_patterns", exclude_patterns),
            ("lstrip_paths", lstrip_paths),
        ]:
            if not isinstance(val, list) or not all(
                isinstance(i, str) for i in val
            ):
                raise ValueError(f"'{name}' must be list of strings")

        for a_, b_ in combinations(lstrip_paths, 2):
            if a_.startswith(b_) or b_.startswith(a_):
                raise PrefixError(
                    f"'{a_}' and '{b_}' triggered a left substring error"
                )

        # Compile gitignore-style patterns
        self._exclude_filter = GitIgnoreSpec.from_lines(
            "gitwildmatch", exclude_patterns
        )
        self._base_path = base_path
        self._follow_symlink_dirs = follow_symlink_dirs
        self._normalize_line_endings = normalize_line_endings
        self._lstrip_paths = lstrip_paths

    def _exclude(self, path):
        """Helper to check, if path matches pre-compiled exclude patterns."""
        return self._exclude_filter.match_file(path)

    def _hash(self, path):
        """Helper to generate hash dictionary for path."""
        hexdigest = _hash_file(
            path,
            _HASH_ALGORITHM,
            self._normalize_line_endings,
        )
        return {_HASH_ALGORITHM: hexdigest}

    def _mangle(self, path, existing_paths, scheme_prefix):
        """Helper for path mangling."""

        # Normalize slashes for cross-platform metadata consistency
        path = path.replace("\\", "/")

        # Left-strip names using configured path prefixes
        for lstrip_path in self._lstrip_paths:
            if path.startswith(lstrip_path):
                path = path[len(lstrip_path) :]
                break

        # Fail if left-stripping above results in duplicates
        if self._lstrip_paths and path in existing_paths:
            raise PrefixError(
                "Prefix selection has resulted in non unique dictionary key "
                f"'{path}'"
            )

        # Prepend passed scheme prefix
        return scheme_prefix + path

    def _strip_scheme_prefix(self, path):
        """Helper to strip file resolver scheme prefix from path."""

        prefix = self.SCHEME + ":"
        if path.startswith(prefix):
            path = path[len(prefix) :]
        else:
            prefix = ""

        return path, prefix

    def hash_artifacts(self, uris):  # noqa: C901
        hashes = {}

        if self._base_path:
            original_cwd = os.getcwd()
            os.chdir(self._base_path)

        for path in uris:
            # Remove scheme prefix, but preserver to re-add later (see _mangle)
            path, prefix = self._strip_scheme_prefix(path)  # noqa: PLW2901

            # Normalize URI before filtering and returning them
            # FIXME: Is this expected behavior? Does this make exclude patterns
            # with slashes platform-dependent? Check how 'gitwildmatch' treats
            # dots and slashes!
            path = normpath(path)  # noqa: PLW2901

            if self._exclude(path):
                continue

            if not exists(path):
                logger.info("path: %s does not exist, skipping..", path)
                continue

            if isfile(path):
                name = self._mangle(path, hashes, prefix)
                hashes[name] = self._hash(path)

            if isdir(path):
                for base, dirs, names in os.walk(
                    path, followlinks=self._follow_symlink_dirs
                ):
                    # Filter directories to avoid unnecessary recursion below
                    # NOTE: Normalize to filter on directory paths without
                    # their dot-slash prefix, if path was dot.
                    dirs[:] = [
                        dirname
                        for dirname in dirs
                        if not self._exclude(normpath(join(base, dirname)))
                    ]

                    for filename in names:
                        # NOTE: Normalize to filter on and return file paths
                        # without their dot-slash prefix, if path was dot.
                        filepath = normpath(join(base, filename))

                        if self._exclude(filepath):
                            continue

                        if not isfile(filepath):
                            logger.info(
                                "File '%s' appears to be a broken symlink. "
                                "Skipping...",
                                filepath,
                            )
                            continue

                        name = self._mangle(filepath, hashes, prefix)
                        hashes[name] = self._hash(filepath)

        # Change back to original current working dir
        if self._base_path:
            os.chdir(original_cwd)

        return hashes

    def hash_artifacts_with_evidence(self, uris):  # noqa: C901, PLR0912
        """Return evidence for files and directory trees.

        Every file is opened once.  Its file descriptor identity is sampled
        before and after reading, and the path is sampled again after closing.
        If either observation differs, the entry is marked ``changed`` instead
        of pretending that the digest describes one snapshot.
        """
        entries = []
        hashes = {}

        if self._base_path:
            original_cwd = os.getcwd()
            os.chdir(self._base_path)

        try:
            for uri in uris:
                path, prefix = self._strip_scheme_prefix(uri)
                path = normpath(path)

                if self._exclude(path):
                    continue

                if not exists(path):
                    logger.info("path: %s does not exist, skipping..", path)
                    continue

                if isfile(path):
                    name = self._mangle(path, hashes, prefix)
                    entry = self._hash_file_with_evidence(
                        path, name, uri, prefix
                    )
                    hashes[name] = entry.hashes
                    entries.append(entry)

                if isdir(path):
                    tree_before = _snapshot_tree(
                        path, self._follow_symlink_dirs
                    )
                    root_entries = []

                    for base, dirs, names in os.walk(
                        path, followlinks=self._follow_symlink_dirs
                    ):
                        dirs[:] = [
                            dirname
                            for dirname in dirs
                            if not self._exclude(normpath(join(base, dirname)))
                        ]

                        for filename in names:
                            filepath = normpath(join(base, filename))

                            if self._exclude(filepath):
                                continue

                            if not isfile(filepath):
                                logger.info(
                                    "File '%s' appears to be a broken symlink. "
                                    "Skipping...",
                                    filepath,
                                )
                                continue

                            name = self._mangle(filepath, hashes, prefix)
                            entry = self._hash_file_with_evidence(
                                filepath, name, name, prefix
                            )
                            hashes[name] = entry.hashes
                            root_entries.append(entry)

                    tree_after = _snapshot_tree(
                        path, self._follow_symlink_dirs
                    )
                    if tree_before != tree_after:
                        changed_paths = _changed_tree_paths(
                            tree_before, tree_after
                        )
                        for entry in root_entries:
                            entry.mark_changed(
                                "source tree changed while it was read"
                            )
                            entry.details["changed_paths"] = changed_paths

                    entries.extend(root_entries)
        finally:
            if self._base_path:
                os.chdir(original_cwd)

        return EvidenceReport(entries=entries, resolver=self.scheme)

    def _hash_file_with_evidence(self, path, name, uri, _prefix):
        """Hash one file and attach its before/read/after identity."""
        before = _snapshot_path(path)

        digest = hashlib.new(_HASH_ALGORITHM)
        with open(path, "rb") as stream:
            opened = _stat_identity(os.fstat(stream.fileno()))
            while True:
                data = stream.read(4096)
                if not data:
                    break

                if self._normalize_line_endings:
                    while data[-1:] == b"\r":
                        extra = stream.read(1)
                        if not extra:
                            break
                        data += extra

                    data = (
                        data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                    )

                digest.update(data)

            read_done = _stat_identity(os.fstat(stream.fileno()))

        after = _snapshot_path(path)
        before = _with_opened_identity(before, opened)
        after = _with_opened_identity(after, read_done)

        status = CONSISTENT if before == after else CHANGED
        reason = None
        if status == CHANGED:
            reason = "source identity changed while it was read"

        source = _file_source(uri, path, self.scheme, before)
        return EvidenceEntry(
            name=name,
            uri=uri,
            hashes={_HASH_ALGORITHM: digest.hexdigest()},
            source=source,
            resolver=self.scheme,
            before=before,
            after=after,
            status=status,
            reason=reason,
        )


class OSTreeResolver(Resolver):
    """Resolver for OSTree repositories."""

    SCHEME = "ostree"

    # defining this separately as it should be pinned to OSTree's default
    # rather than in-toto's
    _HASH_ALGORITHM = "sha256"

    def __init__(self, base_path=None):
        self._base_path = base_path

    def _strip_scheme_prefix(self, path):
        """Helper to strip OSTree resolver scheme prefix from path."""

        return path[len(self.SCHEME + ":") :]

    def _add_scheme_prefix(self, path):
        """Helper to add scheme back after recording the hash."""

        return f"{self.SCHEME}:{path}"

    def _hash(self, path):
        """Helper to hash OSTree commits."""

        ref_path = os.path.join("refs", "heads", path)

        with open(ref_path) as ref:  # noqa: PLW1514, RUF100
            ref_contents = ref.read()
        ref_contents = ref_contents.strip("\n")

        object_path = os.path.join(
            "objects", ref_contents[:2], f"{ref_contents[2:]}.commit"
        )

        hexdigest = _hash_file(object_path, self._HASH_ALGORITHM, False)

        return {self._HASH_ALGORITHM: hexdigest}

    def hash_artifacts(self, uris):
        hashes = {}

        if self._base_path:
            original_cwd = os.getcwd()
            os.chdir(self._base_path)

        try:
            for path in uris:
                # Remove scheme prefix, but preserver to re-add later
                path = self._strip_scheme_prefix(path)  # noqa: PLW2901
                hashes[self._add_scheme_prefix(path)] = self._hash(path)
        finally:
            # Change back to original current working dir
            if self._base_path:
                os.chdir(original_cwd)

        return hashes

    def hash_artifacts_with_evidence(self, uris):
        """Return evidence for OSTree refs, including the commit read."""
        entries = []

        if self._base_path:
            original_cwd = os.getcwd()
            os.chdir(self._base_path)

        try:
            for uri in uris:
                path = self._strip_scheme_prefix(uri)
                before = _ostree_identity(path)
                hashes = self._hash(path)
                after = _ostree_identity(path)

                status = CONSISTENT if before == after else CHANGED
                entry = EvidenceEntry(
                    name=self._add_scheme_prefix(path),
                    uri=uri,
                    hashes=hashes,
                    source=uri,
                    source_identity=before,
                    resolver=self.scheme,
                    before=before,
                    after=after,
                    status=status,
                    reason=(
                        None
                        if status == CONSISTENT
                        else "OSTree ref changed while it was read"
                    ),
                )
                entries.append(entry)
        finally:
            if self._base_path:
                os.chdir(original_cwd)

        return EvidenceReport(entries=entries, resolver=self.scheme)


class DirectoryResolver(Resolver):
    """Directory resolver implementation.

    Implementation of the following shell command for some directory URI:

    find . -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum | sha256sum |
        cut -f1 -d' '

    `exclude_patterns` are not applied on the directory paths passed to
    `hash_artifacts`, but on the files inside the directory. Similarly,
    `follow_symlink_dirs` and `normalize_line_endings` are used on
    subdirectories and files inside the directories passed to `hash_artifacts`.

    """

    SCHEME = "dir"

    def __init__(
        self,
        exclude_patterns=None,
        follow_symlink_dirs=False,
        normalize_line_endings=False,
        lstrip_paths=None,
    ):
        if not exclude_patterns:
            exclude_patterns = []

        if not lstrip_paths:
            lstrip_paths = []

        self._exclude_patterns = exclude_patterns
        self._follow_symlink_dirs = follow_symlink_dirs
        self._normalize_line_endings = normalize_line_endings
        self._lstrip_paths = lstrip_paths

    def _strip_scheme_prefix(self, path):
        """Helper to strip file resolver scheme prefix from path."""

        return path[len(self.SCHEME + ":") :]

    def _mangle(self, path, existing_paths):
        """Helper for path mangling."""

        # Normalize slashes for cross-platform metadata consistency
        path = path.replace("\\", "/")

        # Left-strip names using configured path prefixes
        for lstrip_path in self._lstrip_paths:
            if path.startswith(lstrip_path):
                path = path[len(lstrip_path) :]
                break

        # Prepend passed scheme prefix
        # We do this first because the entries in existing_paths have the scheme
        # affixed already.
        path = self.SCHEME + ":" + path

        # Fail if left-stripping above results in duplicates
        if self._lstrip_paths and path in existing_paths:
            raise PrefixError(
                "Prefix selection has resulted in non unique dictionary key "
                f"'{path}'"
            )

        return path

    def _hash(self, file_hashes):
        """Helper to correctly sort and hash every element."""

        text_repr = ""
        keys = list(file_hashes.keys())
        if keys:
            locale.setlocale(locale.LC_ALL, "C")
            keys.sort(key=cmp_to_key(locale.strcoll))

            text_repr = "\n".join(
                [f"{file_hashes[k][_HASH_ALGORITHM]}  {k}" for k in keys]
            )
            text_repr += "\n"  # trailing new line

        digest_obj = hashlib.new(_HASH_ALGORITHM)
        digest_obj.update(text_repr.encode("utf-8"))

        return {_HASH_ALGORITHM: digest_obj.hexdigest()}

    def hash_artifacts(self, uris):
        hashes = {}

        for path in uris:
            path = self._strip_scheme_prefix(path)  # noqa: PLW2901

            if not os.path.isdir(path):
                raise ValueError(f"path '{path}' is not a directory")

            file_resolver = FileResolver(
                base_path=path,
                exclude_patterns=self._exclude_patterns,
                follow_symlink_dirs=self._follow_symlink_dirs,
                normalize_line_endings=self._normalize_line_endings,
            )

            file_hashes = file_resolver.hash_artifacts(["."])
            if not file_hashes:
                logger.info(
                    "path: %s has no files, recording empty dir...", path
                )

            name = self._mangle(path, hashes)
            hashes[name] = self._hash(file_hashes)

        return hashes

    def hash_artifacts_with_evidence(self, uris):
        """Return evidence for directories, including before/after trees."""
        entries = []
        hashes = {}

        for uri in uris:
            path = self._strip_scheme_prefix(uri)

            if not os.path.isdir(path):
                raise ValueError(f"path '{path}' is not a directory")

            tree_before = _snapshot_tree(path, self._follow_symlink_dirs)

            file_resolver = FileResolver(
                base_path=path,
                exclude_patterns=self._exclude_patterns,
                follow_symlink_dirs=self._follow_symlink_dirs,
                normalize_line_endings=self._normalize_line_endings,
            )

            file_report = file_resolver.hash_artifacts_with_evidence(["."])
            file_hashes = file_report.hashes
            if not file_hashes:
                logger.info(
                    "path: %s has no files, recording empty dir...", path
                )

            tree_after = _snapshot_tree(path, self._follow_symlink_dirs)
            name = self._mangle(path, hashes)
            hashes[name] = self._hash(file_hashes)

            changed_paths = _changed_tree_paths(tree_before, tree_after)
            status = CONSISTENT if not changed_paths else CHANGED
            details = {}
            if changed_paths:
                details["changed_paths"] = changed_paths

            entries.append(
                EvidenceEntry(
                    name=name,
                    uri=uri,
                    hashes=hashes[name],
                    source=uri,
                    source_identity={
                        "path": path,
                        "realpath": os.path.realpath(path),
                    },
                    resolver=self.scheme,
                    before=tree_before,
                    after=tree_after,
                    status=status,
                    reason=(
                        None
                        if status == CONSISTENT
                        else "directory tree changed while it was read"
                    ),
                    details=details,
                )
            )

        return EvidenceReport(entries=entries, resolver=self.scheme)


def _hash_file(path, algo, normalize_line_endings):
    """Returns hashed file."""

    digest = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            # Chunk size is taken from the previously used and now deprecated
            # `securesystemslib.hash.digest_fileobject`.
            data = f.read(4096)
            if not data:
                break

            if normalize_line_endings:
                while data[-1:] == b"\r":
                    c = f.read(1)
                    if not c:
                        break

                    data += c

                data = (
                    data
                    # First Windows
                    .replace(b"\r\n", b"\n")
                    # Then Mac
                    .replace(b"\r", b"\n")
                )

            digest.update(data)

    return digest.hexdigest()


def _stat_identity(st):
    """Return a stable, JSON-serializable identity for a stat result."""
    return {
        "device": int(st.st_dev),
        "inode": int(st.st_ino),
        "mode": int(stat.S_IMODE(st.st_mode)),
        "file_type": int(stat.S_IFMT(st.st_mode)),
        "size": int(st.st_size),
        "mtime_ns": int(getattr(st, "st_mtime_ns", st.st_mtime * 1_000_000_000)),
        "ctime_ns": int(getattr(st, "st_ctime_ns", st.st_ctime * 1_000_000_000)),
    }


def _snapshot_path(path):
    """Return path and identity information for a file or symlink."""
    snapshot = {"path": path.replace("\\", "/")}
    try:
        link_stat = os.lstat(path)
    except OSError:
        return None

    snapshot["lstat"] = _stat_identity(link_stat)
    if stat.S_ISLNK(link_stat.st_mode):
        with contextlib.suppress(OSError):
            snapshot["link_target"] = os.readlink(path)

    try:
        target_stat = os.stat(path)
    except OSError:
        snapshot["stat"] = None
        return snapshot

    snapshot["stat"] = _stat_identity(target_stat)
    snapshot["realpath"] = os.path.realpath(path).replace("\\", "/")
    return snapshot


def _with_opened_identity(snapshot, opened):
    """Attach file-descriptor identity observed while a file is open."""
    result = dict(snapshot or {})
    result["open"] = opened
    return result


def _snapshot_tree(root, followlinks):
    """Snapshot the identities of all paths below ``root``."""
    entries = {}
    for base, dirs, names in os.walk(root, followlinks=followlinks):
        for dirname in dirs:
            path = os.path.join(base, dirname)
            key = os.path.relpath(path, root).replace("\\", "/")
            entries[key] = _snapshot_path(path)

        for filename in names:
            path = os.path.join(base, filename)
            key = os.path.relpath(path, root).replace("\\", "/")
            entries[key] = _snapshot_path(path)

    return {
        "root": _snapshot_path(root),
        "entries": dict(sorted(entries.items())),
    }


def _changed_tree_paths(before, after):
    """Return relative paths whose identities differ between two snapshots."""
    before_entries = (before or {}).get("entries", {})
    after_entries = (after or {}).get("entries", {})
    paths = set(before_entries) | set(after_entries)
    changed = [
        path
        for path in paths
        if before_entries.get(path) != after_entries.get(path)
    ]
    if (before or {}).get("root") != (after or {}).get("root"):
        changed.append(".")

    return sorted(changed)


def _file_source(uri, path, scheme, identity):
    """Build the source value recorded for a file artifact."""
    metadata = {
        "path": path.replace("\\", "/"),
        "realpath": os.path.realpath(path).replace("\\", "/"),
        "resolver": scheme,
    }
    if identity is not None:
        metadata["identity"] = (
            identity.to_dict()
            if isinstance(identity, SourceIdentity)
            else identity
        )
    return ArtifactSource(uri, **metadata)


def _ostree_identity(path):
    """Return the ref/commit identity observed for an OSTree branch."""
    ref_path = os.path.join("refs", "heads", path)
    try:
        with open(ref_path) as ref:  # noqa: PLW1514, RUF100
            ref_contents = ref.read().strip("\n")
    except OSError:
        return {
            "ref": ref_path.replace("\\", "/"),
            "missing": True,
        }

    object_path = os.path.join(
        "objects", ref_contents[:2], f"{ref_contents[2:]}.commit"
    )
    try:
        object_identity = _stat_identity(os.stat(object_path))
    except OSError:
        object_identity = None

    return {
        "ref": ref_path.replace("\\", "/"),
        "commit": ref_contents,
        "object": object_path.replace("\\", "/"),
        "object_identity": object_identity,
    }


def _looks_like_evidence(value):
    if isinstance(value, EvidenceEntry):
        return True
    if not isinstance(value, dict):
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
    return (
        isinstance(value, dict)
        and bool(value)
        and all(
            isinstance(key, str) and isinstance(digest, str)
            for key, digest in value.items()
        )
    )


def _entry_from_resolver_value(  # noqa: C901, PLR0912, PLR0913
    name,
    value,
    resolver=None,
    uri=None,
    source=None,
    before=None,
    after=None,
    status=None,
):
    """Coerce a resolver return value into an :class:`EvidenceEntry`."""
    if isinstance(value, EvidenceEntry):
        entry = value
        if entry.name is None:
            entry.name = name
        if entry.uri is None:
            entry.uri = uri or name
        if entry.resolver is None:
            entry.resolver = resolver
        if not entry.source and source is not None:
            entry.source = ArtifactSource.from_value(source, entry.resolver)
        if entry.before is None and before is not None:
            entry.before = SourceIdentity.from_dict(before)
        if entry.after is None and after is not None:
            entry.after = SourceIdentity.from_dict(after)
        if status is not None:
            entry.status = status
        return entry

    if hasattr(value, "to_dict") and not isinstance(value, type):
        value = value.to_dict()

    if isinstance(value, (tuple, list)):
        values = list(value)
        data = {
            "hashes": values[0] if values else {},
            "source": values[1] if len(values) > 1 else None,
            "before": values[2] if len(values) > 2 else None,
            "after": values[3] if len(values) > 3 else None,
            "status": values[4] if len(values) > 4 else None,
        }
    elif _looks_like_evidence(value):
        data = dict(value)
    elif isinstance(value, dict):
        data = {"hashes": dict(value)}
    elif hasattr(value, "__dict__"):
        data = {
            key: val
            for key, val in vars(value).items()
            if not key.startswith("_")
        }
        if not any(key in data for key in ("hashes", "digest", "hash")):
            for attribute in ("hashes", "digest", "hash"):
                digest = getattr(value, attribute, None)
                if digest is not None:
                    data["hashes"] = digest
                    break
        data.setdefault("hashes", {})
    else:
        data = {"hashes": {}}

    data.setdefault("name", name)
    data.setdefault("uri", uri or name)
    if resolver is not None:
        data.setdefault("resolver", resolver)
    if source is not None:
        data.setdefault("source", source)
    if before is not None:
        data.setdefault("before", before)
    if after is not None:
        data.setdefault("after", after)
    if status is not None:
        data["status"] = status

    return EvidenceEntry.from_dict(data)


def _iter_resolver_hashes(result):
    """Yield ``(name, value)`` pairs from legacy and rich resolver output."""
    if isinstance(result, EvidenceReport):
        for entry in result.entries:
            yield entry.name, entry
        return

    if isinstance(result, dict):
        yield from result.items()
        return

    for value in result:
        if isinstance(value, EvidenceEntry):
            yield value.name, value
        elif isinstance(value, dict):
            yield value.get("name") or value.get("uri"), value


def _uri_for_name(name, uris):
    """Find the input URI that produced an artifact dictionary key."""
    if name is None:
        return uris[0] if len(uris) == 1 else name

    if name in uris:
        return name

    for uri in uris:
        stripped = uri.split(":", 1)[1] if ":" in uri else uri
        if stripped == name or name.endswith(stripped) or stripped.endswith(name):
            return uri

    return uris[0] if len(uris) == 1 else name
