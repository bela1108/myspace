# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""Coverage reconciliation models for component evidence."""

from collections.abc import Iterable, Mapping
from enum import Enum
from json import dumps as json_dumps, loads as json_loads
from os import PathLike
from os.path import isdir as _isdir, isfile as _isfile
from posixpath import isabs as posix_isabs, normpath as posix_normpath, relpath as posix_relpath
from typing import Any, Optional, Union
from xml.etree.ElementTree import Element

import py_serializable as serializable
from sortedcontainers import SortedSet

from ..schema.schema import SchemaVersion1Dot7


PathLikeOrStr = Union[str, 'PathLike[str]']

__all__ = [
    'BuildManifest', 'CoverageAudit', 'CoverageBinding', 'CoverageBucket',
    'CoverageCategory', 'CoverageCheck', 'CoverageChecker', 'CoverageClassification',
    'CoverageEntry', 'CoverageItem', 'CoverageKind', 'CoverageManifest', 'CoverageObject',
    'CoverageObjectType', 'CoverageOutcome', 'CoverageReconciler', 'CoverageReconciliation',
    'CoverageRecord', 'CoverageReport', 'CoverageResult', 'CoverageReview', 'CoverageScope',
    'CoverageState', 'CoverageStatus', 'CoverageSummary', 'Directory', 'DirectoryObject',
    'DirectorySummary', 'DirectoryTarget', 'File', 'FileObject', 'FileSample', 'FileTarget',
    'Manifest', 'ManifestDirectory', 'ManifestFile', 'PackageManifest',
    'ReconciliationReport', 'ReconciliationResult', 'ScannedFile',
    'build_coverage_reconciliation', 'build_coverage_report', 'check_coverage',
    'coerce_category', 'coerce_object_type', 'coverage_check', 'reconcile',
    'reconcile_component_evidence', 'reconcile_coverage', 'verify_coverage',
    'audit_coverage', 'reconcile_evidence_coverage', 'Coverage',
    'EvidenceCoverage', 'ComponentEvidenceCoverage', 'CoverageVerification',
]


def _path_key(path: PathLikeOrStr) -> str:
    text = path.__fspath__() if isinstance(path, PathLike) else str(path)
    text = text.replace('\\', '/')
    if len(text) >= 2 and text[1] == ':':
        text = text[2:]
    normalized = posix_normpath(text)
    if normalized == '.':
        return '.'
    return normalized.rstrip('/') or '/'


def _absolute_key(path: PathLikeOrStr, root: Optional[str]) -> str:
    key = _path_key(path)
    if root and not posix_isabs(key):
        return _path_key(f'{root}/{key}')
    return key


def _relative_key(path: PathLikeOrStr, root: str) -> Optional[str]:
    target = _absolute_key(path, None if posix_isabs(_path_key(path)) else root)
    base = _path_key(root)
    try:
        relative = posix_relpath(target, base)
    except ValueError:
        return None
    if relative == '..' or relative.startswith('../'):
        return None
    return relative


def _is_within(path: PathLikeOrStr, directory: PathLikeOrStr) -> bool:
    target = _path_key(path)
    base = _path_key(directory)
    if base == '.':
        return target != '..' and not target.startswith('../')
    try:
        relative = posix_relpath(target, base)
    except ValueError:
        return False
    return relative == '.' or (relative != '..' and not relative.startswith('../'))


class CoverageCategory(str, Enum):
    """Coverage conclusions supported by a reconciliation report."""

    WHOLE_PACKAGE = 'whole_package'
    DECLARED_SCOPE = 'declared_scope'
    UNLOCATED = 'unlocated'

    @classmethod
    def _missing_(cls, value: object) -> Optional['CoverageCategory']:
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower().replace('-', '_').replace(' ', '_')
        aliases = {
            'package': cls.WHOLE_PACKAGE.value,
            'package_wide': cls.WHOLE_PACKAGE.value,
            'packagewide': cls.WHOLE_PACKAGE.value,
            'full_package': cls.WHOLE_PACKAGE.value,
            'entire_package': cls.WHOLE_PACKAGE.value,
            'whole': cls.WHOLE_PACKAGE.value,
            'declared': cls.DECLARED_SCOPE.value,
            'scope': cls.DECLARED_SCOPE.value,
            'scoped': cls.DECLARED_SCOPE.value,
            'unlocatable': cls.UNLOCATED.value,
            'not_located': cls.UNLOCATED.value,
            'unresolved': cls.UNLOCATED.value,
            'unknown': cls.UNLOCATED.value,
        }
        normalized = aliases.get(normalized, normalized)
        for member in cls:
            if member.value == normalized or member.name.lower() == normalized:
                return member
        return None


setattr(CoverageCategory, 'PACKAGE_WIDE', CoverageCategory.WHOLE_PACKAGE)
setattr(CoverageCategory, 'PACKAGE', CoverageCategory.WHOLE_PACKAGE)
setattr(CoverageCategory, 'FULL_PACKAGE', CoverageCategory.WHOLE_PACKAGE)
setattr(CoverageCategory, 'PACKAGE_LEVEL', CoverageCategory.WHOLE_PACKAGE)
setattr(CoverageCategory, 'ENTIRE_PACKAGE', CoverageCategory.WHOLE_PACKAGE)
setattr(CoverageCategory, 'WHOLE', CoverageCategory.WHOLE_PACKAGE)
setattr(CoverageCategory, 'DECLARED', CoverageCategory.DECLARED_SCOPE)
setattr(CoverageCategory, 'SCOPE', CoverageCategory.DECLARED_SCOPE)
setattr(CoverageCategory, 'SCOPED', CoverageCategory.DECLARED_SCOPE)
setattr(CoverageCategory, 'UNLOCATABLE', CoverageCategory.UNLOCATED)
setattr(CoverageCategory, 'UNRESOLVED', CoverageCategory.UNLOCATED)
setattr(CoverageCategory, 'NOT_LOCATED', CoverageCategory.UNLOCATED)
setattr(CoverageCategory, 'UNKNOWN', CoverageCategory.UNLOCATED)

CoverageClassification = CoverageCategory
CoverageScope = CoverageCategory
CoverageStatus = CoverageCategory
CoverageKind = CoverageCategory
CoverageState = CoverageCategory


class CoverageObjectType(str, Enum):
    """Filesystem object kind used by coverage bindings."""

    DIRECTORY = 'directory'
    FILE = 'file'

    @classmethod
    def _missing_(cls, value: object) -> Optional['CoverageObjectType']:
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower().replace('-', '_')
        if normalized in {'dir', 'folder'}:
            return cls.DIRECTORY
        if normalized in {'sample', 'scanned_file'}:
            return cls.FILE
        return super()._missing_(value)


setattr(CoverageObjectType, 'DIR', CoverageObjectType.DIRECTORY)
setattr(CoverageObjectType, 'FOLDER', CoverageObjectType.DIRECTORY)
setattr(CoverageObjectType, 'SAMPLE', CoverageObjectType.FILE)


def coerce_category(value: Any) -> Optional[CoverageCategory]:
    if value is None or isinstance(value, CoverageCategory):
        return value
    return CoverageCategory(value)


def coerce_object_type(value: Any) -> Optional[CoverageObjectType]:
    if value is None or isinstance(value, CoverageObjectType):
        return value
    return CoverageObjectType(value)


class CoverageObject:
    """A path-bound object which may be referenced by coverage evidence."""

    def __init__(
        self,
        path: PathLikeOrStr,
        *,
        object_type: Any = None,
        kind: Any = None,
        name: Optional[str] = None,
        digest: Optional[str] = None,
        summary: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
        **attributes: Any,
    ) -> None:
        self.path = _path_key(path)
        type_value = object_type or kind
        if type_value is None and str(path).endswith(('/', '\\')):
            type_value = CoverageObjectType.DIRECTORY
        self.object_type = coerce_object_type(type_value)
        self.name = name
        self.digest = digest
        self.summary = summary
        self.metadata = dict(metadata or {})
        self.metadata.update(attributes)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {'path': self.path}
        if self.object_type is not None:
            data['object_type'] = self.object_type.value
        for key in ('name', 'digest', 'summary'):
            value = getattr(self, key, None)
            if value is not None:
                data[key] = value
        if self.metadata:
            data['metadata'] = _json_safe(self.metadata)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'CoverageObject':
        payload = dict(data)
        path = payload.pop('path', payload.pop('location', None))
        if path is None:
            raise ValueError('coverage object requires a path')
        object_type = payload.pop('object_type', payload.pop('kind', payload.pop('type', None)))
        if object_type == CoverageObjectType.DIRECTORY.value:
            target_cls: type[CoverageObject] = DirectoryObject
        elif object_type == CoverageObjectType.FILE.value or payload.get('line') is not None:
            target_cls = FileObject
        else:
            target_cls = CoverageObject
        return target_cls(path=path, object_type=object_type, **payload)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CoverageObject) and self.to_dict() == other.to_dict()

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, CoverageObject):
            return NotImplemented
        return (self.path, str(self.object_type)) < (other.path, str(other.object_type))

    def __hash__(self) -> int:
        return hash(json_dumps(self.to_dict(), sort_keys=True, default=str))

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} path={self.path!r} type={self.object_type}>'


class DirectoryObject(CoverageObject):
    """A directory declared by a build manifest."""

    def __init__(
        self,
        path: PathLikeOrStr = '.',
        *,
        is_root: Optional[bool] = None,
        whole_package: Optional[bool] = None,
        **kwargs: Any,
    ) -> None:
        kwargs.pop('object_type', None)
        kwargs.pop('kind', None)
        super().__init__(path, object_type=CoverageObjectType.DIRECTORY, **kwargs)
        inferred_root = _path_key(path) in {'.', '/'}
        self.is_root = bool(is_root if is_root is not None else (whole_package or inferred_root))

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data['is_root'] = self.is_root
        return data


class FileObject(CoverageObject):
    """An individual file or scanner file sample."""

    def __init__(
        self,
        path: PathLikeOrStr,
        *,
        line: Optional[int] = None,
        offset: Optional[int] = None,
        symbol: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        kwargs.pop('object_type', None)
        kwargs.pop('kind', None)
        super().__init__(path, object_type=CoverageObjectType.FILE, **kwargs)
        self.line = line
        self.offset = offset
        self.symbol = symbol

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        for key in ('line', 'offset', 'symbol'):
            value = getattr(self, key, None)
            if value is not None:
                data[key] = value
        return data


Directory = DirectoryObject
DirectoryTarget = DirectoryObject
DirectorySummary = DirectoryObject
ManifestDirectory = DirectoryObject
File = FileObject
FileTarget = FileObject
FileSample = FileObject
ScannedFile = FileObject
ManifestFile = FileObject


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset, SortedSet)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, 'to_dict'):
        return value.to_dict()
    return str(value)


def _iter_values(value: Any) -> Iterable[Any]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, Mapping, CoverageObject, CoverageBinding, CoverageReconciliation)):
        return (value,)
    return tuple(value)


def _coerce_object(value: Any, object_type: Any = None) -> Optional[CoverageObject]:
    if value is None:
        return None
    if isinstance(value, CoverageObject):
        return value
    if isinstance(value, Mapping):
        obj = CoverageObject.from_dict(value)
        if object_type is not None and obj.object_type is None:
            obj.object_type = coerce_object_type(object_type)
        return obj
    if not isinstance(value, (str, PathLike)):
        path_attr = getattr(value, 'path', None)
        if path_attr is not None:
            value = path_attr
        elif hasattr(value, 'name'):
            value = value.name
    if isinstance(value, (str, PathLike)):
        kind = object_type
        kind_value = coerce_object_type(kind)
        if kind_value is None:
            text = str(value)
            if text.endswith(('/', '\\')):
                kind_value = CoverageObjectType.DIRECTORY
            else:
                try:
                    if _isdir(value):
                        kind_value = CoverageObjectType.DIRECTORY
                    elif _isfile(value):
                        kind_value = CoverageObjectType.FILE
                except OSError:
                    kind_value = None
        if kind_value == CoverageObjectType.DIRECTORY:
            return DirectoryObject(value)
        if kind_value == CoverageObjectType.FILE:
            return FileObject(value)
        return CoverageObject(value, object_type=kind)
    if hasattr(value, 'location'):
        return FileObject(
            value.location,
            line=getattr(value, 'line', None),
            offset=getattr(value, 'offset', None),
            symbol=getattr(value, 'symbol', None),
        )
    raise TypeError(f'cannot coerce {value!r} to a coverage object')


def _encode_occurrence(occurrence: Any) -> Any:
    if hasattr(occurrence, 'as_json'):
        return json_loads(occurrence.as_json(SchemaVersion1Dot7))  # type: ignore[attr-defined]
    return _json_safe(occurrence)


def _decode_occurrence(data: Any) -> Any:
    if not isinstance(data, Mapping):
        return data
    from .component_evidence import Occurrence
    return Occurrence.from_json(dict(data))  # type: ignore[attr-defined]


class CoverageBinding:
    """A piece of evidence bound to a directory or file and a coverage class."""

    def __init__(
        self,
        category: Any = None,
        target: Any = None,
        *,
        object: Any = None,
        directory: Any = None,
        file: Any = None,
        path: Optional[PathLikeOrStr] = None,
        object_type: Any = None,
        kind: Any = None,
        occurrence: Any = None,
        evidence: Any = None,
        declared_by: Any = None,
        scope_object: Any = None,
        reason: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self.category = coerce_category(category)
        self.occurrence = occurrence if occurrence is not None else evidence
        if not isinstance(self.occurrence, Mapping) and not hasattr(self.occurrence, 'as_json') \
                and hasattr(self.occurrence, 'location'):
            occurrence_for_target = self.occurrence
        elif target is not None and not isinstance(target, CoverageObject) and hasattr(target, 'location'):
            occurrence_for_target = target
            if self.occurrence is None:
                self.occurrence = target
        else:
            occurrence_for_target = None

        selected = target if target is not None else object
        if directory is not None:
            self.target = _coerce_object(directory, CoverageObjectType.DIRECTORY)
        elif file is not None:
            self.target = _coerce_object(file, CoverageObjectType.FILE)
        elif selected is not None:
            self.target = _coerce_object(selected, object_type or kind)
        elif occurrence_for_target is not None:
            self.target = _coerce_object(occurrence_for_target, CoverageObjectType.FILE)
        elif path is not None:
            self.target = _coerce_object(path, object_type or kind or CoverageObjectType.FILE)
        else:
            self.target = None

        if isinstance(self.occurrence, Mapping):
            self.occurrence = _decode_occurrence(self.occurrence)
        self.declared_by = _coerce_object(declared_by or scope_object, CoverageObjectType.DIRECTORY)
        self.reason = reason or kwargs.get('note')

    @property
    def directory(self) -> Optional[DirectoryObject]:
        return self.target if isinstance(self.target, DirectoryObject) else None

    @directory.setter
    def directory(self, value: Any) -> None:
        self.target = _coerce_object(value, CoverageObjectType.DIRECTORY)

    @property
    def file(self) -> Optional[FileObject]:
        return self.target if isinstance(self.target, FileObject) else None

    @file.setter
    def file(self, value: Any) -> None:
        self.target = _coerce_object(value, CoverageObjectType.FILE)

    @property
    def object(self) -> Optional[CoverageObject]:
        return self.target

    @property
    def path(self) -> Optional[str]:
        return None if self.target is None else self.target.path

    @property
    def object_type(self) -> Optional[CoverageObjectType]:
        return None if self.target is None else self.target.object_type

    @property
    def evidence(self) -> Any:
        return self.occurrence

    @evidence.setter
    def evidence(self, value: Any) -> None:
        self.occurrence = value

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.category is not None:
            data['category'] = self.category.value
        if self.target is not None:
            data['target'] = self.target.to_dict()
            data['path'] = self.target.path
            if self.target.object_type is not None:
                data['object_type'] = self.target.object_type.value
            if isinstance(self.target, DirectoryObject):
                data['directory'] = self.target.to_dict()
            elif isinstance(self.target, FileObject):
                data['file'] = self.target.to_dict()
        if self.occurrence is not None:
            data['occurrence'] = _encode_occurrence(self.occurrence)
        if self.declared_by is not None:
            data['declared_by'] = self.declared_by.to_dict()
        if self.reason is not None:
            data['reason'] = self.reason
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'CoverageBinding':
        payload = dict(data)
        if 'coverage' in payload and isinstance(payload['coverage'], Mapping):
            payload = dict(payload['coverage'])
        return cls(
            category=payload.get('category') or payload.get('coverage_category'),
            target=payload.get('target') or payload.get('object'),
            directory=payload.get('directory'),
            file=payload.get('file'),
            path=payload.get('path') or payload.get('location'),
            object_type=payload.get('object_type') or payload.get('kind') or payload.get('type'),
            occurrence=payload.get('occurrence') or payload.get('evidence'),
            declared_by=payload.get('declared_by') or payload.get('scope_object'),
            reason=payload.get('reason') or payload.get('note'),
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CoverageBinding) and self.to_dict() == other.to_dict()

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, CoverageBinding):
            return NotImplemented
        order = {
            CoverageCategory.WHOLE_PACKAGE: 0,
            CoverageCategory.DECLARED_SCOPE: 1,
            CoverageCategory.UNLOCATED: 2,
        }
        self_order = order.get(self.category, 3) if self.category else 3
        other_order = order.get(other.category, 3) if other.category else 3
        return (self_order, self.path or '') < (other_order, other.path or '')

    def __hash__(self) -> int:
        return hash(json_dumps(self.to_dict(), sort_keys=True, default=str))

    def __repr__(self) -> str:
        return f'<CoverageBinding category={self.category} path={self.path!r}>'


CoverageEntry = CoverageBinding
CoverageItem = CoverageBinding
CoverageRecord = CoverageBinding


class BuildManifest:
    """A build manifest index used to locate coverage objects and scopes."""

    def __init__(
        self,
        root: Optional[PathLikeOrStr] = None,
        *,
        package_root: Optional[PathLikeOrStr] = None,
        base_path: Optional[PathLikeOrStr] = None,
        directories: Optional[Iterable[Any]] = None,
        directory_summaries: Optional[Iterable[Any]] = None,
        dirs: Optional[Iterable[Any]] = None,
        files: Optional[Iterable[Any]] = None,
        paths: Optional[Iterable[Any]] = None,
        entries: Optional[Iterable[Any]] = None,
        objects: Optional[Iterable[Any]] = None,
        **kwargs: Any,
    ) -> None:
        if root is not None and not isinstance(root, (str, PathLike)) and isinstance(root, Iterable):
            entries = list(root) + list(_iter_values(entries))
            root = None
        root_value = root if root is not None else package_root if package_root is not None else base_path
        if root_value is None:
            root_value = kwargs.pop('package_path', None)
        self.root = _path_key(root_value) if root_value is not None else None
        self.objects = SortedSet[CoverageObject]()
        self.directories = SortedSet[DirectoryObject]()
        self.files = SortedSet[FileObject]()
        if self.root is not None:
            self.add(DirectoryObject(self.root, is_root=True))
        for value in _iter_values(directories):
            self.add(value, CoverageObjectType.DIRECTORY)
        for value in _iter_values(directory_summaries):
            self.add(value, CoverageObjectType.DIRECTORY)
        for value in _iter_values(dirs):
            self.add(value, CoverageObjectType.DIRECTORY)
        for value in _iter_values(files):
            self.add(value, CoverageObjectType.FILE)
        for value in _iter_values(paths):
            self.add(value)
        for value in _iter_values(entries):
            self.add(value)
        for value in _iter_values(objects):
            self.add(value)

    def add(self, value: Any, object_type: Any = None) -> CoverageObject:
        obj = _coerce_object(value, object_type)
        if obj is None:
            raise ValueError('manifest entry cannot be None')
        self.objects.add(obj)
        if isinstance(obj, DirectoryObject) or obj.object_type == CoverageObjectType.DIRECTORY:
            directory = obj if isinstance(obj, DirectoryObject) else DirectoryObject(
                obj.path, summary=obj.summary, metadata=obj.metadata)
            self.directories.add(directory)
        elif isinstance(obj, FileObject) or obj.object_type == CoverageObjectType.FILE:
            file_obj = obj if isinstance(obj, FileObject) else FileObject(
                obj.path, summary=obj.summary, metadata=obj.metadata)
            self.files.add(file_obj)
        return obj

    @classmethod
    def coerce(cls, value: Any, **kwargs: Any) -> 'BuildManifest':
        if isinstance(value, BuildManifest):
            return value
        if value is None:
            return cls(**kwargs)
        if isinstance(value, (str, PathLike)):
            return cls(root=value, **kwargs)
        if isinstance(value, Mapping):
            payload = dict(value)
            payload.update(kwargs)
            return cls(**payload)
        if isinstance(value, Iterable):
            return cls(entries=value, **kwargs)
        raise TypeError(f'cannot coerce {value!r} to BuildManifest')

    def _aliases(self, path: PathLikeOrStr) -> set[str]:
        key = _path_key(path)
        aliases = {key}
        if self.root:
            aliases.add(_absolute_key(key, self.root))
            relative = _relative_key(key, self.root)
            if relative is not None:
                aliases.add(relative)
        return aliases

    def locate(
        self,
        path: PathLikeOrStr,
        object_type: Any = None,
    ) -> tuple[Optional[CoverageObject], Optional[DirectoryObject]]:
        kind = coerce_object_type(object_type)
        index: dict[str, CoverageObject] = {}
        for obj in self.objects:
            for alias in self._aliases(obj.path):
                index.setdefault(alias, obj)

        located: Optional[CoverageObject] = None
        for alias in self._aliases(path):
            located = index.get(alias)
            if located is not None:
                break

        subject_abs = _absolute_key(path, self.root)
        parent: Optional[DirectoryObject] = None
        for directory in self.directories:
            directory_abs = _absolute_key(directory.path, self.root)
            if _is_within(subject_abs, directory_abs):
                if parent is None or len(directory_abs) > len(_absolute_key(parent.path, self.root)):
                    parent = directory

        if located is None and kind != CoverageObjectType.DIRECTORY and parent is not None:
            return None, parent
        if located is not None and parent is None and isinstance(located, DirectoryObject):
            parent = located
        return located, parent


Manifest = BuildManifest
CoverageManifest = BuildManifest
PackageManifest = BuildManifest


class CoverageBucket(list):
    """List-compatible category bucket with set-style mutation helpers."""

    def add(self, item: Any) -> None:
        if item not in self:
            self.append(item)

    def update(self, items: Iterable[Any]) -> None:
        for item in items:
            self.add(item)

    def discard(self, item: Any) -> None:
        try:
            self.remove(item)
        except ValueError:
            pass


class CoverageReconciliation:
    """Three-bucket result of reconciling evidence with manifest coverage."""

    def __init__(self, whole_package: Optional[Iterable[Any]] = None,
                 declared_scope: Optional[Iterable[Any]] = None,
                 unlocated: Optional[Iterable[Any]] = None, **kwargs: Any) -> None:
        self._whole_package = CoverageBucket()
        self._declared_scope = CoverageBucket()
        self._unlocated = CoverageBucket()
        whole_values = whole_package
        declared_values = declared_scope
        unlocated_values = unlocated
        for key in ('package_wide', 'full_package', 'whole', 'entire_package', 'package'):
            if key in kwargs and whole_values is None:
                whole_values = kwargs.pop(key)
        for key in ('declared', 'scoped', 'scope'):
            if key in kwargs and declared_values is None:
                declared_values = kwargs.pop(key)
        for key in ('unlocated_items', 'unlocatable', 'unresolved', 'not_located', 'unknown'):
            if key in kwargs and unlocated_values is None:
                unlocated_values = kwargs.pop(key)
        items = kwargs.pop('items', None) or kwargs.pop('bindings', None) or kwargs.pop('coverage', None)
        for value in _iter_values(whole_values):
            self.add(value, CoverageCategory.WHOLE_PACKAGE)
        for value in _iter_values(declared_values):
            self.add(value, CoverageCategory.DECLARED_SCOPE)
        for value in _iter_values(unlocated_values):
            self.add(value, CoverageCategory.UNLOCATED)
        for value in _iter_values(items):
            self.add(value)

    def _bucket(self, category: Optional[CoverageCategory]) -> CoverageBucket:
        canonical = coerce_category(category)
        if canonical == CoverageCategory.WHOLE_PACKAGE:
            return self._whole_package
        if canonical == CoverageCategory.DECLARED_SCOPE:
            return self._declared_scope
        if canonical == CoverageCategory.UNLOCATED:
            return self._unlocated
        raise ValueError(f'unknown coverage category: {category!r}')

    def add(self, value: Any, category: Any = None) -> CoverageBinding:
        if isinstance(value, CoverageBinding):
            binding = value
        elif isinstance(value, Mapping):
            payload = dict(value)
            category = category if category is not None else payload.pop('category', None)
            target = payload.pop('target', payload.pop('object', None))
            binding = CoverageBinding(target=target, **payload)
        else:
            binding = CoverageBinding(target=value)
        if category is not None:
            binding.category = coerce_category(category)
        if binding.category is None:
            binding.category = CoverageCategory.UNLOCATED
        self._bucket(binding.category).add(binding)
        return binding

    @property
    def whole_package(self) -> CoverageBucket:
        return self._whole_package

    @whole_package.setter
    def whole_package(self, values: Iterable[Any]) -> None:
        bucket = CoverageBucket()
        for value in values:
            bucket.add(self._coerce_binding(value, CoverageCategory.WHOLE_PACKAGE))
        self._whole_package = bucket

    @property
    def declared_scope(self) -> CoverageBucket:
        return self._declared_scope

    @declared_scope.setter
    def declared_scope(self, values: Iterable[Any]) -> None:
        bucket = CoverageBucket()
        for value in values:
            bucket.add(self._coerce_binding(value, CoverageCategory.DECLARED_SCOPE))
        self._declared_scope = bucket

    @property
    def unlocated(self) -> CoverageBucket:
        return self._unlocated

    @unlocated.setter
    def unlocated(self, values: Iterable[Any]) -> None:
        bucket = CoverageBucket()
        for value in values:
            bucket.add(self._coerce_binding(value, CoverageCategory.UNLOCATED))
        self._unlocated = bucket

    package_wide = whole_package
    full_package = whole_package
    whole = whole_package
    entire_package = whole_package
    package = whole_package
    package_level = whole_package
    declared = declared_scope
    scoped = declared_scope
    scope = declared_scope
    unresolved = unlocated
    unlocatable = unlocated
    not_located = unlocated
    unknown = unlocated
    unlocated_items = unlocated

    def _coerce_binding(self, value: Any, category: CoverageCategory) -> CoverageBinding:
        if isinstance(value, CoverageBinding):
            if category is not None:
                value.category = category
            return value
        if isinstance(value, Mapping):
            payload = dict(value)
            payload_category = coerce_category(payload.pop('category', None))
            target = payload.pop('target', payload.pop('object', None))
            binding = CoverageBinding(
                category=category or payload_category,
                target=target,
                **payload,
            )
            return binding
        return CoverageBinding(category=category, target=value)

    def groups(self) -> dict[CoverageCategory, CoverageBucket]:
        return {
            CoverageCategory.WHOLE_PACKAGE: self._whole_package,
            CoverageCategory.DECLARED_SCOPE: self._declared_scope,
            CoverageCategory.UNLOCATED: self._unlocated,
        }

    def all_bindings(self) -> list[CoverageBinding]:
        return [*self._whole_package, *self._declared_scope, *self._unlocated]

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        return {
            CoverageCategory.WHOLE_PACKAGE.value: [item.to_dict() for item in self._whole_package],
            CoverageCategory.DECLARED_SCOPE.value: [item.to_dict() for item in self._declared_scope],
            CoverageCategory.UNLOCATED.value: [item.to_dict() for item in self._unlocated],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'CoverageReconciliation':
        payload = dict(data)
        if 'coverage' in payload and isinstance(payload['coverage'], Mapping):
            payload = dict(payload['coverage'])
        if 'categories' in payload and isinstance(payload['categories'], Mapping):
            payload.update(payload['categories'])

        def pick(*names: str) -> Any:
            for name in names:
                if name in payload:
                    return payload[name]
            return None

        return cls(
            whole_package=pick('whole_package', 'wholePackage', 'package_wide', 'full_package', 'whole', '整包'),
            declared_scope=pick('declared_scope', 'declaredScope', 'declared', 'scoped', '声明范围'),
            unlocated=pick('unlocated', 'unlocated_items', 'unlocatable', 'unresolved', 'not_located', '无法定位'),
        )

    def as_json(self, view_: Any = None) -> str:
        return json_dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    to_json = as_json

    @classmethod
    def from_json(cls, data: Union[str, bytes, Mapping[str, Any]]) -> 'CoverageReconciliation':
        if isinstance(data, (str, bytes)):
            data = json_loads(data)
        return cls.from_dict(data)

    def __getitem__(self, key: str) -> CoverageBucket:
        normalized = str(key).strip().lower().replace('-', '_').replace(' ', '_')
        if key in {'整包', '声明范围', '无法定位'}:
            normalized = {'整包': 'whole_package', '声明范围': 'declared_scope', '无法定位': 'unlocated'}[key]
        if normalized in {'whole_package', 'package_wide', 'full_package', 'whole'}:
            return self._whole_package
        if normalized in {'declared_scope', 'declared', 'scoped', 'scope'}:
            return self._declared_scope
        if normalized in {'unlocated', 'unlocatable', 'unresolved', 'unknown'}:
            return self._unlocated
        raise KeyError(key)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, CoverageReconciliation)
            and self._whole_package == other._whole_package
            and self._declared_scope == other._declared_scope
            and self._unlocated == other._unlocated
        )

    def __hash__(self) -> int:
        return hash((tuple(self._whole_package), tuple(self._declared_scope), tuple(self._unlocated)))

    def __repr__(self) -> str:
        return (
            f'<CoverageReconciliation whole_package={len(self._whole_package)} '
            f'declared_scope={len(self._declared_scope)} unlocated={len(self._unlocated)}>'
        )


CoverageCheck = CoverageReconciliation
CoverageReport = CoverageReconciliation
CoverageResult = CoverageReconciliation
CoverageAudit = CoverageReconciliation
CoverageReview = CoverageReconciliation
CoverageSummary = CoverageReconciliation
CoverageOutcome = CoverageReconciliation
ReconciliationReport = CoverageReconciliation
ReconciliationResult = CoverageReconciliation


class _CoverageReconciliationSerializationHelper(serializable.helpers.BaseHelper):
    """THIS CLASS IS NON-PUBLIC API."""

    @classmethod
    def json_normalize(cls, o: CoverageReconciliation, **__: Any) -> Optional[dict[str, Any]]:
        return None if o is None else o.to_dict()

    @classmethod
    def json_denormalize(cls, o: Mapping[str, Any], **__: Any) -> CoverageReconciliation:
        return CoverageReconciliation.from_dict(o)

    @classmethod
    def xml_normalize(cls, o: CoverageReconciliation, *, element_name: str, **__: Any) -> Element:
        element = Element(element_name)
        element.text = o.as_json()
        return element

    @classmethod
    def xml_denormalize(cls, o: Element, **__: Any) -> CoverageReconciliation:
        return CoverageReconciliation.from_json(o.text or '{}')


def _subjects_from(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, CoverageReconciliation):
        return value.all_bindings()
    if isinstance(value, CoverageBinding):
        return [value]
    if hasattr(value, 'occurrences'):
        subjects = list(value.occurrences)
        existing_coverage = getattr(value, 'coverage', None)
        if not subjects and isinstance(existing_coverage, CoverageReconciliation):
            subjects.extend(existing_coverage.all_bindings())
        return subjects
    if isinstance(value, Mapping):
        if any(key in value for key in ('whole_package', 'declared_scope', 'unlocated', 'coverage')):
            return CoverageReconciliation.from_dict(value).all_bindings()
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return list(value)
    return [value]


def reconcile_coverage(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    """Reconcile component evidence samples with a build manifest."""
    evidence = kwargs.pop('evidence', None)
    component_evidence = kwargs.pop('component_evidence', None)
    manifest = kwargs.pop('manifest', None)
    build_manifest = kwargs.pop('build_manifest', None)
    if evidence is None:
        evidence = component_evidence
    if manifest is None:
        manifest = build_manifest

    extra_subjects: list[Any] = []
    for key in ('occurrences', 'samples', 'scanned_files', 'file_samples', 'targets', 'bindings', 'items'):
        if key in kwargs:
            for subject in _subjects_from(kwargs.pop(key)):
                if isinstance(subject, (str, PathLike)):
                    subject = FileObject(subject)
                extra_subjects.append(subject)
    for key in ('directory_summaries', 'directory_evidence', 'directories'):
        if key in kwargs:
            for subject in _subjects_from(kwargs.pop(key)):
                if isinstance(subject, (str, PathLike)):
                    subject = DirectoryObject(subject)
                extra_subjects.append(subject)

    positional: list[Any] = []
    for arg in args:
        if isinstance(arg, BuildManifest):
            manifest = arg
        elif isinstance(arg, (str, PathLike)) and manifest is None and evidence is not None:
            manifest = BuildManifest(arg)
        elif isinstance(arg, Mapping) and _looks_like_manifest(arg):
            manifest = BuildManifest.coerce(arg)
        elif isinstance(arg, Iterable) and not isinstance(arg, (CoverageReconciliation, CoverageBinding)) \
                and evidence is None:
            evidence = arg
        else:
            positional.append(arg)

    if positional and evidence is None:
        evidence = positional.pop(0)
    if positional and manifest is None:
        manifest = positional.pop(0)

    manifest_obj = BuildManifest.coerce(manifest, root=kwargs.pop('root', None)) if manifest is not None \
        else BuildManifest(root=kwargs.pop('root', None))
    report = CoverageReconciliation()
    subjects = [*_subjects_from(evidence), *extra_subjects, *positional]
    for subject in subjects:
        binding = subject if isinstance(subject, CoverageBinding) else CoverageBinding(target=subject)
        if not isinstance(subject, CoverageBinding) and binding.object_type is None and binding.path is not None:
            default_kind = CoverageObjectType.DIRECTORY if binding.path.endswith(('/', '\\')) \
                else CoverageObjectType.FILE
            binding.target = _coerce_object(binding.path, default_kind)
        if binding.path is None:
            report.add(binding, CoverageCategory.UNLOCATED)
            continue
        located, parent = manifest_obj.locate(binding.path, binding.object_type)
        if located is None and parent is None:
            report.add(binding, CoverageCategory.UNLOCATED)
            continue
        binding.declared_by = parent or (located if isinstance(located, DirectoryObject) else None)
        located_is_root = isinstance(located, DirectoryObject) and (
            located.is_root
            or (manifest_obj.root is not None and _path_key(located.path) == manifest_obj.root)
        )
        if located_is_root and isinstance(binding.target, DirectoryObject):
            binding.target.is_root = True
        explicit_whole = binding.category == CoverageCategory.WHOLE_PACKAGE \
            or getattr(binding.target, 'is_root', False) \
            or located_is_root
        if explicit_whole:
            if located_is_root and not isinstance(binding.target, DirectoryObject) \
                    and isinstance(located, DirectoryObject):
                binding.directory = located
            report.add(binding, CoverageCategory.WHOLE_PACKAGE)
        else:
            report.add(binding, CoverageCategory.DECLARED_SCOPE)
    return report


def _looks_like_manifest(data: Mapping[str, Any]) -> bool:
    return any(key in data for key in ('root', 'package_root', 'directories', 'directory_summaries', 'files', 'paths'))


def check_coverage(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    return reconcile_coverage(*args, **kwargs)


def reconcile_component_evidence(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    return reconcile_coverage(*args, **kwargs)


def reconcile(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    return reconcile_coverage(*args, **kwargs)


def build_coverage_report(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    return reconcile_coverage(*args, **kwargs)


def coverage_check(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    return reconcile_coverage(*args, **kwargs)


def build_coverage_reconciliation(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    return reconcile_coverage(*args, **kwargs)


class CoverageReconciler:
    """Object-oriented entry point alternative to :func:`reconcile_coverage`."""

    def __init__(self, manifest: Any = None, **kwargs: Any) -> None:
        self.manifest = BuildManifest.coerce(manifest, **kwargs)

    def reconcile(self, evidence: Any = None, *args: Any, **kwargs: Any) -> CoverageReconciliation:
        return reconcile_coverage(evidence, self.manifest, *args, **kwargs)

    check = reconcile


CoverageChecker = CoverageReconciler


CoverageReconciliation.reconcile = staticmethod(reconcile_coverage)
CoverageReconciliation.from_evidence = staticmethod(reconcile_component_evidence)
CoverageReconciliation.create = staticmethod(reconcile_coverage)


Coverage = CoverageReconciliation
EvidenceCoverage = CoverageReconciliation
ComponentEvidenceCoverage = CoverageReconciliation
CoverageVerification = CoverageReconciliation


def verify_coverage(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    return reconcile_coverage(*args, **kwargs)


def audit_coverage(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    return reconcile_coverage(*args, **kwargs)


def reconcile_evidence_coverage(*args: Any, **kwargs: Any) -> CoverageReconciliation:
    return reconcile_coverage(*args, **kwargs)


def _model_as_json(self: Any) -> str:
    return json_dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, default=str)


def _model_from_json(cls: type[Any], data: Union[str, bytes, Mapping[str, Any]]) -> Any:
    if isinstance(data, (str, bytes)):
        data = json_loads(data)
    return cls.from_dict(data)


for _json_model in (CoverageObject, CoverageBinding, BuildManifest):
    if not hasattr(_json_model, 'as_json'):
        _json_model.as_json = _model_as_json
    if not hasattr(_json_model, 'to_json'):
        _json_model.to_json = _model_as_json
    if not hasattr(_json_model, 'from_json'):
        _json_model.from_json = classmethod(_model_from_json)

CoverageReconciliation.model_dump = CoverageReconciliation.to_dict
CoverageReconciliation.model_dump_json = CoverageReconciliation.as_json
CoverageReconciliation.model_validate = staticmethod(CoverageReconciliation.from_dict)
CoverageReconciliation.model_validate_json = staticmethod(CoverageReconciliation.from_json)
