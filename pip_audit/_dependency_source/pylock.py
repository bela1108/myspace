"""
Collect dependencies from `pylock.toml` files.
"""

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import tomli
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

from pip_audit._dependency_source import DependencyFixError, DependencySource, DependencySourceError
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency, ResolvedDependency
from pip_audit._service.interface import SkippedDependency
from pip_audit._target import (
    EvidenceStatus,
    LockedDependency,
    TargetEnvironment,
    TargetEnvironmentError,
    evaluate_marker,
)

logger = logging.getLogger(__name__)


class PyLockSource(DependencySource):
    """
    Wraps `pylock.*.toml` dependency collection as a dependency source.
    """

    def __init__(self, filenames: list[Path]) -> None:
        """
        Create a new `PyLockSource`.

        `filenames` provides a list of `pylock.*.toml` files to parse.
        """

        self._filenames = filenames
        self._documents: dict[Path, dict[str, Any]] = {}

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `PyLockSource`.

        Raises a `PyLockSourceError` on any errors.
        """
        for filename in self._filenames:
            yield from self._collect_from_file(filename)

    def _collect_from_file(self, filename: Path) -> Iterator[Dependency]:
        """
        Collect dependencies from a single `pylock.*.toml` file.

        Raises a `PyLockSourceError` on any errors.
        """
        pylock = self._load(filename)

        lock_version = pylock.get("lock-version")
        if not lock_version:
            raise PyLockSourceError(f"{filename}: missing lock-version in lockfile")

        lock_version = Version(lock_version)
        if lock_version.major != 1:
            raise PyLockSourceError(f"{filename}: lockfile version {lock_version} is not supported")

        packages = pylock.get("packages")
        if not packages:
            raise PyLockSourceError(f"{filename}: missing packages in lockfile")
        if not isinstance(packages, list):
            raise PyLockSourceError(f"{filename}: packages is not a list")

        try:
            yield from self._collect_from_packages(packages)
        except PyLockSourceError as e:
            raise PyLockSourceError(f"{filename}: {e}") from e

    def collect_for(self, environment: TargetEnvironment) -> Iterator[LockedDependency]:
        """
        Collect lock entries interpreted for a single target environment.

        Unlike `collect`, this does not flatten the lockfile: packages whose
        markers exclude the target are reported as excluded, and packages with
        no installable artifact are reported as missing evidence instead of
        being silently audited.
        """
        for filename in self._filenames:
            yield from self._collect_for_file(filename, environment)

    def evaluate(self, environment: TargetEnvironment) -> Iterator[LockedDependency]:
        """Alias for `collect_for`."""
        yield from self.collect_for(environment)

    def _collect_for_file(
        self, filename: Path, environment: TargetEnvironment
    ) -> Iterator[LockedDependency]:
        pylock = self._load(filename)

        lock_version = pylock.get("lock-version")
        if not lock_version:
            raise PyLockSourceError(f"{filename}: missing lock-version in lockfile")

        lock_version = Version(lock_version)
        if lock_version.major != 1:
            raise PyLockSourceError(f"{filename}: lockfile version {lock_version} is not supported")

        packages = pylock.get("packages")
        if not packages:
            raise PyLockSourceError(f"{filename}: missing packages in lockfile")
        if not isinstance(packages, list):
            raise PyLockSourceError(f"{filename}: packages is not a list")

        for idx, package in enumerate(packages):
            if not isinstance(package, dict):
                raise PyLockSourceError(f"{filename}: invalid package #{idx}: not a table")
            name = package.get("name")
            if not name:
                raise PyLockSourceError(f"{filename}: invalid package #{idx}: no name")

            yield self._evaluate_package(name, package, environment)

    def _load(self, filename: Path) -> dict[str, Any]:
        if filename not in self._documents:
            try:
                with filename.open(mode="rb") as f:
                    document = tomli.load(f)
            except tomli.TOMLDecodeError as e:
                raise PyLockSourceError(f"{filename}: invalid TOML in lockfile") from e
            self._documents[filename] = document
        return self._documents[filename]

    def _evaluate_package(
        self, name: str, package: dict[str, Any], environment: TargetEnvironment
    ) -> LockedDependency:
        version_string = package.get("version")

        marker = package.get("marker")
        if marker is not None:
            if not isinstance(marker, str):
                return self._locked(
                    name,
                    version_string,
                    EvidenceStatus.INVALID_MARKER,
                    reason="package marker is not a string",
                )

            evaluation = evaluate_marker(marker, environment)
            if evaluation.missing:
                return self._locked(
                    name,
                    version_string,
                    EvidenceStatus.MISSING_MARKER_VARIABLE,
                    reason=f"marker {marker!r} needs {', '.join(evaluation.missing)}",
                    missing=evaluation.missing,
                )
            if evaluation.reason is not None:
                return self._locked(
                    name,
                    version_string,
                    EvidenceStatus.INVALID_MARKER,
                    reason=evaluation.reason,
                )
            if not evaluation.applies:
                return self._locked(
                    name,
                    version_string,
                    EvidenceStatus.EXCLUDED,
                    reason=f"marker {marker!r} does not apply",
                )

        requires_python = package.get("requires-python")
        if requires_python:
            try:
                python_specifier = SpecifierSet(str(requires_python))
            except InvalidSpecifier:
                return self._locked(
                    name,
                    version_string,
                    EvidenceStatus.INVALID_REQUIRES_PYTHON,
                    reason=f"invalid requires-python {requires_python!r}",
                )

            python_version = environment.markers.get(
                "python_full_version", environment.markers.get("python_version")
            )
            if python_version is None:
                return self._locked(
                    name,
                    version_string,
                    EvidenceStatus.MISSING_MARKER_VARIABLE,
                    reason=f"requires-python {requires_python!r} needs python_version",
                    missing=("python_version",),
                )
            if not python_specifier.contains(python_version, prereleases=True):
                return self._locked(
                    name,
                    version_string,
                    EvidenceStatus.EXCLUDED,
                    reason=f"requires-python {requires_python!r} excludes {python_version}",
                )

        if not version_string:
            return LockedDependency(
                name=name,
                version=None,
                status=EvidenceStatus.MISSING_VERSION,
                reason="no version specified",
            )

        version = Version(str(version_string))

        sdist = package.get("sdist")
        if sdist:
            artifact = self._artifact_name(sdist)
            if artifact is None:
                return LockedDependency(
                    name=name,
                    version=str(version),
                    status=EvidenceStatus.INVALID_ARTIFACT,
                    reason="sdist entry has no name or url",
                )
            return LockedDependency(
                name=name,
                version=str(version),
                status=EvidenceStatus.CHECKED,
                artifact=artifact,
                reason="source distribution covers this target",
            )

        wheels = package.get("wheels") or []
        if not isinstance(wheels, list):
            return LockedDependency(
                name=name,
                version=str(version),
                status=EvidenceStatus.INVALID_ARTIFACT,
                reason="wheels is not a list",
            )

        invalid_reasons: list[str] = []
        locked_filenames: list[str] = []
        valid_filenames: list[str] = []
        for wheel in wheels:
            filename = self._artifact_name(wheel)
            if filename is None:
                invalid_reasons.append("wheel entry has no name or url")
                continue

            locked_filenames.append(filename)
            try:
                supported, error = environment.supports_wheel(filename)
            except TargetEnvironmentError as exc:
                return LockedDependency(
                    name=name,
                    version=str(version),
                    status=EvidenceStatus.MISSING_MARKER_VARIABLE,
                    reason=str(exc),
                    missing=(
                        ("python_version",) if "python_version" in str(exc) else ("platform_tags",)
                    ),
                )
            if error is not None:
                invalid_reasons.append(f"{filename}: {error}")
            else:
                valid_filenames.append(filename)
            if error is None and supported:
                return LockedDependency(
                    name=name,
                    version=str(version),
                    status=EvidenceStatus.CHECKED,
                    artifact=filename,
                    reason="compatible wheel covers this target",
                )

        if invalid_reasons and not valid_filenames:
            return LockedDependency(
                name=name,
                version=str(version),
                status=EvidenceStatus.INVALID_ARTIFACT,
                reason="; ".join(invalid_reasons),
            )

        if locked_filenames:
            reason = (
                f"no wheel matches {environment.name}; locked wheels: {', '.join(locked_filenames)}"
            )
        else:
            reason = "lock entry has no wheel or sdist"

        return LockedDependency(
            name=name,
            version=str(version),
            status=EvidenceStatus.MISSING_ARTIFACT,
            reason=reason,
        )

    @staticmethod
    def _artifact_name(artifact: Any) -> str | None:
        if isinstance(artifact, str):
            return artifact
        if not isinstance(artifact, dict):
            return None

        name = artifact.get("name") or artifact.get("filename")
        if isinstance(name, str) and name:
            return name

        url = artifact.get("url")
        if isinstance(url, str) and url:
            return Path(urlparse(url).path).name or None
        return None

    @staticmethod
    def _locked(
        name: str,
        version: Any,
        status: EvidenceStatus,
        *,
        reason: str | None = None,
        missing: tuple[str, ...] = (),
    ) -> LockedDependency:
        return LockedDependency(
            name=name,
            version=str(version) if version is not None else None,
            status=status,
            reason=reason,
            missing=missing,
        )

    def _collect_from_packages(self, packages: list[dict]) -> Iterator[Dependency]:
        """
        Collect dependencies from a list of packages.

        Raises a `PyLockSourceError` on any errors.
        """
        for idx, package in enumerate(packages):
            if not isinstance(package, dict):
                raise PyLockSourceError(f"invalid package #{idx}: not a table")
            name = package.get("name")
            if not name:
                raise PyLockSourceError(f"invalid package #{idx}: no name")

            version = package.get("version")
            if version:
                yield ResolvedDependency(name, Version(version))
            else:
                # Versions are optional in PEP 751, e.g. for source tree specifiers.
                # We mark these as skipped.
                yield SkippedDependency(name, "no version specified")

    def fix(self, fix_version: ResolvedFixVersion) -> None:  # pragma: no cover
        """
        Raises `NotImplementedError` if called.

        We don't support fixing dependencies in lockfiles, since
        lockfiles should be managed/updated by their packaging tool.
        """

        raise NotImplementedError(
            "lockfiles cannot be fixed directly; use your packaging tool to perform upgrades"
        )


class PyLockSourceError(DependencySourceError):
    """A pylock-parsing specific `DependencySourceError`."""

    pass


class PyLockFixError(DependencyFixError):
    """A pylock-fizing specific `DependencyFixError`."""

    pass
