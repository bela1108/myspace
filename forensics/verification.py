"""Offline verification of one party's saved TUF metadata bundle.

The verifier deliberately uses only the low level ``tuf.api`` layer: it loads
files from disk and checks signatures itself, so no network access or
downloader is involved. Each role is verified exactly the way the party's own
trusted root authorizes it:

* root, timestamp, snapshot and the top level targets are verified with
  ``Root.verify_delegate`` against the keys and thresholds stored in root,
* delegated targets roles are verified transitively with
  ``Targets.verify_delegate`` while walking the delegation graph,
* a delegated role file only counts as trustworthy when the delegator that
  names it is itself trustworthy.

Expiry is reported as a warning rather than a hard failure: in a post-incident
forensic setting the metadata may legitimately have expired since capture,
while the signatures still establish who published it.
"""

from __future__ import annotations

import hashlib
from collections import deque
from collections.abc import Iterator
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path

from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.serialization import DeserializationError
from tuf.api.metadata import Metadata, Root, Targets

from forensics.models import (
    Evidence,
    PartyInput,
    PartyResult,
    Statement,
)

TOP_LEVEL_ROLES = ("root", "timestamp", "snapshot", "targets")


class BundleError(Exception):
    """Raised when a bundle cannot be loaded well enough to verify."""


def file_sha256(path: Path) -> str:
    """Return the sha256 hex digest of a saved evidence file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load(path: Path) -> Metadata:
    try:
        return Metadata.from_file(str(path))
    except (DeserializationError, FileNotFoundError, OSError) as exc:
        raise BundleError(f"cannot load {path}: {exc}") from exc


def _display_path(path: Path, base: Path) -> str:
    """Render an evidence path relative to the bundle where possible."""

    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _role_candidates(metadata_dir: Path, role: str) -> list[Path]:
    """Find the on-disk file(s) for a role, supporting versioned names.

    Saved repositories may use either the plain name (``snapshot.json``) or
    the consistent snapshot convention (``3.snapshot.json``). Plain names win
    when both are present.
    """

    plain = metadata_dir / f"{role}.json"
    if plain.exists():
        return [plain]
    return sorted(metadata_dir.glob(f"*.{role}.json"))


def _verify_top_level(
    root: Metadata[Root],
    metadata_dir: Path,
    role: str,
    result: PartyResult,
) -> Metadata | None:
    """Load and verify a top level role against the trusted root."""

    candidates = _role_candidates(metadata_dir, role)
    if not candidates:
        result.errors.append(f"{role}.json is missing from the bundle")
        return None
    if len(candidates) > 1:
        result.warnings.append(
            f"multiple files for role {role}, using {candidates[0].name}"
        )

    path = candidates[0]
    try:
        metadata = _load(path)
        root.signed.verify_delegate(
            role, metadata.signed_bytes, metadata.signatures
        )
    except BundleError as exc:
        result.errors.append(str(exc))
        return None
    except (UnsignedMetadataError, ValueError) as exc:
        result.errors.append(
            f"{_display_path(path, metadata_dir)}: signature threshold not "
            f"met for {role}: {exc}"
        )
        return None

    if metadata.signed.is_expired():
        result.warnings.append(
            f"{role} metadata expired at {metadata.signed.expires.isoformat()}"
        )
    result.verified_roles.append(role)
    return metadata


def _iter_delegations(
    delegator: Metadata[Targets],
) -> Iterator[tuple[str, str]]:
    """Yield ``(role_name, delegator_role_name)`` edges from a targets role.

    Only the standard ordered delegation graph (``delegations.roles``) is
    walked: succinct hash bins are not needed for the demonstration and would
    require materialising every bin. The edge records which delegator to use
    when verifying the child signature.
    """

    signed = delegator.signed
    if signed.delegations is None or signed.delegations.roles is None:
        return
    delegator_name = signed.type if signed.type != "targets" else "targets"
    for role_name in signed.delegations.roles:
        yield role_name, delegator_name


def _verify_delegations(
    metadata_dir: Path,
    top_targets: Metadata[Targets],
    result: PartyResult,
) -> dict[str, Metadata[Targets]]:
    """Walk the delegation graph and keep only fully verified targets roles."""

    verified: dict[str, Metadata[Targets]] = {}
    # The delegator name reported by _iter_delegations for the root role is
    # "targets"; map it back to the actual top level metadata object.
    delegators: dict[str, Metadata[Targets]] = {"targets": top_targets}
    queue: deque[str] = deque(["targets"])

    while queue:
        parent_name = queue.popleft()
        parent = delegators[parent_name]
        for child_name, _ in _iter_delegations(parent):
            if child_name in verified or child_name in delegators:
                continue
            candidates = _role_candidates(metadata_dir, child_name)
            if not candidates:
                result.errors.append(
                    f"delegated role {child_name} is authorized but its "
                    "metadata file is missing"
                )
                continue
            path = candidates[0]
            try:
                child = _load(path)
                parent.signed.verify_delegate(
                    child_name, child.signed_bytes, child.signatures
                )
            except BundleError as exc:
                result.errors.append(str(exc))
                continue
            except (UnsignedMetadataError, ValueError) as exc:
                result.errors.append(
                    f"{_display_path(path, metadata_dir)}: signature "
                    f"threshold not met for {child_name}: {exc}"
                )
                continue

            if not isinstance(child.signed, Targets):
                result.errors.append(
                    f"{child_name} metadata is not a targets role"
                )
                continue
            if child.signed.is_expired():
                result.warnings.append(
                    f"{child_name} metadata expired at "
                    f"{child.signed.expires.isoformat()}"
                )
            verified[child_name] = child
            delegators[child_name] = child
            result.verified_roles.append(child_name)
            queue.append(child_name)

    return verified


def _matches_scope(target_path: str, scope: tuple[str, ...]) -> bool:
    """Match a target path against the party's observed path patterns."""

    if not scope:
        return True
    return any(fnmatchcase(target_path, pattern) for pattern in scope)


def _collect_statements(
    role_name: str,
    metadata: Metadata[Targets],
    metadata_path: Path,
    base: Path,
    scope: tuple[str, ...],
) -> Iterator[Statement]:
    """Build verified statements for in-scope targets of one targets role."""

    digest = file_sha256(metadata_path)
    evidence = Evidence(
        metadata_file=_display_path(metadata_path, base),
        role=role_name,
        metadata_sha256=digest,
        metadata_version=metadata.signed.version,
    )
    for target_path, target_file in metadata.signed.targets.items():
        if not _matches_scope(target_path, scope):
            continue
        yield Statement(
            target_path=target_path,
            length=target_file.length,
            hashes=dict(target_file.hashes),
            evidence=evidence,
            custom=target_file.custom,
        )


def verify_party(
    party: str,
    root_path: Path,
    metadata_dir: Path,
    scope: tuple[str, ...],
    *,
    reference_time: datetime | None = None,
) -> PartyResult:
    """Verify one bundle and extract its independently verifiable statements.

    Args:
        party: Identifier used in the report.
        root_path: Trusted root metadata file vouchsafed by this party.
        metadata_dir: Directory with the saved role metadata files.
        scope: Observed target path patterns; only matching targets count.
        reference_time: Override "now" for expiry checks (used by tests).

    Returns:
        A :class:`PartyResult`; ``verified`` is False when any top level role
        cannot be loaded or verified, in which case no statements are trusted.
    """

    if reference_time is None:
        reference_time = datetime.now(UTC)

    result = PartyResult(
        party=party,
        root_file=_display_path(root_path, metadata_dir),
        verified=False,
        scope=list(scope),
    )

    try:
        root = _load(root_path)
    except BundleError as exc:
        result.errors.append(str(exc))
        return result
    if not isinstance(root.signed, Root):
        result.errors.append("trusted root file does not contain root metadata")
        return result

    # The root must satisfy its own threshold: it is the anchor of trust.
    try:
        root.signed.verify_delegate(
            "root", root.signed_bytes, root.signatures
        )
    except (UnsignedMetadataError, ValueError) as exc:
        result.errors.append(f"root does not meet its own threshold: {exc}")
        return result
    result.verified_roles.append("root")

    top_level: dict[str, Metadata] = {}
    for role in TOP_LEVEL_ROLES:
        path = root_path if role == "root" else None
        if role == "root":
            top_level[role] = root
            continue
        metadata = _verify_top_level(root, metadata_dir, role, result)
        if metadata is None:
            return result
        top_level[role] = metadata

    targets = top_level["targets"]
    if not isinstance(targets.signed, Targets):
        result.errors.append("targets metadata has the wrong payload type")
        return result

    delegated = _verify_delegations(metadata_dir, targets, result)
    result.verified = True

    targets_path = _role_candidates(metadata_dir, "targets")[0]
    for statement in _collect_statements(
        "targets", targets, targets_path, metadata_dir, scope
    ):
        result.statements[statement.target_path] = statement

    for role_name, role_metadata in delegated.items():
        role_path = _role_candidates(metadata_dir, role_name)[0]
        for statement in _collect_statements(
            role_name, role_metadata, role_path, metadata_dir, scope
        ):
            # Targets lower in the graph take precedence, matching the TUF
            # delegation lookup semantics used by clients.
            result.statements[statement.target_path] = statement

    return result


def verify_party_input(party_input: PartyInput) -> PartyResult:
    """Verify a bundle described by a :class:`PartyInput` value object."""

    return verify_party(
        party_input.party,
        party_input.root,
        party_input.metadata_dir,
        party_input.scope,
    )
