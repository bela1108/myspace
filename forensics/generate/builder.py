"""Build small, fully signed TUF bundles for the offline demo.

The builder only uses the low level tuf.api metadata classes and local
CryptoSigner key generation: nothing is fetched. It produces realistic
bundles containing root, timestamp, snapshot, targets and one delegated
targets role so that the cross-check can exercise both top level and
delegated trust paths.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from securesystemslib.signer import CryptoSigner, Signer
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    MetaFile,
    Metadata,
    Role,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

PRETTY = JSONSerializer(compact=False)
_TOP_LEVEL = ('root', 'timestamp', 'snapshot', 'targets')
# The demo fixes the spec version to keep generated output deterministic.
SPEC_VERSION = '1.0.31'


def _expires(days: int) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


def target_file(path: str, content: bytes) -> TargetFile:
    """Build a TargetFile with sha256 and length computed from content."""

    digest = hashlib.sha256(content).hexdigest()
    return TargetFile(
        length=len(content),
        hashes={'sha256': digest},
        path=path,
    )


@dataclass
class BundleKeys:
    """The private signers and the role layout of one demo bundle."""

    signers: dict[str, Signer]
    delegated_role: str

    @classmethod
    def generate(cls, delegated_role: str) -> 'BundleKeys':
        signers = {name: CryptoSigner.generate_ed25519() for name in _TOP_LEVEL}
        signers[delegated_role] = CryptoSigner.generate_ed25519()
        return cls(signers=signers, delegated_role=delegated_role)


def _build_root(keys: BundleKeys) -> Metadata[Root]:
    root = Metadata[Root](
        Root(
            version=1,
            spec_version=SPEC_VERSION,
            expires=_expires(365),
            roles={name: Role([], 1) for name in _TOP_LEVEL},
        )
    )
    for name in _TOP_LEVEL:
        root.signed.add_key(keys.signers[name].public_key, name)
    root.sign(keys.signers['root'])
    return root


def _build_targets(
    keys: BundleKeys,
    top_targets: dict[str, TargetFile],
    delegated_targets: dict[str, TargetFile],
    delegated_paths: list[str],
) -> tuple[Metadata[Targets], Metadata[Targets]]:
    delegated_name = keys.delegated_role
    delegated = Metadata[Targets](
        Targets(
            version=1,
            spec_version=SPEC_VERSION,
            expires=_expires(90),
            targets=dict(delegated_targets),
        )
    )
    delegated.sign(keys.signers[delegated_name])

    delegate_key = keys.signers[delegated_name].public_key
    targets = Metadata[Targets](
        Targets(
            version=1,
            spec_version=SPEC_VERSION,
            expires=_expires(365),
            targets=dict(top_targets),
            delegations=Delegations(
                keys={delegate_key.keyid: delegate_key},
                roles={
                    delegated_name: DelegatedRole(
                        name=delegated_name,
                        keyids=[delegate_key.keyid],
                        threshold=1,
                        terminating=True,
                        paths=delegated_paths,
                    ),
                },
            ),
        )
    )
    targets.sign(keys.signers['targets'])
    return targets, delegated


def _build_snapshot(
    keys: BundleKeys,
    targets: Metadata[Targets],
    delegated: Metadata[Targets],
) -> Metadata[Snapshot]:
    snapshot = Metadata[Snapshot](
        Snapshot(
            version=1,
            spec_version=SPEC_VERSION,
            expires=_expires(30),
            meta={
                'targets.json': MetaFile(version=targets.signed.version),
                f'{keys.delegated_role}.json': MetaFile(
                    version=delegated.signed.version
                ),
            },
        )
    )
    snapshot.sign(keys.signers['snapshot'])
    return snapshot


def _build_timestamp(
    snapshot: Metadata[Snapshot], signer: Signer
) -> Metadata[Timestamp]:
    timestamp = Metadata[Timestamp](
        Timestamp(
            version=1,
            spec_version=SPEC_VERSION,
            expires=_expires(7),
            snapshot_meta=MetaFile(version=snapshot.signed.version),
        )
    )
    timestamp.sign(signer)
    return timestamp


def write_bundle(
    out_dir: Path,
    keys: BundleKeys,
    top_targets: dict[str, TargetFile],
    delegated_targets: dict[str, TargetFile],
    delegated_paths: list[str],
    *,
    omit_role: str | None = None,
) -> dict[str, Path]:
    """Write a fully signed bundle and return the role file paths.

    When omit_role is set, that role file is not written: the bundle
    still references it (in snapshot/delegations), which models a receipt
    whose source material is incomplete.
    """

    out_dir.mkdir(parents=True, exist_ok=True)
    root = _build_root(keys)
    targets, delegated = _build_targets(
        keys, top_targets, delegated_targets, delegated_paths
    )
    snapshot = _build_snapshot(keys, targets, delegated)
    timestamp = _build_timestamp(snapshot, keys.signers['timestamp'])

    files: dict[str, Path] = {}
    planned = {
        'root': (out_dir / 'root.json', root),
        'timestamp': (out_dir / 'timestamp.json', timestamp),
        'snapshot': (out_dir / 'snapshot.json', snapshot),
        'targets': (out_dir / 'targets.json', targets),
        keys.delegated_role: (
            out_dir / f'{keys.delegated_role}.json',
            delegated,
        ),
    }
    for role, (path, metadata) in planned.items():
        if omit_role == role:
            continue
        metadata.to_file(str(path), serializer=PRETTY)
        files[role] = path
    return files
