"""Assemble the demonstration scenario on disk.

The scenario contains three target objects so the report can show all three
outcomes at once:

* release/app-1.4.2.tar.gz is present and fully signed in both bundles, but
  the two parties publish different length/hashes for the same version. Both
  signatures verify, so this is a proven conflict backed by two originals.
* release/firmware-1.4.2.bin is signed on both sides with identical hashes,
  i.e. an agreement on the same release statement.
* release/manifest-1.4.2.json only exists inside a delegated role whose
  metadata file is missing from the beta bundle. Alpha verifies it, beta
  cannot, so the record stays undecided rather than being called a conflict.
"""

from __future__ import annotations

import json
from pathlib import Path

from forensics.generate.builder import (
    BundleKeys,
    target_file,
    write_bundle,
)

DELEGATED_ROLE = 'incident-scope'
DELEGATED_PATHS = ['release/manifest-*.json']

APP_PATH = 'release/app-1.4.2.tar.gz'
FIRMWARE_PATH = 'release/firmware-1.4.2.bin'
MANIFEST_PATH = 'release/manifest-1.4.2.json'

# Both parties declare the same observation scope for the release line.
SCOPE = ['release/*']


def _manifest(party: str) -> dict[str, object]:
    return {
        'party': party,
        'root': f'{party}/root.json',
        'metadata_dir': party,
        'scope': list(SCOPE),
    }


def build_demo(base_dir: Path) -> dict[str, object]:
    """Create both bundles, both manifests and return their paths."""

    base_dir.mkdir(parents=True, exist_ok=True)
    alpha_dir = base_dir / 'alpha'
    beta_dir = base_dir / 'beta'

    # Each party vouches for its own independently generated root.
    alpha_keys = BundleKeys.generate(DELEGATED_ROLE)
    beta_keys = BundleKeys.generate(DELEGATED_ROLE)

    app_alpha = target_file(APP_PATH, b'alpha build of app 1.4.2\n')
    app_beta = target_file(APP_PATH, b'beta build of app 1.4.2 -- different\n')
    firmware = target_file(FIRMWARE_PATH, b'firmware 1.4.2 shared payload\n')
    manifest_file = target_file(
        MANIFEST_PATH, b'{"version": "1.4.2", "note": "incident"}\n'
    )

    alpha_files = write_bundle(
        alpha_dir,
        alpha_keys,
        top_targets={
            APP_PATH: app_alpha,
            FIRMWARE_PATH: firmware,
        },
        delegated_targets={MANIFEST_PATH: manifest_file},
        delegated_paths=list(DELEGATED_PATHS),
    )
    # Beta omits the delegated role file: its source material for the
    # manifest object is incomplete even though snapshot still references it.
    beta_files = write_bundle(
        beta_dir,
        beta_keys,
        top_targets={
            APP_PATH: app_beta,
            FIRMWARE_PATH: firmware,
        },
        delegated_targets={MANIFEST_PATH: manifest_file},
        delegated_paths=list(DELEGATED_PATHS),
        omit_role=DELEGATED_ROLE,
    )

    alpha_manifest = base_dir / 'alpha-manifest.json'
    beta_manifest = base_dir / 'beta-manifest.json'
    alpha_manifest.write_text(
        json.dumps(_manifest('alpha'), indent=2) + '\n',
        encoding='utf-8',
    )
    beta_manifest.write_text(
        json.dumps(_manifest('beta'), indent=2) + '\n',
        encoding='utf-8',
    )

    return {
        'base': base_dir,
        'alpha_bundle': alpha_dir,
        'beta_bundle': beta_dir,
        'alpha_manifest': alpha_manifest,
        'beta_manifest': beta_manifest,
        'alpha_files': alpha_files,
        'beta_files': beta_files,
    }
