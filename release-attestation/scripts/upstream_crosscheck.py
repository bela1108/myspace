#!/usr/bin/env python3
"""Internal upstream cross-check (NOT part of the public bundle).

Runs the reference implementation full verification workflow against the
original evidence: layout signatures, link signature thresholds, artifact
rules (CREATE/MATCH/ALLOW), and the untar inspection with its MATCH rules.
This stays inside the repository and is never shipped to customers; the
customer-facing equivalent is scripts/verify_report.py, which only needs the
public bundle.
"""

import json
import os
import sys
from pathlib import Path

from in_toto.models._signer import load_crypto_signer_from_pkcs8_file
from in_toto.models.metadata import Metadata
from in_toto.verifylib import in_toto_verify

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "tests" / "demo_files"
PEMS = REPO_ROOT / "tests" / "pems"
SCRIPTS = REPO_ROOT / "tests" / "scripts"
WORKDIR = REPO_ROOT / "release-attestation" / "internal-workdir"


def main():
    import shutil

    if WORKDIR.exists():
        for child in WORKDIR.iterdir():
            if child.name == "run-records":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        WORKDIR.mkdir(parents=True)
    (WORKDIR / "run-records").mkdir(exist_ok=True)
    for name in [
        "foo.tar.gz",
        "package.2f89b927.link",
        "write-code.776a00e2.link",
        "demo.layout.template",
    ]:
        shutil.copy(DEMO / name, WORKDIR / name)
    shutil.copytree(SCRIPTS, WORKDIR / "scripts")

    layout = Metadata.load(str(WORKDIR / "demo.layout.template"))
    signer = load_crypto_signer_from_pkcs8_file(
        PEMS / "rsa_private_unencrypted.pem"
    )
    layout.create_signature(signer)
    layout_path = WORKDIR / "signed.layout"
    layout.dump(str(layout_path))

    owner_pubkey = signer.public_key.to_dict()
    owner_pubkey["keyid"] = signer.public_key.keyid
    result = {
        "layout_signer_keyid": signer.public_key.keyid,
        "functionary_keyids": sorted(layout.signed.keys),
        "steps": [step.name for step in layout.signed.steps],
        "inspections": [item.name for item in layout.signed.inspect],
    }
    venv_bin = str(Path(sys.executable).parent)
    os.environ["PATH"] = venv_bin + os.pathsep + os.environ.get("PATH", "")
    previous_cwd = Path.cwd()
    os.chdir(WORKDIR)
    try:
        in_toto_verify(
            Metadata.load(str(layout_path)),
            {signer.public_key.keyid: owner_pubkey},
            link_dir_path=str(WORKDIR),
        )
    finally:
        os.chdir(previous_cwd)
    result["in_toto_verify"] = "PASS"
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
