# SPDX-License-Identifier: Apache-2.0

# Tests for in-toto signature verification adapter.

import json

import pytest

from quota_ledger.demo_support import build_signed_layout
from quota_ledger.demo_support import build_signed_link
from quota_ledger.exceptions import SignatureError
from quota_ledger.exceptions import VerificationError
from quota_ledger.intoto_verify import load_verified_release
from tests.conftest import DIGEST


def test_verified_release_extracts_digest(keys, evidence, tmp_path):
    release = load_verified_release(
        str(tmp_path / "root.layout"), [str(keys["root_pub"])],
        str(tmp_path / "links-channel-a"), "channel-a"
    )
    assert release.artifact_sha256 == DIGEST
    assert release.channel == "channel-a"
    assert release.functionary_keyid == (
        keys["signers"]["channel-a"].public_key.keyid
    )


def test_wrong_root_key_rejects_layout(keys, evidence, tmp_path):
    outsider = keys["signers"]["channel-b"]
    with pytest.raises(SignatureError):
        load_verified_release(
            str(tmp_path / "root.layout"), [str(keys["pubs"]["channel-b"])],
            str(tmp_path / "links-channel-a"), "channel-a"
        )
    assert outsider is not None


def test_tampered_link_is_rejected(keys, evidence, tmp_path):
    link_dir = tmp_path / "links-channel-a"
    link_file = next(link_dir.glob("*.link"))
    data = json.loads(link_file.read_text())
    data["signed"]["products"]["release-bundle.tar.gz"] = {
        "sha256": "ff" * 32
    }
    link_file.write_text(json.dumps(data))
    with pytest.raises(SignatureError):
        load_verified_release(
            str(tmp_path / "root.layout"), [str(keys["root_pub"])],
            str(link_dir), "channel-a"
        )


def test_expired_layout_is_rejected(keys, tmp_path):
    from in_toto.models.layout import Layout, Step
    from in_toto.models.metadata import Metablock
    signer = keys["signers"]["channel-a"]
    step = Step(name="build", pubkeys=[signer.public_key.keyid], threshold=1)
    layout = Layout(keys={}, steps=[step], inspect=[])
    layout.expires = "2000-01-01T00:00:00Z"
    metadata = Metablock(signed=layout)
    metadata.create_signature(keys["root"])
    expired = tmp_path / "expired.layout"
    metadata.dump(str(expired))
    link_dir = tmp_path / "links-expired"
    build_signed_link(signer, DIGEST, link_dir)
    with pytest.raises(VerificationError):
        load_verified_release(
            str(expired), [str(keys["root_pub"])],
            str(link_dir), "channel-a"
        )


def test_unauthorized_link_signer_is_rejected(keys, tmp_path):
    rogue = __import__("quota_ledger.demo_support", fromlist=["x"])
    rogue_signer = rogue.generate_signer()
    layout_path = tmp_path / "root.layout"
    build_signed_layout(
        keys["root"], [keys["signers"]["channel-a"]], layout_path
    )
    link_dir = tmp_path / "links-rogue"
    build_signed_link(rogue_signer, DIGEST, link_dir)
    with pytest.raises(VerificationError):
        load_verified_release(
            str(layout_path), [str(keys["root_pub"])],
            str(link_dir), "channel-a"
        )
