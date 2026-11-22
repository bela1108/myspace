# SPDX-License-Identifier: Apache-2.0

"""Shared pytest fixtures: local keys, signed layout and per-channel links."""

import pytest

from quota_ledger.demo_support import build_signed_layout
from quota_ledger.demo_support import build_signed_link
from quota_ledger.demo_support import generate_signer
from quota_ledger.demo_support import write_key_pair
from quota_ledger.intoto_verify import load_verified_release

DIGEST = "ab" * 32
CHANNELS = ("channel-a", "channel-b")


@pytest.fixture()
def keys(tmp_path):
    root = generate_signer()
    signers = {channel: generate_signer() for channel in CHANNELS}
    _, root_pub = write_key_pair(root, "root", tmp_path / "keys")
    pubs = {}
    for channel, signer in signers.items():
        _, pubs[channel] = write_key_pair(
            signer, channel, tmp_path / "keys"
        )
    return {
        "root": root,
        "root_pub": root_pub,
        "signers": signers,
        "pubs": pubs,
    }


@pytest.fixture()
def evidence(keys, tmp_path):
    layout_path = tmp_path / "root.layout"
    build_signed_layout(
        keys["root"], list(keys["signers"].values()), layout_path
    )
    verified = {}
    for channel in CHANNELS:
        link_dir = tmp_path / f"links-{channel}"
        build_signed_link(keys["signers"][channel], DIGEST, link_dir)
        verified[channel] = load_verified_release(
            str(layout_path), [str(keys["root_pub"])],
            str(link_dir), channel
        )
    return verified
