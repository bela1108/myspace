# SPDX-License-Identifier: Apache-2.0

# Integration tests for the quota-ledger command line interface.

import json

from quota_ledger.cli import main
from quota_ledger.credentials import ENTITLEMENT_TYPE
from quota_ledger.demo_support import build_signed_link
from quota_ledger.demo_support import build_signed_layout
from tests.conftest import DIGEST


def _layout_and_links(keys, tmp_path):
    layout_path = tmp_path / "root.layout"
    build_signed_layout(
        keys["root"], list(keys["signers"].values()), layout_path
    )
    link_dir = tmp_path / "links-channel-a"
    build_signed_link(keys["signers"]["channel-a"], DIGEST, link_dir)
    return layout_path, link_dir


def test_verify_command(keys, tmp_path, capsys):
    layout_path, link_dir = _layout_and_links(keys, tmp_path)
    rc = main([
        "verify", "--layout", str(layout_path),
        "--root-keys", str(keys["root_pub"]),
        "--link-dir", str(link_dir), "--channel", "channel-a",
    ])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["artifact_sha256"] == DIGEST


def test_import_status_replay_commands(keys, tmp_path, capsys):
    from quota_ledger import Credential
    layout_path, link_dir = _layout_and_links(keys, tmp_path)
    signer = keys["signers"]["channel-a"]
    credential = Credential.create(
        signer, ENTITLEMENT_TYPE, "ent-cli", "channel-a", DIGEST,
        {"amount": 4}
    )
    cred_path = tmp_path / "ent.json"
    credential.dump(str(cred_path))
    ledger_dir = tmp_path / "ledger"

    rc = main([
        "import", "--ledger", str(ledger_dir),
        "--credential", str(cred_path),
        "--layout", str(layout_path),
        "--root-keys", str(keys["root_pub"]),
        "--link-dir", str(link_dir),
    ])
    assert rc == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["available_after"] == 4

    rc = main([
        "replay", "--ledger", str(ledger_dir)
    ])
    assert rc == 0
    snapshot = json.loads(capsys.readouterr().out)
    assert len(snapshot["lines"]) == 1
    assert snapshot["lines"][0]["state"] == "open"
