# SPDX-License-Identifier: Apache-2.0

"""End-to-end two-channel release-quota demo.

Flow:
  1. Mint local ed25519 keys: one layout root key and one functionary key
     per delivery channel.
  2. Sign one layout authorizing both functionaries on a shared build step.
  3. Each channel signs a link over the SAME artifact digest.
  4. Import signed entitlements, hold quota, confirm a release on channel A.
  5. Revoke channel B; show that channel A quota and receipts stay intact.
  6. Reopen the ledger from disk and prove replay reconstructs everything.

Run with:  .venv/bin/python examples/demo_two_channels.py [--out DIR]
"""

import argparse
import json
import shutil
from pathlib import Path

from quota_ledger import Credential
from quota_ledger import Ledger
from quota_ledger import load_verified_release
from quota_ledger.credentials import ENTITLEMENT_TYPE
from quota_ledger.credentials import HOLD_TYPE
from quota_ledger.credentials import RELEASE_TYPE
from quota_ledger.credentials import REVOKE_TYPE
from quota_ledger.demo_support import build_signed_layout
from quota_ledger.demo_support import build_signed_link
from quota_ledger.demo_support import generate_signer
from quota_ledger.demo_support import write_key_pair
from quota_ledger.exceptions import PendingCredentialError

CHANNELS = ("channel-a", "channel-b")
SHARED_DIGEST = "ab" * 32


def _sign_and_import(ledger, signer, evidence, ctype, cid, channel,
                     digest, payload=None):
    credential = Credential.create(
        signer, ctype, cid, channel, digest, payload or {}
    )
    credential.verify_signature({signer.public_key.keyid: signer.public_key})
    return ledger.import_credential(credential, evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="demo-out", help="demo data dir")
    args = parser.parse_args()
    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    print("== 1. mint local test keys ==")
    root_signer = generate_signer()
    _, root_pub = write_key_pair(root_signer, "root", out / "keys")
    channel_signers = {}
    for channel in CHANNELS:
        signer = generate_signer()
        channel_signers[channel] = signer
        write_key_pair(signer, channel, out / "keys")
        print(f"  {channel}: keyid {signer.public_key.keyid[:12]}...")

    print("== 2. sign one layout authorizing both channels ==")
    layout_path = out / "root.layout"
    build_signed_layout(
        root_signer, list(channel_signers.values()), layout_path
    )

    print("== 3. each channel signs a link over the same artifact ==")
    evidence = {}
    for channel in CHANNELS:
        link_dir = out / f"links-{channel}"
        build_signed_link(channel_signers[channel], SHARED_DIGEST, link_dir)
        evidence[channel] = load_verified_release(
            str(layout_path), [str(root_pub)], str(link_dir), channel
        )
        print(f"  {channel}: verified digest {SHARED_DIGEST[:16]}...")

    ledger = Ledger(out / "ledger")
    print("== 4. entitlements, hold and release ==")
    _sign_and_import(
        ledger, channel_signers["channel-a"], evidence["channel-a"],
        ENTITLEMENT_TYPE, "ent-a", "channel-a", SHARED_DIGEST,
        {"amount": 5},
    )
    _sign_and_import(
        ledger, channel_signers["channel-b"], evidence["channel-b"],
        ENTITLEMENT_TYPE, "ent-b", "channel-b", SHARED_DIGEST,
        {"amount": 3},
    )
    _sign_and_import(
        ledger, channel_signers["channel-a"], evidence["channel-a"],
        HOLD_TYPE, "hold-a-1", "channel-a", SHARED_DIGEST, {"amount": 2},
    )
    release_receipt = _sign_and_import(
        ledger, channel_signers["channel-a"], evidence["channel-a"],
        RELEASE_TYPE, "release-a-1", "channel-a", SHARED_DIGEST,
        {"amount": 2},
    )
    print(f"  channel-a release receipt: {release_receipt.state_after}")

    print("== 5. a hold arriving before its entitlement is parked ==")
    unknown_digest = "cd" * 32
    early_hold = Credential.create(
        channel_signers["channel-b"], HOLD_TYPE, "hold-early",
        "channel-b", unknown_digest, {"amount": 1}
    )
    early_hold.verify_signature({
        channel_signers["channel-b"].public_key.keyid:
        channel_signers["channel-b"].public_key
    })
    try:
        # No evidence/entitlement for this digest yet: park, do not apply.
        ledger.import_credential(early_hold)
    except PendingCredentialError as exc:
        print(f"  parked: {exc}")
    assert ledger.available_quota("channel-b", SHARED_DIGEST) == 3
    assert ledger.available_quota("channel-b", unknown_digest) == 0

    print("== 6. revoke channel B; channel A stays independently usable ==")
    revoke_receipt = _sign_and_import(
        ledger, channel_signers["channel-b"], evidence["channel-b"],
        REVOKE_TYPE, "revoke-b", "channel-b", SHARED_DIGEST,
    )
    print(f"  channel-b receipt: {revoke_receipt.state_after}")
    print(f"  channel-a available: {ledger.available_quota("channel-a", SHARED_DIGEST)}")
    print(f"  channel-b available: {ledger.available_quota("channel-b", SHARED_DIGEST)}")

    print("== 7. re-import is idempotent (no new event) ==")
    event_count = len(ledger.state.receipts)
    _sign_and_import(
        ledger, channel_signers["channel-b"], evidence["channel-b"],
        REVOKE_TYPE, "revoke-b", "channel-b", SHARED_DIGEST,
    )
    assert len(ledger.state.receipts) == event_count
    print(f"  events unchanged at {event_count}")

    print("== 8. replay the log from disk and reconcile receipts ==")
    replayed = Ledger(out / "ledger")
    assert replayed.snapshot() == ledger.snapshot()
    for channel in CHANNELS:
        receipts = replayed.receipts_for_channel(channel)
        print(f"  {channel}: {len(receipts)} receipts, "
              f"available {replayed.available_quota(channel, SHARED_DIGEST)}")

    snapshot_path = out / "snapshot.json"
    snapshot_path.write_text(json.dumps(replayed.snapshot(), indent=2))
    print(f"== done; snapshot written to {snapshot_path} ==")


if __name__ == "__main__":
    main()
