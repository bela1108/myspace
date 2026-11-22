# SPDX-License-Identifier: Apache-2.0

"""Command line interface for the replayable quota ledger.

Examples:
  quota-ledger verify --layout root.layout --root-keys root_public.pem 
      --link-dir links-a --channel channel-a
  quota-ledger import --ledger ./ledger --credential ent-a.json 
      --layout root.layout --root-keys root_public.pem --link-dir links-a
  quota-ledger status --ledger ./ledger --channel channel-a 
      --artifact <sha256>
  quota-ledger replay --ledger ./ledger
"""

import argparse
import json

from quota_ledger.credentials import Credential
from quota_ledger.exceptions import LedgerError
from quota_ledger.intoto_verify import load_verified_release
from quota_ledger.ledger import Ledger


def _build_parser():
    parser = argparse.ArgumentParser(prog="quota-ledger", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    verify_p = sub.add_parser("verify", help="verify an in-toto bundle")
    _add_layout_args(verify_p)

    import_p = sub.add_parser("import", help="verify and import credential")
    import_p.add_argument("--ledger", required=True)
    import_p.add_argument("--credential", required=True)
    _add_layout_args(import_p, required=False)

    status_p = sub.add_parser("status", help="show quota lines and receipts")
    status_p.add_argument("--ledger", required=True)
    status_p.add_argument("--channel")
    status_p.add_argument("--artifact")

    replay_p = sub.add_parser("replay", help="replay log and print snapshot")
    replay_p.add_argument("--ledger", required=True)
    return parser


def _add_layout_args(parser, required=True):
    parser.add_argument("--layout", required=required)
    parser.add_argument("--root-keys", nargs="+", required=required)
    parser.add_argument("--link-dir", required=required)
    parser.add_argument("--channel")
    parser.add_argument("--link-name")


def _evidence(args):
    if not args.layout:
        return None
    channel = args.channel or "unbound"
    return load_verified_release(
        args.layout, args.root_keys, args.link_dir, channel, args.link_name
    )


def _cmd_verify(args):
    evidence = load_verified_release(
        args.layout, args.root_keys, args.link_dir,
        args.channel, args.link_name
    )
    print(json.dumps({
        "channel": evidence.channel,
        "artifact_sha256": evidence.artifact_sha256,
        "link_name": evidence.link_name,
        "functionary_keyid": evidence.functionary_keyid,
    }, indent=2))
    return 0


def _cmd_import(args):
    credential = Credential.load(args.credential)
    args.channel = credential.channel
    evidence = _evidence(args)
    ledger = Ledger(args.ledger)
    receipt = ledger.import_credential(credential, evidence)
    if receipt is None:
        print("credential already processed: no new event")
    else:
        print(json.dumps(receipt.to_dict(), indent=2))
    return 0


def _cmd_status(args):
    ledger = Ledger(args.ledger)
    if args.channel and args.artifact:
        result = {
            "channel": args.channel,
            "artifact_sha256": args.artifact,
            "available": ledger.available_quota(args.channel, args.artifact),
            "lines": [
                line.to_dict() for line in
                ledger.state.line_for(args.channel, args.artifact)
            ],
        }
    else:
        lines = ledger.state.lines.values()
        if args.channel:
            lines = ledger.lines_for_channel(args.channel)
        result = {"lines": [line.to_dict() for line in lines]}
    print(json.dumps(result, indent=2))
    return 0


def _cmd_replay(args):
    ledger = Ledger(args.ledger)
    ledger.replay()
    print(json.dumps(ledger.snapshot(), indent=2))
    return 0


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "verify": _cmd_verify,
        "import": _cmd_import,
        "status": _cmd_status,
        "replay": _cmd_replay,
    }
    try:
        return handlers[args.command](args)
    except LedgerError as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
