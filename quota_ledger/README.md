# Replayable in-toto Release-Quota Ledger

Two delivery channels can ship the same build artifact, but each channel owns
its own signed release quota. This package wires the existing in-toto signature
verification machinery to an append-only, replayable quota ledger. It decides
who may consume which quota line for a release, using only verified layout and
link metadata plus signed quota credentials.

A shared artifact digest only proves the artifact is the same one; quota lines,
holds, releases, revocations and receipts stay isolated per channel.

## Trust model

- A layout is signed by one or more trusted root keys and must not be expired.
- Links must be signed by functionaries authorized in the layout; the artifact
  digest is read from a verified link product (via in-toto verifylib).
- Quota credentials (entitlement, hold, release, revoke) are in-toto link
  metadata signed with a channel functionary key. No new signature code is
  introduced; signing and verification reuse Metablock.create_signature and
  Metablock.verify_signature.
- A credential whose channel or digest contradicts the verified evidence is
  parked, never applied.

## Ledger semantics

- State is fully derived from a JSON-lines event log; each record is chained
  with sha256(prev_hash, canonical(event)). Tampering breaks replay.
- Quota line states: open -> held -> released, with revoked reachable from
  any live state. Transitions are checked against the predecessor state.
- Re-importing an identical credential is a no-op (idempotent). Reusing a
  credential id with different content raises DuplicateCredentialError.
- A hold/release/revoke without its entitlement raises PendingCredentialError
  and writes nothing; retry once the predecessor credential is supplied.
- Revoking one channel never changes another channel available quota or
  receipts.

## Demo

The demo mints local ed25519 test keys, signs one layout authorizing two
channel functionaries on a shared build step, and each channel signs a link
over the same artifact digest. It then exercises entitlements, a hold, a
release, a parked (predecessor-missing) credential, and a revocation.

    PYTHONPATH=. .venv/bin/python examples/demo_two_channels.py --out demo-out

Expected outcome: channel B ends revoked with zero available quota while
channel A keeps its remaining quota and its own receipt trail; reopening the
ledger replays the identical state.

## CLI

    .venv/bin/python -m quota_ledger.cli verify --layout root.layout \
        --root-keys root_public.pem --link-dir links-a --channel channel-a
    .venv/bin/python -m quota_ledger.cli import --ledger ./ledger \
        --credential ent-a.json --layout root.layout \
        --root-keys root_public.pem --link-dir links-a
    .venv/bin/python -m quota_ledger.cli status --ledger ./ledger \
        --channel channel-a --artifact <sha256>
    .venv/bin/python -m quota_ledger.cli replay --ledger ./ledger

## Tests

    PYTHONPATH=. .venv/bin/python -m pytest \
        tests/test_intoto_verify.py tests/test_ledger.py tests/test_cli.py \
        --confcutdir=tests -p no:cacheprovider

## Layout

- quota_ledger/credentials.py: signed credential wrapper over in-toto links.
- quota_ledger/intoto_verify.py: layout/link signature and digest verification.
- quota_ledger/ledger.py: append-only event log, state machine and receipts.
- quota_ledger/cli.py: verify/import/status/replay command line interface.
- quota_ledger/demo_support.py: local key generation and demo metadata helpers.
- examples/demo_two_channels.py: end-to-end two-channel walkthrough.
