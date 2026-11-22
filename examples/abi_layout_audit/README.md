# Static ABI layout audit example

These inputs demonstrate a non-executing layout review of a fixed-size
device state block.

## Files

- `device_status.pp.c` — preprocessed C declarations (the kind of output
  produced by `cpp -P` / `gcc -E`). Comments and GNU-only spellings must be
  removed by the preprocessor; pycparser parses the result directly.
- `config-ilp32.json` — 32-bit ABI geometry, public field list and export
  ranges.
- `config-lp64.json` — 64-bit ABI geometry with the *same* audit scope, so
  the two reviews are directly comparable.

## Run

From the repository root:

```
python -m abi_layout_audit \
    examples/abi_layout_audit/device_status.pp.c \
    --config examples/abi_layout_audit/config-ilp32.json \
    --config examples/abi_layout_audit/config-lp64.json
```

Add `--format json --output report.json` for machine-readable output. The
process exit code is `0` when every range is `ok`, `2` when a range needs
review or violates the public boundary, and `1` for configuration or parse
errors.

## What the cross-ABI gap shows

The `cross-abi-gap` range covers bytes 10-15.

- On ILP32, bytes 12-15 are the public `unsigned long watchdog` field, while
  bytes 10-11 are alignment padding.
- On LP64 the same six bytes are entirely padding before the 8-byte
  `watchdog`.

Both verdicts name the exact declaration line of the responsible field or
padding. Bitfields (`struct packet_control`) and `#pragma pack` /
`[[gnu::packed]]` rules are never guessed: they are reported as review items
with their declaration location.
