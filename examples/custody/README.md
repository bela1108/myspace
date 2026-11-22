# Offline custody sample

This directory contains the minimal sample for `evtx_custody_reconcile`:

- `system-short.evtx` and `security-short.evtx`: two three-record EVTX files
  derived from the repository fixtures.  Each is a single chunk with a
  recalculated chunk checksum and file header.
- `case.json`: caller-provided record ranges, long-term custodian permissions,
  archive deadline, and the prior holder's retained copy.
- `external_manifest.json`: the external hand-over list.  It contains only
  evidence identifiers, record ranges, receipt identifiers, and digests; it has
  no host, user, subject, record text, or summary content.
- `receipts.json`: an unsigned transfer, a shift-change receipt, a supplemental
  signature that cures the unsigned transfer, and a late receipt.
- `responsibility.json`: the internal responsibility table used to resolve the
  actual signer.  The previous holder's retained copy is deliberately present
  but never used as acceptance evidence.
- `expected_internal.json`, `expected_external.json`: reports generated from the
  sample.  The external report omits actual names and other sensitive fields.

Run:

```bash
.venv/bin/python -m evtx_scripts.evtx_custody_reconcile examples/custody/case.json
.venv/bin/python -m evtx_scripts.evtx_custody_reconcile examples/custody/case.json --json
.venv/bin/python -m evtx_scripts.evtx_custody_reconcile examples/custody/case.json --external-json
```

Expected classification:

| Evidence | Records | Result | Why |
| --- | --- | --- | --- |
| `system-short.evtx` | 12049-12050 | 可继续复查 | shift-change receipt R2, full permission, in external manifest |
| `system-short.evtx` | 12051 | 只剩摘要 | receipt R2 and manifest entry exist, but custody permission is summary-only |
| `security-short.evtx` | 1-2 | 可继续复查 | R1 was only a transferor signature; supplemental R3 was signed by the receiving custodian and amends R1 |
| `security-short.evtx` | 3-3 | 尚未被承接 | R4 was signed after the archive deadline |

The external scope is intentionally not fully matched: the external list names
R4 for `security-short.evtx` 3-3, but R4 is late, so the report records one
manifest range without an effective receipt.  That is the custody gap the
auditor should see before destruction.

Regenerate the sample:

```bash
.venv/bin/python examples/custody/build_samples.py
```
