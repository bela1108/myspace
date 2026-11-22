# Offline License-Conflict Review

This worked example reviews three merged release books. Every book contains
ordinary YARA text-matching rules plus a sample-source license receipt in the
rule metadata. The review runs fully offline on top of `plyara` parsing.

## Inputs

- `books/*.yar` — the release books; each rule must carry `authorization_id`,
  `sample_id`, `receipt_text` and `scope` metadata.
- `sample_manifest.json` — local sample catalog keyed by `sample_id`, binding
  each sample to its registered authorization.
- `approvals.json` — approval scope keyed by `authorization_id`.
- `frozen_rules.json` — frozen rule version and per-rule logic hashes
  (`plyara.utils.generate_hash`).

## Folding rule

Receipts are grouped by their parsed logic hash (identical matching text). A
duplicate receipt is folded **only** when every receipt in the group resolves
to the same concrete `authorization_id`, `sample_id`, `scope` and frozen hash.
Identical wording backed by two different authorizations is retained as two
separate approvals. Scope breaches and frozen-hash drift are reported as
violations and also block folding.

## Run

```sh
PYTHONPATH=src python -m license_audit.cli \
    examples/license_audit/books \
    examples/license_audit/sample_manifest.json \
    examples/license_audit/approvals.json \
    examples/license_audit/frozen_rules.json
```

Add `--json` for machine output or `--output PATH` to write to a file.
Exit code is `0` when there are no violations, `1` when violations exist,
and `2` for bad inputs.

## Acceptance cases

- **FOLDABLE** — `BankerStr_Beta` / `BankerStr_Gamma`: identical text and the
  same conclusive authorization `AZ-7741` (same sample and scope).
- **KEEP_DUPLICATE** — `LoaderSig_Beta` / `LoaderSig_Gamma`: identical receipt
  wording but two distinct authorizations `AUTH-0003` and `AUTH-0099`.
- **VIOLATION** — `RansomNote_Beta` publishes externally while the grant only
  allows internal detection; `BackdoorStr` drifted from the frozen hash.

Each dossier keeps a `trace` pointer of the form `book:rule -> path:lines` so
the original rule text can be opened directly without re-running the review.
