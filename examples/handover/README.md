# Three-receipt acceptance fixture

This directory is a complete, offline acceptance example for the handover
workflow.

| File | Purpose |
| --- | --- |
| `plan.json` | Original two-item remediation plan. Its source metadata intentionally contains an index URL and an internal path. |
| `audit.json` | Offline `pip-audit -f json` result. It also contains source-only URLs and paths. |
| `environment.json` | Environment version snapshot. Its index URL and source path are not disclosed. |
| `handover-package.json` | Generated, redacted, digest-bound package. |
| `receipt-01-requests-complete.json` | Name-only acknowledgement of `REM-001`; the package already binds its target evidence. |
| `receipt-02-requests-repeat.json` | The same rotated item name again, with no new evidence. |
| `receipt-03-jinja2-partial.json` | Name-only acknowledgement of `REM-002`; the package still lacks target-version and clean-recheck evidence. |
| `state.json` | Final state after applying all three receipts. |
| `reconciliation-*.json` | Per-receipt reports. |

Expected final result:

* `REM-001` is `closed` exactly once.
* The repeat of `REM-001` increments `duplicate_lines`, not
  `unique_receipt_lines`.
* `REM-002` remains `in_progress` with `fixed_version` and
  `vulnerability_recheck` missing.

The same result can be reproduced without network access:

```console
$ mkdir -p handover-build
$ pip-audit-handover build \
    --plan examples/handover/plan.json \
    --audit examples/handover/audit.json \
    --environment examples/handover/environment.json \
    --output handover-build/handover-package.json
$ pip-audit-handover receive \
    --package handover-build/handover-package.json \
    --receipt examples/handover/receipt-01-requests-complete.json \
    --state handover-build/state.json \
    --output handover-build/reconciliation-01.json
$ pip-audit-handover receive \
    --package handover-build/handover-package.json \
    --receipt examples/handover/receipt-02-requests-repeat.json \
    --state handover-build/state.json \
    --output handover-build/reconciliation-02.json
$ pip-audit-handover receive \
    --package handover-build/handover-package.json \
    --receipt examples/handover/receipt-03-jinja2-partial.json \
    --state handover-build/state.json \
    --output handover-build/reconciliation-03.json
```
