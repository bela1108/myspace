# Temporal advisory reconciliation example

This example reproduces a common supply-chain timeline:

1. On 2026-11-14 the vendor advisory says the artifact scope is still being
   verified, and no PyPI artifact is listed as affected.
2. `prod` and `staging` are closed by on-call with that snapshot as evidence.
3. On 2026-11-23 the vendor supplements the advisory. The correction is
   effective from 2026-11-20 but is only retrieved on 2026-11-23.
4. `staging` runs `demo-lib==1.1.0`, which falls inside the newly published
   `demo-lib>=1.0.0,<1.2.0` range. `prod` runs `demo-lib==1.3.0` and remains
   outside the range.

The closure ledger is not edited. The later view preserves both closures and
marks only `staging` for reopening.

## Evidence

- `locks/*.pylock.toml`: PEP 751 lockfiles for `prod` and `staging`.
- `audits/*.json`: saved `pip-audit --format=json` results at two instants.
- `advisories/EXAMPLE-2026-0001/*.json`: versioned advisory snapshots, each
  with both `effective_at` and `retrieved_at`.
- `bundle.json`: environment inventory, snapshot references, and closures.
- `views/`: generated comparable views and comparison.

## Run it

External, shareable views:

```console
$ pip-audit reconcile examples/temporal-reconciliation/bundle.json \
    --as-of 2026-11-23 \
    --visible-at 2026-11-15T10:00:00Z \
    --visible-at 2026-11-23T10:00:00Z \
    --audience external \
    --format json \
    --output examples/temporal-reconciliation/views/report.json \
    --write-views examples/temporal-reconciliation/views
```

Internal view with license-restricted reasons:

```console
$ pip-audit reconcile examples/temporal-reconciliation/bundle.json \
    --as-of 2026-11-23 \
    --visible-at 2026-11-23T10:00:00Z \
    --audience internal \
    --format markdown
```

Both external views use the same `as_of` date and the same schema. Diff
`views/view-1.json` and `views/view-2.json` to see the earlier evidence and
the later evidence. `views/comparison.json` lists the reopen work.

## Expected result

- The `2026-11-15` visibility view has no reopen work and both closures remain
  valid for the evidence visible at that instant.
- The `2026-11-23` visibility view contains one affected finding for
  `staging/demo-lib` and one `reopen` work item for
  `INC-2026-1114-staging`.
- `prod` remains closed because `demo-lib==1.3.0` is outside the corrected
  range.
- External views show `reason: null` with `reason_redacted: true` because
  the example reasons use `LicenseRef-Example-Internal`.
