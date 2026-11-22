# Advisory withdrawal re-audit

This example answers a narrow question: after an advisory is withdrawn, which
assets are provably closed, which are still affected, and which cannot be
decided from the supplied evidence?

The audit uses CPE 2.3 name matching and a three-valued evaluation of the
advisory's CPE logical expression. Boolean matching is not sufficient here:
`NO_MATCH` is proof of absence only when the inventory record is complete and
every relevant attribute is provably disjoint. A wildcard or missing component
remains `UNKNOWN`.

## Inputs

- `data/advisory.json`: the withdrawn advisory, its applicability interval, and
  an NVD-style CPE logical expression.
- `data/scope.json`: the asset identifiers explicitly approved by the caller,
  plus per-family coverage evidence. Coverage is complete only when the
  evidence says so and its `covered_from`/`covered_to` interval covers the
  advisory interval.
- `data/inventory_before.json`: the small inventory observed before withdrawal.
- `data/inventory_after.json`: the small inventory observed after withdrawal.
- `data/replacements.json`: verified component replacement credentials.

## Run

```bash
python examples/withdrawal_audit/run_audit.py
```

Write the report to a file:

```bash
python examples/withdrawal_audit/run_audit.py --output report.json
```

## Decision rules

- `web-01` is `confirmed_closed`: the pre-withdrawal snapshot matched the
  advisory, the verified credential `CHG-2026-1116-0042` proves that
  `widget:1.2` was replaced by `widget:2.0`, the new CPE is provably disjoint,
  and the post-withdrawal snapshot contains the new CPE.
- `db-01` is `still_affected`: both snapshots match the advisory, and no
  replacement credential was submitted.
- `edge-01` is `insufficient_evidence`: the installation manifest is
  incomplete and the missing application slot prevents a match or a non-match.
  The `edge` family's coverage evidence is also incomplete, so the family
  cannot be excluded.

A family is never excluded merely because no asset matched. Exclusion requires
complete family inventory evidence whose covered interval includes the whole
advisory applicability interval. Out-of-scope assets are reported separately
and are not reclassified as unaffected.

## Result

The bundled inventory intentionally leaves three different results:

- one `confirmed_closed` asset (`web-01`);
- one `still_affected` asset (`db-01`);
- one `insufficient_evidence` asset (`edge-01`).

Every result includes an ordered `basis` list and evidence references so the
scope can be replayed and challenged.
