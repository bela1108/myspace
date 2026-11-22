# Field Mapping Audit for the Merged Log Source

When a new log source merges several formerly independent fields into one, a
pySigma conversion only emits the target field name. The review team can no
longer tell which original detection condition a converted clause came from.
This package reconstructs that link and exposes where the mapping is reversible,
where it is many-to-one, and where conditional transformations only fire on part
of the rule paths.

## Layout

- `pipeline.py` - processing pipeline modelling the merged log source. It holds
  many-to-one merges, a reversible rename, a one-to-many fan-out, and a
  detection-item-gated transformation that runs on only some rule paths.
- `rules/` - sample Sigma rules on `product: newlog` covering every branch.
- `fake_backend.py` - `AuditBackend`, a `TextQueryTestBackend` subclass that
  captures every converted equality leaf (including IN-optimised and fan-out
  leaves) and globally matches each leaf back to its pre-pipeline condition.
- `auditor.py` - static mapping classification, dynamic collision evidence,
  conditional-path analysis, and Markdown report rendering.
- `tests/test_audit.py` - pytest coverage for all of the above.

## Run

From the repository root (the workspace root, on `sys.path`):

```
.venv/bin/python -m field_mapping_audit.auditor field_mapping_audit/rules
```

The report is printed and written to `field_mapping_audit/review_report.md`.

## What the report proves

- **Reversible** targets map back to a unique source (e.g. `newlog.user`).
- **Many-to-one** targets (`newlog.ip`, `newlog.path`) collapse distinct source
  fields, so the source identity is lost after conversion. Each collision gets a
  minimal witness set: one trace per distinct source field.
- **Fan-out** (`CommandLine` -> `newlog.cmd`, `newlog.cmd_raw`) expands one source
  into several targets; the backend records one leaf per target.
- **Conditional path** (`conditional-computername-tag`) only remaps wildcard
  `ComputerName` items; exact-value items keep their field name and are listed as
  skipped source paths.
