# Testimony Dependency Receipts

`regipy.testimony` provides an opt-in provenance layer for offline plugin exports.
It does not change the default JSON, CSV, or plugin output.

A receipt binds one forensic conclusion/testimony to:

- `hive_value_ranges`: exact registry key/value coordinates, optional byte ranges,
  and SHA-256 fingerprints of the observed bytes or canonical decoded values;
- `plugin`: plugin name and version;
- `caller_interpretation`: the caller-owned interpretation name, version, and
  optional definition (for example FILETIME display timezone);
- `conclusion_sha256`: a digest of the conclusion stored in the export.

Receipt IDs and export bytes are canonical JSON SHA-256 hashes, so the same
synthetic or real key/value batch produces the same receipt and file.

## Create an export

```python
from regipy.testimony import ReceiptRecorder, build_offline_export, write_offline_export

recorder = ReceiptRecorder(
    plugin_name="run_activity",
    plugin_version="1.0.0",
)
dependency = recorder.observe(
    r"Software\Cases\Alpha",
    "LastRunTime",
    data=raw_value_bytes,
    value_type="REG_QWORD",
)
conclusion = {"testimony_id": "T-RUN-TIME", "last_run": "2025-01-01T00:00:00+00:00"}
receipt = recorder.receipt(
    "T-RUN-TIME",
    conclusion,
    [dependency],
    interpretation_name="run_time_policy",
    interpretation_version="1.0.0",
    interpretation_definition={"display_offset": "Z"},
)
export = build_offline_export([conclusion], [receipt])
write_offline_export(export, "run-export.json")
```

## Audit after an interpretation change

```python
from regipy.testimony import ChangeNotice, DependencyScope, audit_export

report = audit_export(
    "run-export.json",
    active_plugins={"run_activity": "2.0.0"},
    interpretations=[
        {"name": "run_time_policy", "version": "1.0.0"},
        {"name": "run_time_policy", "version": "2.0.0"},
    ],
    changes=[
        ChangeNotice(
            change_id="TIME-001",
            plugin_name="run_activity",
            old_plugin_versions=("1.0.0",),
            interpretation_name="run_time_policy",
            old_interpretation_version="1.0.0",
            affected_scopes=(DependencyScope(value_name="LastRunTime"),),
            reason="FILETIME display basis changed from UTC to UTC+08:00",
        )
    ],
)

print([item.testimony_id for item in report.suspended])
print([item.testimony_id for item in report.reusable])
print(report.to_markdown())
```

An empty `affected_scopes` list is intentionally conservative and suspends every
testimony produced by a matching plugin. Supply key/value/component scopes to keep
unrelated testimonies reusable.

Old exports remain ordinary JSON and `read_offline_export()` still loads their
conclusions. If the exact `name@version` interpretation used by a receipt is not
registered in the auditing environment, the finding is reported as
`missing_interpretation_version`; it remains readable but is not marked reusable.

The same audit is available from the command line:

```bash
regipy-receipt-audit run-export.json \
  --active-plugins active-plugins.json \
  --interpretations interpretations.json \
  --changes changes.json \
  --format markdown
```

Use `--check` to exit non-zero when the report has suspended, invalid, or
missing-interpretation findings.
