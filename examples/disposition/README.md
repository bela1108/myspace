# Offline disposition checklist example

This directory contains a synthetic two-device case. It demonstrates:

- repeated policy value overwrites on PC-RELEASE-02, ending in a compliant state;
- the last event on PC-ROLLBACK-01 being a rollback with no later compliant evidence;
- a stale approval that cannot authorize the rolled-back state;
- cross-device duplicate evidence values grouped by SHA-256 while preserving each device decision;
- source-file SHA-256 and JSON/CSV/JSONL approval locators for audit review.

Run from the repository root:

    python -m regipy.disposition \
      examples/disposition/case_manifest.sample.json \
      -o examples/disposition/RELEASE_LIST.sample.md \
      --json-output /tmp/release-list.json

For a real case, copy the JSON files and replace:

1. device IDs and every timestamped plugin observation;
2. the policy ID/version, expected values, and evidence TTL;
3. the independent approval record file and its record IDs/locators.

If policy_version is missing, the report keeps the device under preservation and
lists the exact baseline, export, change/rollback ticket, and versioned approval
materials that must be supplied before release.

The manifest can also read standard regipy-plugins-run JSON through
evidence_snapshots[].plugin_output, or run regipy directly against an offline
hive through evidence_snapshots[].hive_path plus optional log1/log2.
