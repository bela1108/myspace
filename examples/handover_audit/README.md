# Offline Shift Handover Audit Demo

This demo audits one midnight shift against four Sigma rules. It answers three
questions per rule:

- `notifiable` (可通知): the shift can be woken with a reference notification.
- `actionable` (可处置): the shift holds an explicit handling permission.
- `no_substitute` (无替代): a required notify or handle role is off duty and no
  approved substitute covers the rule.

The audit uses a content-backed pySigma rule identity: Sigma UUID plus content
digest. Rule names and titles are display attributes only. This matters because
`midnight-logon-anomaly.yml` and `midnight-logon-anomaly-shadow.yml` share the
same title and the same `name`, but have different UUIDs and different
detections. The observer may handle the shadow rule through an approved
substitute, but that grant does not leak to the primary rule.

## Files

- `rules/`: four Sigma rules, including two same-name rules.
- `pipeline.yml`: pySigma processing pipeline with two branches.
- `shift.yml`: explicit duties, on-duty roles, and one approved substitute.
- `run_demo.py`: loads the files and prints Markdown or JSON.
- `report.md`: generated full report.
- `report.json`: generated machine-readable report.
- `report-reference-only.md`: generated filter output for reference-only chains.

## Run

From the repository root:

```bash
python examples/handover_audit/run_demo.py
python examples/handover_audit/run_demo.py --reference-only
python examples/handover_audit/run_demo.py --format json
python examples/handover_audit/run_demo.py --format json --reference-only
```

Regenerate the checked-in artifacts with:

```bash
python examples/handover_audit/run_demo.py --output examples/handover_audit/report.md
python examples/handover_audit/run_demo.py --format json --output examples/handover_audit/report.json
python examples/handover_audit/run_demo.py --reference-only --output examples/handover_audit/report-reference-only.md
```

## Expected states

| Rule | State | Why |
| --- | --- | --- |
| Midnight Logon Anomaly | actionable | Responder has notify and handle; observer is notified only. |
| Midnight Logon Anomaly (shadow) | actionable | Legacy tier2 handler is covered by an approved substitute. |
| Legacy EDR Heartbeat | notifiable | The disabled `legacy-edr` branch suspends handling until countersign. |
| Weekend Specialist Only | no_substitute | The handler role is off duty and no approved substitute covers it. |

## Reference-only chain

The `Legacy EDR Heartbeat` chain traverses the temporarily disabled
`legacy-edr` processing branch. The report keeps its recipients for reference,
marks `reference_only: true` and `release_basis: false`, and names
`soc-tier2-legacy` as the historical role that must countersign.

Filter it with:

```bash
python examples/handover_audit/run_demo.py --reference-only
```

The output starts with a warning that the chain must not be used as a shift
release basis.

## Safety properties

- Permissions are keyed by identity, never by `name` or `title`.
- Selectors reject `name` and `title` permission grants.
- An ambiguous Sigma UUID with different rule contents is rejected instead of
  merging permissions.
- A substitute counts only when it is approved, covers the entire shift, is on
  duty, and explicitly carries the required notify or handle authority.
- A disabled branch always names a historical countersign role; omitting that
  role is a configuration error.
- A notification chain without an authorized handler is reference-only.
