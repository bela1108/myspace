# Offline Shift Handover Audit - Reference-Only Chains

## Shift

| Field | Value |
| --- | --- |
| Shift | 2026-11-23-night |
| Window | 2026-11-23T00:00:00+08:00 to 2026-11-23T08:00:00+08:00 |
| On duty | night-responder, night-observer |
| Generated at | 2026-11-23T00:00:00+08:00 |
| Rule states | 2 actionable, 1 notifiable, 1 no substitute |
| Reference-only chains | 1 |

Permissions are keyed by rule identity (Sigma UUID plus content digest). Name and title are never used as permission keys.

Filter: reference-only notification chains only. Summary counts still describe the full shift.

## Duplicate names that were not merged

- name: midnight-logon-anomaly
- title: Midnight Logon Anomaly

Each duplicate is audited as a separate identity. A permission granted to one identity does not apply to the other.

## Processing branches

| Branch | Items | State | Countersign role | Reason |
| --- | --- | --- | --- | --- |
| legacy-edr | legacy-edr-enrich | disabled | soc-tier2-legacy | Legacy EDR connector is under maintenance. |

## Approved substitutes

| Approval | For role | Substitute | Effective | Reason |
| --- | --- | --- | --- | --- |
| sub-legacy-tier2 | legacy-tier2 | night-observer | yes | approved_and_on_duty |

## Rule audit

| Identity | Title / name | State | Notify | Handle | No substitute | Countersign | Chain | Reference only |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| uuid:33333333-3333-4333-8333-333333333333:a6cbd234d640c695 | Legacy EDR Heartbeat / legacy-edr-heartbeat | 可通知 (notifiable) | yes | no | no | soc-tier2-legacy | chain:a6ee6b6543a3f9b2 | yes |

## Rules in detail

### Legacy EDR Heartbeat (`uuid:33333333-3333-4333-8333-333333333333:a6cbd234d640c695`)

- Identity: `uuid:33333333-3333-4333-8333-333333333333:a6cbd234d640c695`
- Sigma UUID: 33333333-3333-4333-8333-333333333333
- Name: legacy-edr-heartbeat
- Source: examples/handover_audit/rules/legacy-edr-heartbeat.yml
- State: 可通知 (notifiable)
- Can notify: yes
- Can handle: no
- No substitute: no
- Processing chain: midnight-handover -> legacy-edr-enrich
- Branches: legacy-edr
- Disabled branches: legacy-edr
- Field mappings: ParentImage -> process.parent.executable
- Recipients: night-responder (duty; notify/handle)
- Countersign roles: soc-tier2-legacy
- Notification chain: `chain:a6ee6b6543a3f9b2` (release basis: no; reference only: yes)
- Release blockers: disabled_branch_requires_countersign:legacy-edr:soc-tier2-legacy
- Warnings: processing branch legacy-edr is temporarily disabled; handling is suspended until countersign

## Reference-only notification chains

> These chains are reference material only. They MUST NOT be used as a shift release basis.

### chain:a6ee6b6543a3f9b2

- Rule: Legacy EDR Heartbeat (`uuid:33333333-3333-4333-8333-333333333333:a6cbd234d640c695`)
- State: 可通知 (notifiable)
- Reference only: yes
- Release basis: no
- Recipients: night-responder (duty; notify/handle)
- Handler grants: night-responder (duty; notify/handle)
- Countersign roles: soc-tier2-legacy
- Blockers: disabled_branch_requires_countersign:legacy-edr:soc-tier2-legacy

## Audit warnings

- rule name midnight-logon-anomaly is shared by multiple distinct identities; permissions remain separate
- rule title Midnight Logon Anomaly is shared by multiple distinct identities; permissions remain separate
