# Offline Shift Handover Audit

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
| uuid:22222222-2222-4222-8222-222222222222:3aa3c67b1d6c8ff7 | Midnight Logon Anomaly / midnight-logon-anomaly | 可处置 (actionable) | yes | yes | no |  | chain:215b0dca40d2d024 | no |
| uuid:11111111-1111-4111-8111-111111111111:47d719ef7214b4ff | Midnight Logon Anomaly / midnight-logon-anomaly | 可处置 (actionable) | yes | yes | no |  | chain:336f881c195e41fa | no |
| uuid:44444444-4444-4444-8444-444444444444:13ccb5e72c9466ba | Weekend Specialist Only / weekend-specialist-only | 无替代 (no_substitute) | no | no | yes |  | chain:e563cd6731ff689b | no |

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

### Midnight Logon Anomaly (`uuid:22222222-2222-4222-8222-222222222222:3aa3c67b1d6c8ff7`)

- Identity: `uuid:22222222-2222-4222-8222-222222222222:3aa3c67b1d6c8ff7`
- Sigma UUID: 22222222-2222-4222-8222-222222222222
- Name: midnight-logon-anomaly
- Source: examples/handover_audit/rules/midnight-logon-anomaly-shadow.yml
- State: 可处置 (actionable)
- Can notify: yes
- Can handle: yes
- No substitute: no
- Processing chain: midnight-handover -> -
- Branches: -
- Disabled branches: -
- Recipients: night-observer (duty+substitute; notify/handle)
- Countersign roles: -
- Notification chain: `chain:215b0dca40d2d024` (release basis: yes; reference only: no)
- Warnings: rule name or title is shared with another distinct rule identity; permissions were not merged

### Midnight Logon Anomaly (`uuid:11111111-1111-4111-8111-111111111111:47d719ef7214b4ff`)

- Identity: `uuid:11111111-1111-4111-8111-111111111111:47d719ef7214b4ff`
- Sigma UUID: 11111111-1111-4111-8111-111111111111
- Name: midnight-logon-anomaly
- Source: examples/handover_audit/rules/midnight-logon-anomaly.yml
- State: 可处置 (actionable)
- Can notify: yes
- Can handle: yes
- No substitute: no
- Processing chain: midnight-handover -> normalize-logon-fields
- Branches: -
- Disabled branches: -
- Field mappings: UserName -> user.name, ComputerName -> host.name
- Recipients: night-responder (duty; notify/handle), night-observer (duty; notify/reference-only)
- Countersign roles: -
- Notification chain: `chain:336f881c195e41fa` (release basis: yes; reference only: no)
- Warnings: rule name or title is shared with another distinct rule identity; permissions were not merged

### Weekend Specialist Only (`uuid:44444444-4444-4444-8444-444444444444:13ccb5e72c9466ba`)

- Identity: `uuid:44444444-4444-4444-8444-444444444444:13ccb5e72c9466ba`
- Sigma UUID: 44444444-4444-4444-8444-444444444444
- Name: weekend-specialist-only
- Source: examples/handover_audit/rules/weekend-specialist-only.yml
- State: 无替代 (no_substitute)
- Can notify: no
- Can handle: no
- No substitute: yes
- Processing chain: midnight-handover -> -
- Branches: -
- Disabled branches: -
- Recipients: -
- Uncovered duties: weekend-specialist-only (role weekend-specialist: role_off_duty_no_approved_substitute)
- Countersign roles: -
- Notification chain: `chain:e563cd6731ff689b` (release basis: no; reference only: no)
- Release blockers: no_notification_recipients, no_authorized_handler, required_handler_has_no_substitute

## Notification chains

### chain:a6ee6b6543a3f9b2

- Rule: Legacy EDR Heartbeat (`uuid:33333333-3333-4333-8333-333333333333:a6cbd234d640c695`)
- State: 可通知 (notifiable)
- Reference only: yes
- Release basis: no
- Recipients: night-responder (duty; notify/handle)
- Handler grants: night-responder (duty; notify/handle)
- Countersign roles: soc-tier2-legacy
- Blockers: disabled_branch_requires_countersign:legacy-edr:soc-tier2-legacy

### chain:215b0dca40d2d024

- Rule: Midnight Logon Anomaly (`uuid:22222222-2222-4222-8222-222222222222:3aa3c67b1d6c8ff7`)
- State: 可处置 (actionable)
- Reference only: no
- Release basis: yes
- Recipients: night-observer (duty+substitute; notify/handle)
- Handler grants: night-observer (duty+substitute; notify/handle)
- Countersign roles: -

### chain:336f881c195e41fa

- Rule: Midnight Logon Anomaly (`uuid:11111111-1111-4111-8111-111111111111:47d719ef7214b4ff`)
- State: 可处置 (actionable)
- Reference only: no
- Release basis: yes
- Recipients: night-responder (duty; notify/handle), night-observer (duty; notify/reference-only)
- Handler grants: night-responder (duty; notify/handle)
- Countersign roles: -

### chain:e563cd6731ff689b

- Rule: Weekend Specialist Only (`uuid:44444444-4444-4444-8444-444444444444:13ccb5e72c9466ba`)
- State: 无替代 (no_substitute)
- Reference only: no
- Release basis: no
- Recipients: -
- Handler grants: -
- Countersign roles: -
- Blockers: no_notification_recipients, no_authorized_handler, required_handler_has_no_substitute

## Audit warnings

- rule name midnight-logon-anomaly is shared by multiple distinct identities; permissions remain separate
- rule title Midnight Logon Anomaly is shared by multiple distinct identities; permissions remain separate
