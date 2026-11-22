# Offline handover audit: shift-night-2026-11-23

- Audit time: `2026-11-23T02:10:00+08:00`
- Rules audited: 4
- Release-basis chains: 2
- Reference-only chains: 1

## Status summary

| Status | Count |
| --- | ---: |
| `notifiable` | 1 |
| `actionable` | 2 |
| `no_substitute` | 1 |

## Notification chains

| Chain | Rule | Rule ID | Status | Notify | Handle | Release basis | Countersign |
| --- | --- | --- | --- | --- | --- | --- | --- |
| chain-11111111-1111-4111-8111-111111111111 | Suspicious PowerShell Encoded Command | `11111111-1111-4111-8111-111111111111` | `actionable` | bob (security-analyst), alice (endpoint-commander) | alice (endpoint-commander) | yes | - |
| chain-22222222-2222-4222-8222-222222222222 | Suspicious PowerShell Encoded Command | `22222222-2222-4222-8222-222222222222` | `notifiable` | bob (security-analyst), alice (endpoint-commander) | alice (endpoint-commander) | no | deputy-endpoint-lead |
| chain-33333333-3333-4333-8333-333333333333 | Cloud Administrator Role Granted | `33333333-3333-4333-8333-333333333333` | `actionable` | bob (security-analyst) | frank (cloud-commander, substitute) | yes | - |
| chain-44444444-4444-4444-8444-444444444444 | Impossible Travel Sign-in | `44444444-4444-4444-8444-444444444444` | `no_substitute` | bob (security-analyst) | - | no | - |

## Reference-only chains

- `chain-22222222-2222-4222-8222-222222222222` (Suspicious PowerShell Encoded Command, `22222222-2222-4222-8222-222222222222`): reference only; do **not** use this chain as an on-call release basis.

## Closed branches and countersigns

- `chain-22222222-2222-4222-8222-222222222222` / `endpoint-mirror-release`: temporarily_disabled; countersign role: `deputy-endpoint-lead`.

## Warnings

- Title 'Suspicious PowerShell Encoded Command' is shared by 2 rule UUIDs; permissions and chains remain separate.
- Approved substitution RFC-2026-1122-09 for role 'identity-commander' is outside its validity window at audit time.
