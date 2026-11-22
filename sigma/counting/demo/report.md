# Counting Contract Check Report

- Correlation rules checked: 4 (3 determined, 1 undetermined)
- Count-based correlations: 3 | unique-value correlations: 1

## Count-based correlations

### Privileged operation burst (count based) (`priv_op_burst_count`) — determined

- Location: `priv_op_burst_count`
- Type: `event_count` on basis `count`
- Timespan: 600s | threshold: `{"operator": "gte", "count": 6}`

| Branch | Log source | Verdict | Identity fields | Time precision | Reason |
| --- | --- | --- | --- | --- | --- |
| app_privileged_operation | windows/security | determined | EventRecordID | 1s | Identity provable via EventRecordID; time precision 1s within timespan. |

| Scenario | Verdict | Raw events | De-dup count | Unique values | Naive alert | Contract alert |
| --- | --- | --- | --- | --- | --- | --- |
| single_write | determined | 5 | 5 | n/a | no | no |
| dual_write | determined | 10 | 5 | n/a | yes | no |
| missing_identity | undetermined | 5 | n/a | n/a | no | undetermined |

**Threshold changes (attributed alerts):**
- Rule `priv_op_burst_count` in scenario `dual_write` (count): naive=alert -> contract=no alert.

### Privileged ops across two log sources (one branch without contract) (`priv_op_cross_source_temporal`) — determined

- Location: `priv_op_cross_source_temporal`
- Type: `temporal` on basis `count`
- Timespan: 900s | threshold: `{"operator": "gte", "count": 2}`

| Branch | Log source | Verdict | Identity fields | Time precision | Reason |
| --- | --- | --- | --- | --- | --- |
| app_privileged_operation | windows/security | determined | EventRecordID | 1s | Identity provable via EventRecordID; time precision 1s within timespan. |
| app_audit_operation | windows/app-audit | determined | EventRecordID, Hostname | 5s | Identity provable via EventRecordID, Hostname; time precision 5s within timespan. |

| Scenario | Verdict | Raw events | De-dup count | Unique values | Naive alert | Contract alert |
| --- | --- | --- | --- | --- | --- | --- |
| single_write | determined | 5 | 5 | n/a | yes | yes |
| dual_write | determined | 10 | 5 | n/a | yes | yes |
| missing_identity | undetermined | 5 | n/a | n/a | yes | undetermined |

### Privileged op followed by un-contracted legacy event (`priv_op_with_legacy_temporal`) — undetermined

- Location: `priv_op_with_legacy_temporal`
- Type: `temporal` on basis `count`
- Timespan: 900s | threshold: `{"operator": "gte", "count": 2}`

| Branch | Log source | Verdict | Identity fields | Time precision | Reason |
| --- | --- | --- | --- | --- | --- |
| app_privileged_operation | windows/security | determined | EventRecordID | 1s | Identity provable via EventRecordID; time precision 1s within timespan. |
| app_generic_legacy | windows/generic-legacy | undetermined | n/a | n/a | No counting contract declared for log source; dual-write duplicates cannot be distinguished from distinct operations. |

| Scenario | Verdict | Raw events | De-dup count | Unique values | Naive alert | Contract alert |
| --- | --- | --- | --- | --- | --- | --- |
| single_write | determined | 5 | 5 | n/a | yes | yes |
| dual_write | determined | 10 | 5 | n/a | yes | yes |
| missing_identity | undetermined | 5 | n/a | n/a | yes | undetermined |

## Unique-value correlations

### Distinct users using privileges (unique value based) (`priv_op_distinct_users`) — determined

- Location: `priv_op_distinct_users`
- Type: `value_count` on basis `unique_value`
- Timespan: 600s | threshold: `{"operator": "gte", "count": 5, "field": "User"}`

| Branch | Log source | Verdict | Identity fields | Time precision | Reason |
| --- | --- | --- | --- | --- | --- |
| app_privileged_operation | windows/security | determined | EventRecordID | 1s | Identity provable via EventRecordID; time precision 1s within timespan. |

| Scenario | Verdict | Raw events | De-dup count | Unique values | Naive alert | Contract alert |
| --- | --- | --- | --- | --- | --- | --- |
| single_write | determined | 5 | 5 | 3 | no | no |
| dual_write | determined | 10 | 5 | 3 | no | no |
| missing_identity | undetermined | 5 | n/a | 3 | no | undetermined |
