# pip-audit temporal reconciliation

As of: 2026-11-23

| View | Visible at | Audience | Reopen environments |
| --- | --- | --- | --- |
| earlier | 2026-11-15T10:00:00Z | external | none |
| later | 2026-11-23T10:00:00Z | external | staging |

### earlier

- As of: 2026-11-23
- Visible at: 2026-11-15T10:00:00Z
- Audience: external
- Reopen environments: none
- Redacted reasons: 4

#### Environment prod

Artifacts: demo-lib==1.3.0, other-lib==2.0.0

No affected artifacts in this view.

| Closure | Advisory | Decision status | Current status | Reopen | Decision reason |
| --- | --- | --- | --- | --- | --- |
| INC-2026-1114-prod | EXAMPLE-2026-0001 | not_affected | not_affected | no | (redacted: license restriction) |

#### Environment staging

Artifacts: demo-lib==1.1.0, other-lib==2.0.0

No affected artifacts in this view.

| Closure | Advisory | Decision status | Current status | Reopen | Decision reason |
| --- | --- | --- | --- | --- | --- |
| INC-2026-1114-staging | EXAMPLE-2026-0001 | not_affected | not_affected | no | (redacted: license restriction) |


### later

- As of: 2026-11-23
- Visible at: 2026-11-23T10:00:00Z
- Audience: external
- Reopen environments: staging
- Redacted reasons: 5

#### Environment prod

Artifacts: demo-lib==1.3.0, other-lib==2.0.0

No affected artifacts in this view.

| Closure | Advisory | Decision status | Current status | Reopen | Decision reason |
| --- | --- | --- | --- | --- | --- |
| INC-2026-1114-prod | EXAMPLE-2026-0001 | not_affected | not_affected | no | (redacted: license restriction) |

#### Environment staging

Artifacts: demo-lib==1.1.0, other-lib==2.0.0

| Artifact | Version | Advisory | Status | Effective | Retrieved | Conflict | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| demo-lib | 1.1.0 | EXAMPLE-2026-0001 | affected | 2026-11-20T00:00:00Z | 2026-11-23T09:00:00Z | no | (redacted: license restriction) |

| Closure | Advisory | Decision status | Current status | Reopen | Decision reason |
| --- | --- | --- | --- | --- | --- |
| INC-2026-1114-staging | EXAMPLE-2026-0001 | not_affected | affected | yes | (redacted: license restriction) |

| Action | Artifact | Advisory | Previous closure | Reason |
| --- | --- | --- | --- | --- |
| reopen | demo-lib | EXAMPLE-2026-0001 | INC-2026-1114-staging | (redacted: license restriction) |


## Why the earlier closure was valid

| Closure | Environment | Advisory | Decision status | Decision reason | Evidence |
| --- | --- | --- | --- | --- | --- |
| INC-2026-1114-prod | prod | EXAMPLE-2026-0001 | not_affected | (redacted: license restriction) | advisory snapshot 2026-11-14 |
| INC-2026-1114-staging | staging | EXAMPLE-2026-0001 | not_affected | (redacted: license restriction) | advisory snapshot 2026-11-14 |

## Work to reopen now

| Environment | Artifact | Advisory | Status | Previous closure | Reason |
| --- | --- | --- | --- | --- | --- |
| staging | demo-lib | EXAMPLE-2026-0001 | affected | INC-2026-1114-staging | (redacted: license restriction) |

## Status changes

| Environment | Artifact | Advisory | Before | After | Action |
| --- | --- | --- | --- | --- | --- |
| staging | demo-lib | EXAMPLE-2026-0001 | not_affected | affected | reopen |
