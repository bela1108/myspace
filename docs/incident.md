# Offline Credential-Incident Recomputation

`detect_secrets.incident` re-derives, entirely offline, who is responsible for
each detect-secrets finding and how much review time remains, by replaying an
explicit event history over fixed inputs.

The same inputs always reproduce the same decisions, and every decision is
appended to an immutable audit trail so past decisions remain queryable even
after owners, paths or exemptions change.

## Inputs

One JSON document (see `test_data/incident/handoff_case.json`) with:

- `findings`: pre-existing detect-secrets findings. Each entry keeps its
  natural identity (`type` + `hashed_secret`) plus a caller-assigned stable
  `finding_id`, `filename` and `line_number`.
- `ownership`: the explicit repository ownership history. Every record has a
  `path_prefix`, a `team`, a half-open validity window (`effective_from`
  inclusive, `effective_to` exclusive, `null` means still in force) and a
  `record_id`. The longest matching prefix in force at the event time wins.
- `exemptions`: finite-lived exemptions. Each is bound to both a `finding_id`
  and the exact `path` the finding occupied when granted, with `granted_at`,
  `expires_at` and an optional `revoked_at`.
- `events`: the ordered timeline (see below).
- `review_sla_days`: the baseline review window applied when a finding is
  first registered (default 30).

## Events

| `event_type` | Meaning |
| --- | --- |
| `finding_introduced` | Registers a finding occurrence and assigns its owner and SLA review deadline. |
| `code_moved` | Moves the occurrence to a new path; responsibility is re-resolved from the ownership history for the new path, the review deadline carries over, and exemptions do not travel. |
| `finding_forked` | Copies a finding to a second path; the two occurrences become independent and can never share one exemption. |
| `ownership_changed` | Re-attributes responsibility (from the ownership table or an explicit team) without moving code; the review deadline is unchanged. |
| `exemption_granted` | Attaches a time-limited exemption and extends the review deadline to its expiry when later. |
| `exemption_revoked` | Withdraws an exemption early; a suppressed occurrence reopens. |
| `suppress` | Attempts to close one occurrence. Allowed only with a live exemption bound to that exact finding and path; otherwise the attempt is recorded as `suppression_rejected`. |

## Guarantees

- **Traceable responsibility.** Every audit entry cites the ownership record
  (`ownership_record_id`) or exemption record (`exemption_id`) the decision
  used, along with the team and the reason.
- **Exemptions stay path-bound.** After a move or fork, an exemption glued to
  the old path cannot close the new occurrence, so one expired exemption can
  never silence two sibling occurrences.
- **Rejections are audited.** A failed suppression is a first-class audit
  entry rather than an exception, keeping the failed attempt reviewable.
- **Deterministic replay.** Events are sorted by `(timestamp, event_id)`;
  duplicate event ids and non-monotonic reuse of an engine are rejected.

## Running

```bash
python -m detect_secrets.incident test_data/incident/handoff_case.json \
    --report report.json --text
```

The JSON report contains a `summary`, the current `findings` (one entry per
occurrence, including owner, ownership record, review deadline and state) and
the full `audit_trail`. The `--text` flag additionally prints a compact
human-readable view on stderr.
