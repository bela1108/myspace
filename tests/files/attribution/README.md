# Attribution replay fixtures

These fixtures are small replay controls for the offline attribution tests.

| Case | Rules | Changes | Expected |
| --- | --- | --- | --- |
| `single_loss` | `alert_a`, `alert_b` match different events | archive `alert_a`, conversion-unsupported `alert_b` | each change loses the complete alert for its own event |
| `pair_loss` | `redundant_high_a` and `redundant_high_b` both match the same event | downgrade `redundant_high_a`, archive `redundant_high_b` | either change alone loses nothing; together they lose `phone` but retain `ticket` |

`routing.yml` maps `high` to `phone` and `ticket`, and everything from informational upward to
`ticket`.  The `ticket` queue is a `QueueKind.TICKET`; `phone` remains a notification queue.

The expected pair result is therefore a queue-level / notification loss, not an
`alert_lost` result: the backend ticket still exists.
