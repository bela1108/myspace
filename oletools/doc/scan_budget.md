# Budget-aware object scanning

The budget-aware API lets a gateway allocate parsing work per Office object
instead of letting one large document drain a batch-wide pool.

```python
from oletools.scan_backend import (
    OfficeScanBackend, ScanBudget, SyntheticContainer,
)

budget = ScanBudget(container=1000, macro=500, attachment=2000)
budget.allocate("large.docx", container=900, macro=450, attachment=1800)
budget.allocate("small.doc", container=100, macro=50, attachment=200)

backend = OfficeScanBackend()
result = backend.scan(container, budget)
if result.paused:
    print(result.covered_prefix, result.unprocessed)
    print(result.pause.category, result.pause.needed)

budget.top_up("small.doc", container=100, macro=50, attachment=200)
result = backend.resume(result)
```

Each object is charged independently for `container`, `macro` extraction and
`attachment` decoding. A scan only commits to the covered prefix when an
object completes all configured stages. When a stage does not fit, the
result keeps the findings proven so far and reports the unprocessed stage
unit range. Resuming reuses completed object verdicts, so topping up one
object cannot change another object that was already decided.

`VBA_Parser` accepts optional `budget` and `object_id` arguments, and
`oleobj.process_file`/`rtfobj.process_file` accept the same optional
accounting for attachment decoding.
