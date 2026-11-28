# Read-only evidence inventory

`asn1crypto.inventory` walks CMS and PKCS#12 wrapper trees without changing the
input bytes. It is useful for triaging an old evidence bundle that contains a
mix of `ContentInfo`, `SignedData`, `EnvelopedData`, PFX, `AuthenticatedSafe`
and `SafeBag` structures.

```python
from asn1crypto.inventory import inventory

with open('evidence.der', 'rb') as f:
    result = inventory(f.read(), max_nodes=100, max_bytes=65536)

for entry in result.entries:
    if entry.opaque:
        print(entry.path, entry.kind, entry.reason)
    elif entry.has_unvisited_children:
        print(entry.path, entry.kind, 'children not reviewed')
```

The result is a dict with attribute access. Important keys are `entries`,
`roots`, `complete`, `truncated`, `stop_reason`, `stop_detail`, and
`independent_siblings`.

Each entry contains:

 - `path`, `parent`, `children` and `depth` for the structural position
 - `kind`, `classification`, `status`, `openable` and `opaque` for triage
 - `offset`, `end_offset`, `header_length`, `content_length` and `source` for
   provenance in the original bundle
 - `complete`, `unvisited_children` and `has_unvisited_children` for budget
   truncation

## Budgets

`max_nodes` limits the number of reviewed structural nodes. `max_bytes` limits
the number of raw bytes reviewed. A container costs its header; its children
are charged as they are visited. An opaque payload is kept as a single layer
and its contents are not opened, but its encoded length still counts toward
`max_bytes`.

A parent is appended before its children. If a budget is reached while
descending, the confirmed parent is retained together with its source range,
and `complete` becomes `False`. `unvisited_children` (also available as
`has_unvisited_children` and `has_more_children`) then reports that child items
remain. `stop_detail` names the retained parent explicitly.

Independent sibling items are never discarded just because one branch could
not be opened. When a cutoff boundary leaves siblings that can still be
reviewed, `independent_siblings` and the parent's `sibling_continuation` record
why those items are independent. Unreadable child values are recorded in
`errors`, while siblings with known boundaries continue to be reviewed.

## Opaque layers

Encrypted CMS content, encrypted PKCS#8 keys, compressed CMS content and raw
embedded data are retained as `opaque=True` entries with a `reason` such as
`encrypted`, `compressed` or `raw`. They are not decrypted or decompressed by
the inventory tool.
