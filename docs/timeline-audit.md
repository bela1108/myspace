# Offline timeline audit

The `cyclonedx.timeline` package audits evidence taken from CycloneDX BOMs
produced at different lifecycle stages.  It is fully offline: it reads JSON or
XML documents, extracts dated lifecycle/component evidence, resolves
caller-supplied ordering claims, and checks whether all claims can hold at the
same time.

## Command line

```console
python -m cyclonedx.timeline stage-a.json stage-b.xml \
    --claim "phase:delivery before phase:installation"
```

Use `--constraints claims.json` for larger claim sets, `--phase-order` to add
the standard predefined lifecycle order (`design`, `pre-build`, `build`,
`post-build`, `operations`, `discovery`, `decommission`), and
`--format text` for a human-readable summary.  The default output is stable
JSON.  A successful audit exits with status 0 even when it reports a conflict;
add `--fail-on-conflict` to exit with status 1 in that case.

## Evidence extraction

One dated evidence item is created for each of:

- the BOM manifest itself (`metadata.timestamp`);
- each declared lifecycle phase or named lifecycle;
- each component (`metadata.component` and `components`, recursively);
- each component evidence occurrence;
- event-like or timestamp-bearing properties (`event:timestamp`, `occurredAt`,
  `deliveredAt`, and similar names).

A timestamp with a seconds component is an instant.  A date-only timestamp such
as `2026-11-20` denotes the whole UTC day, from `00:00:00.000000` through
`23:59:59.999999`.  The audit therefore keeps every legal placement inside that
day instead of silently treating it as midnight.  A minute-only or hour-only
timestamp is treated as the corresponding interval.  Timestamps with no offset
are interpreted as UTC.

Evidence IDs are derived from the BOM identity (`serialNumber` and `version`)
and from stable content keys.  They do not contain load indexes or file-system
paths, so shuffling the input file order does not change any evidence ID.

## Claims

A claim document may contain a list, or an object with a `constraints`, `order`,
`claims`, or `relations` list:

```json
{
  "constraints": [
    {"before": "phase:delivery", "after": "phase:installation", "id": "builder-claim"},
    {"from": "bom:urn:uuid:2222...@1", "to": "phase:delivery", "relation": "before"}
  ]
}
```

Text claim files and inline claims are also accepted:

```text
phase:delivery < phase:installation
phase:installation after phase:delivery
```

Supported relations are `before`, `after`, `not_before`, `not_after`, and
`same`.  A claim may use any of these selector forms:

- an exact evidence ID;
- `phase:NAME` or `stage:NAME` - the manifests that declare that lifecycle;
- `lifecycle:NAME` - the per-BOM lifecycle evidence entries;
- `bom:IDENTIFIER`, `serial:IDENTIFIER`, or `file:BASENAME` - a manifest;
- `component:REF`, `component:NAME`, or `component:NAME@VERSION`;
- `occurrence:LOCATION` or `occurrence:BOM_REF`;
- `property:NAME`;
- `evidence:ID`.

A selector without a prefix is matched against lifecycle names, component
identities, occurrence locations, file names, and evidence IDs.  If a selector
matches several evidence items, the claim is expanded to every applicable pair.

## Conflict reporting

The audit combines all claims with every extracted time interval.  If the
conjunction is satisfiable, `order.entailed` lists relations that hold in every
legal arrangement, `order.possible` lists relations that hold in at least one,
and `order.ambiguous` lists pairs for which both directions are legal.  When
the stage manifests are few enough, `order.legalOrders` enumerates all stage
orders that satisfy the entailed precedence, and `legalOrdersTruncated` says
whether the enumeration hit its safety cap.
`witness` gives one concrete set of times that satisfies all claims.

If the conjunction is unsatisfiable, the report contains `minimalConflicts`
with a deterministic minimum-cardinality set of contradictory claims:

```json
{
  "constraintIds": ["reverse"],
  "evidenceIds": ["bom:...#manifest", "bom:...#manifest"],
  "bomIds": ["bom:...@1", "bom:...@1"],
  "sources": ["builder.json", "installer.json"],
  "reason": "evidence-order-conflict"
}
```

Each conflict names the claims, the evidence endpoints, the BOMs, and the source
files.  The reason is `order-cycle` when the claims alone form a cycle, and
`evidence-order-conflict` when a claim contradicts the dated evidence bounds.
Unrelated BOMs are not included in a minimal conflict.

## Python API

```python
from cyclonedx.timeline import audit_timelines

report = audit_timelines(
    ["builder.json", "installer.json"],  # paths, raw JSON/XML bytes, or dicts
    [{"before": "phase:delivery", "after": "phase:installation", "id": "builder-claim"}],
)
data = report.to_json()
print(data["consistent"], data["minimalConflict"])
```

Use `collect_evidence(paths)` to inspect the extracted evidence without
resolving claims.
