# Historical snapshot evidence

Registry **values do not have their own timestamps**. A key `LastWrite` value
belongs to the key (NK record) and only says when that key record was last
written. Treating it as the time of a RecentDocs document, a TypedPaths entry,
or any other individual value breaks down as soon as snapshots from different
acquisitions are merged: one value can change while another value under the
same key stays byte-identical, and a key can be deleted and recreated under the
same name with an unrelated value history.

`regipy.snapshots` builds per-value evidence timelines from an ordered set of
hive snapshots. The key clock and the value content evidence are reported as
separate facts.

## Rules

- Snapshot observation times come from the investigator. They are never taken
  from a key `LastWrite`.
- A value change is reported as the interval between the two surrounding
  snapshots, for example `(2023-01-01T00:00:00+00:00, 2023-02-01T00:00:00+00:00]`.
  No exact value modification time is invented.
- Values with identical content across consecutive snapshots form one content
  segment. `first_seen` and `last_seen` describe when the content was observed,
  not when it was created.
- If only the key clock changes and every tracked value is byte-identical, the
  change is reported as a `key_only_change`. It proves that the parent key
  changed and explicitly does not prove any child value change.
- If a key is absent in at least one snapshot between two present snapshots,
  the key is treated as deleted and recreated. Old-instance and new-instance
  values are never merged across that breakpoint.

## Python API

```python
import datetime as dt

from regipy.registry import RegistryHive
from regipy.snapshots import Snapshot, compare_snapshots

snapshots = [
    Snapshot.from_hive(
        RegistryHive("NTUSER-2023-01.DAT"),
        timestamp=dt.datetime(2023, 1, 1, tzinfo=dt.timezone.utc),
        name="2023-01",
    ),
    Snapshot.from_hive(
        RegistryHive("NTUSER-2023-02.DAT"),
        timestamp=dt.datetime(2023, 2, 1, tzinfo=dt.timezone.utc),
        name="2023-02",
    ),
]

result = compare_snapshots(snapshots)  # recentdocs + typed_paths by default
```

Use a single plugin or arbitrary key paths when needed:

```python
from regipy.plugins.ntuser.typed_paths import TypedPathsPlugin
from regipy.snapshots import build_value_timelines

typed_paths_only = TypedPathsPlugin.compare_snapshots(snapshots)
ad_hoc = build_value_timelines(
    snapshots,
    key_paths=[r"\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"],
)
```

The historical API is opt-in. The regular single-hive plugin query still works
with the same output shape:

```python
from regipy.plugins.ntuser.typed_paths import TypedPathsPlugin

plugin = TypedPathsPlugin(RegistryHive("NTUSER.DAT"), as_json=True)
plugin.run()
```

## CLI

```bash
regipy-snapshot-timeline   NTUSER-2023-01.DAT@2023-01-01T00:00:00Z   NTUSER-2023-02.DAT@2023-02-01T00:00:00Z   -o snapshot-evidence.json
```

If the `@timestamp` suffix is omitted, the hive header last modification time
is used and the output records `timestamp_source: hive_header`.

## Output

Top-level keys:

- `snapshots` - observation time and source for each input snapshot.
- `key_evidence` - per key: instances, key clock observations, key clock
  changes, key-only changes, and deletion/recreation breakpoints.
- `value_timelines` - the per-value evidence timeline. Each value record has
  `segments`, `transitions`, `range`, `breaks`, and a separate `key_clock`
  summary marked `used_as_value_timestamp: false`.
- `breakpoints` - flattened deletion/recreation boundaries.
- `key_only_changes` - flattened control entries that prove only the parent key
  changed.

A value transition looks like this:

```json
{
  "kind": "modified",
  "from_content": "cmd",
  "to_content": "C:\\Users\\analyst\\Desktop",
  "interval": {
    "not_before": "2023-01-01T00:00:00+00:00",
    "not_after": "2023-02-01T00:00:00+00:00",
    "iso8601": "(2023-01-01T00:00:00+00:00, 2023-02-01T00:00:00+00:00]"
  },
  "key_clock_context": {
    "used_as_value_timestamp": false
  }
}
```

A deletion/recreation breakpoint separates the two key instances:

```json
{
  "kind": "key_deleted_and_recreated",
  "missing_snapshots": [{"index": 1, "name": "deleted"}],
  "interval": {
    "iso8601": "(2023-01-01T00:00:00+00:00, 2023-03-01T00:00:00+00:00]"
  },
  "rule": "Values are never merged across this breakpoint."
}
```

A parent-only control item:

```json
{
  "control": true,
  "proves": ["the_parent_key_last_write_changed"],
  "does_not_prove": ["that_any_tracked_value_changed"],
  "value_changes": []
}
```

## Limitations

- A deletion and recreation that happens entirely between two observations,
  without any snapshot showing the key absent, cannot be distinguished from an
  ordinary modification by this method.
- Snapshot timestamps should be acquisition times. They should normally be
  later than the key clocks inside the hive; a key clock later than its snapshot
  observation time indicates clock skew and should be investigated.
- Value identity is the registry value name within a key instance. RecentDocs
  numeric slots rotate by design, so a slot is a value identity while the
  decoded document name is content evidence.
