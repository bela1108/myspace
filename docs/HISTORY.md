# Historical snapshot comparison

A registry value has no native timestamp. NK.LastWrite belongs to the key and
can change because of parent-key or sibling activity, so it must not be copied
onto every value as if it were the value write time.

regipy.history compares several captures of the same hive and produces
per-value evidence timelines. Snapshot observation times bound the evidence:
if a value is first seen in snapshot B and the preceding snapshot A did not
contain it, its creation lies between A and B. The key clock remains a
separate field.

    from regipy.history import analyze_recentdocs_history, analyze_typed_paths_history

    snapshots = [
        {"observed_at": "2024-01-01T00:00:00+00:00", "hive": "/cases/ntuser-2024-01.dat"},
        {"observed_at": "2024-02-01T00:00:00+00:00", "hive": "/cases/ntuser-2024-02.dat"},
        {"observed_at": "2024-03-01T00:00:00+00:00", "hive": "/cases/ntuser-2024-03.dat"},
    ]

    recent = analyze_recentdocs_history(snapshots)
    for value in recent.value_timelines:
        print(value.value_name, value.content, value.first_observed, value.last_observed)
        print(value.valid_from_earliest, value.valid_from_latest)
        print(value.valid_to_earliest, value.valid_to_latest)

    typed = analyze_typed_paths_history(snapshots)
    print(typed.to_dict())

Each timeline has three distinct pieces of evidence:

* observations - the value content actually seen in each snapshot.
* first_observed / last_observed - the observed content range.
* valid_from_* / valid_to_* - the outer possible-validity bounds derived
  from the surrounding snapshots, not from NK.LastWrite.

key_clock lists the key-level LastWrite values separately. A key that is
absent in an intermediate snapshot, or whose LastWrite moves backwards,
starts a new generation and emits a breakpoint; old values are never joined
to values from the recreated key. A LastWrite change with unchanged value
content is reported as parent_key_only and does not create a new value
timeline segment.

## Plugin opt-in

Single-hive plugin calls keep their original output. Pass snapshots (or
include_history=True) to use the evidence view:

    from regipy.registry import RegistryHive
    from regipy.plugins.ntuser.recentdocs import RecentDocsPlugin

    current = RegistryHive("/cases/ntuser-2024-03.dat")
    plugin = RecentDocsPlugin(current, as_json=True, snapshots=snapshots)
    plugin.run()
    print(plugin.entries["value_timelines"])
    print(plugin.entries["breakpoints"])
    print(plugin.entries["parent_only_changes"])
