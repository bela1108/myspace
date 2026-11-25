# DistributedLinkTracker lineage samples

These four local LNK files are binary-patched copies of `tests/samples/sample9`
with distinct TrackerDataBlock identities and header timestamps. They exercise
the conservative lineage rules without any network lookup.

| sample | machine | gen | current identity | birth identity | interpretation |
| --- | --- | --- | --- | --- | --- |
| backup-a | desk-old | 1 | A | A | original snapshot in backup 1 |
| backup-b | desk-old | 1 | A | A | second copy of the same snapshot |
| backup-c | desk-new | 2 | B | A | migration/copy from identity A |
| backup-d | desk-new | 2 | C | B | follow-on migration/copy from B |

`backup-a` and `backup-b` share the exact current identity. That sharing is
reported as possible `snapshot_reuse`; it is not treated as proof that one is
the ancestor of the other. Because both also carry identity A, both are
retained as equally supported predecessors of `backup-c`. Reviewers can decide
which of the two is the continuation and which is only a backup.

`four_samples_lnk.json` points at the binary files. `four_samples.json` contains
the equivalent tracker mappings and can be used without reading LNK binaries.
