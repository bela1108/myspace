# Matching core-file mappings to candidate originals

`NT_FILE` records the path, virtual range and page offset of file-backed
mappings, but not the original file build-id, device or inode. When an
evidence package has several archives for the same recorded path, use the
static matcher instead of guessing from archive names.

```python
from elftools.elf.corefile import ArchiveCandidate, match_core_files

with open("core.elf", "rb") as core:
    with open("first/libfoo.so", "rb") as first:
        with open("second/libfoo.so", "rb") as second:
            manifest = match_core_files(core, [
                ArchiveCandidate("/usr/lib/libfoo.so", first, "first"),
                ArchiveCandidate("/usr/lib/libfoo.so", second, "second"),
            ])
print(manifest.to_json())
```

The matcher opens only archives the caller passes explicitly. A path in
`NT_FILE` is metadata; it is never resolved or opened implicitly. Candidate
sources may be binary streams, `ELFFile` objects or explicitly passed paths.

## Evidence rules

1. Each `NT_FILE` page offset must be covered by a candidate `PT_LOAD`, and
   all ranges of one instance must imply one load bias.
2. Bytes retained in core `PT_LOAD` segments are compared at the recorded
   file offsets. Gaps are missing evidence, not a mismatch.
3. A readable GNU build-id in mapped core pages is compared with the
   candidate build-id when its note page is present.
4. Device and inode metadata are never required or consulted.

Mappings for one path are split by load bias, so a path can have multiple
process or file instances without conflating their evidence.

## Outcomes

- `matched` (`resolution: unique`): exactly one candidate is consistent and
  has positive mapped-byte or build-id evidence.
- `unconfirmed`: multiple candidates remain possible, or no conclusive
  page/build-id evidence was retained.
- `contradicted`: every candidate is excluded by layout, byte or build-id
  evidence.
- `missing`: no candidate archive was supplied for the path.

Reproducible fixtures are in `test/testfiles_for_unittests/core_matching/`;
`manifest.json` records one unique match, one unconfirmed duplicate-path case
and one evidence contradiction. `make_fixtures.py` regenerates the images.
