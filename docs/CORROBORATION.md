# Offline identity corroboration

`regipy-corroborate` answers a narrow question:

> Given several registry exports and caller-registered provenance, do the
> independently verifiable name links support one subject, is evidence
> missing, or do the exports conflict?

It is an internal review helper. It is not an automatic attribution engine and
it does not turn content similarity into identity.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `same_subject` | At least two independent lineages resolve the same verified name nodes, with no identity or integrity conflict. |
| `missing_evidence` | No direct conflict was found, but the exports lack independent, verifiable name links. Clone content counts once. |
| `conflict` | The exports resolve the same identifier type to different values, a functional identity constraint fails, the same key path and timestamp carry different value digests, or a cited hive value fails verification. |

The three verdict strings are stable API values. Callers should compare against
`regipy.corroboration.Verdict`.

## What is combined

The reviewer keeps three evidence layers separate.

### Sampling source

Caller-registered provenance: `source_id`, `acquisition_id`,
`collected_from`, `collector`, `image_sha256`, and `derived_from`.

This layer controls lineage. Two exports in one derivative chain, or with the
same acquisition image hash, are one lineage. Their repeated content is not
independent corroboration.

### Volume identity

Caller-registered `volume_serial`, `disk_signature`, `disk_guid`,
`volume_label`, `device_serial`, and related fields.

Volume identity groups artifacts. A clone normally preserves it, so a shared
volume fingerprint does not prove that one person used the volume.

Volume identities are compared field by field over the overlapping strong
fields (`disk_guid`, `disk_signature`, `volume_serial`, `device_serial`). A
match is a shared volume, entirely different fields are treated as different
volumes, and a mixed result (for example the same serial but a different disk
signature) is a volume-identity conflict.

The registry-internal root key identity (for example
`CMI-CreateHive{...}`) is recorded separately as `hive_identity`. It is useful
for clone detection but is not a volume serial.

### Name associations

An association links two identity endpoints, for example:

```
profile_path C:\Users\alice  <->  account_name alice
sid S-1-5-21-...-1001         <->  account_name alice
sid S-1-5-21-...-1001         <->  profile_path C:\Users\alice
computer_name HOST-01         <->  computer_name HOST-01
```

regipy reads the cited hive value and marks the association `verified=True`,
`verified=False`, or unverified. A caller association becomes primary
evidence only when it is independently verifiable and successfully checked
against the hive value. Unverified assertions remain supplemental and produce
`missing_evidence`.

Built-in extraction covers NTUSER `Shell Folders` and `Volatile Environment`,
SOFTWARE `ProfileList`, and SAM `Users\Names`. Other artifacts can be supplied
as explicit associations with an `evidence_path` and `value_name`.

## Content anchors

A content anchor is a key path plus its last-write timestamp plus a digest of
its values. It detects copying:

- Same path, same timestamp, same digest: identical content.
- Same path, same timestamp, different digest: content conflict.
- Same path, different timestamp: content drift.

Identical anchors are reported explicitly. When exports are clone-related,
the reviewer states that the identical paths and timestamps are expected from
cloning and are not independent subject evidence.

## Plugin output

Plugin output is always:

```json
{
  "origin": "plugin",
  "role": "supplemental",
  "used_as_source": false,
  "can_establish_identity": false
}
```

Plugins can enrich the review and can corroborate an already primary finding,
but they never become an original source and never upgrade
`missing_evidence` to `same_subject`.

## Case manifest

The smallest useful manifest is one export with a sampling source, a volume
identity, and a verifiable name association. A multi-export case looks like
this:

```json
{
  "case_id": "CASE-001",
  "claim": "The exports were left by one user.",
  "target_exports": ["EXP-A", "EXP-B"],
  "exports": [
    {
      "export_id": "EXP-A",
      "hive_path": "path/to/NTUSER.DAT.xz",
      "hive_type": "ntuser",
      "sampling_source": {
        "source_id": "SRC-A",
        "acquisition_id": "ACQ-A",
        "image_sha256": "..."
      },
      "volume_identity": {
        "volume_serial": "...",
        "disk_signature": "...",
        "origin": "caller",
        "independently_verifiable": false
      },
      "name_associations": [
        {
          "identifier_type": "profile_path",
          "identifier": "C:\\Users\\alice",
          "name_type": "account_name",
          "name": "alice",
          "method": "shell_folders:AppData",
          "evidence_path": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
          "value_name": "AppData",
          "origin": "hive",
          "independently_verifiable": true
        }
      ],
      "auto_extract": true
    }
  ]
}
```

`auto_extract` adds regipy-derived anchors and associations. Explicit
associations are still checked against the hive. `anchor_paths` and `plugins`
can override the defaults.

For an explicit association, `value_role` is `identifier` (default) or
`name`; it tells the verifier which endpoint the cited hive value must match.

## CLI

Run a review:

```bash
regipy-corroborate case.json -o review.json --markdown review.md
```

Replace one identity record and see which associations stop holding:

```bash
regipy-corroborate case.json \
  --replace-export EXP-B \
  --replace-record volume \
  --replace-value "{\"volume_serial\":\"DEADBEEF\",\"disk_signature\":\"0xDEADBEEF\"}" \
  --replace-note "counterfactual clone volume record" \
  -o replacement.json --markdown replacement.md
```

Use `--fail-on-conflict` for an automated gate that exits with status 2 on a
conflict verdict.

## Replacement semantics

Every identity input is an `IdentityRecord`. Record ids are stable and
addressable, for example:

- `source`
- `volume`
- `hive_identity`
- `profile:c-users-vibranium`
- `anchor:control-panel-desktop`
- `plugin:typed-urls`

The replacement result lists:

- `invalidated_associations`: associations that were active before the
  replacement and are no longer active.
- `surviving_associations`: associations that remain active.
- `added_associations`: new associations created by the replacement.
- `resolved_conflicts`: conflicts that the replacement resolved.
- `pairwise_changes`: pairwise verdict or independence changes.

For example, replacing the clone volume record invalidates only
`link:volume:EXP-A:EXP-B`. The clone lineage, shared hive identity, identical
anchors, and the name links survive. Replacing the clone name record instead
invalidates the two name links and can turn the clone pair from
`missing_evidence` into `conflict`, while the volume and lineage links survive.

This is the dependency view needed to show which associations rely on a given
identity record.

## Repository example

The fixtures under `examples/corroboration/` use the three NTUSER exports in
`regipy_tests/data/`:

| File | Purpose |
| --- | --- |
| `three_ntuser_case.json` | Three-export case manifest. Acquisition metadata is synthetic and marked `fixture=true`. |
| `three_ntuser_review.json` | Machine-readable internal review. |
| `three_ntuser_review.md` | Human-readable review. |
| `internal_review_summary_zh.md` | Chinese internal-review summary. |
| `clone_volume_replacement.json` | Counterfactual clone volume-record replacement. |
| `clone_name_replacement.json` | Counterfactual clone name-record replacement. |
| `synthetic_same_subject_case.json` | Non-evidentiary example of the `same_subject` branch. |

The three-export result is `conflict`:

- `EXP-A` and `EXP-B` share one clone lineage and six of seven identical
  anchors, including Shell Folders and User Shell Folders. Their pair is
  `missing_evidence` because clone content is not independent.
- `EXP-A` and `EXP-C`, and `EXP-B` and `EXP-C`, resolve different account
  names and profile paths, so both pairs are `conflict`.
- Matching plugin digests for `EXP-A` and `EXP-B` are supplemental only.

## Operating rules

1. Never count clone content twice.
2. Never count a plugin value as an original source.
3. Never infer a person from a volume serial, a hive GUID, or content identity
   alone.
4. Treat caller metadata as an assertion until checked against acquisition
   records.
5. Report missing evidence as `missing_evidence`, not as a weak `same_subject`.
6. Treat the output as an internal review artifact unless the underlying
   acquisition and identity records are independently validated.
