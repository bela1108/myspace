# Offline TUF release-statement cross-check

A read-only forensic entry point for the post-incident question: two mirrors
each handed in signed TUF metadata claiming to describe the same release, and
the network is gone. Do their independently verifiable release statements
actually conflict?

Everything runs offline against locally saved files. The tool uses only the
low level `tuf.api` metadata classes; no updater, fetcher or network client
is constructed.

## What is compared

Each party supplies three things through a small JSON manifest:

1. the saved metadata bundle (root, timestamp, snapshot, targets and any
   delegated roles),
2. the root metadata that party itself vouches for,
3. the observation scope, i.e. the target path patterns it claims to have
   observed.

For each party the tool first verifies the whole trust chain against that
party's own root:

* root must meet its own signature threshold,
* timestamp, snapshot and targets are verified with
  `Root.verify_delegate`,
* delegated targets roles are verified transitively while walking the
  delegation graph with `Targets.verify_delegate`,
* a delegated role is only trusted when the delegator naming it is itself
  trusted,
* expiry is reported as a warning, not a hard failure, because captured
  metadata may have expired after the incident while still proving who
  signed it.

Only afterwards are the resulting target statements (length, content hashes
and signed `custom` fields) compared, and only for target paths that lie in
the observation scope of both parties.

## The three outcomes

| Outcome | Meaning |
| --- | --- |
| `consistent` | Both sides verified a statement for the path and length, hashes and signed custom fields are identical. |
| `conflict` | Both sides independently verified a statement, but the published content claims differ. The verdict carries evidence pointing at both original metadata files. |
| `undecided` | Only one side could provide an in-scope, verified statement, or a trust chain could not be verified. Missing material and broken chains never prove a disagreement, so the record stays open. |

A `conflict` verdict always includes, for both parties, the original
metadata file name, the role and its version, and the on-disk sha256 of that
file, so the two signed originals can be reopened independently of this tool.

## Running the demo

The demo generates two fully signed bundles with independent roots and three
target objects:

* `release/app-1.4.2.tar.gz` - properly signed on both sides but with
  different length/hashes for the same version: a proven conflict backed by
  two originals,
* `release/firmware-1.4.2.bin` - identical signed statements on both sides,
* `release/manifest-1.4.2.json` - lives in a delegated role whose metadata
  file is missing from one bundle: same release version but incomplete source
  material, so it is reported as undecided rather than a conflict.

```sh
python -m forensics.demo --output-dir demo_output
```

The Markdown report is printed to stdout and the JSON evidence report is
written to `demo_output/crosscheck-report.json`. The process exits with code
2 when at least one proven conflict is found, otherwise 0.

## Running against real saved receipts

Prepare one manifest per party (paths are resolved relative to the manifest
file):

```json
{
  "party": "alpha",
  "root": "alpha/root.json",
  "metadata_dir": "alpha",
  "scope": ["release/*"]
}
```

Then run:

```sh
python -m forensics \
  --alpha alpha-manifest.json \
  --beta beta-manifest.json \
  --format markdown
```

Use `--format json` for the stable machine-readable report, and `--output`
to write it to a file instead of stdout.

## Package layout

* `forensics/models.py` - statements, evidence, verdicts and the report
  data model,
* `forensics/verification.py` - offline, per-party trust chain verification,
* `forensics/crosscheck.py` - scope handling and the comparison decision
  rules,
* `forensics/report.py` - JSON and Markdown rendering,
* `forensics/cli.py` - the read-only command line entry point,
* `forensics/generate/` - builders that produce fully signed demo bundles
  without any network access,
* `tests/test_forensics.py` - unit tests covering all three outcomes,
  signature tampering and custom-field conflicts.
