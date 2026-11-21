# Group-Coverage Reports

Some environments cannot persist baselines at all: even the one-to-one
stable fingerprints (`hashed_secret`) that baselines use to track individual
candidates across scans are not allowed to leave the machine. The
group-coverage export path exists for these cases. It proves that the scan
covered everything it should have, and that the rule set was capable, while
exporting **only aggregate, k-anonymized counts**.

## Generating a Report

```bash
$ detect-secrets scan --coverage-report --min-group-size 3 --all-files > coverage.json
```

To reconcile a fresh scan against a previously exported report (e.g. two
generations of a build):

```bash
$ detect-secrets scan --coverage-diff coverage.gen1.json --all-files > coverage.gen2.json
```

The reconciliation is embedded in the output under `reconciliation`.

## What the Report Contains

* `coverage`: every file in scope, tallied by outcome --
  * `scanned_files`: fully processed by all configured detectors,
  * `skipped_files`: legitimately excluded by configured filters
    (e.g. non-text files),
  * `failed_files`: selected for scanning, but the detectors could not
    complete (e.g. unreadable files). A non-zero count here means coverage
    is *not* proven.
* `plugins_used`: the detectors that were active (rule capability).
* `groups`: findings tallied per detector. No filenames, line numbers, or
  hashes ever appear.

## k-Anonymity (`--min-group-size`)

The caller approves a minimum group size `N` (default 3). Detector groups
with fewer than `N` findings are never exported individually:

* they are pooled into `__merged_small_groups__` if the pool itself reaches
  `N`, or
* exported as `__suppressed_small_groups__` with **no counts at all**
  otherwise (`totals.findings_hidden_max` bounds the hidden mass by `N - 1`).

This guarantees that two reports -- even from consecutive builds -- cannot
be differenced to recover the status of any specific candidate.

## Reconciliation Rules

`reconcile_reports` (and `--coverage-diff`) only ever compares aggregate
groups:

* groups present in both reports with equal counts are `stable`;
* anything else (`changed`, `appeared`, `disappeared`, or pooled-group
  membership changes) flips `coverage_consistent` to `false` and sets
  `requires_fresh_review`;
* when pooled-group membership changes between versions, counts are
  **not** subtracted (that would leak sub-minimum group sizes) -- the pool
  is flagged `unattributable`;
* `individual_findings_actionable` is always `false`: without fingerprints,
  no individual alert can be carried over or closed from these reports.

When a scan scope splits (e.g. a monorepo broken into per-project scans),
combine the in-memory tallies *before* exporting, so k-anonymity is applied
once on the combined totals:

```python
from detect_secrets.core import coverage

combined = coverage.CoverageReport()
for project in projects:
    combined.combine(coverage.scan_coverage(project, should_scan_all_files=True))
report = combined.export(min_group_size=3)
```

See `scripts/coverage_group_demo.py` for an end-to-end demonstration on
three synthetic projects, including group splits, failed files, suppression,
and a disappearing alert.
