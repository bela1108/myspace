# Offline Plugin Evaluation

## Why

Choosing secret-detection plugins by their global hit count is misleading:
a plugin can improve the aggregate score while regressing on the file families
that matter most for our codebase. The `detect_secrets.eval` package runs an
offline, fully synthetic evaluation that keeps every metric broken down by
source-file family, so trade-offs stay visible.

The evaluation never touches the network and never verifies secrets. It only
consumes synthetic files plus an authoritative `labels.json` manifest.

## Concepts

- **File family** -- a label on each synthetic file (for example `python`,
  `config`, or `docs`). Candidates are grouped by the family of the file they
  were found in.
- **Ground-truth label** -- the exact file, line, and character span of one
  synthetic secret.
- **Overlapping hits** -- when a plugin reports several findings that overlap
  the same labelled span, they describe one truth. Only the first counts as a
  discovery; the rest are recorded as **duplicate coverage**.
- **Unmeasurable label** -- a ground-truth secret that no plugin in the suite
  detects at all. These are listed explicitly per family.
- **Failed plugin** -- a plugin that raises while loading or scanning. It is
  isolated and reported separately, never mixed into healthy metrics.

## Metrics per (plugin, family)

- `found` -- distinct ground-truth labels this plugin covers.
- `incremental` -- labels added on top of every plugin ranked ahead of it.
- `duplicate_hits` -- redundant findings on labels already found by this plugin.
- `false_positives` -- findings that overlap no labelled span.
- `missed` -- labels in the family this plugin does not cover.
- `coverage` / `precision` / `duplicate_rate` -- derived ratios.

## Running the evaluation

Text tables (one row per plugin x family, plus a per-family summary):

```
python -m detect_secrets.eval \
    --dataset test_data/eval/python_heavy \
    --plugin AWSKeyDetector \
    --plugin GitHubTokenDetector \
    --plugin KeywordDetector
```

Compare a baseline configuration against a candidate. The comparison table
flags every family whose coverage regressed, even when the global number goes
up:

```
python -m detect_secrets.eval \
    --dataset test_data/eval/python_heavy \
    --baseline KeywordDetector \
    --candidate GitHubTokenDetector
```

Pass `--json` for a machine-readable payload and repeat `--dataset` to evaluate
several corpora in one run.

## Bundled datasets

Two intentionally small and imbalanced synthetic corpora live under
`test_data/eval`:

- `python_heavy` -- seven of ten labels sit in Python files; config and docs
  are thin minorities.
- `doc_heavy` -- six of nine labels sit in Markdown prose; code and config are
  thin minorities.

Because the families are so unbalanced, a global improvement can easily hide a
regression on the under-represented families. The per-family tables and the
`REGRESSED` markers make those cases obvious.

## Adding a dataset

Create a directory with the synthetic files and a `labels.json` manifest. Each
label points at one secret via its 0-based character span on a 1-based line:

```json
{
  "name": "my-corpus",
  "files": [
    {
      "path": "python/app.py",
      "family": "python",
      "labels": [
        {"id": "app-1", "line": 3, "start": 12, "end": 32, "kind": "aws"}
      ]
    }
  ]
}
```

Spans are validated against the files at load time so a manifest typo fails
loudly instead of silently scoring every plugin as a miss.
