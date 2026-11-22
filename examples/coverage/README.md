# Coverage ledger demo: two zero-finding scans that are not duplicates

Both security scans reported **0 findings**, so release assumed the
second scan was a duplicate of the first. The coverage ledgers say
otherwise:

- **Scan A** (`ledger-model-layer.json`, shard `model-layer`) only ever
  covered `src/model_layer.py`. Its source digest proves it never saw
  `src/api_layer.py`.
- **Scan B** (`ledger-full-scan.json`, shard `full-scan`) covered both
  files, but rule `B608` raised on every file and silently never ran.
  Zero findings, but the `FAIL` cells explain why this scan cannot
  pass the coverage gate.

`coverage-table.txt` is the merged rule x file coverage table;
`gate-output.txt` shows the gate verdicts. The two ledgers have
different source digests, so neither may fill the other's gaps.
`ledger-full-scan-rerun.json` is a re-run of the `full-scan` shard with
the rule fixed: same shard id, so it may replace its own cells, and the
gate passes.

## Reproduce

```sh
python make_demo.py
```

## Usage

Write a ledger during a scan:

```sh
bandit -r src/ --coverage-out ledger.json --coverage-shard full-scan
```

Merge ledgers offline and evaluate the gate (exit 1 on failure):

```sh
bandit-coverage merge ledger-model-layer.json ledger-full-scan.json \
    -o merged.json --table coverage-table.txt
bandit-coverage gate ledger-full-scan.json --table
```

Ledger cell states, recorded per rule x file:

- `selected`: rule was selected but no execution outcome was recorded
  (a coverage gap; fails the gate).
- `completed`: rule executed to completion on the file.
- `failed`: rule raised while executing on the file (fails the gate).
- `not_applicable`: rule skipped because none of the AST node types it
  checks appear in the file.

Merge rules:

- Ledgers may only fill each other's gaps when source digest and config
  (rule selection) digest match.
- Re-running the same shard may replace the cells that shard owns.
- Differing definitive states from different shards are surfaced as
  conflicts and fail the gate.
