# Review Plan Generator

Generates a reviewer assignment plan for detected secrets from an **offline**
baseline, ready to hand off to the distribution program.

## Usage

```bash
python scripts/review_plan/generate_plan.py \
    --baseline scripts/review_plan/data/baseline.json \
    --roster scripts/review_plan/data/roster.json \
    --output-dir scripts/review_plan/output
```

## Inputs

- `data/baseline.json` - offline detect-secrets baseline. Each result becomes a
  candidate (`FND-001`, `FND-002`, ...), ordered deterministically by filename
  and line number.
- `data/roster.json` - reviewer roster:
  - `required_seats_per_finding`: seats counted in actual people (default 2).
  - `test_path_prefixes`: path prefixes that count as test-department material.
  - Per reviewer: `clearance.test_paths`, `recent_authored_paths` (a reviewer
    never sees their own recent code), `absent`, and `substitute_for`.
  - A substitute is only activated while a primary they cover is absent, and
    their own clearance still applies (substitute boundary).

## Outputs

- `output/plan_internal.json` - **internal only**. Full paths, seat-to-reviewer
  directory, and for every unassigned candidate an explanation (absence,
  authorship conflict, missing clearance, substitute boundary).
- `output/distribution_manifest.json` - external hand-off. Contains only
  opaque seat tokens mapped to candidate IDs and evidence aliases
  (`EVID-<hash>`). Unassigned candidates and their reasons never appear here.
- `output/seats/<SEAT>.json` - one file per seat; each seat receives only the
  materials assigned to that seat.

Evidence aliases are one-way (SHA-256 over candidate ID, path and hashed
secret), so external lists reveal neither real paths nor secret hashes.

## Tests

```bash
pytest scripts/review_plan/generate_plan_test.py
```
