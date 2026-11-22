# Offline Closure Judgement

The `detect_secrets.closure` package decides -- offline, next to a baseline --
whether a historical secret alert may be closed because the credential was
rotated. It only ever handles **fingerprints** (40/64-char hex digests, like
the `hashed_secret` values in a baseline); secret plaintext is never read or
accepted.

## Inputs

A case is a single JSON file (see `detect_secrets/closure/io.py`):

- `fingerprint`: the fictional credential fingerprint the alert is about
- `environment`: the environment the decision applies to
- `evaluated_at`: the moment the rotation windows are checked against
- `scope`: the **frozen** branch scope (`name`, `frozen_at`, `branches`)
- `receipts`: approved rotation receipts, each with a rotation `window`, an
  `environment`, a `revocation_scope` (branches where the old identifier is
  declared invalid), and an optional `based_on` citation of another receipt

## Semantics

- The window, environment and revocation-scope checks are validated
  **separately**; a receipt's revocation scope must stay inside the frozen
  branch scope.
- A branch is `CLOSABLE` only if a grounded receipt covers it. A receipt is
  grounded when it is approved, passes all checks, and its citation chain
  bottoms out in a receipt that cites nothing. Receipts may cite each other,
  but a citation **cycle produces no proof**.
- Every report is stamped with the `version` of the evidence bundle it was
  computed from.

## CLI

```bash
# per-branch decision
python -m detect_secrets.closure evaluate case.json [--json]

# auditor flow: revoke a (test) receipt, persist version+1, show the diff:
# which branches reopened, which are still closable, and under which
# evidence version the original decision held
python -m detect_secrets.closure revoke case.json TST-002 [--json]

# list the fingerprints of a detect-secrets baseline (hashes only)
python -m detect_secrets.closure fingerprints .secrets.baseline
```
