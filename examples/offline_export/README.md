# Offline export planner

Offline, repository-side planning for handing over the *minimal* set of
signed TUF role files that a review group needs to re-verify specific
targets without network access.

## Why

A review contract may only require the review group to see the two targets
it was asked about. Shipping the entire mirrored `repository/metadata` tree
exceeds that material scope and leaks unrelated delegations. The planner
computes the smallest verification bundle from three offline inputs:

1. the repository existing role metadata (the delegation graph and
   signature material);
2. the target hit conditions already encoded in the delegations
   (`paths`, `path_hash_prefixes`, succinct bins and terminating flags);
3. a caller-supplied *transferable manifest* naming the role files that are
   actually allowed to leave the repository.

It produces two things:

- a hand-off ready, de-duplicated role file list (`roles`); and
- a structured no-proof range (`gaps`) for every target that cannot be fully
  re-verified from the delivered material.

## Non-goals and hard rules

The planner never signs, re-aliases or fabricates metadata and never reaches
out to a network. In particular it does not hide a missing role:

- if the signed role file is not transferable, the target is reported as a
  `role_not_transferable` gap, not replaced by an unsigned alias;
- if the delivered signatures do not meet the role threshold, it is reported
  as `threshold_unmet`, not papered over with an arbitrary digest;
- if `snapshot.meta` does not anchor the role version, it is reported as
  `not_in_snapshot`.

Target payloads themselves are out of scope: the bundle contains role
metadata and the no-proof description, not the target files.

## How the minimal set is found

The walk mirrors `Updater._preorder_depth_first_walk`: preorder, depth-first,
in delegation order, honouring terminating delegations and the configured
delegation limit. For every targets-type role on the path the planner gates
the material before accepting it:

1. the role must be in the transferable manifest;
2. its bytes must parse as a signed `targets` metadata;
3. the delegating role keys must verify the required signature threshold
   (the same `get_verification_result` check the client uses);
4. `snapshot.meta` must contain the `<role>.json` version anchor.

Top-level roles form the shared trust chain. `root` is the offline trust
anchor (present, parseable and self-threshold verified), `timestamp` and
`snapshot` additionally prove their threshold against the delivered root
keys, and every targets-type role is pinned through `snapshot.meta`.

### Merging several requests

Multiple target requests share one top-level chain. The planner unions the
per-target delegated chains and de-duplicates by role name, so a common
parent (for example `targets`) is handed over once while each leaf role only
appears if some request actually reaches it. A target whose chain cannot be
fully delivered stays in the no-proof range; it never weakens the bundle for
the targets that can still be proven.

## Gap reasons

| Reason | Meaning |
| --- | --- |
| `role_not_transferable` | signed role file is withheld from the manifest |
| `role_unreadable` | delivered bytes do not parse as the expected metadata |
| `threshold_unmet` | delivered signatures are below the role threshold |
| `not_in_snapshot` | no `snapshot.meta` entry anchors the role version |
| `delegation_limit` | the walk exceeded `max_delegations` |
| `target_not_found` | no reached role claims the target path |
| `delegation_missing` | the delegator does not describe the child role |

`delegation_missing` is part of the reason enum for completeness; with a
well-formed delegation graph the traversal only follows roles the delegator
describes, so it is not expected in normal operation.

## Files and usage

- `offline_export_planner.py` - the planner, transfer manifest and plan types.
- `demo_small_image.py` - a small signed image with two leaf roles and two
  shared-parent requests, run directly:

  ```bash
  python examples/offline_export/demo_small_image.py
  ```

  The demo shows three manifests against one repository:

  1. every role transferable - shared parent chain merges, both targets
     proven, each leaf emitted once;
  2. `role-bar` withheld - request A still proves, request B is reported as
     `role_not_transferable`;
  3. `role-bar` delivered without signatures - reported as
     `threshold_unmet` instead of being silently accepted.

`OfflineExportPlanner.materialize()` writes the gated role files
byte-for-byte from the delivered source plus a `plan.json` containing the
role list and the no-proof range. Nothing is generated or signed at export
time.

### Minimal API sketch

```python
planner = OfflineExportPlanner(metadata_source, transfer_manifest)
plan = planner.plan(["pkg/foo/app-1.tar", "pkg/bar/app-2.tar"])

plan.role_names()      # minimal, de-duplicated hand-off roles
plan.proven_targets    # targets fully re-verifiable offline
plan.unproven_targets  # targets that stay in the no-proof range
plan.gaps              # structured reason per unprovable target
planner.materialize(plan, output_dir)
```

## Tests

The behaviour is covered by `tests/test_offline_export_planner.py`:
minimal-set merge, single-request pruning, withheld roles, under-signed
roles, missing snapshot anchors, terminating delegation backtracking,
unclaimed targets, withheld anchors and bundle materialization.
