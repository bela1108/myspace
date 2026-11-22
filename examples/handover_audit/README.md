# Offline handover audit demo

This demo shows how to audit a night-shift handover with pySigma rule identities and a
processing pipeline. It is intentionally data-driven: shift duties, approved substitutions,
branch ownership and branch closures come from `scenario.yml`.

Run it from the repository root:

```sh
.venv/bin/python examples/handover_audit/run_demo.py --check
```

Useful filters:

```sh
.venv/bin/python examples/handover_audit/run_demo.py --reference-only
.venv/bin/python examples/handover_audit/run_demo.py --status no_substitute
```

The script writes `report.json` and `report.md`. The demo contains:

- two rules with the same title but different UUIDs; they never share permissions;
- two people woken by notifications, but only explicitly assigned roles may handle;
- an active approved substitute;
- an expired substitute, producing the `no_substitute` state;
- a temporarily disabled release branch with a historical countersign role;
- exactly one `reference_only` chain that must not be used as a release basis.
