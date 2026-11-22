# Reviewing ambiguous registry findings

The review layer (`regipy.review`) lets a caller supply two or more sets of
interpretation rules and evaluate them against the *same* collected material.
It is opt-in; existing parsing and plugin output are unchanged.

The central rule is conservative:

- every supplied interpretation must match **and** agree before a subject is
  `confirmed`;
- if a dependency key or value is missing, the subject stays `pending`;
- a historical claim such as "enabled" is never repeated as a verdict unless
  the evidence actually supports it.

## Quick start

```bash
regipy-review /path/to/SYSTEM \
  --rule-set examples/review/smb_signing_legacy.json \
  --rule-set examples/review/smb_signing_domain_server.json \
  --prior-claim smb_signing=enabled \
  -o review.json
```

```python
from regipy.review import review_hive

report = review_hive(
    "/path/to/SYSTEM",
    [
        "examples/review/smb_signing_legacy.json",
        "examples/review/smb_signing_domain_server.json",
    ],
    prior_claims={"smb_signing": "enabled"},
)
```

## The report

For each subject the report contains:

- `status`: `confirmed` only when all supplied interpretations matched and
  produced the same conclusion; otherwise `pending`.
- `verdict`: the agreed conclusion, or `None` while pending.
- `candidates`: concrete conclusions produced by the supplied interpretations.
- `interpretations`: one entry per rule set, including the matched rule,
  conditions, assumptions, evidence, plugin names, and raw entry ranges.
- `divergence.assumptions`: the assumption dimensions on which the
  interpretations disagree.
- `prior_claim`: present when `--prior-claim` / `prior_claims` is supplied.
  `disputed` means at least one fully sourced interpretation contradicts the
  historical claim.

### Provenance

Every condition keeps a `hive_value` evidence item with the resolved key path,
value name, type, and raw value. If the same value exists in plugin output, a
`plugin_entry` evidence item is added with:

- `plugin`: the plugin name;
- `entry_path`: where the entry sits in the plugin output;
- `entry_indices`: list indices for list-based output;
- `raw_entry_range`: `plugin`, `entry_path`, `entry_indices`, `start`, `end`,
  `range`, and `value_index`.

This is the audit trail: an investigator can point at the plugin and the exact
raw entry that supports an interpretation. If the plugin entry disagrees with
the hive value, the condition becomes `pending` with
`reason: plugin_hive_mismatch` rather than silently choosing one source.

## Rule-set schema

```json
{
  "name": "domain_server",
  "description": "Alternative interpretation for a domain-joined host.",
  "plugins": ["services", "host_domain_name"],
  "assumptions": {
    "scope": "Server parameters govern SMB signing on a domain-joined host.",
    "sufficiency": "Both server signing flags must be 1."
  },
  "rules": [
    {
      "id": "domain.server_signing_disabled",
      "subject": "smb_signing",
      "conclusion": "disabled",
      "conditions": [
        {
          "id": "domain.is_domain_joined",
          "path": "\\CurrentControlSet\\Services\\Tcpip\\Parameters",
          "value": "Domain",
          "op": "non_empty",
          "assumption": "scope",
          "evidence": {
            "plugin": "host_domain_name",
            "entry_index": "current",
            "field": "domain"
          }
        },
        {
          "id": "domain.server_enable_signature",
          "path": "\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
          "value": "EnableSecuritySignature",
          "op": "eq",
          "expected": 0,
          "assumptions": ["scope", "sufficiency"]
        }
      ]
    }
  ]
}
```

### Conditions

- `path`: registry key path. `\CurrentControlSet` (or the
  `{current_control_set}` token) is resolved through `\Select\Current`.
- `value`: registry value name. Matching is case-insensitive by default.
- `op`: `eq`, `ne`, `in`, `not_in`, `exists`, `missing`, `non_empty`, `empty`,
  `truthy`, `falsy`, `contains`, `not_contains`, `startswith`, `endswith`,
  `regex`, `gt`, `ge`, `lt`, or `le`.
- `expected`: comparison operand where the operator needs one.
- `case_sensitive`: optional, default `false`.
- `assumption`: one assumption dimension, or `assumptions` for several.
- `evidence`: optional plugin-location hint. Without it, the reviewer searches
  plugin entries recursively for a key record with a matching `path` and
  `values` list.
- `raw_entry_range`: optional declared fallback if plugin output is not
  available.

Conditions may read other keys. A missing dependency is not treated as false;
it makes the rule `pending`.

## Worked example: SMB signing

`EnableSecuritySignature` exists in two different scopes:

- `LanmanWorkstation\Parameters` describes client behaviour;
- `LanmanServer\Parameters` describes the server role.

On the example SYSTEM hive the workstation flag is `1`, while both server
flags are `0`, and `Tcpip\Parameters\Domain` is non-empty. The historical
one-line report looked only at the workstation flag and said `enabled`.

The two example rule sets disagree on exactly two assumptions:

- `scope`: whether workstation parameters or server parameters govern the
  host;
- `sufficiency`: whether one enable flag is enough, or both server flags are
  required.

The review therefore returns `pending`, records the `enabled` and `disabled`
candidates, and marks the historical claim `disputed` with
`domain_server` as the refuting interpretation. It does **not** output
"enabled" as the conclusion.

## Status values

- `confirmed`: all supplied rule sets matched and agreed.
- `pending`: anything else, including missing dependencies, disagreeing
  interpretations, incomplete evidence, or no matching rule.

`pending` is intentional. In a forensic review, an unconfirmed configuration
must remain explicitly unconfirmed rather than defaulting to "enabled".
