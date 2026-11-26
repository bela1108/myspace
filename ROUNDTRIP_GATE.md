# Offline round-trip quality gate

This repository includes a conservative, Plyara-based semantic gate for small
YARA rules. It parses the pre-format and post-format rule sources with the
checked-in Plyara parser, links private helper rules, and searches a finite
match/count model for Boolean condition counterexamples.

The gate does not invoke YARA or require network access. Its counterexamples
are abstract scan environments: each string is assigned an occurrence count,
where `0` means “does not match” and any positive value means “matches”.

## Accepted local Boolean subset

Only the following condition forms are accepted for an equivalence
certificate:

- Boolean literals: `true`, `false`.
- Ordinary string atoms: `$name` and anonymous `$`.
- Parentheses and Boolean operators: `not`, `and`, `or`.
- Quantifiers over declared strings:
  - `any of them`
  - `all of them`
  - `none of them`
  - `N of them`
  - the same forms with `$*` or `($a, $prefix*, ...)`.
- Exact count constraints:
  - `#name == N`, `!= N`, `>= N`, `<= N`, `> N`, `< N`
  - `#name in (low..high)`.
- References to private rules in the same source pack.

For exact count constraints, each string receives a small domain containing
zero and every boundary value needed by the constants in the rule. For rules
without count constraints, each string is tested as absent (`0`) or present
(`1`). The resulting Cartesian product is exhaustive for the accepted unary
count predicates within the configured assignment budget.

## Deliberately uncertain syntax

The gate fails closed with `inconclusive` for syntax outside that subset. The
machine-readable boundary is in
`src/plyara/roundtrip_gate.py` as `UNCERTAIN_CAPABILITIES`. It includes:

- imported modules and their functions;
- `for` iteration clauses;
- `@a[i]` positions and `!a[i]` lengths;
- `$a at offset` and offset ranges;
- arithmetic and bitwise expressions;
- `filesize`, `entrypoint`, and other scan-environment values;
- public/global/external rule references;
- includes and preprocessing;
- aggregate counts such as `#prefix*` and bare anonymous `#`.

String, scope, or rule-set changes are reported separately as hard semantic
definition changes instead of being treated as formatting noise.

## Color notification fixture

A concrete rule pack lives under `rules/color_notifications/`:

- `baseline/color_notifications.yar`: compact pre-format rules.
- `formatted/color_notifications.yar`: uniformly formatted but equivalent rules.
- `changed/color_notifications.yar`: explicit condition mutations with witnesses.

Regenerate the checked sample exports:

```sh
.venv/bin/python examples/color_notification_gate.py
```

The outputs in `reports/color_notifications/` are separated by concern:

- `format_differences.diff` and `format_differences.json`: textual formatting differences.
- `condition_changes.json` and `condition_changes.md`: red condition changes and explicit counterexamples.
- `uncertain_capabilities.json`: amber unsupported/uncertain syntax records.
- `formatted_gate_report.json` and `changed_gate_report.json`: full gate reports.

Notification colors mean:

- green: formatting-only difference or proven equivalent;
- red: condition/definition change with an explicit counterexample, blocking release;
- amber: syntax outside the proven subset, requiring human/YARA validation.

## CLI

Compare two files or two equally organized directories:

```sh
.venv/bin/python -m plyara.roundtrip_gate \
  rules/color_notifications/baseline \
  rules/color_notifications/formatted \
  --out-dir reports/roundtrip
```

Useful separate exports:

```sh
.venv/bin/python -m plyara.roundtrip_gate baseline.yar formatted.yar \
  --format-diff-out format.diff \
  --counterexamples-out condition-changes.json \
  --report-json-out gate-report.json
```

Exit status is `0` for a proven pass, `2` for a hard semantic/parse/rule-set
failure, and `3` when unsupported syntax makes the result inconclusive.

The parse → Plyara rebuild half of the round trip is also available as
`plyara.roundtrip_gate.plyara_rebuild` and is covered by a color-pack test.
