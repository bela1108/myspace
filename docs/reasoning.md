# Multi-Explanation Reasoning

Some synthetic samples admit more than one plausible explanation at the time
they are first reviewed. The `detect_secrets.audit.reasoning` package keeps
these competing interpretations, the evidence behind them, and the auditor's
reasons without forcing an early, possibly wrong, conclusion.

## Building a case

```python
from detect_secrets.audit.reasoning import (
    Evidence,
    Exclusion,
    Explanation,
    Finding,
    ReasoningCase,
    save_case,
)

case = ReasoningCase(
    case_id='sample-1',
    evidence=[
        Evidence('eA', 'why reading A is plausible'),
        Evidence('eB', 'why reading B is plausible'),
    ],
    explanations=[
        Explanation('A', 'first interpretation', evidence_ids=('eA',)),
        Explanation('B', 'second interpretation', evidence_ids=('eB',)),
        Explanation('C', 'uncontested context', evidence_ids=()),
    ],
    exclusions=[
        Exclusion('A', 'B', 'the two readings cannot hold together'),
    ],
    findings=[
        Finding('F1', 'plausible under either reading', ('A', 'B')),
        Finding('F3', 'backed by uncontested context', ('C',)),
    ],
)

save_case(case, 'sample-1.reasoning')
```

Every explanation and every exclusion stores its own `reason`. An exclusion is
symmetric: declaring `Exclusion('A', 'B', ...)` means `A` and `B` can never
appear in the same self-consistent set, regardless of argument order.

## Self-consistent worlds

`ReasoningCase.consistent_worlds()` enumerates every maximal set of viable
explanations that contains no excluded pair. Each world is one interpretation
the currently active evidence still permits. In the example above the worlds
are `{A, C}` and `{B, C}`.

An explanation is *viable* while every piece of evidence it relies on is
active. An explanation that needs no evidence stays viable until an exclusion
removes it.

## Which findings can be registered?

A finding is exported as `registered` only when a single supporting
explanation survives **every** self-consistent world. This is deliberately
stricter than "some explanation in each world supports it":

- `F3` is registered because `C` belongs to both worlds.
- `F1` stays `pending`: `A` supports it in `{A, C}` and `B` supports it in
  `{B, C}`, but `A` and `B` never coexist, so there is no common support.

```python
case.export()
# {
#     'case_id': 'sample-1',
#     'selected_explanation_id': None,
#     'findings': [
#         {'id': 'F1', 'status': 'pending', ...},
#         {'id': 'F3', 'status': 'registered', ...},
#     ],
# }
```

## Withdrawing evidence restores the unknown

Evidence is never silently deleted. `withdraw_evidence` marks it inactive,
which removes any explanation that depended on it from the viable set. If the
auditor had already committed (`select_explanation`) to an explanation that is
no longer viable, that commitment is cleared and the case is unknown again:

```python
case.select_explanation('A')
case.withdraw_evidence('eA')
case.selected_explanation_id      # None
case.restore_evidence('eA')       # re-activates the evidence
```

## Reading an established audit baseline

Reasoning baselines are versioned JSON documents written by `save_case` and
read by `load_case`. They do not replace the secret-scan baseline. An
already-audited `detect-secrets` baseline remains readable through
`load_legacy_baseline`, which preserves existing `is_secret` labels.
