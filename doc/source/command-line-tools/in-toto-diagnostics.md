# in-toto-diagnostics

`in-toto-diagnostics` is an offline release review tool. It does not execute
inspections and does not contact any network or key server. For every step of
the passed layout it:

- classifies each available link signature as `valid`, `unauthorized`,
  `invalid_signature` or `expired_key`, reusing the same authorization and
  signature rules as `in-toto-verify`;
- groups validly signed links that report provably identical materials and
  products, counting distinct authorized functionaries towards the step
  threshold; and
- reports the minimal conflicting artifact fields and their signers when at
  least two groups independently meet the threshold.

Invalid or unauthorized signatures explain missing evidence but never join a
valid group. The tool prints a deterministic JSON report (the same report for
any ordering of the input links), which can be embedded into in-toto review
tooling. It exits `1` if any step has conflicting views or insufficient
evidence, and `0` when every step has a single consistent view.

```{eval-rst}
.. argparse::
  :ref: in_toto.in_toto_diagnostics.create_parser
  :prog: in-toto-diagnostics
  :noepilog: true
```
