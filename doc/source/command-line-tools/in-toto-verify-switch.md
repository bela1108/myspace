# in-toto-verify-switch

`in-toto-verify-switch` verifies a release that follows a build incident in
which a fallback build was allowed to ship. It runs entirely offline and
replays only signed layout and link metadata.

Two layouts are verified with separate manual sign-off keys:

* the fallback (incident) layout, and
* the normal (post-recovery) layout.

For the first normal release after recovery, the command compares the products
recorded by the fallback build with the cache contents at the junction and the
materials consumed by the normal build. A fallback artifact that remains in
the cache, or is consumed by the normal build, is quarantined unless a signed
review manifest lists the exact same path and hashes.

The verdict never depends on a last-written `mode` marker, file modification
time, the clock, or the network. If concurrent links coexist for a step, all
trusted links are evaluated. Links that disagree on artifacts fail closed
instead of selecting whichever file was written last.

```{eval-rst}
.. argparse::
  :ref: in_toto.in_toto_verify_switch.create_parser
  :prog: in-toto-verify-switch
  :noepilog: true
```
