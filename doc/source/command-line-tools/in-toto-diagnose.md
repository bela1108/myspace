# in-toto-diagnose

```{eval-rst}
.. argparse::
  :ref: in_toto.in_toto_diagnose.create_parser
  :prog: in-toto-diagnose
  :noepilog: true
```

`in-toto-diagnose` is an offline diagnostic for layout authors. It does not
verify signatures or execute inspections. Instead, it simulates artifact-rule
queues against link-like materials and products so that a broad `ALLOW` that
silently hollows out a later mandatory `MATCH` becomes visible.

For a signed or unsigned layout, pass `--layout` and the directory containing
the corresponding link metadata:

```console
$ in-toto-diagnose --layout root.layout --link-dir links --json
```

For a self-contained fixture, pass a JSON scenario with steps and offline
artifact sets:

```json
{
  "steps": [
    {
      "name": "build",
      "expected_products": [
        ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "source"],
        ["ALLOW", "*"],
        ["DISALLOW", "*"]
      ],
      "materials": {},
      "products": {"foo": {"sha256": "..."}}
    },
    {
      "name": "source",
      "products": {"foo": {"sha256": "..."}}
    }
  ]
}
```

The report lists, for each rule, what it could consume, what it actually
consumed, and which earlier rule consumed the intersection. It also runs the
declared order, an independent-rule swap, and a permutation that places a
broad consumer in front of a mandatory `MATCH`. The last permutation exposes
a hollowed-out constraint even when the `MATCH` is still present in the layout.
