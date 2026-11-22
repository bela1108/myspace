# Compliance review example

This directory contains a deliberately failing template used by the
acceptance test in `tests/test_compliance.py`.

`templates/incident.html` extends `templates/base.html`.  The parent has a
default `incident` block that includes the host notice, but the child
overrides that block without calling `super()`.  The child includes the
notice only on the non-empty `items` path, so the ordinary preview has the
marker while the empty-list path does not.

Run the review with:

```console
python -m jinja2.compliance --config examples/compliance/compliance.json
```

The expected finding is an `E_MISSING_MARKER` error whose reachable path
contains `items is empty`.
