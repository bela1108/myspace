# Registration acceptance

This local-only layer compares application-archive coordinates with X.509
`Name` structures parsed by `asn1crypto`. It does not modify CSR or certificate
DER/PEM content.

A record is accepted as the same registered entity only when all of the
following hold:

- the as-of date is inside the approved change period (and archive period, if present);
- the CSR `AttributeType` set matches the declaration exactly;
- the legacy department/normalized name coordinates match an approved declaration;
- the declared RDN sequence matches, including RDN order and multi-valued RDN grouping.

The checked-in declaration is `approved_name_changes.json`. Synthetic signed CSRs
and an archive fixture live in `../tests/fixtures/acceptance/`.

Run the focused tests:

```sh
.venv/bin/python -m unittest tests.test_registration_acceptance -v
```

Run a local archive-to-CSR check:

```sh
.venv/bin/python -m registration_acceptance archive \
  --archive tests/fixtures/acceptance/application_archive.json \
  --application-id APP-2026-092 \
  --declarations registration_acceptance/approved_name_changes.json \
  --as-of 2026-11-27
```

Exit code `0` means accepted, `2` means a policy rejection, and `1` means usage
or input failure.
