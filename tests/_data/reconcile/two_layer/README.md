# Two-layer archive reconciliation fixture

Logical layout:

```
release-1.0.tar
|-- META-INF/MANIFEST.json
|-- META-INF/sbom.cdx.json
`-- payload/runtime.tar
    |-- app/...          (12 files)
    |-- lib/...          (16 files)
    |-- plugins/...      (8 files)
    `-- vendor/...       (8 files)
```

The outer archive holds 3 records and the inner archive holds 44 records, so
the read-only manifest has 47 archive records in total. `sbom.cdx.json`
declares 40 components.

Intentional evidence:

- F002/F003 are packaging records and are covered by exclusion EX-003. In
  decisions-v1 only F002 is in scope; decisions-v2 enlarges the scope to F003.
- `vendor/requests/__init__.py` and `vendor/requests_copy/__init__.py` have
  the same SHA-256 digest but different archive paths (digest fan-out).
- `vendor/runtime/shared.py` is declared by both `runtime-core` and
  `runtime-compat` (location contention).
- `optional-codec` has an approved exclusion and no archive record.
- `ghost-helper` has no archive record and no exclusion.
- `app/config/release.json` and `plugins/legacy_compat.py` have archive
  records and no declaration.

All tar metadata is fixed (mtime 0, uid/gid 0), so the fixture bytes are
stable and are checked by `tests/test_reconcile.py`.
