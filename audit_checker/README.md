# Audit credential checker

Backend-facing pycparser checker for protected configuration writes.

## API

```python
from audit_checker import check_c_code

report = check_c_code(preprocessed_c, contracts, function="configure")
```

`report` is JSON-serializable. Its `verdict` is one of `missing_credential`,
`duplicate_credential`, `missing_and_duplicate`, `rollback_clean`,
`undecidable`, or `clean`. Each exit has `status`, ledger counts, boundaries,
and both structured `path` and source-readable `path_text`.

## Contracts

Map callee names to `role`, `resource_arg`, and optional `success_return`.
Roles accept English and Chinese labels: `change`/`变更`,
`withdraw`/`撤回`/`回滚`, and `credential`/`commit`/`凭据`/`提交凭据`.

```python
contracts = {
    "protected_write": {"role": "change", "resource_arg": 0, "success_return": 0},
    "withdraw_resource": {"role": "withdraw", "resource_arg": 0},
    "commit_credential": {"role": "credential", "resource_arg": 0},
}
```

Resource keys follow the indexed argument through constants, locals, helper
parameters, and `struct->field` expressions. A write is counted only when the
branch condition establishes its success. Failed and withdrawn writes require
zero credentials.

## Coverage

The symbolic execution explores both feasible-looking sides of conditions,
shared `goto cleanup` labels, early returns, `break`/`continue`, loops at 0/1/2
iterations with balanced-loop widening, and one layer of local helper. An
uncontracted non-pure external call adds a proof boundary and makes affected
exits `undecidable`; known C library names are treated as pure.

## Demo and tests

```bash
python -m audit_checker.demo
python -m pytest tests/test_audit_checker.py -q -p no:cacheprovider \
  --confcutdir=tests -o addopts=''
```

The synthetic C file demonstrates missing audit, duplicate audit through a
helper, clean rollback, and an unknown external policy boundary.
