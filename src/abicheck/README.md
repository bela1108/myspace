# abicheck — read-only managed ABI responsibility check

`abicheck` compares two versions of a managed assembly using only `dnfile`
read APIs. It never writes to the inspected files.

## Inputs

* two assembly versions (file paths, in-memory bytes, or already-open `dnPE`);
* the caller's entry list — `EntrySpec(type_name, member_name?, parameter_types?)`;
* the approved type sources — `SupportedTypeSource(assembly_name, type_names?)`,
  the only external references accepted as evidence.

## Verdicts

* `SUPPORTED` — the old public identity is still present with an equivalent
  name, interpreted parameter/return signature and visibility. Row position in
  the metadata tables is ignored, so reshuffled rows never count as a diff.
* `IDENTITY_CHANGED` — a public identity demonstrably moved: renamed/removed
  type or member, changed base type, changed parameter/return signature or
  parameter direction, or narrowed visibility.
* `UNRESOLVED` — the metadata lacks the evidence needed to decide, typically a
  reference into a missing AssemblyRef/component or an unapproved type source.
  The checker never turns this into a positive or a negative conclusion.

## Synthetic test material

`abicheck.synthetic` builds ordinary, metadata-only PE32+CLI assemblies from
in-memory models, so the tests need neither a .NET toolchain nor external
binary fixtures. See `tests/abi/` for the covered scenarios.
