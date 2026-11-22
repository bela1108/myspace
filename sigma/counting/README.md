# Offline Counting Contract Check

When an application is migrated to dual-write collection, one logical
operation can arrive twice (count inflation), while operations without a
stable event number can be collapsed into one (count collapse). Both change
the result of Sigma correlation rules before any backend query is run.

This package adds an offline counting contract layer between correlation
rule parsing and conversion. It never talks to a SIEM: it decides from
declared contracts whether a correlation rule is provably de-duplicable, and
it replays a fixed event set to make inflation/collapse observable.

## Counting contract

Each log source may declare a contract (see demo/contracts.yml):

- identity_fields: one or more fields whose combined values uniquely identify
  a single logical operation.
- equivalences: provably equivalent field mappings. Only 1:1 renames and
  declared bijective transforms are accepted; conflicting mappings are
  rejected at load time.
- time_precision: the minimum timestamp granularity the source guarantees. A
  precision coarser than the correlation timespan makes a branch
  undetermined, because events inside a window cannot be proven distinct by
  time.

## Verdict semantics

Every branch (referenced base rule) is evaluated independently:

- determined: the branch log source has a contract whose identity is provable
  and whose time precision fits the correlation timespan.
- undetermined: no contract, no provable identity, or insufficient time
  precision. The verdict carries the branch name, log source and a human
  readable reason so the result is directly locatable.

A correlation rule is determined only when ALL branches are determined; a
single undetermined branch makes the whole rule report an undetermined result
instead of silently producing a wrong count.

Group-by and unique-value fields partition or select already de-duplicated
rows, so they are intentionally not required to be identity fields.

## Counting basis

Reports keep the two correlation families separate:

- count based (event_count, temporal, temporal_ordered and the
  sum/avg/percentile/median aggregates) compare a number of events against a
  threshold;
- unique value based (value_count) compare the number of distinct field
  values. Dual-write duplicates inflate raw events but must not change the
  distinct-value cardinality once rows are de-duplicated on identity.

## Replay scenarios

The same small logical-operation set (demo/operations.yml) is materialized
three ways:

- single_write: one event per operation;
- dual_write: every operation emitted by two collectors;
- missing_identity: the identity field is removed, modeling operations
  without an event number.

For each scenario the engine records the raw count, the contract-aware
de-duplicated count, distinct-value cardinality and both the naive and
contract-aware alert decisions. When their alert decisions differ, the report
attributes the threshold change to the concrete rule + scenario + basis.
Missing identity yields an explicit undetermined outcome rather than a guess.

## Usage

Run the bundled demonstration and write JSON/Markdown reports:

    python -m sigma.counting.cli

Programmatic use:

    from sigma.counting.checker import CountingContractChecker
    from sigma.counting.registry import CountingContractRegistry

    registry = CountingContractRegistry.from_file("contracts.yml")
    result = CountingContractChecker(registry).check(correlation_rule)
    if result.undetermined_branches:
        ...  # block conversion / surface the locatable branches
