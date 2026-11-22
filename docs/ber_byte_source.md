# Read-only BER byte sources and provenance

`asn1crypto.core.ParseContext` adds an opt-in provenance layer for BER/DER
material that must be compared or archived without losing its original bytes.
It keeps a read-only `ByteSource` over the input and attaches absolute spans to
values parsed through the context.

## Basic use

```python
from asn1crypto import core

context = core.ParseContext(encoded_bytes)
value = context.load(spec=MyRecord)

context.bytes          # the complete original input
context.source         # read-only ByteSource over the whole input
value.raw_bytes        # exact bytes for this value, header and trailer included
value.source.offset    # absolute start offset
value.source.end       # absolute end offset
value.path             # e.g. ("payload", "text")
value.evidence         # all evidence in this value and its descendants
```

`ParseContext` defaults to `preserve_encoding=True`, so `value.dump()` returns
the original bytes while the value is unmodified. `value.dump(force=True)` or
`value.dump(preserve=False)` produces DER. A forced re-encoding does not change
`value.raw_bytes`, `value.source`, or `context.bytes`.

## Two comparison results

```python
result = left.compare(right)
result.value_equal     # semantic ASN.1 equality
result.bytes_equal     # byte-for-byte equality of the original encodings
```

The same answers are available directly as `left.value_equal(right)` and
`left.bytes_equal(right)`. `ComparisonResult` also exposes `left_evidence`,
`right_evidence` and `evidence`.

Semantic equality compares canonical DER constructed without modifying either
input. A definite-length encoding and a legal indefinite-length BER encoding of
the same value therefore report `value_equal == True` and
`bytes_equal == False`.

## Evidence

`ParseEvidence` objects are locatable through `offset`, `end`, `length`, `path`
and `data`. The categories are:

- `ParseEvidence.ALTERNATE_ENCODING` for acceptable non-DER encodings. Specific
  `reason` values include `indefinite_length`, `constructed_string`,
  `nonminimal_length`, `nonminimal_integer`, `noncanonical_boolean` and
  `canonical_encoding`.
- `ParseEvidence.EXPLICIT_DEFAULT` for a field that was present in the input
  even though its value equals the ASN.1 DEFAULT.
- `ParseEvidence.UNINTERPRETED` for a value parsed without a schema, including
  an unresolved `Any`.

Convenience views are available as `context.alternate_encodings`,
`context.explicit_defaults`, `context.uninterpreted` and
`context.find_evidence(...)`.

## Definite/indefinite control sample

The test suite uses two encodings of the same record. The first is
definite-length and includes an explicit DEFAULT. The second uses legal
indefinite lengths and constructed strings:

```
30 14  02 01 01  04 04 01 02 03 04
       30 06  0c 01 61  02 01 07
       02 01 01

30 80  02 01 01
       24 80  04 02 01 02  04 02 03 04  00 00
       30 80  2c 80  0c 01 61  0c 00  00 00  02 01 07  00 00
       02 01 01
       00 00
```

Reading `payload.text`, `payload.counter` and the defaulted `retain` field does
not rewrite either input. Comparing the two reports semantic equality and
different original bytes, with each difference located by offset.
