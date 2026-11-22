# Read-only capture direction audit

`dpkt.capture_audit` answers a narrow forensic question for two offline
captures of the same TCP service:

> Given a small set of trusted time anchors, TCP handshake segments that can be
> connected by sequence/acknowledgement numbers, and the collector wiring
> records, which observed session directions have enough evidence to confirm or
> reverse the direction written on the work order?

The module reads packet files with `dpkt` and never writes to them. The CLI
refuses to use an input capture path as an output path.

## Evidence model

The audit deliberately separates evidence from context.

| Evidence | Strength | Use |
| --- | --- | --- |
| `SYN` + `SYN-ACK` + `ACK` linked by exact `seq`/`ack` numbers | strong | establishes which endpoint is the client; a missing final `ACK` still leaves a strong 2-of-3 link for direction |
| trusted time anchor | strong for the anchored capture/time | pins the mirror polarity at a known-good time |
| wiring record | candidate alone; supported after a trusted baseline | describes an expected change, but a record can itself be wrong |
| work-order claim | claim only | compared against evidence; never treated as proof |
| ports / packet counts | display only | shown for context; never used to decide direction |

A successful handshake link uses all of the following:

* the reverse 4-tuple (`src`/`dst` addresses and ports);
* `SYN-ACK.ack == (SYN.seq + 1) mod 2**32`;
* when the final ACK is captured, `ACK.ack == (SYN-ACK.seq + 1) mod 2**32`;
* the final ACK has a compatible sequence number and is seen after the
  `SYN-ACK` in the same capture (a cross-capture clock offset is tolerated and
  reported).

The link works across the two capture files. A recorder clock offset does not
prevent a complementary `SYN` / `SYN-ACK` pair from being joined, because the
sequence/acknowledgement numbers, not wall-clock ordering, are the primary
link.

### Polarity vocabulary

A capture polarity is the role of the source side of its observed traffic:

* `client` - the capture source is the TCP client / SYN sender;
* `server` - the capture source is the TCP server / SYN-ACK sender;
* `bidirectional` - one capture sees both directions, so a single
  source-role claim is too narrow.

Directions are normalised to:

* `client_to_server`
* `server_to_client`
* `bidirectional`

`normal` and `reversed` are accepted in a claim/anchor/wiring record and are
resolved against the capture `declared_direction`. For example, if
`declared_direction` is `client_to_server`, then `reversed` means
`server_to_client`.

### Time anchors and wiring epochs

Anchors are trusted observations. A wiring record is an untrusted transition
record. For a sample at time *t*, the resolver uses the latest event at or
before *t*:

* a trusted anchor at or before *t* gives an anchored/confirmed polarity;
* an untrusted wiring record after a trusted baseline anchor gives a
  **supported** inference (anchor baseline + recorded change);
* a wiring record with no trusted anchor baseline gives only a **candidate**
  polarity;
* if a later trusted anchor corroborates the wiring transition, the transition
  is considered explained;
* two trusted anchors that imply different polarities with no recorded change
  between them are reported as a conflict, with both anchor IDs in
  `conflicts[].sources`;
* a wiring record that contradicts a later trusted anchor is reported as a
  conflict, with the record and the anchor as sources.

An anchor is assumed to hold until the next trusted event or recorded wiring
change. The report records the exact trace used. There is no hidden use of
packet counts or port numbers to fill a gap.

## Case JSON

```json
{
  "service": "diagnostic-service",
  "captures": [
    {
      "id": "cap_a",
      "path": "captures/a.pcap",
      "declared_direction": "client_to_server"
    },
    {
      "id": "cap_b",
      "path": "captures/b.pcap",
      "declared_direction": "server_to_client"
    }
  ],
  "anchors": [
    {
      "id": "A1",
      "time": "2026-11-20T10:00:00Z",
      "capture": "cap_a",
      "source_role": "client",
      "basis": "bench test with a known client"
    }
  ],
  "wiring": [
    {
      "id": "W1",
      "time": 1763633100,
      "captures": ["cap_a", "cap_b"],
      "direction": "reversed",
      "note": "mirror leads swapped after maintenance"
    }
  ],
  "claims": [
    {
      "id": "C1",
      "capture": "cap_a",
      "from": 1763632800,
      "to": 1763633600,
      "direction": "client_to_server",
      "source": "work order"
    }
  ],
  "opinions": [
    {
      "investigator": "Li",
      "sample": {"capture": "cap_a", "src": "10.10.0.10", "sport": 40000},
      "direction": "client_to_server",
      "note": "SYN sender is normally the client"
    },
    {
      "investigator": "Wang",
      "sample": {"capture": "cap_a", "src": "10.10.0.10", "sport": 40000},
      "direction": "server_to_client",
      "note": "the mirror polarity is not independently pinned"
    }
  ]
}
```

`time`/`from`/`to` may be epoch seconds or ISO-8601. `captures` may also be an
object keyed by capture id. Relative capture paths are resolved against the
case file directory.

### Anchors

| Field | Meaning |
| --- | --- |
| `id` | traceable identifier quoted in reports |
| `time` | trusted observation time |
| `capture` | capture id, or `*` / a list |
| `source_role` | `client` or `server` |
| `direction` | alternative to `source_role`: `client_to_server`, `server_to_client`, `normal`, `reversed` |
| `client_endpoint`, `server_endpoint` | optional explicit endpoint roles for a bidirectional capture |
| `basis` | human explanation retained in the report |

Anchors are trusted by default. Set `"trusted": false` only if you want to
downgrade one to a wiring-style candidate.

### Wiring records

Wiring records use the same polarity fields as anchors. They are **not**
trusted by default. Use `"trusted": true` only if the record is itself a
verified observation.

### Claims

`claims` are work-order statements. A claim is either capture-window scoped
(no `sample`) or sample scoped (`sample` references a session id, a flow
string, a `capture#packet` reference, or a selector object).

A capture-window claim says: the source side of this capture is the claimed
role for this window. A sample-scoped claim says: this session observed
direction is the claimed direction. For a bidirectional capture, a
single-direction claim is reported as too narrow (`conflict`).

See `claims` in the report for `confirmed`, `supported`, `reversed`,
`candidate`, `contradicted_candidate`, `conflict`, and `undetermined`.

### Investigator opinions / disputes

An opinion has `investigator`, `sample`, and `direction`. Multiple opinions on
the same sample are accepted. If they disagree on a half-handshake sample and
no linked reciprocal segment connects it (a nearby anchor does not by itself
promote a half-handshake to confirmed):

* the session direction becomes `undetermined`;
* both opinions are kept;
* `why_pending` explains that both assignments remain consistent with the
  captured bytes;
* packet references and the handshake state are retained.

If a linked handshake or trusted anchor independently decides the sample, the
dispute is marked `resolved_by_evidence` instead of being suppressed.

## CLI

```bash
python examples/audit_capture_directions.py case.json
python examples/audit_capture_directions.py case.json --json report.json
python examples/audit_capture_directions.py case.json --markdown report.md
python examples/audit_capture_directions.py case.json --strict
```

Without a case file:

```bash
python examples/audit_capture_directions.py \
  --capture cap_a=a.pcap \
  --capture cap_b=b.pcap \
  --anchors anchors.json \
  --wiring wiring.json \
  --claims claims.json \
  --opinions opinions.json \
  --service diagnostic-service
```

The default stdout format is Markdown. `--format json` prints JSON instead.
`--strict` exits non-zero if conflicts remain (`2`) or if unresolved
undetermined sessions/claims remain (`3`).

## Python API

```python
from dpkt.capture_audit import audit_case_file, render_markdown, write_report

report = audit_case_file("case.json")
print(render_markdown(report))
write_report(report, json_path="report.json", markdown_path="report.md")
```

For a programmatic case without a file:

```python
from dpkt.capture_audit import audit_files

report = audit_files(
    captures=[
        {"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"},
        {"id": "cap_b", "path": "b.pcap", "declared_direction": "server_to_client"},
    ],
    anchors=[{"id": "A1", "time": 1000, "capture": "cap_a", "source_role": "client"}],
    claims=[{"id": "C1", "capture": "cap_a", "direction": "client_to_server"}],
)
```

## Report sections

* **Summary** - counts for sessions, claims, candidates, conflicts, disputes.
* **Evidence rules** - repeated so a reader cannot mistake ports/counts for
  direction evidence.
* **Inputs** - packet counts and SHA-256 per capture.
* **Trusted time anchors / Wiring records** - exact inputs and trust flags.
* **Claim verdicts** - each work-order claim with evidence grade and anchor
  trace.
* **Sessions** - handshake state, linked segments (`capture#index`), direction
  status, per-capture display-only ports/counts.
* **Candidates** - half-handshakes and other non-confirmed samples, retained
  rather than discarded.
* **Conflicts** - mutually exclusive sources with the conflicting IDs and
  packet/session references.
* **Investigator disputes** - both opinions and why a half-handshake remains
  pending.
* **Reversal traceability** - for every confirmed reversal, the trusted anchor
  and wiring events plus the linked handshake segments used to interpret the
  work-order label.

## Limitations

* The tool does not guess direction from well-known ports, payload contents, or
  packet counts. Those fields are display-only.
* It does not correct arbitrary recorder clock offsets. Exact TCP
  sequence/acknowledgement linkage is used across captures, and time ordering is
  only a secondary preference. If a link is ambiguous, it stays a candidate or
  a conflict.
* IPv4 and simple IPv6 TCP captures are supported. IPv6 extension-header
  chains are not reassembled.
* Only TCP is analysed; the audit is about mirrored TCP session direction, not
  UDP or higher-level protocol semantics.
