Slot-scoped advisory adjudication
=================================

Problem
-------

A control cabinet can have one host number but several application slots.
Each slot can own a different component version.  A disposition report that
aggregates only by host cannot distinguish the slots, so a fix for one slot can
accidentally close the alarm set of another slot.

``cpe.advisory`` adds a slot-scoped adjudication layer on top of the CPE 2.3
name-matching implementation.  It keeps three identities separate:

* the cabinet and its single host number,
* the application slot, and
* the component witness that made a condition true.

The engine never treats a host roll-up as a slot roll-up.

Conditions
----------

A condition has a CPE pattern and a scope:

``host``
    The condition can only be witnessed by a host-common component.  A
    slot-bound component is not eligible, even when its CPE matches.

``slot``
    The condition is evaluated against the slot currently being adjudicated.
    It can only be witnessed by a component that belongs to that slot.  A
    component that exists only in another slot is reported as a shadow match,
    never as a witness.

A slot-scoped condition may set ``slot_id`` to make it required only for that
slot.  Without ``slot_id`` it is required for every slot and is always
evaluated against the components of that slot.

The advisory ``operator`` is ``AND`` by default.  With ``AND`` every required
condition must match.  With ``OR`` one match is enough.

Witness identity
----------------

Every successful match produces a :class:`cpe.advisory.Witness` with:

* ``component_id``,
* the component CPE,
* ``source_snapshot_id``,
* ``condition_id`` and ``condition_scope``, and
* ``component_slots``.

A closure record stores these witnesses.  A later adjudication can therefore
check the exact component identity instead of re-deriving a match from a host
summary.  :meth:`cpe.advisory.SlotAdjudicator.build_closure_record` is the
supported constructor; it refuses to close a condition that was not matched
for the slot.

Closure rules
-------------

A :class:`cpe.advisory.ClosureRecord` has a set of ``slot_ids``:

* ``slot_ids`` empty is a legacy host-aggregated closure.  It can cover a
  host-scoped condition, but it cannot cover a slot-scoped condition.
* ``slot_ids`` containing one slot closes that slot only.
* ``slot_ids`` containing several slots is an explicit joint closure, used for
  a shared component.  Every affected slot must be listed.

A closure from another slot is never a substitute for the target slot.  It may
be reused for a host-common condition because the host component is common, but
the target slot still needs its own witness, or an explicit joint closure, for
every slot-scoped condition.  In particular, even when the same CPE string is
present in both slots, the closure identity and the witness ownership do not
match.

Responsibility changes
----------------------

The report explains three scenarios.

Shared component
    One component belongs to several slots.  A physical fix may be shared, but
    the audit responsibility is joint.  Close each slot explicitly, or create
    one joint closure whose ``slot_ids`` name every affected slot.  A
    single-slot closure does not discharge the other slot.

Migration to a new slot
    When the same component identity moves to a new slot, the old closure is
    historical evidence only.  Host-common evidence can remain valid if the
    host component is unchanged, but every slot-scoped condition must be
    re-witnessed by the new slot.  Responsibility moves to the new slot owner
    at the migration snapshot.

Single-slot supplement
    A snapshot can re-evidence only one slot.  The other slots keep the newest
    earlier evidence that actually covered them and keep their previous owners.
    A single-slot supplement is never promoted to a host-wide disposition.

Snapshots and carried-over evidence
-----------------------------------

``Snapshot.evidence_slots`` records which slots were actually re-evidenced.
``None`` means all slots.  When the set contains one slot, that is a
single-slot supplement.  Snapshots are processed in the order given in the
case.  ``EvidenceTimeline`` resolves each slot independently:

* slot-bound components come from the newest snapshot that re-evidenced that
  slot, and
* host-common components come from the newest snapshot with host evidence.

Nothing is borrowed from another slot.

Python API
----------

The demo case is in ``examples/slot_advisory_case.json``::

    from cpe.advisory import load_case, query_case, report_to_dict

    case = load_case("examples/slot_advisory_case.json")
    report = query_case(case)

    for snapshot in report.snapshots:
        for slot_id, slot in sorted(snapshot.slots.items()):
            print(snapshot.snapshot_id, slot_id, slot.applicability.status)
            print("  closure:", slot.closure.status)
            for check in slot.substitution_checks:
                print("  blocked:", check.source_closure_id,
                      check.reason_code)

The structured form is JSON-serialisable::

    import json
    from cpe.advisory import report_to_dict

    payload = report_to_dict(report)
    print(json.dumps(payload, ensure_ascii=False, indent=2))

The core classes are:

``Cabinet``
    Cabinet id, single host id, and application slots.

``Component``
    Component id, CPE, and the slots that own it.  Empty ``slots`` means
    host-common.

``Snapshot``
    Components observed at a point in time, plus the evidence scope.

``Condition`` and ``Advisory``
    The bulletin conditions and their host or slot scope.

``Witness`` and ``ClosureRecord``
    The exact match identity and the disposition record that carries it.

``EvidenceTimeline`` and ``SlotAdjudicator``
    Per-slot evidence resolution and adjudication.

Command line
------------

Run the bundled fictional cabinet and its two snapshots::

    python -m cpe.advisory --demo

Run the migration example::

    python -m cpe.advisory examples/slot_migration_case.json

Emit structured JSON::

    python -m cpe.advisory --demo --json

Restrict the rendered output to one snapshot::

    python -m cpe.advisory --demo --snapshot snap-2026-11-22T09:30:00+08:00

The report lists, for every slot in every snapshot:

* the applicability status,
* the matched witness or the shadow matches,
* the closure status and missing conditions,
* why each other-slot closure cannot substitute, and
* the responsibility notes for the detected scenarios.

Input format
------------

A case is a JSON object with ``cabinet``, ``advisory``, ``snapshots``, and an
optional ``closures`` list.  A compact example::

    {
      "cabinet": {
        "cabinet_id": "CAB-07",
        "host_id": "HOST-0007",
        "slots": [
          {"slot_id": "A", "application": "feed control"},
          {"slot_id": "B", "application": "reflux control"}
        ]
      },
      "advisory": {
        "advisory_id": "ADV-2026-014",
        "operator": "AND",
        "conditions": [
          {
            "condition_id": "host-runtime",
            "scope": "host",
            "cpe": "cpe:2.3:a:acme:plc_runtime:4.2.1:*:*:*:*:*:*:*"
          },
          {
            "condition_id": "slot-a-hmi",
            "scope": "slot",
            "slot_id": "A",
            "cpe": "cpe:2.3:a:acme:hmi:2.1:*:*:*:*:*:*:*"
          },
          {
            "condition_id": "slot-b-hmi",
            "scope": "slot",
            "slot_id": "B",
            "cpe": "cpe:2.3:a:acme:hmi:3.0:*:*:*:*:*:*:*"
          }
        ]
      },
      "snapshots": [
        {
          "snapshot_id": "snap-1",
          "cabinet_id": "CAB-07",
          "evidence_slots": ["A", "B"],
          "components": [
            {
              "component_id": "hmi-a-01",
              "cpe": "cpe:2.3:a:acme:hmi:2.1:*:*:*:*:*:*:*",
              "slots": ["A"]
            }
          ]
        }
      ]
    }

Matching uses the CPE 2.3 superset relation from ``CPESet2_3``.  URI,
formatted-string, and WFN inputs are normalised to WFN before comparison, so
the condition and the inventory component can use different CPE 2.3 styles.
