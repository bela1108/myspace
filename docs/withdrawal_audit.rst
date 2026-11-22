Advisory withdrawal re-audit
============================

Purpose
-------
When an advisory is withdrawn, a maintenance desk may have already
shut down every asset that looked related.  This audit replays the
decision with four independent inputs: the advisory CPE expression,
the inventory scope approved by the caller, the before/after inventory
snapshots, and component replacement credentials.

It produces a provable scope with three distinct outcomes:

* confirmed_closed: the asset was affected and is now provably closed;
* still_affected: the current inventory still matches the advisory;
* insufficient_evidence: the supplied evidence cannot prove either.

Inputs
------

* advisory expression and applicability interval;
* caller-approved asset identifiers and per-family coverage evidence;
* inventory before withdrawal and inventory after withdrawal;
* verified replacement credentials keyed by asset and component slot.

Three-valued matching
---------------------
The core package exposes boolean name matching.  A boolean false is not
safe here because a failed match may mean the inventory is incomplete.
The audit therefore keeps three values:

* MATCH: every attribute relation is EQUAL or SUPERSET;
* NO_MATCH: at least one attribute is provably DISJOINT;
* UNKNOWN: a wildcard, missing component, SUBSET, or UNDEFINED relation.

UNKNOWN propagates through AND and OR.  It is never converted to
NO_MATCH.  Only a complete manifest can turn "no matching component" into
NO_MATCH.

Decision rules
--------------
A replacement credential closes an asset only when all of the following
hold: the credential is verified; it identifies a credential reference;
the old CPE matches the advisory; the new CPE is provably disjoint; the
old and new values agree with the before and after snapshots; and the
effective time falls between advisory publication and the after snapshot.

If the after snapshot still matches, the asset is still affected even if a
credential claims a replacement.  If the before snapshot matched and the
after snapshot is disjoint without a valid credential, the change is not
provable and the result is insufficient evidence.

Family exclusion rule
---------------------
A family is excluded only when its coverage evidence is marked complete,
the covered interval includes the whole advisory applicability interval,
the evidence asset list agrees with the caller-approved scope, and every
asset in the family is NO_MATCH in both snapshots.

No match alone is never enough.  An incomplete family remains unresolved,
and out-of-scope assets are reported separately without being reclassified
as unaffected.

Running the example
-------------------
::

    python examples/withdrawal_audit/run_audit.py
    python examples/withdrawal_audit/run_audit.py --output report.json

The bundled inventory yields one asset in each outcome: web-01 is
confirmed_closed, db-01 is still_affected, and edge-01 is
insufficient_evidence.  Every row carries an ordered basis list and
evidence references.
