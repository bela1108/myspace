.. # Licensed under the Apache License, Version 2.0 (the "License");
   # you may not use this file except in compliance with the License.
   # You may obtain a copy of the License at
   #
   #     http://www.apache.org/licenses/LICENSE-2.0
   #
   # Unless required by applicable law or agreed to in writing, software
   # distributed under the License is distributed on an "AS IS" BASIS,
   # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   # See the License for the specific language governing permissions and
   # limitations under the License.
   #
   # SPDX-License-Identifier: Apache-2.0

Archive reconciliation
======================

``cyclonedx.reconcile`` is a traceable entry point for comparing the read-only
file manifest of a delivered archive with the component declarations in a
CycloneDX BOM. It is intentionally separate from BOM serialization: the evidence
is never modified, and an audit can be repeated after an exclusion decision
changes.

Inputs
------

The audit takes three independent inputs:

1. **Archive manifest** - immutable records with ``entry_id``, container path,
   content digest, and optional size or media type.
2. **Component declarations** - extracted from a CycloneDX BOM or supplied as a
   declaration JSON file. Hashes come from ``component.hashes`` and locations
   come from ``component.evidence.occurrences``.
3. **Exclusion decisions** - explicit decisions with an owner, timestamp,
   rationale, revision, target side, and at least one selector. Decisions are
   never implicit filters.

JSON shapes
~~~~~~~~~~~

An archive manifest entry can use an explicit container chain:

.. code-block:: json

   {
     "entry_id": "F004",
     "containers": ["release-1.0.tar", "payload/runtime.tar"],
     "path": "app/main.py",
     "hashes": [{"algorithm": "SHA-256", "value": "0123..."}],
     "size": 4096
   }

A declaration file is a list of component-shaped objects (or a
``components`` object). Hashes accept ``algorithm``/``value`` or the
CycloneDX names ``alg``/``content``. Locations may be canonical strings or
``containers`` plus ``path`` objects.

An exclusion decision must name a target and at least one selector:

.. code-block:: json

   {
     "decision_id": "EX-003",
     "target": "archive-record",
     "revision": 2,
     "status": "approved",
     "decided_by": "Forensics Board",
     "decided_at": "2026-11-20",
     "rationale": "SBOM and container carrier are packaging records.",
     "entry_ids": ["F002", "F003"]
   }


Locations inside layered containers
-----------------------------------

An archive path records the container chain from outermost to innermost and the
member path inside the innermost container. The canonical string uses ``!/`` as
the separator:

.. code-block:: text

   release-1.0.tar!/payload/runtime.tar!/app/main.py

``ArchivePath`` preserves the chain as ``containers`` plus ``path``. This is
what makes a declaration that was produced before packing still comparable to
the post-packaging location: both sides normalize to the same canonical path,
and the report always shows the containing layers.

Matching rules
--------------

Matching is deterministic and conservative:

* A declaration that names a location present in the manifest is anchored to
  that record. If hashes also agree, the basis is ``location-and-digest``. If
  the hashes disagree, the record is still linked, but it is reported as a
  content conflict.
* If no declared location exists, a declaration is linked only when its digest
  identifies exactly one archive record. This supports files moved inside the
  archive without guessing between copies.
* If a digest identifies several archive records and the declaration supplies
  no location anchor, the declaration is left unresolved instead of being
  assigned to an arbitrary copy.

Two different ambiguities
-------------------------

The report keeps these findings separate:

* **Digest fan-out** - one digest appears at multiple archive paths. The
  finding lists every path and every declaring component.
* **Location contention** - one path is declared by multiple components. The
  finding lists every component and the one archive record they all claim.

These are different questions. Digest fan-out is about content duplication
across paths; location contention is about multiple ownership claims at one
location. The summary counts them independently, and a record can carry both
flags.

Exclusions and re-audit
-----------------------

``ExclusionDecision`` selectors are combined with AND across dimensions and OR
within a dimension. For example, a decision can target one component reference
and one location glob at the same time. An empty decision is rejected, because
a blanket ignore is not an auditable exclusion.

``Reconciler`` holds the read-only manifest and declarations. Each call to
``audit`` takes a complete decision set. ``diff_audits`` compares two results
and reports record transitions such as ``archive-only -> excluded``, along with
manifest, declaration, and policy fingerprints. A changed decision scope
therefore produces a new audit without re-reading or mutating the evidence.

Python API
----------

.. code-block:: python

   from cyclonedx.reconcile import Reconciler, diff_audits
   from cyclonedx.reconcile.loaders import (
       decisions_from_file,
       declarations_from_bom_file,
       manifest_from_file,
   )

   manifest = manifest_from_file("manifest.json")
   declarations = declarations_from_bom_file("sbom.cdx.json")
   reconciler = Reconciler(manifest, declarations)

   before = reconciler.audit(decisions_from_file("decisions-v1.json"))
   after = reconciler.audit(decisions_from_file("decisions-v2.json"))
   change = diff_audits(before, after)

A one-shot call is also available:

.. code-block:: python

   from cyclonedx.reconcile import reconcile

   result = reconcile(manifest, declarations, decisions)

Command line
------------

.. code-block:: shell

   python -m cyclonedx.reconcile \
     --manifest manifest.json \
     --bom sbom.cdx.json \
     --decisions decisions-v2.json \
     --baseline-decisions decisions-v1.json

Use ``--json`` for a machine-readable document. Use ``--fail-on-unexplained``
to return exit status 2 when archive-only, declaration-only, ambiguous, or
conflicting records remain.

Output categories
-----------------

The text report always renders these categories separately:

* **Archive records without declaration** - physical records with no component
  claim and no approved exclusion.
* **Declarations without archive record** - component claims with no physical
  record and no approved exclusion.
* **Confirmed exclusions** - records that would otherwise be in one of the two
  categories, but are covered by an approved decision. The report includes the
  decision id, revision, owner, timestamp, and rationale.

Content conflicts, unresolved ambiguities, digest fan-out, and location
contention are displayed before those three sections so that they are never
silently folded into an unexplained count.

Fixture
-------

``tests/_data/reconcile/two_layer`` is a static two-layer archive fixture:

* ``release-1.0.tar`` has 3 outer records, including ``payload/runtime.tar``.
* The inner tar has 44 records, for 47 archive records total.
* ``sbom.cdx.json`` declares 40 components.
* Two paths share one SHA-256 digest.
* One path is declared by two components.
* ``decisions-v1.json`` excludes only the SBOM envelope; ``decisions-v2.json``
  extends that decision to the nested container carrier.

Run ``examples/reconcile_archive.py`` to print the baseline audit, the re-audit
diff, and the revised three-section report.
