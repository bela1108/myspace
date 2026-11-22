Source-Independence Checks
==========================

The ``stix2.provenance`` package answers a narrow case-file question: when
several reports repeat the same statement, do they represent several independent
collections, or are some of them retelling one underlying collection?

The checker reads only local STIX 2 evidence.  It does not contact a TAXII
server, dereference external URLs, or compare free text.  Instead it builds a
graph from:

* ``observed-data`` objects (the observations);
* self-declared citations on an observation, read from configurable properties
  such as ``citation_refs`` or from STIX-ID-shaped ``external_references``;
* STIX ``relationship`` objects with caller-selected provenance types, and
  caller-supplied ``collection_relations`` / ``citations`` links.

``report`` objects are counted for context (``report_count`` and
``referenced_observation_count``), but they are not source nodes themselves.
A report is a claim about observations, not a collection event.  A caller who
wants to use a standard reference property as a citation can add that property
to ``citation_properties``; for example, using ``object_refs`` together with
``source_types=("observed-data", "report")`` makes reports participate as
claim nodes.

Observations connected directly or transitively, including mutual citation
cycles, belong to one source component.  A source component contributes at
most one independent source.

Public and custodian views
--------------------------

.. code-block:: python

   import stix2
   from stix2.provenance import CUSTODIAN_VIEW, PUBLIC_VIEW, check_independence

   public = check_independence(bundle, view=PUBLIC_VIEW)
   custodian = check_independence(bundle, view=CUSTODIAN_VIEW)

   public.independent_sources_lower_bound
   public.independent_sources          # None: exact counts are not public
   custodian.independent_sources       # exact local component count

A restricted observation is one carrying a marking-definition configured as
custodian-only.  The caller may pass the marking IDs explicitly:

.. code-block:: python

   public = check_independence(
       bundle,
       restricted_markings=["marking-definition--..."],
   )

For convenience, marking definitions whose name, definition type, or statement
contains ``CUSTODIAN``, ``CUSTODY``, or ``保管`` are also recognised.  Automatic
recognition can be disabled with ``auto_detect_restricted_markings=False``.

In the custodian view restricted observations are ordinary graph nodes, so
references to them resolve and the exact count is available.  In the public
view they are removed entirely.  A public reference to a restricted target is
therefore reported exactly like a reference to a missing identifier:

* ``target_ref`` is ``None``;
* ``reason`` is ``"unresolved"``;
* no restricted identifier, name, count, or existence flag appears anywhere in
  the public result.

This gives a strong, testable privacy property: two inputs that differ only in
whether a cited target is restricted or simply absent produce byte-identical
public results.

Lower bounds
------------

The public result exposes two bounds:

``independent_sources_lower_bound`` / ``closed_plus_open_bound``
   The evidence-model lower bound: the number of fully resolved components plus
   one for all open components.  This is the useful bound when restricted
   observations are cited targets only.

``conservative_lower_bound``
   A stricter bound for callers who assume a restricted observation may itself
   cite visible observations.  If any visible component has an unresolved
   reference, a hidden observation could connect it to another visible
   component, so this bound drops to one.  When every public reference is
   resolved, it equals the number of visible components.

The custodian view returns the exact local component count and sets all bounds
to that value.

The public bound is computed from visible evidence.  Restricted observations
which are never referenced by visible content are treated as absent; the
custodian view remains the authoritative exact local count.  If no observation
is visible, the public lower bound is zero: asserting a positive count would
disclose that a restricted observation exists.

Reference gaps
--------------

``result.gaps`` contains every unresolved citation or collection relationship.
The public form is deliberately indistinguishable between a restricted target
and an absent target.  The custodian form retains the actual target identifier
for genuinely missing targets and resolves restricted targets to ordinary
edges.  Cycles are handled by a union-find pass, so mutual citations terminate
and merge their members into one component.

Caller-registered links
-----------------------

A caller may register relations that are not represented by STIX SROs:

.. code-block:: python

   # Both observations came from the same collection key.
   check_independence(
       objects,
       collection_relations={obs_a.id: "seizure-17", obs_b.id: "seizure-17"},
   )

   # An explicit link between two observations.
   check_independence(objects, collection_relations=[(obs_a.id, obs_b.id)])

   # A citation supplied outside the STIX object.
   check_independence(objects, citations={obs_a.id: [obs_b.id]})

Mapping values which are not observation identifiers are treated as opaque
collection keys.  They are used for merging only and are never emitted in the
public result.

Command line
------------

The package also has a read-only command-line entry point:

.. code-block:: bash

   python -m stix2.provenance bundle.json --view public
   python -m stix2.provenance bundle.json --view custodian \
       --restricted-marking marking-definition--...

The command writes the same ``as_dict()`` representation as the Python API.
The public view remains redacted regardless of the input file.

Walkthrough
-----------

``examples/provenance_independence.py`` builds three small exhibits:

* three reports backed by three genuinely independent observations;
* two reports relaying one restricted original; and
* the opening narrative: three reports where two relay one restricted source
  and the third is independent.

The script asserts the public redaction property and prints the redacted public
result.  It does not write restricted identifiers or names to disk.
