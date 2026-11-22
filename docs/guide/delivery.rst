Embargo-Aware Delivery Previews
===============================

``stix2.delivery`` answers the publisher question: given a receiving category
and a delivery time, which objects and relationships may be sent together?

Embargo metadata is carried on ordinary STIX objects using custom properties:

* ``x_embargo_until`` (or ``x_declassify_at``/``x_public_at``) sets the
  release time;
* ``x_release_categories`` limits the receiving categories;
* ``x_restricted_cases`` names restricted cases whose independent embargo
  policies must also be satisfied;
* a relationship may pin the endpoint version it was written against with
  ``x_source_version`` or ``x_target_version``.

Basic preview
-------------

.. code-block:: python

   from stix2.delivery import preview_delivery

   preview = preview_delivery(
       objects=bundle_or_list_of_stix_objects,
       receiving_categories=["partner"],
       at="2026-12-01T00:00:00Z",
   )

   print(preview.released_ids)
   print(preview.blocked_ids)
   print(preview.permits["relationship--..."].reason)
   print(preview.to_bundle().serialize(pretty=True))

Relationships are only released when both endpoints are released.  If a
relationship release time is later than both endpoints, its permit is
``denied`` and has ``still_blocks_publication=True`` until that time.

Selected versions
-----------------

When several versions of an object ID are supplied, the latest version whose
``modified`` (or ``created``) time is not later than the delivery time is
used.  Each object item records ``version`` and ``version_property``; each
relationship records ``source_version``/``target_version`` and spec versions.
When a relationship declares a version, the declared version is used for the
object in the bundle as well.

Temporary extension
-------------------

.. code-block:: python

   extended = preview.extend_embargo(
       ["relationship--..."],
       "2027-01-15T00:00:00Z",
       reason="case review",
   )

   print(extended.updated_ids)
   print(extended.by_id["relationship--..."].revision)

Unchanged items keep their original revision and timestamp.

Before and after an embargo lift
--------------------------------

.. code-block:: python

   from stix2.delivery import preview_transition

   transition = preview_transition(
       objects=objects,
       receiving_categories=["partner"],
       embargo_until="2027-01-15T00:00:00Z",
   )
   transition.save("previews", stem="case-42")
   # writes previews/case-42-before.json and previews/case-42-after.json

Cycles
------

Relationships retain their STIX direction (``source_ref -> target_ref``).
Cycles are reported with a deterministic path and per-edge directions; each
relationship item also has ``cycle_id``, ``cycle_path`` and
``cycle_next_ref``.
