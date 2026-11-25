Change-window announcement adjudication
=======================================

``cpe.change_adjudication`` adds a time-aware policy layer on top of the CPE
name matcher.  It is intended for the case where the inventory, an upgrade
change, a rollback change, and an announcement overlap in time.

Inputs
------

The main entry point accepts a JSON-style payload (or four positional
sequences) containing:

``assets``
    Original assets and their component CPE names.
``tickets``
    Change tickets with ``asset_id``, ``starts_at``, ``ends_at``, and the CPE
    expressions in ``planned_components``/``planned_cpes``.  A ticket can list
    ``component_ids`` as well.
``observations``
    Actual ``upgrade``, ``rollback``, or inventory observations.  An optional
    ``previous_observation_id`` links consecutive changes explicitly.
``announcements``
    Announcement ids and CPE expressions (or CPE names).
``aliases``
    Optional CPE aliases.  An alias is usable only at or after both its
    ``effective_at`` and ``recorded_at`` times, so a late backfill cannot
    retroactively authorize an earlier window.

Example
-------

.. code-block:: python

    from cpe import adjudicate_announcements

    result = adjudicate_announcements(payload, as_of="2026-11-20T13:00:00Z")
    work_list = result.remediation_list()

The result contains per-component decisions with three important states:

* ``deferred``: the current CPE matches the announcement, and an active ticket
  covers that exact component and window.
* ``remediation``: the announcement matches but no valid deferral covers it.
  ``returned_after_deferral`` explains announcements that came back after a
  partial rollback.
* ``manual_review``: the state cannot be proven, for example because an
  inventory interval is missing or two overlapping changes do not have
  chainable evidence.

Every remediation entry records the announcement expression, the observed and
resolved CPE names, the matching CPE fields, and the observation/ticket
evidence used.  The exported list is sorted by stable identifiers; changing
the order of observations in the input does not change the list.

Command line
------------

.. code-block:: console

    $ python -m cpe.change_adjudication payload.json --as-of 2026-11-20T13:00:00Z
    $ python -m cpe.change_adjudication payload.json --remediation-only
    $ python -m cpe payload.json --remediation-only

Use ``--output FILE`` to write the deterministic JSON result to a file.
