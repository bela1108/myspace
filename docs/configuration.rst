Offline configuration interpretation
====================================

The :mod:`cpe.configuration` module evaluates a small advisory
configuration tree against a device inventory without any network access.
An advisory can combine CPE clauses with ``AND``, ``OR`` and exclusion
nodes.  A device is affected only when every required clause in the
``AND`` expression is satisfied and no exclusion clause matches.

Three inventory observations
----------------------------

Every inventory item has one of three observations:

``seen``
    The component was collected and its CPE Name is known.

``absent``
    The inventory explicitly established that the component is not present.

``pending``
    The component has not been collected yet.  This is unknown evidence,
    not an absence.

The distinction matters for exclusions.  An uncollected item must never be
treated as an exclusion that holds: an exclusion leaf whose evidence is
``pending`` evaluates to unknown, and the enclosing device remains
``undetermined``.

Configuration format
--------------------

The following configuration requires a vulnerable Linux system and the
vulnerable backup agent.  The final ``EXCLUDE`` clause prevents a device
with the patched agent from matching::

    from collections import OrderedDict

    CONFIG = OrderedDict((
        ("id", "advisory-2026-0001"),
        ("operator", "AND"),
        ("children", [
            OrderedDict((
                ("id", "system-clause"),
                ("key", "os"),
                ("cpe", "cpe:/o:acme:linux:1.2"),
            )),
            OrderedDict((
                ("id", "plugin-clause"),
                ("key", "plugin"),
                ("cpe", "cpe:/a:acme:backup_agent:3.1"),
            )),
            OrderedDict((
                ("id", "mitigation-clause"),
                ("operator", "EXCLUDE"),
                ("key", "mitigation"),
                ("cpe", "cpe:/a:acme:backup_agent:3.1:patched"),
            )),
        ]),
    ))

``AND``, ``OR``, ``NOT`` and ``EXCLUDE`` are supported.  A node can also
use ``exclusions`` as a list; this is shorthand for adding an ``EXCLUDE``
child to an ``AND`` node.  A leaf uses ``cpe`` (or a component mapping)
and may name its inventory slot with ``key``.

Interpreting a device
---------------------

::

    from cpe.configuration import explain

    result = explain(CONFIG, device)
    result.status              # affected, undetermined or excluded
    result.truth               # true, false or unknown
    result.clauses["system-clause"]
    result.evidence["os"]

Each clause explanation contains the matched or non-matching CPE component
values.  For example, ``result.evidence["os"]["components"]`` contains the
expected and observed values of ``part``, ``vendor``, ``product``,
``version`` and the remaining CPE attributes, plus the relation that was
used to match them.  Composite nodes keep their child clauses, so the
evidence needed to support every sub-clause is still available.

Synthetic devices
-----------------

``synthetic_devices()`` returns three inventories that exercise the three
device-level conclusions:

* ``device-affected``: matching system and plugin, with the mitigation
  explicitly absent.  The result is ``affected``.
* ``device-pending``: matching system, but the plugin and mitigation were
  not collected.  The result is ``undetermined``; the pending mitigation is
  not treated as exclusion evidence.
* ``device-excluded``: matching system and plugin, but the patched
  mitigation is explicitly seen.  The exclusion node matches, so the result
  is ``excluded``.

Revision after a system change
------------------------------

::

    from cpe.configuration import ConfigurationExplainer, synthetic_devices

    explainer = ConfigurationExplainer(CONFIG)
    explainer.add_device(synthetic_devices()["affected"])

    revision = explainer.revise_system_version(
        "device-affected", "cpe:/o:acme:linux:2.0")

    revision.previous_status   # affected
    revision.current_status    # excluded
    revision.revoked           # conclusions that used the os evidence
    revision.preserved         # plugin-only conclusions that were retained

revise_system_version also accepts a bare version such as "2.0"
when the inventory already has a system CPE; only the version component is
replaced.

Revisions are dependency-aware.  Only clauses whose evidence set contains
the changed component (``os`` in this example) are revoked.  Conclusions
that depend only on the plugin evidence remain valid and appear in
``preserved``.
