License decisions
=================

The license decision API lives beside the license model and evaluates a BOM
against a channel policy. It is available from
cyclonedx.model.license, cyclonedx.model.license_decision, and
cyclonedx.model.license_policy.

SPDX expressions keep their expression semantics:

* A AND B requires both conditions.
* A OR B selects one feasible branch; alternatives are retained.
* A WITH E is one condition. The exception is reported separately and is
  never turned into an extra AND condition.

Example
-------

.. code-block:: python

    from cyclonedx.model.bom import Bom
    from cyclonedx.model.license import LicensePolicy, decide_license_compliance

    policy = LicensePolicy(
        channel='public-store',
        allowed=['MIT', 'Apache-2.0'],
        binary_allowed=['MIT', 'Apache-2.0'],
        source_allowed=['MIT', 'Apache-2.0', 'GPL-3.0-only'],
    )

    decision = decide_license_compliance(
        bom,
        policy,
        release_scope='source',  # or 'binary'
    )

    if decision.allowed:
        print(decision.selected_expression)
    else:
        for conflict in decision.conflicts:
            print(conflict.component.name, conflict.atom, conflict.reason)

The default component sets are source: required and optional; binary:
required. Use component_scope to select a CycloneDX component scope
explicitly, or source_component_scopes/binary_component_scopes on the policy.

Declared, concluded, and observed licenses are reported on every selected
condition and conflict. Result objects also retain the original BOM, component,
license, and expression-detail objects so an auditable decision can be linked
back to the source document.
