Handoff pre-checks
==================

.. py:module:: jks.handoff

When the same JKS backup is handed off to several systems, each receiving
system may apply a different convention when comparing aliases (exact match,
lower-casing, full Unicode case folding, or a fixed legacy alias mapping).
Importing a backup can then silently overwrite an already trusted entry.

The :mod:`jks.handoff` module provides an embeddable, read-only pre-check.
The caller supplies, per target, the alias folding rule and the public list
of aliases already present on that target. The pre-check only reasons about
entry identity (aliases); it never reads certificate or key material and
never modifies the supplied keystore, so the normal read path is untouched.

Each backup alias is classified independently for every target as:

* a **conflict** when its folded alias matches an existing target alias;
* **unconfirmed** when the rule cannot map the alias, or when multiple
  backup entries fold onto the same effective alias;
* **conflict-free** when the folded alias is unique in the backup and absent
  from the target's existing aliases.

Example
-------

.. code-block:: python

    import jks
    from jks.handoff import (
        precheck_handoff, ExactRule, LowerCaseRule, CaseFoldRule, MappedRule,
    )

    ks = jks.KeyStore.load("backup.jks", "storepass")
    report = precheck_handoff(ks, [
        ("legacy", MappedRule({"rootca": "rootca"}), ["rootca"]),
        ("modern", CaseFoldRule(),                    ["rootca"]),
        ("exact",  ExactRule(),                       ["RootCA"]),
    ])

    for target in report:
        print(target.name, target.conflicts, target.unconfirmed, target.conflict_free)

Alias rules
-----------

.. autoclass:: AbstractAliasRule
    :members:

.. autoclass:: ExactRule
    :members:

.. autoclass:: LowerCaseRule
    :members:

.. autoclass:: CaseFoldRule
    :members:

.. autoclass:: MappedRule
    :members:

.. autoclass:: CallableRule
    :members:

Results
-------

.. autoclass:: TargetPrecheckResult
    :members:

.. autoclass:: HandoffPrecheckReport
    :members:

.. autofunction:: precheck_handoff

Exceptions
----------

.. automodule:: jks.handoff
    :show-inheritance:
    :members: HandoffException, AliasNotMappableException, DuplicateBackupAliasException
