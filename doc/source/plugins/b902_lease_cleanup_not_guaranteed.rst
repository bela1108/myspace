========================================
B902: lease_cleanup_not_guaranteed
========================================

.. automodule:: bandit.plugins.lease_lifecycle
   :no-index:

Deregistration exists, but it is not in an unconditional ``finally`` block
and an exception/rethrow path may bypass it.
