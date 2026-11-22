Handover Audit
==============

The ``sigma.audit.handover`` module performs offline shift handover audits. It
uses pySigma rule identity, a processing pipeline trace, explicit shift duties,
and approved substitutes. It does not convert rules or send notifications.

Rule IDs and names
------------------

.. autofunction:: sigma.audit.handover.rule_identity

.. autoclass:: sigma.audit.handover.RuleIdentity
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.RuleSelector
   :members:
   :undoc-members:

Shift input
-----------

.. autoclass:: sigma.audit.handover.Shift
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.ShiftDuty
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.SubstituteApproval
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.SubstituteStatus
   :members:
   :undoc-members:

Processing branches
-------------------

.. autoclass:: sigma.audit.handover.ProcessingBranch
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.ProcessingTrace
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.BranchState
   :members:
   :undoc-members:

Audit results
-------------

.. autoclass:: sigma.audit.handover.HandoverState
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.RuleAudit
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.Recipient
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.UncoveredDuty
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.NotificationChain
   :members:
   :undoc-members:

.. autoclass:: sigma.audit.handover.HandoverReport
   :members:
   :undoc-members:

Entry points
------------

.. autofunction:: sigma.audit.handover.audit_handover

.. autofunction:: sigma.audit.handover.audit_shift_handover

.. autoclass:: sigma.audit.handover.HandoverConfig
   :members:
   :undoc-members:

.. autofunction:: sigma.audit.handover.audit_from_config
