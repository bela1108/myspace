Handover Assessment
===================

The handover assessment API inspects COSE_Encrypt metadata without decrypting the protected payload or unwrapping
recipient key material. It combines recipient headers with a caller-supplied offline roster and local handover material
to classify each recipient as eligible, ineligible, or information-incomplete.

Local handover material records every still-valid concurrent path, including the specific old group that holds the
path. Nested recipients are evaluated in their enclosing recipient context: an old-group subtree remains available
through an unexpired concurrent path, while a nested recipient explicitly attached to the new archive group is treated
as replaced and no longer depends on that old path.

.. module:: pycose.handover

.. autoclass:: HandoverMaterial
    :members:

.. autoclass:: HandoverAssessment
    :members:

.. autoclass:: RecipientAssessment
    :members:

.. autoclass:: ConcurrentRecipientPath
    :members:

.. autofunction:: assess_handover
