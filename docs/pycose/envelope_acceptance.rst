Local envelope acceptance
=========================

``pycose.envelope_acceptance`` checks an existing COSE_Encrypt or
COSE_Encrypt0 evidence envelope without exposing its plaintext.  The caller
supplies a business manifest, caller-authorized local test keys, and metadata
constraints that have already been verified by the surrounding system.

The acceptance result contains recipient node names, allowed and requested
purposes, allowed and requested attachment groups, and structural digests.  It
never contains the decrypted payload.

Scope rules
-----------

* Every envelope recipient node must occur exactly once in the manifest.
* A node may be bound to only one commitment.  Two different commitments for
  the same node raise :class:`~pycose.envelope_acceptance.PolicyConflictError`.
* A requested purpose must be in the commitment's ``purposes`` set.
* Every requested attachment group must be in the commitment's
  ``attachment_groups`` set.
* A local test key is only used for its own authorized node and may carry a
  narrower purpose or attachment-group authorization.
* A pass receipt is constructed only after all checks, including internal
  payload authentication, have succeeded.  A rejected check has no receipt.

Example
-------

.. code-block:: python

    from pycose import accept_envelope

    report = accept_envelope(
        envelope_bytes,
        manifest={
            "recipients": {
                "auditor": {"purposes": ["audit"], "attachment_groups": ["exhibits"]},
                "counsel": {"purposes": ["litigation"], "attachment_groups": ["privileged"]},
            }
        },
        test_keys={"auditor": local_test_key},
        constraints={"purpose": "audit", "attachment_groups": ["exhibits"]},
    )

    # report.receipt is present only when report.accepted is true.

API
---

.. automodule:: pycose.envelope_acceptance
    :members:
    :exclude-members: AcceptanceConstraints

