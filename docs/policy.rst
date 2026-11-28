Signature Policy API
====================

.. currentmodule:: securesystemslib.policy

The policy API supports retiring a signature algorithm class without losing
access to historical receipts. It keeps three concerns strictly separate:

* the **verification capability** of the local machine or a remote backend,
  represented by :class:`VerifierBackend` implementations,
* the **policy version** that decides which schemes are allowed for new
  material and which are kept for historical review only, represented by
  :class:`VerificationPolicy`, and
* the **material purpose** of a concrete :class:`Receipt`, represented by
  :class:`MaterialPurpose`.

A :class:`ComplianceReport` states, per receipt, whether the policy or the
verification environment has to change.

Retirement model
----------------

Two policy versions ship with the library:

* ``2025.2`` allows all registered schemes, including the legacy RSA
  PKCS#1 v1.5 class, for new material.
* ``2026.1`` moves the RSA PKCS#1 v1.5 class
  (``rsa-pkcs1v15-sha224`` ... ``rsa-pkcs1v15-sha512``) to review-only:
  new material must use a modern scheme such as RSASSA-PSS, ECDSA, Ed25519 or
  ML-DSA, while historical receipts remain verifiable.

Policies are plain data and know nothing about backends; the same policy can
be enforced offline, against a partial remote deployment or a test double.

Backends and partial deployments
---------------------------------

:class:`LocalVerifierBackend` verifies fully offline with ``pyca/cryptography``
and derives its capabilities from
``securesystemslib.signer.KEY_FOR_TYPE_AND_SCHEME``. Optional capabilities that
are not installed are reported as unsupported rather than as invalid
signatures.

:class:`FakeVerifierBackend` is a configurable test double: it can remove
individual schemes to simulate a partial backend, simulate an outage, or force
verification failures for selected schemes. Verification of supported schemes
is delegated to the real offline verifier, so tampered receipts are still
detected.

Readable historical receipts
-----------------------------

A :class:`Receipt` can be parsed without any backend. When the local
environment has no verifier for a claimed scheme, the key is represented by
:class:`UnsupportedKey`: every original field stays inspectable and
re-serializable, and an actual verification attempt raises
:class:`VerifierCapabilityError` instead of pretending the signature is bad.

Verdicts
--------

:func:`check_receipt` and :func:`check_receipts` return one of four outcomes:

* ``compliant`` -- the policy allows the usage and a signature verified,
* ``policy_change_required`` -- the policy does not allow the usage; changing
  the verification environment cannot fix it,
* ``environment_change_required`` -- the policy allows the usage but no
  available backend can verify it; install or restore the capability,
* ``signature_invalid`` -- a capable backend rejected the signature.

Example
-------

.. code-block:: python

    from securesystemslib.policy import (
        FakeVerifierBackend,
        LocalVerifierBackend,
        MaterialPurpose,
        POLICY_FOR_VERSION,
        Receipt,
        check_receipts,
    )

    policy = POLICY_FOR_VERSION["2026.1"]
    backends = [FakeVerifierBackend(name="acme"), LocalVerifierBackend()]

    receipts = [Receipt.from_dict(data) for data in historical_envelope]
    report = check_receipts(receipts, policy, backends)

    # Items needing a policy decision (e.g. a review-only scheme on new
    # material) versus items needing an environment fix (missing verifier).
    print(report.policy_changes())
    print(report.environment_changes())
    print(report.to_text())

API documentation
-----------------

.. autoclass:: securesystemslib.policy.VerificationPolicy
   :members:
.. autoclass:: securesystemslib.policy.MaterialPurpose
   :members:
.. autodata:: securesystemslib.policy.policy.POLICY_FOR_VERSION
   :no-value:
.. autodata:: securesystemslib.policy.policy.LEGACY_RSA_PKCS1V15_SCHEMES
   :no-value:
.. autodata:: securesystemslib.policy.policy.MODERN_SCHEMES
   :no-value:

.. autoclass:: securesystemslib.policy.VerifierBackend
   :members:
.. autoclass:: securesystemslib.policy.LocalVerifierBackend
   :members:
.. autoclass:: securesystemslib.policy.FakeVerifierBackend
   :members:
.. autoclass:: securesystemslib.policy.VerifierCapabilityError
.. autoclass:: securesystemslib.policy.BackendUnavailableError

.. autoclass:: securesystemslib.policy.Receipt
   :members:
.. autoclass:: securesystemslib.policy.UnsupportedKey
   :members:
.. autoclass:: securesystemslib.policy.ReceiptParseError

.. autoclass:: securesystemslib.policy.CheckOutcome
   :members:
.. autoclass:: securesystemslib.policy.CheckResult
   :members:
.. autoclass:: securesystemslib.policy.ComplianceReport
   :members:
.. autofunction:: securesystemslib.policy.check_receipt
.. autofunction:: securesystemslib.policy.check_receipts
