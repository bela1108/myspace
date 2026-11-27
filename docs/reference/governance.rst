Governance
==========

The ``sigma.governance`` package provides a purpose gate for governed detection samples. It
keeps sample provenance, rule match results and dual-person confirmations on independent
purpose allowlists and produces formal coverage reports that contain only evidence approved for
the requested purpose.

See also: :doc:`/guides/purpose_gate` for a step-by-step introduction with examples.

Enums
-----

.. autoclass:: sigma.governance.EvidenceKind
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.governance.SamplePurpose
   :members:
   :undoc-members:
   :show-inheritance:

Sample Identity and Records
---------------------------

.. autoclass:: sigma.governance.SampleSource
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.governance.SampleKey
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.governance.SampleRecord
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.governance.MatchResultRecord
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.governance.DualPersonConfirmation
   :members:
   :undoc-members:
   :show-inheritance:

Purpose Gate
------------

.. autoclass:: sigma.governance.PurposeGate
   :members:
   :undoc-members:
   :show-inheritance:

Offline Coverage Reporting
--------------------------

.. autofunction:: sigma.governance.run_offline_coverage

.. autoclass:: sigma.governance.RuleCoverageReport
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.governance.CoverageEntry
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.governance.RejectedEntry
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.governance.OfflineRunResult
   :members:
   :undoc-members:
   :show-inheritance:
