=====================
olefile API Reference
=====================

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Summary
-------

.. autosummary::
    olefile.isOleFile
    olefile.OleFileIO
    olefile.OleMetadata
    olefile.FormatEvidence
    olefile.FormatEvidenceItem
    olefile.get_format_evidence
    olefile.enable_logging


olefile module
--------------

.. automodule:: olefile
    :members:
    :undoc-members:
    :show-inheritance:


Format evidence report
----------------------

``OleFileIO.get_format_evidence()`` and ``olefile.get_format_evidence()``
return a read-only report that keeps file-format evidence separate from
parsing. The report evaluates testable CFB constraints (header signature,
byte order, major version, sector geometry, reserved fields and sector
counts), lists compatibility clues (minor version, transaction signature,
directory FILETIMEs and CLSIDs), and exposes incompatible declarations as
``contradictions``.

Timestamps are FILETIME values in directory entries. A zero value means
that the time was not set, so the corresponding attribute is listed in
``ineligible_attributes`` and cannot be used to infer a save generation.
CLSIDs are reported with their origin: the header CLSID is a reserved field,
while storage class IDs come from directory entries and are compatibility
clues only. The report never mutates the file or the parsing state.

Example::

    import olefile

    ole = olefile.OleFileIO("document.doc")
    report = ole.get_format_evidence()
    print(report.summary)
    print(report.contradictions)
    print(report.ineligible_attributes)
