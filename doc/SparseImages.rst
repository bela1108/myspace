=============================================
Sparse / Partial OLE Image Forensics
=============================================

.. module:: olefile.sparse

A forensic acquisition of a compound document sometimes synchronises only
a subset of its sectors ("pages"). The :mod:`olefile.sparse` module analyses
such a partial image **read-only**, driven by an explicit manifest of the
sectors that are available, and reports three kinds of evidence separately.

1. **Directory identity** - the streams and storages described by the
   directory entries that are present (name, type, start sector, size).
2. **Allocation-chain evidence** - what the FAT / MiniFAT link tables say
   about each stream, independently of whether the referenced data pages are
   currently present.
3. **Actual stream content** - what can really be read and hashed, byte range
   by byte range.

Guarantees
----------

- A missing page is never reported as an all-zero sector. Reading a missing
  sector raises :class:`SectorUnavailable`; content reports record a gap
  instead of padding with zeros. A real sector that genuinely contains zeros
  is still reported as present and complete.
- Streams that reference the same missing page keep independent state. Each
  stream owns its own chain walk, present/gap ranges and digests, so the page
  can be restored and evaluated per stream later.
- Every sector that is read is recorded in an evidence ledger keyed by its
  original logical offset and SHA-256 digest, keeping the source summary and
  its offset association traceable after repair.

Typical workflow
----------------

1. Build or obtain a manifest of available sector numbers.
2. Open the image with :func:`open_sparse_image` (or :class:`SparseOleImage`
   plus :class:`SparseOleVerifier`).
3. Inspect :meth:`SparseOleVerifier.directory_identities` and call
   :meth:`SparseOleVerifier.verify_stream` / ``verify_all``.
4. When a page is restored, call :meth:`SparseOleVerifier.reverify` with the
   newly available sectors; only the dependent streams are re-checked.

API reference
-------------

.. automodule:: olefile.sparse
    :members:
    :undoc-members:
    :show-inheritance:
