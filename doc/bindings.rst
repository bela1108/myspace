:mod:`macholib.bindings` --- Per-slice static import binding check
======================================================================

.. module:: macholib.bindings
   :synopsis: Per-slice static import binding analysis

This module reads the import information that a Mach-O image declares,
without loading or running the image.  Each fat-architecture slice is
analyzed independently.

The report uses three sources of evidence:

* ``LC_SYMTAB`` for the nlist entries and the string table.
* ``LC_DYSYMTAB`` for the undefined-symbol range (``iundefsym`` and
  ``nundefsym``).
* Dylib load commands for the one-based library ordinal in ``n_desc``.

Only ``LC_LOAD_DYLIB``, ``LC_LOAD_WEAK_DYLIB``, ``LC_REEXPORT_DYLIB``,
``LC_LAZY_LOAD_DYLIB`` and ``LC_LOAD_UPWARD_DYLIB`` consume ordinals.
``LC_ID_DYLIB`` is deliberately not counted.

.. function:: analyze_bindings(source[, include_outside_range=False])

   Return a :class:`BindingsReport` for a path or an already-loaded
   :class:`macholib.MachO.MachO` object.  The report contains one
   :class:`SliceBindings` object per Mach-O slice.

.. class:: ImportBinding

   One undefined symbol in one slice.  Important attributes include:

   ``name``, ``ordinal``, ``module``, ``dylib``, ``weak``, ``special``,
   ``status``, ``resolution``, ``reason``, ``slice_index`` and
   ``symbol_index``.  The symbol index and slice index are part of the row
   identity, so equal names are not merged.

   Statuses are ``bound``, ``weak``, ``special``, ``unresolved`` and
   ``unverified``.  ``unresolved`` keeps the ordinal and the reason when no
   matching dylib command or readable module name is available.
   ``unverified`` marks a symbol that was found in the symbol table but not
   in the declared undefined range.

.. class:: BindingsReport

   ``slices`` contains every slice.  ``bindings`` is the flat, ordered list
   of all rows; it is never deduplicated by symbol name.  Use
   ``by_symbol(name)`` when every occurrence of a name is wanted, and
   ``find(name, ordinal=..., module=...)`` to select a specific attribution.

Command line::

   python -m macholib.bindings [--json] [--strict] FILE ...
   python -m macholib bindings [--json] [--strict] FILE ...

