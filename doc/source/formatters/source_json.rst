source-json
-----------

.. automodule:: bandit.formatters.source_json
   :no-index:

Source maps
===========

When the scanned Python files are generated (for example by a template
engine or another code generator), Bandit can project each finding back to
the template or hand-written source that produced it.  The projection never
rewrites a finding: the real scan location (``filename``, ``line_number``,
``line_range`` and column offsets) is always preserved, and the projection
is added as a separate ``source_refs`` list.

A source map is a JSON document keyed by the path of each generated file.
Every segment describes an inclusive range of generated lines together with
the corresponding inclusive source range::

    {
      "version": 1,
      "generated_files": {
        "build/generated.py": [
          {
            "generated_start": 1,
            "generated_end": 4,
            "source_file": "templates/job.tmpl",
            "source_start": 10,
            "source_end": 13
          },
          {
            "generated_start": 7,
            "generated_end": 7,
            "source_file": "hand_written.py",
            "source_line": 3
          }
        ]
      }
    }

Pass the map to Bandit with ``--source-map``::

    bandit --source-map build/source_map.json -f source-json build/

Projection rules
----------------

* A generated range that maps to several source locations produces one
  candidate per location (one-to-many); all candidates are retained.
* A finding whose line range crosses a mapping boundary contributes one
  candidate per overlapping segment.  Any generated lines no segment covers
  are reported explicitly with the ``unmapped_generated_gap`` reason instead
  of being silently dropped.
* A segment whose source file is missing, whose source range is out of
  bounds, whose generated range is out of bounds, or which is malformed is
  kept as an ``invalid`` candidate carrying a machine-readable ``reason``.
* Only line numbers supplied by the map are emitted.  Multi-line or partial
  overlaps are reported as ranges with ``source_line`` set to ``null``;
  Bandit never invents a unique line number.

Baselines
---------

Baselines continue to be read and written using the original scan evidence.
Projected ``source_refs`` are omitted when baseline reports are loaded, so
baseline comparisons are unaffected by source mapping.  Use the regular
``json`` formatter (not ``source-json``) together with ``--baseline``.
