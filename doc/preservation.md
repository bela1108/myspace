# Read-only note preservation planning

`elftools.elf.preservation` computes the smallest set of whole file pages that
keeps a set of note-backed product claims independently verifiable.  It is a
planning tool: it reads the ELF, never writes it, and verifies that the file
SHA-256 is unchanged when it finishes.

This is useful when a delivery package has to be trimmed to a few pages, but a
third party must still be able to check specific claims such as "this is build
ID X" or "this binary was linked by GNU gold 1.12".

## Two views, one provenance rule

ELF notes can be exposed by both:

-   `SHT_NOTE` sections (the section-header view)
-   `PT_NOTE` segments (the program-header view)

The same bytes may be reachable from both views, from only one view, or from
more than one section.  A claim therefore pins **both** the note payload and
the provenance that is allowed to prove it:

``` python
ClaimSpec(
    'build-id',
    'the delivered bytes carry build-id b02145ac',
    NoteSelector(name='GNU', type='NT_GNU_BUILD_ID',
                 desc_sha256='9c303c12...'),
    Provenance(view='section', name='.note.gnu.build-id'),
)
```

If an identical note exists in a `PT_NOTE` segment, or in a different section,
it is **not** accepted as a substitute for a claim pinned to
`.note.gnu.build-id`.  The planner reports the claim as unsatisfiable instead
of quietly widening the provenance.

## License view

Pages are retained only when they come from the real file and are inside the
project-licensed byte ranges:

``` python
LicenseView('redistributable', ((0, 4096), (0x10000, 0x11000)))
```

A page is retainable only if the whole page lies inside an allowed range.  If
every occurrence of a claim falls outside the licensed pages, the claim is
reported as unsatisfiable with a license-specific reason.  Omitting the view
means the whole file is allowed (the pyelftools source itself is public
domain).

## Pages and proofs

For a note at `[offset, offset + size)`, every page it touches is required.  A
note that straddles a page boundary cannot be proven from either half alone.
Several claims may share one page; the page is counted once, but each claim
keeps its own independent proof.

The planner solves an exact minimum set cover over the pages of the candidate
proofs.  It then reports:

-   the minimum feasible page set;
-   which pages are **irreplaceable** (no alternative minimum plan avoids
    them), and which claims make each page a sole provider;
-   for every page in the minimum set, the exact claims and independent proofs
    that would be lost if that page were cut;
-   for a budget below the minimum, the best achievable coverage and the
    independent proofs that are given up.

The minimum covers the pages that carry the pinned note bytes.  Each proof in
the receipt records its offset, size, raw digest and provenance, so a verifier
can check the retained bytes without re-parsing the trimmed file.  If the
trimmed file itself must remain a parseable ELF, also keep the pages holding
the ELF header and the section/program header tables; those framing pages are
not added automatically because they do not carry note evidence.

## Command line

``` text
python scripts/elf_preservation.py \
    --claims examples/preservation_claims.json \
    test/testfiles_for_unittests/arm_exidx_test.so.elf
```

The example manifest contains three claims for that real ARM ELF.  Use
`--json` for a machine-readable receipt, and `--page-size` / `--budget` to
override the manifest.

`examples/preservation_claims_sample.json` is the compact counterpart for
`examples/sample_exe64.elf`, whose three notes all sit on page 0 (the ABI tag,
the SuSE note, and the GNU build-id).

Manifest format:

``` json
{
  "page_size": 4096,
  "budget": 1,
  "license": {"label": "whole-file", "ranges": [[0, 3024936]]},
  "claims": [
    {
      "id": "gold-linker-1.12",
      "description": "linked with GNU gold 1.12",
      "match": {"name": "GNU", "type": "NT_GNU_GOLD_VERSION",
                "desc_sha256": "6d264851..."},
      "provenance": {"view": "section", "name": ".note.gnu.gold-version"}
    }
  ]
}
```

`match.offset` pins one exact occurrence.  `provenance.index` pins a section or
segment index; segment occurrences use the owner label `PT_NOTE#<index>`.
