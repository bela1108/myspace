# Core-file matching fixtures

Each subdirectory contains one synthetic ELF64 core image and two archives
that claim the same `NT_FILE` path. `manifest.json` is the evidence inventory:

- `unique`: one retained page and build-id select `widget-a.so`.
- `unconfirmed`: the page offsets are recorded but no page evidence remains,
  so the two same-path archives cannot be distinguished.
- `contradicted`: the retained page agrees with neither archive.

Run `python3 make_fixtures.py` to regenerate everything. The generator uses
only the standard library and does not need a compiler or a live process.
