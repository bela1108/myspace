"""Generate the small core-file matching fixtures.

The files are synthetic so that the three evidence cases stay readable and
can be regenerated without a compiler or a live process.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path


PAGE = 4096
EM_X86_64 = 62
ET_DYN = 3
ET_CORE = 4
PT_LOAD = 1
PT_NOTE = 4
NT_FILE = 0x46494C45
NT_GNU_BUILD_ID = 3

HERE = Path(__file__).resolve().parent
CASE_PATHS = {
    "unique": "/opt/acme/libwidget.so",
    "unconfirmed": "/opt/acme/libshared.so",
    "contradicted": "/opt/acme/libbroken.so",
}


def _elf_header(e_type: int, phnum: int, phoff: int = 64) -> bytes:
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    return struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        e_type,
        EM_X86_64,
        1,
        0,
        phoff,
        0,
        0,
        64,
        56,
        phnum,
        64,
        0,
        0,
    )


def _phdr(
    p_type: int,
    p_offset: int,
    p_vaddr: int,
    p_filesz: int,
    p_memsz: int,
    p_flags: int,
    p_align: int,
) -> bytes:
    return struct.pack(
        "<IIQQQQQQ",
        p_type,
        p_flags,
        p_offset,
        p_vaddr,
        p_vaddr,
        p_filesz,
        p_memsz,
        p_align,
    )


def _build_id_note(build_id: bytes) -> bytes:
    note = struct.pack("<III", 4, len(build_id), NT_GNU_BUILD_ID)
    note += b"GNU\0" + build_id
    return note + b"\0" * (-len(note) % 4)


def _original_file(case: str, tag: bytes, build_id: bytes) -> bytes:
    note_offset = 0x100
    note = _build_id_note(build_id)
    phdrs = b"".join(
        (
            _phdr(PT_LOAD, 0, 0, PAGE, PAGE, 5, PAGE),
            _phdr(PT_LOAD, PAGE, PAGE, PAGE, PAGE, 6, PAGE),
            _phdr(PT_NOTE, note_offset, 0, len(note), len(note), 4, 4),
        )
    )
    image = bytearray(PAGE * 2)
    image[:64] = _elf_header(ET_DYN, 3)
    image[64:64 + len(phdrs)] = phdrs
    image[note_offset:note_offset + len(note)] = note
    marker = f"PYELFTOOLS-CORE-MATCH:{case}:".encode("ascii") + tag
    image[0x200:0x200 + len(marker)] = marker
    image[PAGE + 0x80:PAGE + 0x84] = b"DATA"
    image[PAGE + 0x100:PAGE + 0x100 + len(tag)] = tag
    return bytes(image)


def _nt_file_note(path: str, base: int, entries: list[tuple[int, int, int]]) -> bytes:
    desc = struct.pack("<QQ", len(entries), PAGE)
    for vm_start, vm_end, page_offset in entries:
        desc += struct.pack("<QQQ", vm_start, vm_end, page_offset)
    desc += b"".join(path.encode("utf-8") + b"\0" for _ in entries)
    note = struct.pack("<III", 5, len(desc), NT_FILE)
    note += b"CORE\0" + b"\0" * 3
    note += desc
    return note + b"\0" * (-len(note) % 4)


def _core_file(
    path: str,
    base: int,
    evidence: bytes | None,
) -> bytes:
    mappings = [(base, base + PAGE, 0), (base + PAGE, base + PAGE * 2, 1)]
    note = _nt_file_note(path, base, mappings)
    note_offset = 0x100
    data_offset = 0x1000
    phnum = 1 + (1 if evidence is not None else 0)
    phdrs = [_phdr(PT_NOTE, note_offset, 0, len(note), len(note), 4, 4)]
    if evidence is not None:
        phdrs.append(_phdr(PT_LOAD, data_offset, base, len(evidence), len(evidence), 5, PAGE))

    header = _elf_header(ET_CORE, phnum)
    phdr_data = b"".join(phdrs)
    image = bytearray(data_offset)
    image[:64] = header
    image[64:64 + len(phdr_data)] = phdr_data
    image[note_offset:note_offset + len(note)] = note
    if evidence is not None:
        image += evidence
    return bytes(image)


def main() -> None:
    candidate_a = _original_file("a", b"A", bytes.fromhex("aa" * 20))
    candidate_b = _original_file("b", b"B", bytes.fromhex("bb" * 20))

    cases = {
        "unique": {
            "core": _core_file(CASE_PATHS["unique"], 0x700000000000, candidate_a[:PAGE]),
            "archives": [("widget-a.so", candidate_a), ("widget-b.so", candidate_b)],
            "expected": {
                "status": "matched",
                "selected": "widget-a.so",
                "reason": "first mapped page and readable build-id match only widget-a.so",
            },
        },
        "unconfirmed": {
            "core": _core_file(CASE_PATHS["unconfirmed"], 0x710000000000, None),
            "archives": [("shared-a.so", candidate_a), ("shared-b.so", candidate_b)],
            "expected": {
                "status": "unconfirmed",
                "selected": None,
                "reason": "all evidence pages are absent and both layouts are plausible",
            },
        },
        "contradicted": {
            "core": _core_file(
                CASE_PATHS["contradicted"],
                0x720000000000,
                b"\xa5" * PAGE,
            ),
            "archives": [("broken-a.so", candidate_a), ("broken-b.so", candidate_b)],
            "expected": {
                "status": "contradicted",
                "selected": None,
                "reason": "the retained page matches neither same-path archive",
            },
        },
    }

    manifest = {
        "schema": "pyelftools-core-file-match-fixtures-v1",
        "page_size": PAGE,
        "cases": [],
    }
    for name, case in cases.items():
        case_dir = HERE / name
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "core.elf").write_bytes(case["core"])
        archives = []
        for filename, contents in case["archives"]:
            (case_dir / filename).write_bytes(contents)
            archives.append(
                {
                    "path": CASE_PATHS[name],
                    "file": f"{name}/{filename}",
                    "label": filename,
                }
            )
        expected = case["expected"]
        manifest["cases"].append(
            {
                "case": name,
                "core": f"{name}/core.elf",
                "archives": archives,
                "status": expected["status"],
                "selected": expected["selected"],
                "expected": expected,
            }
        )

    manifest["inventory"] = [
        {
            "case": item["case"],
            "status": item["status"],
            "selected": item["selected"],
        }
        for item in manifest["cases"]
    ]

    (HERE / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
