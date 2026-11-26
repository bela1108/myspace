#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from io import BytesIO
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from elftools.elf.elffile import ELFFile  # noqa: E402


FIXTURE = HERE / "table_refs.o"
SOURCE = HERE / "table_refs.s"
DECLARATION = HERE / "build-declaration.json"

R_X86_64_64 = 1
R_X86_64_PC32 = 2
RELOC_NAMES = {
    0: "R_X86_64_NONE",
    1: "R_X86_64_64",
    2: "R_X86_64_PC32",
    9: "R_X86_64_GOTPCREL",
    10: "R_X86_64_32",
    11: "R_X86_64_32S",
}
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_cstring(data: bytes, start: int) -> tuple[str, int]:
    end = data.index(0, start)
    return data[start:end].decode("utf-8"), end - start + 1


def flag_dict(value: int) -> dict[str, Any]:
    return {
        "raw": hex(value),
        "WRITE": bool(value & SHF_WRITE),
        "ALLOC": bool(value & SHF_ALLOC),
        "EXECINSTR": bool(value & SHF_EXECINSTR),
    }


def expected_reloc_entry_size(elfclass: int, is_rela: bool) -> int:
    if elfclass == 64:
        return 24 if is_rela else 16
    return 12 if is_rela else 8



def portable_fixture_path(elf_path: Path) -> str:
    try:
        relative_name = elf_path.relative_to(HERE).name
        return str(Path("evidence_plan") / relative_name)
    except ValueError:
        return str(elf_path)


def build_model(elf_path: Path = FIXTURE) -> dict[str, Any]:
    elf_path = Path(elf_path)
    data = elf_path.read_bytes()
    elf = ELFFile(BytesIO(data))
    header = elf.header
    sections = list(elf.iter_sections())

    if elf.elfclass != 64 or not elf.little_endian or elf.get_machine_arch() != "x64":
        raise AssertionError("fixture must be little-endian ELF64 x86-64")
    if header.e_type != "ET_REL":
        raise AssertionError(f"fixture must be ET_REL, got {header.e_type}")

    rodata_indices = [
        index
        for index, section in enumerate(sections)
        if section.name == ".rodata" and section["sh_type"] == "SHT_PROGBITS"
    ]
    if len(rodata_indices) != 1:
        raise AssertionError(f"expected one .rodata, found {rodata_indices}")
    rodata_index = rodata_indices[0]
    rodata = sections[rodata_index]

    reloc_indices = [
        index
        for index, section in enumerate(sections)
        if section["sh_type"] in ("SHT_REL", "SHT_RELA")
        and section["sh_info"] == rodata_index
    ]
    if len(reloc_indices) != 1:
        raise AssertionError(f"expected one .rela.rodata, found {reloc_indices}")
    reloc_index = reloc_indices[0]
    reloc_section = sections[reloc_index]
    is_rela = reloc_section["sh_type"] == "SHT_RELA"
    expected_size = expected_reloc_entry_size(elf.elfclass, is_rela)
    if reloc_section["sh_entsize"] != expected_size:
        raise AssertionError("relocation entry size does not match ELF class/type")

    symtab_index = reloc_section["sh_link"]
    symtab = sections[symtab_index]
    strtab_index = symtab["sh_link"]
    strtab = sections[strtab_index]
    shstrtab_index = header.e_shstrndx
    shstrtab = sections[shstrtab_index]

    relocations = list(reloc_section.iter_relocations())

    def one_reloc(r_type: int) -> tuple[int, Any]:
        matches = [
            (index, reloc)
            for index, reloc in enumerate(relocations)
            if reloc["r_info_type"] == r_type
        ]
        if len(matches) != 1:
            raise AssertionError(f"expected one relocation type {r_type}, found {matches}")
        return matches[0]

    abs_entry_index, abs_reloc = one_reloc(R_X86_64_64)
    pc_entry_index, pc_reloc = one_reloc(R_X86_64_PC32)
    if abs_reloc["r_info_sym"] != pc_reloc["r_info_sym"]:
        raise AssertionError("the two explanations do not share one symbol index")

    symbol_index = abs_reloc["r_info_sym"]
    symbol = symtab.get_symbol(symbol_index)
    if symbol.name != "shared_symbol":
        raise AssertionError(f"unexpected shared symbol {symbol.name!r}")
    target_index = symbol["st_shndx"]
    if not isinstance(target_index, int):
        raise AssertionError("shared symbol must be defined in a real section")
    target_section = sections[target_index]

    atoms: dict[str, dict[str, Any]] = {}

    def add_range(
        atom_id: str,
        *,
        offset: int,
        size: int,
        why: str,
        claims: set[str],
    ) -> None:
        if size <= 0:
            raise AssertionError(f"atom {atom_id} has non-positive size {size}")
        if offset < 0 or offset + size > len(data):
            raise AssertionError(f"atom {atom_id} range {offset}:{offset + size} is outside ELF")
        if atom_id in atoms:
            atoms[atom_id]["claims"].update(claims)
            return
        atoms[atom_id] = {
            "id": atom_id,
            "kind": "elf_byte_range",
            "container": elf_path.name,
            "offset": offset,
            "size": size,
            "sha256": sha256_bytes(data[offset:offset + size]),
            "why": why,
            "claims": set(claims),
        }

    ehsize = header.e_ehsize
    add_range(
        "ehdr",
        offset=0,
        size=ehsize,
        why="EI_CLASS, endianness, e_type, e_machine, e_shoff and e_shstrndx",
        claims={"abs", "pcrel"},
    )

    needed_section_indices = {
        rodata_index,
        reloc_index,
        symtab_index,
        strtab_index,
        shstrtab_index,
        target_index,
    }
    for section_index in sorted(needed_section_indices):
        section = sections[section_index]
        shdr_offset = int(header.e_shoff) + section_index * int(header.e_shentsize)
        add_range(
            f"shdr:{section_index}:{section.name}",
            offset=shdr_offset,
            size=int(header.e_shentsize),
            why="section type/flags/offset/size and sh_link/sh_info relationship",
            claims={"abs", "pcrel"},
        )

        name_offset = int(section["sh_name"])
        if name_offset:
            name, name_size = read_cstring(shstrtab.data(), name_offset)
            add_range(
                f"section-name:{section_index}:{name}",
                offset=int(shstrtab["sh_offset"]) + name_offset,
                size=name_size,
                why="NUL-terminated section name referenced by sh_name",
                claims={"abs", "pcrel"},
            )

    symbol_offset = int(symtab["sh_offset"]) + symbol_index * int(symtab["sh_entsize"])
    add_range(
        "symbol:shared_symbol",
        offset=symbol_offset,
        size=int(symtab["sh_entsize"]),
        why="st_name, st_value and st_shndx bind both relocations to one symbol",
        claims={"abs", "pcrel"},
    )

    symbol_name_offset = int(symbol["st_name"])
    symbol_name, symbol_name_size = read_cstring(strtab.data(), symbol_name_offset)
    add_range(
        "string:shared_symbol",
        offset=int(strtab["sh_offset"]) + symbol_name_offset,
        size=symbol_name_size,
        why="NUL-terminated symbol name reached through st_name and symtab.sh_link",
        claims={"abs", "pcrel"},
    )

    symbol_size = int(symbol["st_size"])
    if symbol_size:
        add_range(
            "target-symbol-bytes",
            offset=int(target_section["sh_offset"]) + int(symbol["st_value"]),
            size=symbol_size,
            why="optional content corroboration inside st_shndx section; not needed for S/A/P arithmetic",
            claims={"corroboration"},
        )

    def add_claim_atoms(claim: str, entry_index: int, reloc: Any, width: int) -> None:
        add_range(
            f"relocation:{claim}",
            offset=int(reloc_section["sh_offset"]) + entry_index * int(reloc_section["sh_entsize"]),
            size=int(reloc_section["sh_entsize"]),
            why=f"exact {RELOC_NAMES.get(reloc['r_info_type'], reloc['r_info_type'])} record",
            claims={claim},
        )
        add_range(
            f"table-slot:{claim}",
            offset=int(rodata["sh_offset"]) + int(reloc["r_offset"]),
            size=width,
            why=f"{width}-byte table extent named by r_offset",
            claims={claim},
        )

    add_claim_atoms("abs", abs_entry_index, abs_reloc, 8)
    add_claim_atoms("pcrel", pc_entry_index, pc_reloc, 4)

    def addend_and_values(reloc: Any, width: int) -> tuple[int, bytes, int, int, int]:
        slot_offset = int(reloc["r_offset"])
        raw_slot = rodata.data()[slot_offset:slot_offset + width]
        if reloc.is_RELA():
            addend = int(reloc["r_addend"])
        else:
            addend = int.from_bytes(
                raw_slot,
                "little" if elf.little_endian else "big",
                signed=True,
            )
        symbol_address = int(target_section["sh_addr"]) + int(symbol["st_value"])
        patch_address = int(rodata["sh_addr"]) + int(reloc["r_offset"])
        return addend, raw_slot, symbol_address, patch_address, symbol_address + addend

    abs_addend, abs_raw, abs_s, abs_p, abs_value = addend_and_values(abs_reloc, 8)
    pc_addend, pc_raw, pc_s, pc_p, _ = addend_and_values(pc_reloc, 4)
    pc_value = pc_s + pc_addend - pc_p

    claims = {
        "abs": {
            "title": "64-bit absolute address explanation",
            "formula": "write64(P, S + A_abs)",
            "relocation_index": abs_entry_index,
            "relocation_type": abs_reloc["r_info_type"],
            "relocation_type_name": RELOC_NAMES[abs_reloc["r_info_type"]],
            "r_offset": abs_reloc["r_offset"],
            "addend": hex(abs_addend),
            "raw_slot_hex": abs_raw.hex(),
            "S_linktime": hex(abs_s),
            "P_linktime": hex(abs_p),
            "recomputed_linktime_value": hex(abs_value),
        },
        "pcrel": {
            "title": "32-bit PC-relative displacement explanation",
            "formula": "write32(P, S + A_pc - P)",
            "relocation_index": pc_entry_index,
            "relocation_type": pc_reloc["r_info_type"],
            "relocation_type_name": RELOC_NAMES[pc_reloc["r_info_type"]],
            "r_offset": pc_reloc["r_offset"],
            "addend": hex(pc_addend),
            "raw_slot_hex": pc_raw.hex(),
            "S_linktime": hex(pc_s),
            "P_linktime": hex(pc_p),
            "recomputed_linktime_value": hex(pc_value),
        },
    }

    for claim_id in claims:
        claims[claim_id]["required_atom_ids"] = sorted(
            atom_id for atom_id, atom in atoms.items() if claim_id in atom["claims"]
        )

    model = {
        "fixture_path": portable_fixture_path(elf_path),
        "fixture_name": elf_path.name,
        "file_size": len(data),
        "fixture_sha256": sha256_bytes(data),
        "header": {
            "elfclass": elf.elfclass,
            "data_encoding": "ELFDATA2LSB" if elf.little_endian else "ELFDATA2MSB",
            "e_type": header.e_type,
            "e_machine": header.e_machine,
            "machine_arch": elf.get_machine_arch(),
            "e_version": header.e_version,
            "e_ehsize": header.e_ehsize,
            "e_shoff": header.e_shoff,
            "e_shentsize": header.e_shentsize,
            "e_shnum": header.e_shnum,
            "e_shstrndx": shstrtab_index,
            "e_phoff": header.e_phoff,
            "e_phnum": header.e_phnum,
        },
        "relationships": {
            "rodata_section_index": rodata_index,
            "relocation_section_index": reloc_index,
            "relocation_section_name": reloc_section.name,
            "relocation_is_RELA": is_rela,
            "symtab_section_index": symtab_index,
            "strtab_section_index": strtab_index,
            "shstrtab_section_index": shstrtab_index,
            "shared_symbol_index": symbol_index,
            "shared_symbol_name": symbol.name,
            "shared_symbol_value": hex(symbol["st_value"]),
            "shared_symbol_shndx": target_index,
            "target_section": target_section.name,
        },
        "read_only_evidence": {
            "section": rodata.name,
            "sh_type": rodata["sh_type"],
            "flags": flag_dict(int(rodata["sh_flags"])),
            "runtime_PT_LOAD_permissions_proven": False,
            "scope_note": (
                "ET_REL has no program headers. Section flags prove an allocated, "
                "non-writable PROGBITS table; runtime read-only PTE permissions require "
                "a linked ELF's PT_LOAD record."
            ),
        },
        "claims": claims,
        "atoms": [
            {**atom, "claims": sorted(atom["claims"])}
            for atom_id, atom in sorted(atoms.items())
        ],
    }
    return model


def declaration_document() -> dict[str, Any]:
    source_bytes = SOURCE.read_bytes()
    fixture_bytes = FIXTURE.read_bytes()
    try:
        clang_version = subprocess.check_output(
            ["clang", "--version"], text=True, stderr=subprocess.STDOUT
        ).splitlines()[0]
    except (OSError, subprocess.CalledProcessError):
        clang_version = "clang unavailable during refresh"
    return {
        "schema": "elf-evidence-build-declaration/v1",
        "fixture": FIXTURE.name,
        "source": SOURCE.name,
        "target": "x86_64-unknown-elf",
        "assemble_command": [
            "clang",
            "--target=x86_64-unknown-elf",
            "-c",
            SOURCE.name,
            "-o",
            FIXTURE.name,
        ],
        "execution_policy": "assemble_only; do not execute the ET_REL fixture",
        "toolchain": clang_version,
        "source_sha256": sha256_bytes(source_bytes),
        "fixture_sha256": sha256_bytes(fixture_bytes),
        "expected_elf": {
            "elfclass": 64,
            "data_encoding": "ELFDATA2LSB",
            "e_type": "ET_REL",
            "machine_arch": "x64",
        },
    }


def refresh_declaration() -> dict[str, Any]:
    document = declaration_document()
    write_json(DECLARATION, document)
    return document


def load_declaration(model: dict[str, Any]) -> dict[str, Any]:
    if not DECLARATION.exists():
        raise FileNotFoundError(f"missing build declaration: {DECLARATION}")
    declaration = json.loads(DECLARATION.read_text())
    if declaration["fixture_sha256"] != model["fixture_sha256"]:
        raise AssertionError("fixture hash does not match build declaration")
    if declaration["source_sha256"] != sha256_file(SOURCE):
        raise AssertionError("source hash does not match build declaration")
    return declaration


def with_external_atoms(
    model: dict[str, Any],
    *,
    include_source: bool,
) -> list[dict[str, Any]]:
    atoms = [dict(atom) for atom in model["atoms"]]
    declaration_bytes = DECLARATION.read_bytes()
    atoms.append(
        {
            "id": "build_declaration",
            "kind": "external_file",
            "container": DECLARATION.name,
            "offset": 0,
            "size": len(declaration_bytes),
            "sha256": sha256_bytes(declaration_bytes),
            "why": "build target, command, execution policy and source/fixture hashes",
            "claims": ["abs", "pcrel"],
        }
    )
    if include_source:
        source_bytes = SOURCE.read_bytes()
        atoms.append(
            {
                "id": "assembly_source",
                "kind": "external_file",
                "container": SOURCE.name,
                "offset": 0,
                "size": len(source_bytes),
                "sha256": sha256_bytes(source_bytes),
                "why": "reproduction input for rebuilding the legal ELF fixture",
                "claims": ["reproduction"],
            }
        )
    return atoms


def selected_atoms(atoms: list[dict[str, Any]], claims: set[str]) -> list[dict[str, Any]]:
    return [atom for atom in atoms if claims & set(atom["claims"])]


def merge_ranges(atoms: list[dict[str, Any]]) -> dict[str, list[dict[str, int]]]:
    by_container: dict[str, list[tuple[int, int]]] = {}
    for atom in atoms:
        if atom["kind"] != "elf_byte_range":
            continue
        by_container.setdefault(atom["container"], []).append(
            (int(atom["offset"]), int(atom["offset"]) + int(atom["size"]))
        )
    merged: dict[str, list[dict[str, int]]] = {}
    for container, ranges in by_container.items():
        ordered = sorted(ranges)
        current_start, current_end = ordered[0]
        out: list[dict[str, int]] = []
        for start, end in ordered[1:]:
            if start <= current_end:
                current_end = max(current_end, end)
            else:
                out.append({"offset": current_start, "end": current_end, "size": current_end - current_start})
                current_start, current_end = start, end
        out.append({"offset": current_start, "end": current_end, "size": current_end - current_start})
        merged[container] = out
    return merged


def physical_input_bytes(atoms: list[dict[str, Any]]) -> tuple[int, int, int]:
    ranges = merge_ranges(atoms)
    elf_bytes = sum(item["size"] for items in ranges.values() for item in items)
    external_bytes = sum(int(atom["size"]) for atom in atoms if atom["kind"] == "external_file")
    return elf_bytes + external_bytes, elf_bytes, external_bytes


def interval_union_size(intervals: list[tuple[int, int]]) -> int:
    if not intervals:
        return 0
    ordered = sorted(intervals)
    start, end = ordered[0]
    total = 0
    for next_start, next_end in ordered[1:]:
        if next_start <= end:
            end = max(end, next_end)
        else:
            total += end - start
            start, end = next_start, next_end
    return total + end - start


def with_interval(
    intervals: list[tuple[int, int]], start: int, end: int
) -> list[tuple[int, int]]:
    return [*intervals, (start, end)]


def plan_report(
    *,
    claims: set[str],
    budget: int | str | None,
    priority: str,
    include_source: bool,
) -> dict[str, Any]:
    model = build_model()
    declaration = load_declaration(model)
    atoms = with_external_atoms(model, include_source=include_source)
    required = selected_atoms(atoms, claims)
    required.sort(key=lambda atom: atom["id"])
    total_bytes = sum(int(atom["size"]) for atom in required)
    ranges = merge_ranges(required)
    range_bytes = sum(item["size"] for items in ranges.values() for item in items)
    physical_bytes, _, external_bytes = physical_input_bytes(required)

    closure_costs = {}
    closure_physical_costs = {}
    for claim in ("abs", "pcrel"):
        closure = selected_atoms(atoms, {claim})
        closure_costs[claim] = sum(int(atom["size"]) for atom in closure)
        closure_physical_costs[claim], _, _ = physical_input_bytes(closure)

    resolved_budget: int | None
    if budget is None:
        resolved_budget = None
    elif budget == "abs":
        resolved_budget = closure_physical_costs["abs"]
    elif budget == "pcrel":
        resolved_budget = closure_physical_costs["pcrel"]
    elif budget == "union-minus-pcrel-extra":
        pcrel_only = [
            atom
            for atom in required
            if set(atom["claims"]) == {"pcrel"}
        ]
        resolved_budget = physical_bytes - physical_input_bytes(pcrel_only)[0]
    else:
        resolved_budget = int(budget)

    budget_report: dict[str, Any] | None = None
    if resolved_budget is not None:
        priority_rank = {
            "ehdr": 0,
            "build_declaration": 1,
        }

        def rank(atom: dict[str, Any]) -> tuple[int, str]:
            atom_id = atom["id"]
            if atom_id in priority_rank:
                return priority_rank[atom_id], atom_id
            if priority in atom["claims"]:
                return 2, atom_id
            if "abs" in atom["claims"] and "pcrel" in atom["claims"]:
                return 1, atom_id
            return 3, atom_id

        ordered = sorted(required, key=rank)
        retained: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []
        used = 0
        covered_ranges: dict[str, list[tuple[int, int]]] = {}
        covered_external: set[str] = set()
        for atom in ordered:
            marginal = int(atom["size"])
            candidate_ranges = covered_ranges
            if atom["kind"] == "elf_byte_range":
                container = atom["container"]
                intervals = covered_ranges.get(container, [])
                start = int(atom["offset"])
                end = start + int(atom["size"])
                before = interval_union_size(intervals)
                candidate = with_interval(intervals, start, end)
                after = interval_union_size(candidate)
                marginal = after - before
                candidate_ranges = {**covered_ranges, container: candidate}
            elif atom["container"] in covered_external:
                marginal = 0

            if used + marginal > resolved_budget:
                missing.append(atom)
                continue

            retained.append(atom)
            used += marginal
            if atom["kind"] == "elf_byte_range":
                covered_ranges = candidate_ranges
            else:
                covered_external.add(atom["container"])

        retained_ids = {atom["id"] for atom in retained}
        valid_claims = [
            claim
            for claim in ("abs", "pcrel")
            if claim in claims
            and all(atom_id in retained_ids for atom_id in model["claims"][claim]["required_atom_ids"])
            and any(aid == "build_declaration" for aid in retained_ids)
        ]
        missing_for_claims = sorted(claims - set(valid_claims))
        budget_report = {
            "cap_bytes": resolved_budget,
            "required_record_bytes": total_bytes,
            "required_physical_bytes": physical_bytes,
            "used_physical_bytes": used,
            "deficit_bytes": max(0, physical_bytes - resolved_budget),
            "feasible": resolved_budget >= physical_bytes,
            "priority": priority,
            "valid_claims_after_packing": valid_claims,
            "unsupported_claims_after_packing": missing_for_claims,
            "retained_atom_ids": sorted(retained_ids),
            "missing_atoms": missing,
            "recomputation": {
                "elf_range": "seek to offset in table_refs.o and hash exactly size bytes",
                "external_file": "read path and hash the whole declared file",
                "full_closure_deficit_bytes": max(0, physical_bytes - resolved_budget),
                "additional_unique_bytes_after_packing": max(0, physical_bytes - used),
            },
        }

    return {
        "schema": "elf-evidence-plan/v1",
        "declaration": declaration,
        "model": model,
        "requested_claims": sorted(claims),
        "minimum_closure": {
            "record_bytes": total_bytes,
            "merged_elf_range_bytes": range_bytes,
            "external_bytes": external_bytes,
            "physical_input_bytes": physical_bytes,
            "closure_costs_including_declaration": closure_costs,
            "physical_closure_costs": closure_physical_costs,
            "merged_ranges": ranges,
            "atoms": required,
        },
        "budget": budget_report,
    }


def carve_package(claims: set[str], out_dir: Path, include_source: bool) -> dict[str, Any]:
    report = plan_report(
        claims=claims,
        budget=None,
        priority="abs",
        include_source=include_source,
    )
    model = report["model"]
    required = report["minimum_closure"]["atoms"]
    out_dir.mkdir(parents=True, exist_ok=True)
    atom_dir = out_dir / "atoms"
    atom_dir.mkdir(exist_ok=True)
    range_dir = out_dir / "ranges"
    range_dir.mkdir(exist_ok=True)

    elf_bytes = FIXTURE.read_bytes()
    trimmed_elf = out_dir / f"{FIXTURE.stem}.trimmed.elf"
    with trimmed_elf.open("wb") as trimmed:
        trimmed.truncate(len(elf_bytes))
        for range_spec in report["minimum_closure"]["merged_ranges"].get(FIXTURE.name, []):
            start = int(range_spec["offset"])
            end = int(range_spec["end"])
            trimmed.seek(start)
            trimmed.write(elf_bytes[start:end])

    range_files: list[dict[str, Any]] = []
    range_paths: dict[tuple[str, int, int], str] = {}
    for container, ranges in report["minimum_closure"]["merged_ranges"].items():
        source_bytes = elf_bytes if container == FIXTURE.name else (HERE / container).read_bytes()
        for range_spec in ranges:
            start = int(range_spec["offset"])
            end = int(range_spec["end"])
            payload = source_bytes[start:end]
            safe_name = f"{container}.{start}-{end}.bin"
            relative_path = f"ranges/{safe_name}"
            (range_dir / safe_name).write_bytes(payload)
            range_paths[(container, start, end)] = relative_path
            range_files.append({
                "container": container,
                "offset": start,
                "end": end,
                "size": end - start,
                "sha256": sha256_bytes(payload),
                "package_path": relative_path,
            })

    for index, atom in enumerate(required):
        safe_name = f"{index:02d}-" + atom["id"].replace(":", "_").replace("/", "_") + ".bin"
        if atom["kind"] == "external_file":
            payload = (HERE / atom["container"]).read_bytes()
            if sha256_bytes(payload) != atom["sha256"]:
                raise AssertionError(f"hash mismatch while carving {atom['id']}")
            (atom_dir / safe_name).write_bytes(payload)
            atom["package_path"] = f"atoms/{safe_name}"
            continue

        atom_start = int(atom["offset"])
        atom_end = atom_start + int(atom["size"])
        containing = None
        for range_spec in report["minimum_closure"]["merged_ranges"][atom["container"]]:
            if int(range_spec["offset"]) <= atom_start and atom_end <= int(range_spec["end"]):
                containing = range_spec
                break
        if containing is None:
            raise AssertionError(f"no merged range contains atom {atom['id']}")
        range_start = int(containing["offset"])
        range_end = int(containing["end"])
        package_path = range_paths[(atom["container"], range_start, range_end)]
        range_payload = (range_dir / Path(package_path).name).read_bytes()
        slice_start = atom_start - range_start
        payload = range_payload[slice_start:slice_start + int(atom["size"])]
        if sha256_bytes(payload) != atom["sha256"]:
            raise AssertionError(f"hash mismatch while slicing {atom['id']}")
        atom["package_path"] = package_path
        atom["package_slice_offset"] = slice_start
        atom["package_slice_size"] = int(atom["size"])

    report["range_files"] = range_files
    report["carved_elf"] = trimmed_elf.name
    write_json(out_dir / "evidence-manifest.json", report)
    return report


def verify_package(manifest_path: Path) -> None:
    manifest_path = Path(manifest_path)
    package_dir = manifest_path.parent
    manifest = json.loads(manifest_path.read_text())
    checked = 0
    for atom in manifest["minimum_closure"]["atoms"]:
        package_path = atom.get("package_path")
        if not package_path:
            raise AssertionError(f"atom {atom['id']} has no package_path")
        payload = (package_dir / package_path).read_bytes()
        if "package_slice_offset" in atom:
            slice_start = int(atom["package_slice_offset"])
            slice_size = int(atom["package_slice_size"])
            payload = payload[slice_start:slice_start + slice_size]
        if sha256_bytes(payload) != atom["sha256"]:
            raise AssertionError(f"packaged atom hash mismatch: {atom['id']}")
        checked += 1

    carved_summary = None
    carved_name = manifest.get("carved_elf")
    if carved_name:
        carved_model = build_model(package_dir / carved_name)
        relationships = carved_model["relationships"]
        if relationships["shared_symbol_name"] != "shared_symbol":
            raise AssertionError("carved ELF lost shared symbol relationship")
        if set(carved_model["claims"]) != {"abs", "pcrel"}:
            raise AssertionError("carved ELF lost one relocation explanation")
        carved_summary = {
            "path": carved_name,
            "logical_size": carved_model["file_size"],
            "fixture_sha256": carved_model["fixture_sha256"],
        }

    print(json.dumps({
        "status": "package_ok",
        "manifest": str(manifest_path),
        "atoms_checked": checked,
        "carved_elf": carved_summary,
    }, indent=2, sort_keys=True))


def print_verification() -> None:
    model = build_model()
    declaration = load_declaration(model)
    print(json.dumps({"status": "ok", "declaration_schema": declaration["schema"], "model": model}, indent=2, sort_keys=True))


def parse_claims(value: str) -> set[str]:
    if value == "both":
        return {"abs", "pcrel"}
    claims = set(value.split(","))
    if not claims <= {"abs", "pcrel"}:
        raise argparse.ArgumentTypeError("claims must be abs, pcrel, both, or abs,pcrel")
    return claims


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("verify")
    sub.add_parser("refresh-declaration")

    verify_package_parser = sub.add_parser("verify-package")
    verify_package_parser.add_argument("--manifest", type=Path, required=True)

    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--claims", type=parse_claims, default="both")
    plan_parser.add_argument("--budget")
    plan_parser.add_argument("--priority", choices=("abs", "pcrel"), default="abs")
    plan_parser.add_argument("--include-source", action="store_true")
    plan_parser.add_argument("--out", type=Path)

    carve_parser = sub.add_parser("carve")
    carve_parser.add_argument("--claims", type=parse_claims, default="both")
    carve_parser.add_argument("--include-source", action="store_true")
    carve_parser.add_argument("--out", type=Path, default=HERE / "out" / "both")

    args = parser.parse_args(argv)
    if args.command == "verify":
        print_verification()
        return 0
    if args.command == "verify-package":
        verify_package(args.manifest)
        return 0
    if args.command == "refresh-declaration":
        document = refresh_declaration()
        print(json.dumps({"status": "refreshed", "fixture_sha256": document["fixture_sha256"]}, indent=2))
        return 0
    if args.command == "plan":
        report = plan_report(
            claims=args.claims,
            budget=args.budget,
            priority=args.priority,
            include_source=args.include_source,
        )
        text = json.dumps(report, indent=2, sort_keys=True)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text + "\n")
        print(text)
        if report["budget"] and not report["budget"]["feasible"]:
            return 2
        return 0
    if args.command == "carve":
        report = carve_package(args.claims, args.out, args.include_source)
        print(json.dumps({"status": "carved", "out": str(args.out), "atoms": len(report["minimum_closure"]["atoms"])}, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
