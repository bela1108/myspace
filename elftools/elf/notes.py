#-------------------------------------------------------------------------------
# elftools: elf/notes.py
#
# ELF notes
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from ..common.utils import bytes2str, roundup, struct_parse
from ..construct import CString
from .note_types import (
    LEGACY_NOTE_TYPE_REGISTRY,
    NOTE_TYPE_REGISTRY,
    NOTE_TYPE_REGISTRIES,
    NOTE_TYPE_MANIFEST,
    NOTE_TYPE_NAMESPACES,
    NOTE_TYPE_VOCABULARY_VERSION,
    NOTE_TYPE_VOCABULARIES,
    NoteTypeConflict,
    NoteTypeEntry,
    NoteTypeInterpretation,
    NoteTypeNameLookup,
    NoteTypeNamespace,
    NoteTypeSymbolGroup,
    NoteTypeVocabulary,
    get_note_type_vocabulary,
    iter_note_type_conflicts,
    iter_shared_note_type_symbols,
    legacy_note_type_name,
    resolve_note_type,
    resolve_note_type_name,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..construct.lib.container import Container
    from .elffile import ELFFile


__all__ = [
    'LEGACY_NOTE_TYPE_REGISTRY',
    'NOTE_TYPE_REGISTRY',
    'NOTE_TYPE_REGISTRIES',
    'NOTE_TYPE_MANIFEST',
    'NOTE_TYPE_NAMESPACES',
    'NOTE_TYPE_VOCABULARY_VERSION',
    'NOTE_TYPE_VOCABULARIES',
    'NoteTypeConflict',
    'NoteTypeEntry',
    'NoteTypeInterpretation',
    'NoteTypeNameLookup',
    'NoteTypeNamespace',
    'NoteTypeSymbolGroup',
    'NoteTypeVocabulary',
    'iter_note_type_conflicts',
    'iter_notes',
    'iter_shared_note_type_symbols',
    'get_note_type_vocabulary',
    'legacy_note_type_name',
    'resolve_note_type',
    'resolve_note_type_name',
]


def iter_notes(
    elffile: ELFFile,
    offset: int,
    size: int,
    vocabulary: NoteTypeVocabulary | str | None = None,
) -> Iterator[Container]:
    """ Yield complete notes within a section or segment.

        ``n_type`` keeps the historical symbolic-or-integer value. The raw
        on-disk code is always available as ``n_type_raw``. Each interpretation
        also carries its owner namespace, source, vocabulary version and any
        same-owner conflict in ``n_type_interpretation``.
    """
    end = offset + size
    nhdr_size = elffile.structs.Elf_Nhdr.sizeof()
    # Note: a note's name and data are 4-byte aligned, but it's possible there's
    # additional padding at the end to satisfy the alignment requirement of the segment.
    while offset + nhdr_size <= end:
        note: Container = struct_parse(
            elffile.structs.Elf_Nhdr,
            elffile.stream,
            stream_pos=offset)
        disk_namesz = roundup(note['n_namesz'], 2)
        disk_descsz = roundup(note['n_descsz'], 2)
        note_end = offset + nhdr_size + disk_namesz + disk_descsz
        # Validate the whole note, including padding, before reading its body.
        if note_end > end:
            break

        name_data = elffile.stream.read(disk_namesz)
        if len(name_data) != disk_namesz:
            break
        if note['n_namesz']:
            note['n_name'] = bytes2str(CString('').parse(name_data))
        else:
            note['n_name'] = None

        raw_type = note['n_type']
        interpretation = resolve_note_type(
            note['n_name'],
            raw_type,
            e_type=elffile['e_type'],
            vocabulary=vocabulary,
        )
        note['n_type_raw'] = raw_type
        note['n_type'] = interpretation.legacy
        note['n_type_name'] = interpretation.name
        note['n_type_description'] = interpretation.description
        note['n_type_owner'] = interpretation.owner
        note['n_type_source'] = interpretation.source
        note['n_type_source_version'] = interpretation.vocabulary_version
        note['n_type_vocabulary_version'] = interpretation.vocabulary_version
        note['n_type_registry_version'] = interpretation.registry_version
        note['n_type_disputed'] = interpretation.disputed
        note['n_type_conflicts'] = (
            interpretation.entries if interpretation.disputed else ()
        )
        note['n_type_candidates'] = interpretation.candidates
        note['n_type_candidate_names'] = interpretation.candidate_names
        note['n_type_interpretation'] = interpretation
        note['n_type_provenance'] = interpretation.as_dict()
        # Compatibility aliases for callers that use the vocabulary terms
        # rather than the ELF field names.
        note['n_type_code'] = raw_type
        note['n_type_symbol'] = interpretation.name
        note['n_type_namespace'] = interpretation.owner
        note['n_type_legacy'] = interpretation.legacy

        desc_data = elffile.stream.read(disk_descsz)
        if len(desc_data) != disk_descsz:
            break
        desc_data = desc_data[:note['n_descsz']]
        note['n_descdata'] = desc_data
        # Structured decoders must stay within this descriptor, even when its
        # contents are malformed and more bytes follow in the file.
        if note['n_type'] == 'NT_GNU_ABI_TAG':
            note['n_desc'] = struct_parse(elffile.structs.Elf_abi,
                                          BytesIO(desc_data))
        elif note['n_type'] == 'NT_GNU_BUILD_ID':
            note['n_desc'] = bytes(desc_data).hex()
        elif note['n_type'] == 'NT_GNU_GOLD_VERSION':
            note['n_desc'] = bytes2str(desc_data)
        elif note['n_type'] == 'NT_PRPSINFO':
            note['n_desc'] = struct_parse(elffile.structs.Elf_Prpsinfo,
                                          BytesIO(desc_data))
        elif note['n_type'] == 'NT_FILE':
            note['n_desc'] = struct_parse(elffile.structs.Elf_Nt_File,
                                          BytesIO(desc_data))
        elif note['n_type'] == 'NT_GNU_PROPERTY_TYPE_0':
            off = 0
            desc_stream = BytesIO(desc_data)
            props: list[Container] = []
            while off < len(desc_data):
                p: Container = struct_parse(elffile.structs.Elf_Prop, desc_stream, off)
                off += roundup(p.pr_datasz + 8, 2 if elffile.elfclass == 32 else 3)
                props.append(p)
            note['n_desc'] = props
        else:
            note['n_desc'] = desc_data
        note['n_offset'] = offset
        note['n_size'] = note_end - offset
        offset = note_end
        yield note
