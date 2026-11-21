"""
Static analysis of Mach-O symbol bindings.

The dynamic linker resolves an undefined symbol using the library ordinal
stored in ``n_desc``.  In a two-level namespace that ordinal names a dylib
load command; this module turns that information into a per-slice report.

The report deliberately keeps the slice, symbol index, and ordinal in its
identity.  Two slices, or two symbols in one slice, can therefore import the
same symbol name from different modules without being merged.

The code only reports what the file proves:

* ``LC_SYMTAB`` supplies the nlist entries and string table.
* ``LC_DYSYMTAB`` supplies the undefined-symbol range.
* Dylib load commands supply the ordinal-to-module mapping.

Weak references, special ordinals, and entries whose module cannot be proved
are retained with their own status instead of being silently resolved.
"""

from __future__ import absolute_import, print_function

import json
import os
import struct
import sys

from macholib.mach_o import (
    CPU_TYPE_NAMES,
    DYNAMIC_LOOKUP_ORDINAL,
    EXECUTABLE_ORDINAL,
    LC_LAZY_LOAD_DYLIB,
    LC_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    MAX_LIBRARY_ORDINAL,
    MH_CIGAM_64,
    MH_FORCE_FLAT,
    MH_MAGIC_64,
    MH_TWOLEVEL,
    N_EXT,
    N_PBUD,
    N_STAB,
    N_TYPE,
    N_UNDF,
    N_WEAK_REF,
    SELF_LIBRARY_ORDINAL,
    get_cpu_subtype,
    nlist,
    nlist_64,
)
from macholib.ptypes import sizeof

__all__ = [
    "Binding",
    "BindingReport",
    "BindingsReport",
    "DYLIB_LOAD_COMMANDS",
    "DylibModule",
    "DylibReference",
    "ImportEntry",
    "ImportReport",
    "ModuleReference",
    "NAMESPACE_FLAT",
    "NAMESPACE_TWO_LEVEL",
    "ImportBinding",
    "SliceBindings",
    "SliceBindingReport",
    "SliceImportReport",
    "STATUS_BOUND",
    "STATUS_RESOLVED",
    "STATUS_SPECIAL",
    "STATUS_UNKNOWN",
    "STATUS_UNRESOLVED",
    "STATUS_UNVERIFIED",
    "STATUS_WEAK",
    "analyze",
    "analyze_bindings",
    "analyze_imports",
    "check_imports",
    "inspect_bindings",
    "analyze_macho",
    "check_bindings",
    "iter_bindings",
    "main",
]


# Namespace modes -----------------------------------------------------------

NAMESPACE_TWO_LEVEL = "two-level"
NAMESPACE_FLAT = "flat"


# Row statuses --------------------------------------------------------------
#
# ``bound``      a normal undefined symbol resolved to a dylib load command
# ``weak``       N_WEAK_REF was set (the resolved module is still reported)
# ``special``    ordinal 0x00, 0xfe, or 0xff
# ``unresolved`` evidence exists but does not name a module
# ``unverified`` the symbol was not in the dynamic undefined range

STATUS_BOUND = "bound"
STATUS_WEAK = "weak"
STATUS_SPECIAL = "special"
STATUS_UNRESOLVED = "unresolved"
STATUS_UNVERIFIED = "unverified"

# Compatibility spellings for callers that use the more common names.
STATUS_RESOLVED = STATUS_BOUND
STATUS_UNKNOWN = STATUS_UNRESOLVED


# Resolution kinds ----------------------------------------------------------

RESOLUTION_DYLIB = "dylib"
RESOLUTION_SPECIAL = "special"
RESOLUTION_UNRESOLVED = "unresolved"
RESOLUTION_UNVERIFIED = "unverified"


SPECIAL_ORDINAL_NAMES = {
    SELF_LIBRARY_ORDINAL: "self",
    DYNAMIC_LOOKUP_ORDINAL: "dynamic_lookup",
    EXECUTABLE_ORDINAL: "executable",
}

SPECIAL_ORDINAL_CONSTANTS = {
    SELF_LIBRARY_ORDINAL: "SELF_LIBRARY_ORDINAL",
    DYNAMIC_LOOKUP_ORDINAL: "DYNAMIC_LOOKUP_ORDINAL",
    EXECUTABLE_ORDINAL: "EXECUTABLE_ORDINAL",
}


# These are the load commands that take part in the dylib ordinal table.
# LC_ID_DYLIB is intentionally absent: an image's own install name is not a
# dependency and does not consume an ordinal.
DYLIB_LOAD_COMMANDS = frozenset(
    (
        LC_LOAD_DYLIB,
        LC_LOAD_WEAK_DYLIB,
        LC_REEXPORT_DYLIB,
        LC_LAZY_LOAD_DYLIB,
        LC_LOAD_UPWARD_DYLIB,
    )
)

DYLIB_COMMAND_NAMES = {
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
    LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
    LC_LAZY_LOAD_DYLIB: "LC_LAZY_LOAD_DYLIB",
    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
}


def _decode(raw):
    """Decode bytes from a Mach-O file without losing undecodable bytes."""
    if raw is None:
        return None
    if not isinstance(raw, bytes):
        return raw
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "surrogateescape")


def _as_bytes(value):
    if value is None or isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        value = str(value)
    return value.encode("utf-8", "surrogateescape")


def _name_matches(name, name_bytes, value):
    """Compare a symbol name to either a text or bytes argument."""
    if isinstance(value, bytes):
        if name_bytes is not None:
            return name_bytes == value
        return _as_bytes(name) == value
    if isinstance(value, str):
        if name is not None:
            return name == value
        return _decode(name_bytes) == value
    return False


class DylibReference(object):
    """A dylib load command and the ordinal it occupies."""

    __slots__ = (
        "ordinal",
        "command_index",
        "command",
        "command_name",
        "path",
        "weak",
        "name_error",
    )

    def __init__(
        self,
        ordinal,
        command_index,
        command,
        path,
        weak=False,
        name_error=None,
    ):
        self.ordinal = int(ordinal)
        self.command_index = int(command_index)
        self.command = int(command)
        self.command_name = DYLIB_COMMAND_NAMES.get(command, str(command))
        self.path = path
        self.weak = bool(weak)
        self.name_error = name_error

    @property
    def name(self):
        return self.path

    @property
    def module(self):
        return self.path

    @property
    def dylib_name(self):
        return self.path

    @property
    def install_name(self):
        return self.path

    @property
    def load_command(self):
        return self.command

    @property
    def is_system(self):
        return bool(
            self.path
            and (
                self.path.startswith("/usr/lib/")
                or self.path.startswith("/System/Library/")
                or self.path.startswith("/System/iOSSupport/")
            )
        )

    def as_dict(self):
        return {
            "ordinal": self.ordinal,
            "command_index": self.command_index,
            "command": self.command_name,
            "name": self.path,
            "weak": self.weak,
            "is_system": self.is_system,
            "name_error": self.name_error,
        }

    def __str__(self):
        if self.path is None:
            return "<dylib ordinal %d>" % (self.ordinal,)
        return self.path

    def __repr__(self):
        return "<DylibReference ordinal=%d command=%s path=%r>" % (
            self.ordinal,
            self.command_name,
            self.path,
        )

    def __eq__(self, other):
        if isinstance(other, DylibReference):
            return (
                self.ordinal == other.ordinal
                and self.path == other.path
                and self.command_index == other.command_index
            )
        if isinstance(other, bytes):
            return _as_bytes(self.path) == other
        if isinstance(other, str):
            return self.path == other
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.ordinal, self.command_index, self.path))


class ImportBinding(object):
    """One undefined symbol in one Mach-O slice."""

    __slots__ = (
        "slice_index",
        "slice_offset",
        "arch",
        "cputype",
        "cpusubtype",
        "endian",
        "symbol_index",
        "undefined_index",
        "name",
        "name_bytes",
        "string_index",
        "ordinal",
        "weak",
        "special",
        "status",
        "resolution",
        "module",
        "dylib",
        "reason",
        "n_type",
        "n_desc",
        "n_sect",
        "n_value",
        "two_level",
        "in_dynamic_range",
    )

    def __init__(
        self,
        slice_index,
        slice_offset,
        arch,
        cputype,
        cpusubtype,
        endian,
        symbol_index,
        undefined_index,
        name,
        name_bytes,
        ordinal,
        string_index,
        weak,
        special,
        status,
        resolution,
        module=None,
        dylib=None,
        reason=None,
        n_type=0,
        n_desc=0,
        n_sect=0,
        n_value=0,
        two_level=False,
        in_dynamic_range=True,
    ):
        self.slice_index = int(slice_index)
        self.slice_offset = int(slice_offset)
        self.arch = arch
        self.cputype = int(cputype)
        self.cpusubtype = int(cpusubtype)
        self.endian = endian
        self.symbol_index = int(symbol_index)
        self.undefined_index = undefined_index
        self.name = name
        self.name_bytes = name_bytes
        self.string_index = int(string_index)
        self.ordinal = int(ordinal)
        self.weak = bool(weak)
        self.special = special
        self.status = status
        self.resolution = resolution
        self.module = module
        self.dylib = dylib
        self.reason = reason
        self.n_type = int(n_type)
        self.n_desc = int(n_desc)
        self.n_sect = int(n_sect)
        self.n_value = int(n_value)
        self.two_level = bool(two_level)
        self.in_dynamic_range = bool(in_dynamic_range)

    # Common aliases -------------------------------------------------------

    @property
    def symbol(self):
        return self.name

    @property
    def symbol_name(self):
        return self.name

    @property
    def symbol_bytes(self):
        return self.name_bytes

    @property
    def n_strx(self):
        return self.string_index

    @property
    def library(self):
        return self.dylib

    @property
    def dylib_path(self):
        return self.module

    @property
    def path(self):
        return self.module

    @property
    def library_ordinal(self):
        return self.ordinal

    @property
    def dylib_ordinal(self):
        return self.ordinal

    @property
    def module_ordinal(self):
        return self.ordinal

    @property
    def dylib_index(self):
        """The one-based dylib command index, or None for special values."""
        if self.dylib is None:
            return None
        return self.dylib.ordinal

    @property
    def module_index(self):
        return self.dylib_index

    @property
    def dylib_command_index(self):
        if self.dylib is None:
            return None
        return self.dylib.command_index

    @property
    def namespace(self):
        return NAMESPACE_TWO_LEVEL if self.two_level else NAMESPACE_FLAT

    @property
    def arch_lower(self):
        return self.arch.lower()

    @property
    def module_name(self):
        return self.module

    @property
    def dylib_name(self):
        return self.module

    @property
    def install_name(self):
        return self.module

    @property
    def weak_reference(self):
        return self.weak

    @property
    def ordinal_name(self):
        """A readable name for the ordinal itself."""
        if self.special is not None:
            return self.special
        if self.module is not None:
            return self.module
        return None

    @property
    def special_ordinal(self):
        return SPECIAL_ORDINAL_CONSTANTS.get(self.ordinal)

    @property
    def binding_status(self):
        return self.status

    @property
    def state(self):
        return self.status

    @property
    def ordinal_label(self):
        name = self.ordinal_name
        if name is None:
            return "%d (unresolved)" % (self.ordinal,)
        return "%d (%s)" % (self.ordinal, name)

    @property
    def key(self):
        """The identity of a report row.

        Symbol indices are per slice.  Including the slice index and the
        undefined-range index keeps duplicate names distinct.
        """
        return (self.slice_index, self.symbol_index)

    @property
    def row_id(self):
        return self.key

    @property
    def attribution(self):
        return (self.ordinal, self.module)

    @property
    def is_weak(self):
        return self.weak

    @property
    def is_special(self):
        return self.special is not None

    @property
    def is_bound(self):
        return self.status == STATUS_BOUND

    @property
    def is_resolved(self):
        return self.resolution == RESOLUTION_DYLIB

    @property
    def is_verified(self):
        return self.in_dynamic_range

    @property
    def has_module(self):
        return self.module is not None

    @property
    def is_unknown(self):
        return self.resolution in (RESOLUTION_UNRESOLVED, RESOLUTION_UNVERIFIED)

    @property
    def is_system(self):
        return bool(
            self.module
            and (
                self.module.startswith("/usr/lib/")
                or self.module.startswith("/System/Library/")
                or self.module.startswith("/System/iOSSupport/")
            )
        )

    @property
    def is_public_system(self):
        return self.is_system

    @property
    def module_basename(self):
        return None if self.module is None else os.path.basename(self.module)

    @property
    def is_undefined(self):
        return (self.n_type & N_STAB) == 0 and (self.n_type & N_TYPE) in (
            N_UNDF,
            N_PBUD,
        )

    @property
    def evidence(self):
        return {
            "in_symbol_table": True,
            "in_dynamic_range": self.in_dynamic_range,
            "dylib_ordinal_known": self.dylib is not None,
            "dylib_name_known": self.module is not None,
            "two_level_namespace": self.two_level,
        }

    def matches_name(self, value):
        return _name_matches(self.name, self.name_bytes, value)

    def as_dict(self):
        return {
            "slice_index": self.slice_index,
            "slice_offset": self.slice_offset,
            "arch": self.arch,
            "cputype": self.cputype,
            "cpusubtype": self.cpusubtype,
            "symbol_index": self.symbol_index,
            "undefined_index": self.undefined_index,
            "name": self.name,
            "name_bytes": (
                None if self.name_bytes is None else self.name_bytes.decode("latin-1")
            ),
            "string_index": self.string_index,
            "ordinal": self.ordinal,
            "ordinal_name": self.ordinal_name,
            "ordinal_label": self.ordinal_label,
            "dylib_index": self.dylib_index,
            "dylib_command_index": self.dylib_command_index,
            "module": self.module,
            "module_basename": self.module_basename,
            "is_system": self.is_system,
            "weak": self.weak,
            "special": self.special,
            "special_ordinal": self.special_ordinal,
            "status": self.status,
            "resolution": self.resolution,
            "reason": self.reason,
            "namespace": self.namespace,
            "two_level": self.two_level,
            "in_dynamic_range": self.in_dynamic_range,
            "n_type": self.n_type,
            "n_desc": self.n_desc,
            "n_sect": self.n_sect,
            "n_value": self.n_value,
            "evidence": self.evidence,
        }

    def __getitem__(self, key):
        if key == "symbol":
            return self.name
        if key == "dylib_name":
            return self.module
        return self.as_dict()[key]

    def __eq__(self, other):
        if not isinstance(other, ImportBinding):
            return NotImplemented
        return self.key == other.key and self.ordinal == other.ordinal

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.key, self.ordinal))

    def __str__(self):
        name = self.name
        if name is None:
            name = "<unnamed>"
        return "%s -> %s [%s]" % (name, self.ordinal_label, self.status)

    def __repr__(self):
        return (
            "<ImportBinding slice=%d symbol=%r ordinal=%d module=%r "
            "status=%s weak=%r>"
            % (
                self.slice_index,
                self.name,
                self.ordinal,
                self.module,
                self.status,
                self.weak,
            )
        )


Binding = ImportBinding
ImportEntry = ImportBinding
DylibModule = DylibReference
ModuleReference = DylibReference


class SliceBindings(object):
    """Binding information for one Mach-O header (one fat-architecture slice)."""

    def __init__(
        self,
        index,
        filename,
        offset,
        size,
        arch,
        cputype,
        cpusubtype,
        cpusubtype_name,
        endian,
        two_level,
        dylibs,
        bindings,
        problems=None,
        ranges=None,
        header=None,
        symtab=None,
        dysymtab=None,
    ):
        self.index = int(index)
        self.filename = filename
        self.offset = int(offset)
        self.size = size
        self.arch = arch
        self.cputype = int(cputype)
        self.cpusubtype = int(cpusubtype)
        self.cpusubtype_name = cpusubtype_name
        self.endian = endian
        self.two_level = bool(two_level)
        self.dylibs = tuple(dylibs)
        self.bindings = tuple(bindings)
        self.problems = tuple(problems or ())
        self.ranges = dict(ranges or {})
        self.header = header
        self.symtab = symtab
        self.dysymtab = dysymtab

    # Common aliases -------------------------------------------------------

    @property
    def imports(self):
        return self.bindings

    @property
    def entries(self):
        return self.bindings

    @property
    def path(self):
        return self.filename

    @property
    def namespace(self):
        return NAMESPACE_TWO_LEVEL if self.two_level else NAMESPACE_FLAT

    @property
    def arch_lower(self):
        return self.arch.lower()

    @property
    def undefined_range(self):
        return self.ranges.get("undefined")

    @property
    def locals_range(self):
        return self.ranges.get("locals")

    @property
    def external_range(self):
        return self.ranges.get("external")

    @property
    def weak_bindings(self):
        return tuple(item for item in self.bindings if item.weak)

    @property
    def special_bindings(self):
        return tuple(item for item in self.bindings if item.is_special)

    @property
    def unresolved_bindings(self):
        return tuple(
            item for item in self.bindings if item.resolution == RESOLUTION_UNRESOLVED
        )

    @property
    def ok(self):
        return not self.problems and all(
            item.resolution == RESOLUTION_DYLIB for item in self.bindings
        )

    @property
    def system_bindings(self):
        return tuple(item for item in self.bindings if item.is_system)

    @property
    def non_system_bindings(self):
        return tuple(item for item in self.bindings if not item.is_system)

    def dylib(self, ordinal):
        if 1 <= ordinal <= len(self.dylibs):
            return self.dylibs[ordinal - 1]
        return None

    def by_symbol(self, name):
        return tuple(item for item in self.bindings if item.matches_name(name))

    def by_module(self, module):
        return tuple(item for item in self.bindings if item.module == module)

    def as_dict(self):
        return {
            "index": self.index,
            "offset": self.offset,
            "size": self.size,
            "arch": self.arch,
            "cputype": self.cputype,
            "cpusubtype": self.cpusubtype,
            "cpusubtype_name": self.cpusubtype_name,
            "endian": self.endian,
            "namespace": self.namespace,
            "two_level": self.two_level,
            "dylibs": [item.as_dict() for item in self.dylibs],
            "bindings": [item.as_dict() for item in self.bindings],
            "problems": list(self.problems),
            "ranges": self.ranges,
            "has_symtab": self.symtab is not None,
            "has_dysymtab": self.dysymtab is not None,
        }

    def __iter__(self):
        return iter(self.bindings)

    def __len__(self):
        return len(self.bindings)

    def __getitem__(self, index):
        if isinstance(index, (str, bytes)):
            return self.by_symbol(index)
        return self.bindings[index]

    def __repr__(self):
        return "<SliceBindings index=%d arch=%r offset=%d bindings=%d>" % (
            self.index,
            self.arch,
            self.offset,
            len(self.bindings),
        )


class BindingsReport(object):
    """A per-slice static binding report for a Mach-O file."""

    def __init__(self, filename, slices):
        self.filename = filename
        self.slices = tuple(slices)
        bindings = []
        for item in self.slices:
            bindings.extend(item.bindings)
        self.bindings = tuple(bindings)

    @property
    def imports(self):
        return self.bindings

    @property
    def entries(self):
        return self.bindings

    @property
    def path(self):
        return self.filename

    @property
    def ok(self):
        return not self.problems and all(
            item.resolution == RESOLUTION_DYLIB for item in self.bindings
        )

    @property
    def system_bindings(self):
        return tuple(item for item in self.bindings if item.is_system)

    @property
    def non_system_bindings(self):
        return tuple(item for item in self.bindings if not item.is_system)

    @property
    def problems(self):
        result = []
        for item in self.slices:
            for problem in item.problems:
                result.append((item.index, problem))
        return tuple(result)

    def slice(self, index):
        return self.slices[index]

    def by_symbol(self, name):
        return tuple(item for item in self.bindings if item.matches_name(name))

    def by_module(self, module):
        return tuple(item for item in self.bindings if item.module == module)

    def grouped_by_module(self):
        result = {}
        for item in self.bindings:
            result.setdefault(item.module, []).append(item)
        return dict((key, tuple(value)) for key, value in result.items())

    def grouped_by_symbol(self):
        result = {}
        for item in self.bindings:
            result.setdefault(item.name, []).append(item)
        return dict((key, tuple(value)) for key, value in result.items())

    def find(self, name, ordinal=None, module=None):
        result = []
        for item in self.bindings:
            if not item.matches_name(name):
                continue
            if ordinal is not None and item.ordinal != ordinal:
                continue
            if module is not None and item.module != module:
                continue
            result.append(item)
        return tuple(result)

    def as_dict(self):
        return {
            "filename": self.filename,
            "slices": [item.as_dict() for item in self.slices],
            "bindings": [item.as_dict() for item in self.bindings],
            "problems": list(self.problems),
        }

    def dumps(self, **kw):
        kw.setdefault("indent", 2)
        kw.setdefault("sort_keys", True)
        return json.dumps(self.as_dict(), **kw)

    def to_json(self, **kw):
        return self.dumps(**kw)

    def format_lines(self):
        lines = [str(self.filename)]
        for item in self.slices:
            lines.append(
                "  [slice %d] %s offset=%d namespace=%s"
                % (item.index, item.arch, item.offset, item.namespace)
            )
            for problem in item.problems:
                lines.append("    ! %s" % (problem,))
            for binding in item.bindings:
                name = binding.name if binding.name is not None else "<unnamed>"
                lines.append(
                    "    %s -> %s [%s]"
                    % (name, binding.ordinal_label, binding.status)
                )
        return lines

    def format(self):
        return "\n".join(self.format_lines())

    def __iter__(self):
        return iter(self.bindings)

    def __len__(self):
        return len(self.bindings)

    def __getitem__(self, index):
        if isinstance(index, (str, bytes)):
            return self.by_symbol(index)
        return self.bindings[index]

    def __repr__(self):
        return "<BindingsReport filename=%r slices=%d bindings=%d>" % (
            self.filename,
            len(self.slices),
            len(self.bindings),
        )


# Backwards/forwards friendly class spellings.
BindingReport = BindingsReport
ImportReport = BindingsReport
SliceBindingReport = SliceBindings
SliceImportReport = SliceBindings


def _read_symbols(fp, header, symtab, problems):
    """Read nlist entries and their string-table names for one slice."""
    if symtab is None:
        problems.append("missing LC_SYMTAB")
        return []

    strsize = int(symtab.strsize)
    fp.seek(header.offset + int(symtab.stroff))
    strtab = fp.read(strsize)
    if len(strtab) != strsize:
        problems.append(
            "truncated string table: read %d of %d bytes" % (len(strtab), strsize)
        )

    fp.seek(header.offset + int(symtab.symoff))
    if header.MH_MAGIC in (MH_MAGIC_64, MH_CIGAM_64):
        cls = nlist_64
    else:
        cls = nlist

    symbols = []
    for index in range(int(symtab.nsyms)):
        try:
            entry = cls.from_fileobj(fp, _endian_=header.endian)
        except (struct.error, ValueError) as exc:
            problems.append(
                "truncated symbol table at index %d: %s" % (index, exc)
            )
            break

        name_index = int(entry.n_un) & 0xFFFFFFFF
        name_bytes = None
        name_error = None
        if name_index == 0:
            name_bytes = b""
            name_error = "symbol has an empty string-table index"
        elif name_index >= len(strtab):
            name_error = "string table index %d is outside the string table" % (
                name_index,
            )
        else:
            end = strtab.find(b"\x00", name_index)
            if end < 0:
                end = len(strtab)
            name_bytes = strtab[name_index:end]

        symbols.append((entry, name_bytes, name_error))

    return symbols


def _read_dylibs(header, problems):
    """Return dylib load commands in the order used by symbol ordinals."""
    result = []
    for command_index, (load_command, command, data) in enumerate(header.commands):
        if int(load_command.cmd) not in DYLIB_LOAD_COMMANDS:
            continue

        ordinal = len(result) + 1
        path = None
        name_error = None
        try:
            # lc_str offsets are relative to the start of the load command.
            header_size = sizeof(load_command.__class__) + sizeof(command.__class__)
            name_offset = int(command.name) - header_size
            if name_offset < 0 or name_offset > len(data):
                name_error = (
                    "dylib name offset %d is outside command data"
                    % (int(command.name),)
                )
            else:
                raw = data[name_offset:]
                end = raw.find(b"\x00")
                if end >= 0:
                    raw = raw[:end]
                path = _decode(raw)
                if path == "":
                    name_error = "dylib name is empty"
                    path = None
        except (AttributeError, ValueError, TypeError) as exc:
            name_error = "cannot read dylib name: %s" % (exc,)

        if name_error is not None:
            problems.append("ordinal %d: %s" % (ordinal, name_error))

        result.append(
            DylibReference(
                ordinal=ordinal,
                command_index=command_index,
                command=load_command.cmd,
                path=path,
                weak=int(load_command.cmd) == LC_LOAD_WEAK_DYLIB,
                name_error=name_error,
            )
        )

    return result


def _ranges(dysymtab):
    if dysymtab is None:
        return {}
    return {
        "locals": (int(dysymtab.ilocalsym), int(dysymtab.nlocalsym)),
        "external": (int(dysymtab.iextdefsym), int(dysymtab.nextdefsym)),
        "undefined": (int(dysymtab.iundefsym), int(dysymtab.nundefsym)),
    }


def _is_undefined(entry):
    n_type = int(entry.n_type)
    return (n_type & N_STAB) == 0 and (n_type & N_TYPE) in (N_UNDF, N_PBUD)


def _make_binding(
    header,
    slice_index,
    arch,
    two_level,
    dylibs,
    symbol_index,
    undefined_index,
    entry,
    name_bytes,
    name_error,
    in_dynamic_range,
):
    n_type = int(entry.n_type)
    n_desc = int(entry.n_desc) & 0xFFFF
    ordinal = (n_desc >> 8) & 0xFF
    weak = bool(n_desc & N_WEAK_REF)
    name = _decode(name_bytes)

    # Old linkers could produce 254 dylib ordinals; 0xfe is only the
    # dynamic-lookup sentinel when the image does not have that many dylibs.
    legacy_max_ordinal = (
        ordinal == DYNAMIC_LOOKUP_ORDINAL and len(dylibs) >= DYNAMIC_LOOKUP_ORDINAL
    )
    special = None if legacy_max_ordinal else SPECIAL_ORDINAL_NAMES.get(ordinal)
    dylib = None
    module = None
    resolution = RESOLUTION_UNRESOLVED
    reason = None

    if special is not None:
        resolution = RESOLUTION_SPECIAL
        reason = {
            SELF_LIBRARY_ORDINAL: "self library ordinal",
            DYNAMIC_LOOKUP_ORDINAL: "dynamic lookup ordinal",
            EXECUTABLE_ORDINAL: "main executable ordinal",
        }[ordinal]
    elif 1 <= ordinal <= MAX_LIBRARY_ORDINAL or legacy_max_ordinal:
        if ordinal <= len(dylibs):
            dylib = dylibs[ordinal - 1]
            if dylib.path is None:
                reason = "dylib ordinal %d has no readable module name" % (ordinal,)
            else:
                module = dylib.path
                resolution = RESOLUTION_DYLIB
        else:
            reason = "dylib ordinal %d has no matching load command" % (ordinal,)
    else:
        reason = "dylib ordinal %d is not valid" % (ordinal,)

    if name_error is not None:
        reason = name_error
    elif not name_bytes:
        reason = "symbol has no string-table name"

    if not in_dynamic_range:
        resolution = RESOLUTION_UNVERIFIED
        status = STATUS_UNVERIFIED
        if reason is None:
            reason = "symbol is outside the LC_DYSYMTAB undefined range"
    elif not name_bytes:
        status = STATUS_UNVERIFIED
    elif weak:
        # A weak reference remains weak even when its module is known.
        status = STATUS_WEAK
    elif special is not None:
        status = STATUS_SPECIAL
    elif module is not None:
        status = STATUS_BOUND
    else:
        status = STATUS_UNRESOLVED

    return ImportBinding(
        slice_index=slice_index,
        slice_offset=header.offset,
        arch=arch,
        cputype=header.header.cputype,
        cpusubtype=header.header.cpusubtype,
        endian=header.endian,
        symbol_index=symbol_index,
        undefined_index=undefined_index,
        name=name,
        name_bytes=name_bytes,
        ordinal=ordinal,
        string_index=int(entry.n_un) & 0xFFFFFFFF,
        weak=weak,
        special=special,
        status=status,
        resolution=resolution,
        module=module,
        dylib=dylib,
        reason=reason,
        n_type=n_type,
        n_desc=n_desc,
        n_sect=int(entry.n_sect),
        n_value=int(entry.n_value),
        two_level=two_level,
        in_dynamic_range=in_dynamic_range,
    )


def _symbol_indexes(symbols, dysymtab, problems):
    """Select the undefined-symbol range, with a conservative fallback."""
    if dysymtab is None:
        problems.append("missing LC_DYSYMTAB")
        selected = []
        for index, (entry, _name_bytes, _name_error) in enumerate(symbols):
            if _is_undefined(entry) and (int(entry.n_type) & N_EXT):
                selected.append((index, None, "", False))
        return selected

    start = int(dysymtab.iundefsym)
    count = int(dysymtab.nundefsym)
    end = start + count

    if start < 0 or count < 0:
        problems.append(
            "invalid LC_DYSYMTAB undefined range: start=%d count=%d" % (start, count)
        )
        return []
    if start > len(symbols) or end > len(symbols):
        problems.append(
            "LC_DYSYMTAB undefined range %d..%d exceeds %d symbols"
            % (start, end, len(symbols))
        )

    selected = []
    for index in range(start, min(end, len(symbols))):
        selected.append((index, index - start, "", True))
    return selected


def analyze_slice(
    macho,
    header,
    index=0,
    include_outside_range=False,
    include_unverified=None,
):
    """Analyze one Mach-O header from *macho*.

    ``header`` is a :class:`macholib.MachO.MachOHeader`.  The function opens
    ``macho.filename`` once and reads the slice's symbol table.
    """
    if include_unverified is not None:
        include_outside_range = include_unverified

    problems = []
    cputype = int(header.header.cputype)
    cpusubtype = int(header.header.cpusubtype)
    arch = CPU_TYPE_NAMES.get(cputype, str(cputype))
    cpusubtype_name = get_cpu_subtype(cputype, header.header.cpusubtype)

    flags = int(header.header.flags)
    two_level = bool(flags & MH_TWOLEVEL) and not bool(flags & MH_FORCE_FLAT)

    dylibs = _read_dylibs(header, problems)
    symtab = header.getSymbolTableCommand()
    dysymtab = header.getDynamicSymbolTableCommand()

    with open(macho.filename, "rb") as fp:
        symbols = _read_symbols(fp, header, symtab, problems)

    selected = _symbol_indexes(symbols, dysymtab, problems)
    bindings = []
    for symbol_index, undefined_index, _unused, in_range in selected:
        entry, name_bytes, name_error = symbols[symbol_index]
        bindings.append(
            _make_binding(
                header,
                index,
                arch,
                two_level,
                dylibs,
                symbol_index,
                undefined_index,
                entry,
                name_bytes,
                name_error,
                in_range,
            )
        )

    # If requested, keep undefined symbols outside the declared range, but
    # mark them unverified.  They are never promoted to normal bindings.
    if include_outside_range and dysymtab is not None:
        selected_indexes = set(
            symbol_index for symbol_index, _i, _u, _r in selected
        )
        for symbol_index, (entry, name_bytes, name_error) in enumerate(symbols):
            if symbol_index in selected_indexes:
                continue
            if not _is_undefined(entry):
                continue
            bindings.append(
                _make_binding(
                    header,
                    index,
                    arch,
                    two_level,
                    dylibs,
                    symbol_index,
                    None,
                    entry,
                    name_bytes,
                    name_error,
                    False,
                )
            )

    bindings.sort(key=lambda item: item.symbol_index)

    return SliceBindings(
        index=index,
        filename=macho.filename,
        offset=header.offset,
        size=header.size,
        arch=arch,
        cputype=cputype,
        cpusubtype=cpusubtype,
        cpusubtype_name=cpusubtype_name,
        endian=header.endian,
        two_level=two_level,
        dylibs=dylibs,
        bindings=bindings,
        problems=problems,
        ranges=_ranges(dysymtab),
        header=header,
        symtab=symtab,
        dysymtab=dysymtab,
    )


def analyze_macho(
    macho, include_outside_range=False, include_unverified=None
):
    """Analyze every slice of an already-loaded :class:`MachO` object."""
    if include_unverified is not None:
        include_outside_range = include_unverified

    return BindingsReport(
        macho.filename,
        [
            analyze_slice(
                macho,
                header,
                index=index,
                include_outside_range=include_outside_range,
            )
            for index, header in enumerate(macho.headers)
        ],
    )


def analyze_bindings(
    source, include_outside_range=False, include_unverified=None
):
    """Analyze a path or :class:`MachO` object.

    ``include_unverified`` is accepted as an alias for
    ``include_outside_range`` so callers can express the same intent with
    either name.
    """
    if include_unverified is not None:
        include_outside_range = include_unverified

    if hasattr(source, "headers") and hasattr(source, "filename"):
        macho = source
    else:
        from macholib.MachO import MachO

        macho = MachO(source)

    return analyze_macho(macho, include_outside_range=include_outside_range)


# Short and verb-oriented aliases.
analyze = analyze_bindings
analyze_imports = analyze_bindings
analyze_import_bindings = analyze_bindings
check_bindings = analyze_bindings
check_imports = analyze_bindings
get_bindings = analyze_bindings
inspect_bindings = analyze_bindings

# Mapping-style access is convenient for report serialization.
ImportBinding.to_dict = ImportBinding.as_dict
SliceBindings.to_dict = SliceBindings.as_dict
BindingsReport.to_dict = BindingsReport.as_dict


def iter_bindings(source, **kw):
    return iter(analyze_bindings(source, **kw))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    as_json = False
    include_outside = False
    strict = False
    paths = []
    for arg in argv:
        if arg == "--json":
            as_json = True
        elif arg in ("--include-outside-range", "--include-unverified"):
            include_outside = True
        elif arg == "--strict":
            strict = True
        elif arg in ("-h", "--help"):
            print(
                "usage: python -m macholib.bindings "
                "[--json] [--strict] FILE ..."
            )
            return 0
        else:
            paths.append(arg)

    if not paths:
        print(
            "usage: python -m macholib.bindings [--json] [--strict] FILE ...",
            file=sys.stderr,
        )
        return 2

    exit_code = 0
    for path in paths:
        report = analyze_bindings(path, include_outside_range=include_outside)
        if as_json:
            print(report.dumps())
        else:
            print(report.format())

        if strict:
            if not report.ok:
                exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
