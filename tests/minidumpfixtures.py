#!/usr/bin/env python3
"""
Deterministic, hand-built minidump fixtures for the read-only impact
analyzer tests.

The generator emits real minidump binaries (valid header, directory and
streams parseable by minidump.minidumpfile.MinidumpFile) without any
external sample. From one identical small sample it derives three trimmed
variants: a complete dump, a dump missing a substitutable stream, and a
dump whose directory entry survived while the referenced backing data did
not. Only file layout matters; the filler payloads are fixed marker bytes
that the analyzer must never surface.
"""

import struct

from minidump.constants import MINIDUMP_STREAM_TYPE


def u16(value):
    return struct.pack('<H', value)


def u32(value):
    return struct.pack('<I', value)


def u64(value):
    return struct.pack('<Q', value)


def location(data_size, rva):
    return u32(data_size) + u32(rva)


def directory_entry(stream_type, data_size, rva):
    return u32(stream_type) + location(data_size, rva)


def system_info_stream():
    data = u16(9)            # ProcessorArchitecture = AMD64
    data += u16(6)           # ProcessorLevel
    data += u16(0x2601)      # ProcessorRevision
    data += struct.pack('<BB', 1, 1)  # NumberOfProcessors, ProductType
    data += u32(10)          # MajorVersion
    data += u32(0)           # MinorVersion
    data += u32(19045)       # BuildNumber
    data += u32(2)           # PlatformId
    data += u32(0)           # CSDVersionRva
    data += u16(0x110)       # SuiteMask
    data += u16(0)           # Reserved2
    data += b'\x00' * 16     # ProcessorFeatures[2] for AMD64
    return data


def thread_list_stream(thread_id, stack_va, stack_size, stack_rva,
        context_size, context_rva):
    data = u32(1)                          # NumberOfThreads
    data += u32(thread_id)                 # ThreadId
    data += u32(0)                         # SuspendCount
    data += u32(32)                        # PriorityClass
    data += u32(8)                         # Priority
    data += u64(0x7ffd0000)                # Teb
    data += u64(stack_va)                  # Stack.StartOfMemoryRange
    data += location(stack_size, stack_rva)
    data += location(context_size, context_rva)
    return data


def exception_stream(thread_id, context_size, context_rva,
        exception_code=0xC0000005, exception_address=0x00007FF601001234):
    data = u32(thread_id)                  # ThreadId
    data += u32(0)                         # alignment
    data += u32(exception_code)            # ExceptionCode
    data += u32(0)                         # ExceptionFlags
    data += u64(0)                         # ExceptionRecord
    data += u64(exception_address)         # ExceptionAddress
    data += u32(0)                         # NumberParameters
    data += u32(0)                         # unused alignment
    data += u64(0) * 15                    # ExceptionInformation
    data += location(context_size, context_rva)
    return data


def memory_list_stream(ranges):
    data = u32(len(ranges))
    for start_va, size, rva in ranges:
        data += u64(start_va)
        data += location(size, rva)
    return data


def module_list_stream():
    # A single, zeroed module entry is enough to prove presence/absence of
    # the module-resolution capability without pulling PE parsing in.
    entry = u64(0x00007FF601000000)        # BaseOfImage
    entry += u32(0x4000)                   # SizeOfImage
    entry += u32(0)                        # CheckSum
    entry += u32(0)                        # TimeDateStamp
    entry += u32(0)                        # ModuleNameRva
    entry += b'\x00' * (52 + 4 + 4)        # VersionInfo, CvRecord, MiscRecord
    entry += u64(0) + u64(0)               # Reserved0/1
    return u32(1) + entry


MODULE_ENTRY_SIZE = 108


def module_list_stream():
    # A single zeroed module entry proves presence/absence of the
    # module-resolution capability without pulling PE parsing in.
    entry = u64(0x00007FF601000000)        # BaseOfImage
    entry += u32(0x4000)                   # SizeOfImage
    entry += b'\x00' * (MODULE_ENTRY_SIZE - 12)
    return u32(1) + entry


# Deterministic addresses/sizes shared by every derived variant.
THREAD_ID = 0x0909
FAULTING_STACK_VA = 0x000000E0CAD00000
STACK_SIZE = 0x200
CONTEXT_SIZE = 0x40
STACK_FILLER = b'STACK-MEMORY-MARKER' + b'\xCC' * (STACK_SIZE - 20)
CONTEXT_FILLER = b'CONTEXT-MARKER' + b'\x00' * (CONTEXT_SIZE - 14)


def build_complete_dump():
    # Layout: 28-byte header | directory (5 * 12) | stream regions.
    # A single ordered region list drives both payload placement and
    # directory emission, so RVAs can never drift from the actual bytes.
    stream_types = [
        MINIDUMP_STREAM_TYPE.SystemInfoStream,
        MINIDUMP_STREAM_TYPE.ThreadListStream,
        MINIDUMP_STREAM_TYPE.ExceptionStream,
        MINIDUMP_STREAM_TYPE.MemoryListStream,
        MINIDUMP_STREAM_TYPE.ModuleListStream,
    ]
    directory_rva = 28
    cursor = directory_rva + len(stream_types) * 12

    regions = []   # (stream_type_or_None, payload)
    directory = [] # (stream_type, size, rva) in directory-slot order

    def reserve(payload, stream_type=None):
        nonlocal cursor
        rva = cursor
        regions.append(payload)
        if stream_type is not None:
            directory.append((stream_type, len(payload), rva))
        cursor += len(payload)
        return rva

    sys_rva = reserve(system_info_stream(),
        MINIDUMP_STREAM_TYPE.SystemInfoStream)

    # Reserve the shared stack/context payloads first so the thread list,
    # exception stream and memory list all reference the same regions.
    stack_rva = reserve(STACK_FILLER)
    context_rva = reserve(CONTEXT_FILLER)

    reserve(
        thread_list_stream(
            THREAD_ID, FAULTING_STACK_VA, STACK_SIZE, stack_rva,
            CONTEXT_SIZE, context_rva,
        ),
        MINIDUMP_STREAM_TYPE.ThreadListStream,
    )
    reserve(
        exception_stream(THREAD_ID, CONTEXT_SIZE, context_rva),
        MINIDUMP_STREAM_TYPE.ExceptionStream,
    )
    reserve(
        memory_list_stream([(FAULTING_STACK_VA, STACK_SIZE, stack_rva)]),
        MINIDUMP_STREAM_TYPE.MemoryListStream,
    )
    reserve(
        module_list_stream(),
        MINIDUMP_STREAM_TYPE.ModuleListStream,
    )

    # Directory slots follow the declared stream order, independent of the
    # physical region order.
    directory.sort(key=lambda item: stream_types.index(item[0]))
    header = b'MDMP'
    header += u16(0xA793)                  # Version
    header += u16(0)                       # ImplementationVersion
    header += u32(len(stream_types))       # NumberOfStreams
    header += u32(directory_rva)
    header += u32(0)                       # CheckSum
    header += u32(0)                       # TimeDateStamp
    header += u32(0)                       # Flags

    directory_bytes = b''.join(
        directory_entry(stype.value, size, rva)
        for stype, size, rva in directory
    )
    return header + directory_bytes + b''.join(regions)


def _header_fields(data):
    (signature, version, impl, number_of_streams, directory_rva,
        checksum, timestamp, flags) = struct.unpack('<4sHHIIIII', data[:28])
    return {
        'signature': signature,
        'version': version,
        'impl': impl,
        'number_of_streams': number_of_streams,
        'directory_rva': directory_rva,
        'checksum': checksum,
        'timestamp': timestamp,
        'flags': flags,
    }


def _read_directory(data, header):
    entries = []
    base = header['directory_rva']
    for index in range(header['number_of_streams']):
        offset = base + index * 12
        stream_type, size, rva = struct.unpack('<III', data[offset:offset + 12])
        entries.append({
            'index': index,
            'stream_type': MINIDUMP_STREAM_TYPE(stream_type),
            'size': size,
            'rva': rva,
        })
    return entries


def _rewrite_directory(data, header, entries):
    output = bytearray(data)
    base = header['directory_rva']
    for entry in entries:
        offset = base + entry['index'] * 12
        output[offset:offset + 12] = directory_entry(
            entry['stream_type'].value, entry['size'], entry['rva'],
        )
    return bytes(output)


def trim_stream(data, stream_type):
    # Rewrite the directory slot in place as UnusedStream while keeping the
    # header stream count and every directory slot intact. This mirrors a
    # compression pass that drops the logical stream but leaves the on-disk
    # layout alone, so all surviving RVAs keep resolving. The parser skips
    # UnusedStream entries but still visits the following slots.
    header = _header_fields(data)
    entries = _read_directory(data, header)
    target = next(entry for entry in entries
        if entry['stream_type'] == stream_type)
    target['stream_type'] = MINIDUMP_STREAM_TYPE.UnusedStream
    output = bytearray(_rewrite_directory(data, header, entries))
    output[0:28] = (
        b'MDMP' + u16(header['version']) + u16(header['impl'])
        + u32(header['number_of_streams'])
        + u32(header['directory_rva']) + u32(header['checksum'])
        + u32(header['timestamp']) + u32(header['flags'])
    )
    return bytes(output)


def dangle_referenced_data(data, stream_type):
    # Keep the directory entry but push its RVA past end of file, modeling
    # an entry that survived compression while its backing data was removed.
    header = _header_fields(data)
    entries = _read_directory(data, header)
    target = next(entry for entry in entries
        if entry['stream_type'] == stream_type)
    target['rva'] = len(data) + 0x1000
    return _rewrite_directory(data, header, entries)


def build_variants():
    complete = build_complete_dump()
    # Variant B: the module list is a substitutable, symbol-resolution-only
    # carrier. Removing it degrades symbol/module resolution while leaving
    # exception facts, threads, register context and stack memory intact, so
    # a partial (not blocked) crash reconstruction must still be provable.
    without_modules = trim_stream(
        complete, MINIDUMP_STREAM_TYPE.ModuleListStream,
    )
    # Variant C: the exception directory entry stays, but its referenced
    # context payload no longer resolves inside the file.
    dangling_exception = dangle_referenced_data(
        complete, MINIDUMP_STREAM_TYPE.ExceptionStream,
    )
    return {
        'complete': complete,
        'without_modules': without_modules,
        'dangling_exception': dangling_exception,
    }
