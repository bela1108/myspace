import struct

from minidump.constants import MINIDUMP_STREAM_TYPE

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x8
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10
CONTEXT_XSTATE = CONTEXT_AMD64 | 0x40
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT

def x64_context(regs, flags=CONTEXT_FULL, xmm=None, vector=None):
    raw = bytearray(0x4D0)
    struct.pack_into('<I', raw, 0x30, flags)
    for name, offset in (('SegCs', 0x38), ('SegDs', 0x3A), ('SegEs', 0x3C), ('SegFs', 0x3E), ('SegGs', 0x40), ('SegSs', 0x42)):
        if name in regs:
            struct.pack_into('<H', raw, offset, regs[name] & 0xFFFF)
    if 'EFlags' in regs:
        struct.pack_into('<I', raw, 0x44, regs['EFlags'] & 0xFFFFFFFF)
    if 'MxCsr' in regs:
        struct.pack_into('<I', raw, 0x34, regs['MxCsr'] & 0xFFFFFFFF)
    for index, name in enumerate(('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7')):
        if name in regs:
            struct.pack_into('<Q', raw, 0x48 + index * 8, regs[name])
    fields = ('Rax', 'Rcx', 'Rdx', 'Rbx', 'Rsp', 'Rbp', 'Rsi', 'Rdi', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'Rip')
    for index, name in enumerate(fields):
        if name in regs:
            struct.pack_into('<Q', raw, 0x78 + index * 8, regs[name])
    for index, value in (xmm or {}).items():
        struct.pack_into('<Q', raw, 0x1A0 + index * 16, value & 0xFFFFFFFFFFFFFFFF)
    for index, value in (vector or {}).items():
        struct.pack_into('<Q', raw, 0x300 + index * 16, value & 0xFFFFFFFFFFFFFFFF)
    return bytes(raw)

def _system_info(architecture):
    return struct.pack('<HHHBBIIIIIHHQQ', architecture, 6, 0, 1, 1, 10, 0, 19045, 2, 0, 0x100, 0, 0, 0)

def _thread_list(thread_id, context_size, context_rva):
    thread = struct.pack('<IIIIQQIIII', thread_id, 0, 0, 0, 0, 0, 0, 0, context_size, context_rva)
    return struct.pack('<I', 1) + thread

def _exception_stream(thread_id, context_size, context_rva, address=0x401001):
    params = [0x1, address] + [0] * 13
    record = struct.pack('<II', thread_id, 0)
    record += struct.pack('<IIQQII', 0xC0000005, 0, 0, address, 2, 0)
    record += struct.pack('<15Q', *params)
    record += struct.pack('<II', context_size, context_rva)
    return record

def build_minidump(thread_id=0x1234, architecture=9, exception_context=b'', thread_context=b'', exception_address=0x401001, missing_exception_context=False, missing_thread_context=False):
    header_size = 28
    cursor = header_size + 3 * 12
    sysinfo = _system_info(architecture)
    sysinfo_rva = cursor
    cursor += len(sysinfo)
    thread_list_rva = cursor
    cursor += 4 + 48
    exception_rva = cursor
    cursor += 168
    thread_context_rva = cursor
    if missing_thread_context:
        thread_context = b''
        thread_context_rva = 0
    cursor += len(thread_context)
    exception_context_rva = cursor
    if missing_exception_context:
        exception_context = b''
        exception_context_rva = 0
    cursor += len(exception_context)
    thread_list = _thread_list(thread_id, len(thread_context), thread_context_rva)
    exception = _exception_stream(thread_id, len(exception_context), exception_context_rva, exception_address)
    header = b'MDMP' + struct.pack('<HHIIIII', 1, 1, 3, header_size, 0, 0, 0)
    directory = b''.join([
        struct.pack('<III', MINIDUMP_STREAM_TYPE.SystemInfoStream.value, len(sysinfo), sysinfo_rva),
        struct.pack('<III', MINIDUMP_STREAM_TYPE.ThreadListStream.value, len(thread_list), thread_list_rva),
        struct.pack('<III', MINIDUMP_STREAM_TYPE.ExceptionStream.value, len(exception), exception_rva),
    ])
    return b''.join([header, directory, sysinfo, thread_list, exception, thread_context, exception_context])
