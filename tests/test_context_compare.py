import io

from minidump.context import (
    ContextComparer,
    ContextSource,
    RegisterStatus,
    compare_contexts,
)
from minidump.minidumpfile import MinidumpFile
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
from tests.context_fixture import (
    CONTEXT_CONTROL,
    CONTEXT_DEBUG_REGISTERS,
    CONTEXT_FLOATING_POINT,
    CONTEXT_INTEGER,
    CONTEXT_XSTATE,
    build_minidump,
    x64_context,
)

EXCEPTION_FLAGS = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT | CONTEXT_XSTATE
THREAD_FLAGS = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS

def parse(data):
    return MinidumpFile.parse_bytes(data)

def x64_fixture():
    exception = x64_context(
        {'Rax': 0x1111, 'Rip': 0x401001, 'Rsp': 0x500000, 'Dr0': 0},
        flags=EXCEPTION_FLAGS,
        xmm={0: 0xAAAA},
        vector={0: 0xCCCC},
    )
    thread = x64_context(
        {'Rax': 0x2222, 'Rip': 0x777777, 'Rsp': 0x600000, 'Dr0': 0xDEAD},
        flags=THREAD_FLAGS,
        xmm={0: 0},
    )
    return parse(build_minidump(exception_context=exception, thread_context=thread))

def test_x64_comparison_binds_thread_architecture_and_validity():
    comparison = x64_fixture().get_context_comparison()
    assert comparison.thread_id == 0x1234
    assert comparison.architecture == PROCESSOR_ARCHITECTURE.AMD64
    assert comparison.exception.context_flags == EXCEPTION_FLAGS
    assert comparison.thread.context_flags == THREAD_FLAGS
    assert comparison.exception.register_validity['floating_point'] is True
    assert comparison.thread.register_validity['floating_point'] is False
    assert comparison.thread.register_validity['debug'] is True

def test_x64_prefers_exception_time_value_and_labels_thread_snapshot():
    comparison = x64_fixture().get_context_comparison()
    row = comparison.get('Rax')
    assert row.exception.source == ContextSource.EXCEPTION
    assert row.thread.source == ContextSource.THREAD
    assert row.value == 0x1111
    assert row.thread_value == 0x2222
    assert row.captured_at_exception is True
    assert row.thread_state_only is False
    assert row.agrees is False
    report = comparison.to_report()
    assert 'exception-time capture' in report
    assert 'normal thread state' in report
    assert '0x1111' in report and '0x2222' in report

def test_non_general_register_can_be_available_on_only_one_side():
    comparison = x64_fixture().get_context_comparison()
    xmm = comparison.get('Xmm0')
    assert xmm.captured_at_exception is True
    assert xmm.thread is not None
    assert xmm.thread.status == RegisterStatus.INVALID
    assert xmm.thread.value is None
    vector = comparison.get('Vector0')
    assert vector.captured_at_exception is True
    assert vector.value == 0xCCCC
    dr0 = comparison.get('Dr0')
    assert dr0.captured_at_exception is False
    assert dr0.thread_state_only is True
    assert dr0.value == 0xDEAD
    assert 'thread snapshot only' in dr0.explanation

def test_missing_exception_context_page_does_not_fabricate_values():
    thread = x64_context({'Rax': 0x2222, 'Rip': 0x777777}, flags=THREAD_FLAGS)
    comparison = parse(build_minidump(
        exception_context=thread,
        thread_context=thread,
        missing_exception_context=True,
    )).get_context_comparison()
    assert comparison.exception.available is False
    assert comparison.exception.missing_reason
    assert comparison.thread.available is True
    row = comparison.get('Rax')
    assert row.exception is None
    assert row.thread_state_only is True
    assert row.value == 0x2222
    assert 'not present in either context' not in row.explanation

def test_unknown_architecture_retains_raw_context_and_source_without_zero_values():
    comparison = parse(build_minidump(
        architecture=0x1234,
        exception_context=bytes([0xAA]) * 64,
        thread_context=bytes([0xBB]) * 64,
    )).get_context_comparison()
    assert comparison.architecture == PROCESSOR_ARCHITECTURE.UNKNOWN
    assert comparison.architecture_raw == 0x1234
    row = comparison.get('raw_context')
    assert row is not None
    assert row.exception.value is None
    assert row.thread.value is None
    assert row.exception.raw == bytes([0xAA]) * 64
    assert row.thread.raw == bytes([0xBB]) * 64
    assert row.exception.source == ContextSource.EXCEPTION
    assert row.thread.source == ContextSource.THREAD
    assert row.source == ContextSource.EXCEPTION
    assert row.valid is None
    assert 'not reported as zero' in comparison.to_report()

def test_direct_context_objects_use_same_rule():
    exception = x64_context({'Rax': 1}, flags=CONTEXT_CONTROL | CONTEXT_INTEGER)
    thread = x64_context({'Rax': 2}, flags=CONTEXT_CONTROL | CONTEXT_INTEGER)
    comparison = compare_contexts(
        exception,
        thread,
        thread_id=0x77,
        architecture='x64',
    )
    assert comparison.thread_id == 0x77
    assert comparison.get('Rax').value == 1
    assert comparison.get('Rax').thread_value == 2
