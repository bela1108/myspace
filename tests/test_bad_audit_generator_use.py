from __future__ import absolute_import, division, print_function, unicode_literals

import ast
import textwrap

import pytest

from dlint.audit_generator import (
    STATE_EARLY_BREAK,
    STATE_EARLY_CLOSE,
    STATE_EXHAUSTED,
    STATE_FINALLY_SUPPRESSED,
    STATE_NOT_STARTED,
    STATE_UNKNOWN_CONSUMER,
    AuditGeneratorAnalyzer,
)
from dlint.linters.base import Flake8Result
from dlint.linters.bad_audit_generator_use import BadAuditGeneratorUseLinter


def parse(source):
    return ast.parse(textwrap.dedent(source).lstrip("\n"))


def analyze(source):
    return AuditGeneratorAnalyzer().analyze(parse(source))


CASES = [
    (
        'not_started',
        STATE_NOT_STARTED,
        6,
        """
        def audit_integers():
            yield 1
            yield 2
            audit_confirm('done')

        gen = audit_integers()
        """,
    ),
    (
        'early_close',
        STATE_EARLY_CLOSE,
        8,
        """
        def audit_integers():
            yield 1
            yield 2
            audit_confirm('done')

        gen = audit_integers()
        next(gen)
        gen.close()
        """,
    ),
    (
        'early_break',
        STATE_EARLY_BREAK,
        7,
        """
        def audit_integers():
            yield 1
            yield 2
            audit_confirm('done')

        for number in audit_integers():
            break
        """,
    ),
    (
        'normal_exhaustion',
        STATE_EXHAUSTED,
        6,
        """
        def audit_integers():
            yield 1
            yield 2
            audit_confirm('done')

        list(audit_integers())
        """,
    ),
    (
        'unknown_external_consumer',
        STATE_UNKNOWN_CONSUMER,
        6,
        """
        def audit_integers():
            yield 1
            yield 2
            audit_confirm('done')

        external_consumer(audit_integers())
        """,
    ),
    (
        'unknown_bound_external_consumer',
        STATE_UNKNOWN_CONSUMER,
        7,
        """
        def audit_integers():
            yield 1
            yield 2
            audit_confirm('done')

        gen = audit_integers()
        external_consumer(gen)
        """,
    ),
    (
        'finally_suppresses_generator_exit',
        STATE_FINALLY_SUPPRESSED,
        7,
        """
        def audit_integers():
            try:
                yield 1
                yield 2
                audit_confirm('done')
            finally:
                return True

        gen = audit_integers()
        next(gen)
        gen.close()
        """,
    ),
    (
        'return_wrapper_normal_exhaustion',
        STATE_EXHAUSTED,
        9,
        """
        def audit_integers():
            yield 1
            yield 2
            audit_confirm('done')

        def one_layer():
            return audit_integers()

        list(one_layer())
        """,
    ),
    (
        'return_wrapper_early_close',
        STATE_EARLY_CLOSE,
        11,
        """
        def audit_integers():
            yield 1
            yield 2
            audit_confirm('done')

        def one_layer():
            return audit_integers()

        wrapped = one_layer()
        next(wrapped)
        wrapped.close()
        """,
    ),
    (
        'yield_from_wrapper_early_break',
        STATE_EARLY_BREAK,
        10,
        """
        def audit_integers():
            yield 1
            yield 2
            audit_confirm('done')

        def one_layer():
            yield from audit_integers()

        for number in one_layer():
            break
        """,
    ),
]


@pytest.mark.parametrize(
    ('case_id', 'expected_state', 'expected_line', 'source'),
    CASES,
    ids=[case[0] for case in CASES],
)
def test_audit_generator_state_table(
    case_id, expected_state, expected_line, source
):
    findings = analyze(source)

    assert [(finding.state, finding.lineno) for finding in findings] == [
        (expected_state, expected_line),
    ]

    linter = BadAuditGeneratorUseLinter()
    linter.visit(parse(source))
    results = linter.get_results()

    assert len(results) == 1
    assert isinstance(results[0], Flake8Result)
    assert results[0].lineno == expected_line
    assert expected_state in results[0].message


def test_table_covers_requested_states():
    states = {case[1] for case in CASES}

    assert {
        STATE_NOT_STARTED,
        STATE_EARLY_CLOSE,
        STATE_EARLY_BREAK,
        STATE_EXHAUSTED,
        STATE_FINALLY_SUPPRESSED,
        STATE_UNKNOWN_CONSUMER,
    } <= states
