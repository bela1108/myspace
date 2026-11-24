from __future__ import absolute_import, division, print_function, unicode_literals

import ast
import textwrap

import pytest

from dlint.audit_generator import (
    AuditGeneratorAnalyzer,
    STATE_EARLY_BREAK,
    STATE_EARLY_CLOSE,
    STATE_EXHAUSTED,
    STATE_FINALLY_SUPPRESSED,
    STATE_NOT_STARTED,
    STATE_UNKNOWN_CONSUMER,
)
from dlint.linters.bad_audit_generator_use import BadAuditGeneratorUseLinter


def parse(source):
    return ast.parse(textwrap.dedent(source).lstrip('\n'))
