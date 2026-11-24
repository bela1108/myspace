from __future__ import absolute_import, division, print_function, unicode_literals

import os
import tempfile
import unittest

import dlint


SAFE_SOURCE = '''\
import os
from dlint.toctou import open_safe


def safe_flow(path):
    if os.path.exists(path):
        fd = open_safe(path)
        descriptor = fd
        return os.read(descriptor, 1024)
'''

RACE_SOURCE = '''\\
import os


def race_flow(path, replacement):
    if os.path.exists(path):
        os.rename(path, path + '.old')
        os.rename(replacement, path)
        with open(path, 'rb') as handle:
            return handle.read()
'''


class TOCTOUFlowTest(dlint.test.base.BaseTest):
    def test_safe_alias_flow_has_no_lint(self):
        node = self.get_ast_node(SAFE_SOURCE)
        report = dlint.toctou.analyze(node)
        self.assertEqual([], [item.status for item in report if item.status != 'safe'])
        self.assertEqual(1, len(report.safe))
        self.assertTrue(report.safe[0].check_line in (5, 6))
        self.assertEqual(9, report.safe[0].use_line)

        linter = dlint.linters.BadTOCTOUUseLinter()
        linter.visit(node)
        self.assertEqual([], linter.get_results())
class TemporaryDirectoryFlowTest(unittest.TestCase):
    def test_temporary_directory_flows(self):
        flows = dlint.toctou.simulate_flows()
        self.assertEqual(dlint.toctou.SAFE, flows['safe'].status)
        self.assertEqual(b'checked-content', flows['safe'].observed)
        self.assertEqual(dlint.toctou.RACE, flows['race'].status)
        self.assertEqual(b'attacker-content', flows['race'].observed)
        self.assertEqual(dlint.toctou.UNKNOWN, flows['unknown'].status)
        self.assertEqual(b'checked-content', flows['unknown'].observed)
