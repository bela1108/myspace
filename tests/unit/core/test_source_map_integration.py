#
# SPDX-License-Identifier: Apache-2.0
import json
import tempfile

import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.core import source_map


class SourceMapIntegrationTests(testtools.TestCase):
    def _manager_with_issue(self, smap=None):
        conf = config.BanditConfig()
        mgr = manager.BanditManager(conf, "file", source_map=smap)
        result = issue.Issue(
            bandit.LOW,
            issue.Cwe.OS_COMMAND_INJECTION,
            bandit.HIGH,
            "shell=True",
            lineno=2,
            test_id="B602",
        )
        result.fname = "build/generated.py"
        result.linerange = [2]
        result.test = "subprocess_popen_with_shell_equals_true"
        mgr.results.append(result)
        return mgr, result

    def test_no_map_leaves_source_refs_none(self):
        mgr, result = self._manager_with_issue()
        mgr.apply_source_map()
        self.assertIsNone(result.source_refs)

    def test_map_attaches_references_without_touching_evidence(self):
        smap = source_map.SourceMap(
            files={
                "build/generated.py": [
                    source_map.SourceSegment(1, 3, "t.tmpl", 7, 9)
                ]
            },
            verify_files=False,
        )
        mgr, result = self._manager_with_issue(smap)
        mgr._file_line_counts["build/generated.py"] = 3
        mgr.apply_source_map()

        self.assertEqual(2, result.lineno)
        self.assertEqual([2], result.linerange)
        self.assertEqual("build/generated.py", result.fname)
        self.assertEqual(1, len(result.source_refs))
        self.assertEqual(
            "mapped", result.source_refs[0].as_dict()["status"]
        )
        self.assertEqual(8, result.source_refs[0].source_line)

    def test_as_dict_includes_refs_but_from_dict_drops_them(self):
        smap = source_map.SourceMap(
            files={
                "build/generated.py": [
                    source_map.SourceSegment(1, 3, "t.tmpl", 7, 9)
                ]
            },
            verify_files=False,
        )
        mgr, result = self._manager_with_issue(smap)
        mgr._file_line_counts["build/generated.py"] = 3
        mgr.apply_source_map()

        encoded = result.as_dict(with_code=False)
        self.assertIn("source_refs", encoded)
        self.assertEqual(
            "t.tmpl", encoded["source_refs"][0]["source_file"]
        )
        # from_dict always expects the scan evidence payload, incl. code
        encoded["code"] = "2 shell=True\n"

        # round-tripping through a baseline must use the scan evidence only
        restored = issue.issue_from_dict(encoded)
        self.assertIsNone(restored.source_refs)
        self.assertEqual(2, restored.lineno)
        self.assertEqual("build/generated.py", restored.fname)

    def test_map_load_from_json_file(self):
        payload = {
            "version": 1,
            "generated_files": {
                "build/generated.py": [
                    {
                        "generated_start": 1,
                        "generated_end": 3,
                        "source_file": "t.tmpl",
                        "source_start": 7,
                        "source_end": 9,
                    }
                ]
            },
        }
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        self.addCleanup(__import__("os").unlink, handle.name)
        json.dump(payload, handle)
        handle.close()

        loaded = source_map.SourceMap.load(handle.name, verify_files=False)
        self.assertTrue(loaded.has_mapping("build/generated.py"))
