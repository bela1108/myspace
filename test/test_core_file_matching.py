# elftools tests
import json
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from pathlib import Path

from elftools.elf.corefile import (
    ArchiveCandidate,
    CoreMatchStatus,
    get_core_file_mappings,
    match_core_files,
)
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).parent / "testfiles_for_unittests" / "core_matching"


class TestCoreFileMatching(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))

    def archive_specs(self, case):
        return [
            (item["path"], ROOT / item["file"], item["label"])
            for item in case["archives"]
        ]

    def run_case(self, case):
        with ExitStack() as stack:
            core = stack.enter_context(open(ROOT / case["core"], "rb"))
            candidates = [
                ArchiveCandidate(path, stack.enter_context(open(archive, "rb")), label)
                for path, archive, label in self.archive_specs(case)
            ]
            return match_core_files(core, candidates)

    def test_manifest_has_three_distinct_outcomes(self):
        expected = {
            case["case"]: case["expected"] for case in self.manifest["cases"]
        }
        self.assertEqual(set(expected), {"unique", "unconfirmed", "contradicted"})
        self.assertEqual(expected["unique"]["status"], "matched")
        self.assertEqual(expected["unconfirmed"]["status"], "unconfirmed")
        self.assertEqual(expected["contradicted"]["status"], "contradicted")

    def test_uniquely_matched_item(self):
        case = self.manifest["cases"][0]
        result = self.run_case(case)
        self.assertEqual(len(result.modules), 1)
        module = result.modules[0]
        self.assertEqual(module.status, CoreMatchStatus.MATCHED)
        self.assertEqual(module.selected.label, case["expected"]["selected"])
        assessments = {item.label: item for item in module.instances[0].candidates}
        self.assertTrue(assessments["widget-a.so"].build_id_match)
        self.assertGreater(assessments["widget-a.so"].matched_bytes, 0)
        self.assertFalse(assessments["widget-b.so"].consistent)

    def test_missing_evidence_pages_do_not_select_a_name(self):
        case = self.manifest["cases"][1]
        result = self.run_case(case)
        module = result.modules[0]
        self.assertEqual(module.status, CoreMatchStatus.UNCONFIRMED)
        self.assertIsNone(module.selected)
        self.assertEqual(
            [item.status for item in module.instances[0].candidates],
            ["unconfirmed", "unconfirmed"],
        )
        self.assertTrue(
            all(
                item.compared_bytes == 0 and item.missing_bytes == 8192
                for item in module.instances[0].candidates
            )
        )

    def test_contradictory_mapped_bytes(self):
        case = self.manifest["cases"][2]
        result = self.run_case(case)
        module = result.modules[0]
        self.assertEqual(module.status, CoreMatchStatus.CONTRADICTED)
        self.assertIsNone(module.selected)
        self.assertTrue(
            all(
                not item.consistent and item.first_mismatch is not None
                for item in module.instances[0].candidates
            )
        )

    def test_elffile_convenience_methods(self):
        case = self.manifest["cases"][0]
        with ExitStack() as stack:
            core = stack.enter_context(open(ROOT / case["core"], "rb"))
            elf = ELFFile(core)
            mappings = elf.get_core_file_mappings()
            self.assertEqual(len(mappings), 2)
            self.assertEqual(mappings[0].path, case["archives"][0]["path"])
            candidates = [
                ArchiveCandidate(path, stack.enter_context(open(archive, "rb")), label)
                for path, archive, label in self.archive_specs(case)
            ]
            result = elf.match_core_files(candidates)
            self.assertEqual(result.modules[0].status, CoreMatchStatus.MATCHED)

    def test_mapping_input_and_explicit_stream_access(self):
        case = self.manifest["cases"][0]
        with ExitStack() as stack:
            core = stack.enter_context(open(ROOT / case["core"], "rb"))
            group = {}
            for path, archive, _label in self.archive_specs(case):
                group.setdefault(path, []).append(
                    stack.enter_context(open(archive, "rb"))
                )
            result = match_core_files(core, group)
            self.assertEqual(result.modules[0].selected.label, case["archives"][0]["path"])

    def test_mapping_parser_preserves_duplicate_paths(self):
        mappings = get_core_file_mappings(ROOT / self.manifest["cases"][0]["core"])
        self.assertEqual([mapping.page_offset for mapping in mappings], [0, 1])
        self.assertEqual(mappings[0].path, mappings[1].path)


    def test_duplicate_archive_names_are_not_identity(self):
        case = self.manifest["cases"][0]
        with ExitStack() as stack:
            core = stack.enter_context(open(ROOT / case["core"], "rb"))
            candidates = [
                ArchiveCandidate(path, stack.enter_context(open(archive, "rb")), "same.so")
                for path, archive, _label in self.archive_specs(case)
            ]
            result = match_core_files(core, candidates)
        module = result.modules[0]
        self.assertEqual(module.status, CoreMatchStatus.MATCHED)
        self.assertEqual(module.selected.label, "same.so")
        self.assertEqual(module.selected.archive.index, 0)
        self.assertEqual(
            [item.archive.index for item in module.instances[0].candidates],
            [0, 1],
        )


    def test_does_not_resolve_paths_recorded_in_nt_file(self):
        case = self.manifest["cases"][0]
        with ExitStack() as stack:
            core = stack.enter_context(open(ROOT / case["core"], "rb"))
            candidates = [
                ArchiveCandidate(path, stack.enter_context(open(archive, "rb")), label)
                for path, archive, label in self.archive_specs(case)
            ]
            with patch("builtins.open", side_effect=AssertionError("implicit open")):
                result = match_core_files(core, candidates)
        self.assertEqual(result.modules[0].status, CoreMatchStatus.MATCHED)


if __name__ == "__main__":
    unittest.main()
