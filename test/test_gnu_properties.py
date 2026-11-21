import os
import shutil
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from scripts.gnu_property_inventory import main as cli_main
from elftools.elf.elffile import ELFFile
from elftools.elf.gnu_properties import (
    CoverageStatus,
    build_property_inventory,
    render_text,
)
from elftools.elf.sections import NoteSection


_X86_FIXTURE = os.path.join(
    "test", "testfiles_for_unittests", "gnu_hash_collision.so.elf"
)
_AARCH64_FIXTURE = os.path.join(
    "test", "testfiles_for_readelf", "aarch64-pac-bti.so.elf"
)
_GNU_PROPERTY_NOTE_TYPE = 5
_UNRECOGNIZED_NOTE_TYPE = 0x12345678


class TestGnuPropertyInventory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)

    def _copy_x86(self, name: str) -> str:
        path = os.path.join(self._tmpdir.name, name)
        shutil.copyfile(_X86_FIXTURE, path)
        return path

    def _remove_property_declaration(self, path: str) -> None:
        with ELFFile.load_from_path(path) as elf:
            note = next(
                note
                for section in elf.iter_sections()
                if isinstance(section, NoteSection)
                for note in section.iter_notes()
                if note["n_type"] == "NT_GNU_PROPERTY_TYPE_0"
            )
            note_offset = int(note["n_offset"])

        with open(path, "r+b") as stream:
            stream.seek(note_offset + 8)
            stream.write(struct.pack("<I", _UNRECOGNIZED_NOTE_TYPE))

    def _make_unknown_machine(self, path: str) -> None:
        with ELFFile.load_from_path(path) as elf:
            note = next(
                note
                for section in elf.iter_sections()
                if isinstance(section, NoteSection)
                for note in section.iter_notes()
                if note["n_type"] == "NT_GNU_PROPERTY_TYPE_0"
            )
            note_offset = int(note["n_offset"])

        with open(path, "r+b") as stream:
            stream.seek(18)
            stream.write(struct.pack("<H", 0x1234))
            stream.seek(note_offset + 16)
            stream.write(struct.pack("<I", _UNRECOGNIZED_NOTE_TYPE))

    def _scenario(
        self,
        *,
        remove_declaration: bool,
    ) -> tuple[list[str], object]:
        main = self._copy_x86("main-x86.elf")
        dependency = self._copy_x86("lib-x86.so.elf")
        if remove_declaration:
            self._remove_property_declaration(dependency)
        files = [main, dependency, _AARCH64_FIXTURE]
        return files, build_property_inventory(files)

    def test_full_three_artifact_inventory(self) -> None:
        files, inventory = self._scenario(remove_declaration=False)
        self.assertEqual(len(inventory.artifacts), 3)

        x86 = next(
            report
            for report in inventory.architectures
            if report.machine == "EM_X86_64"
        )
        self.assertEqual(x86.declared_intersection, 0x3)
        self.assertEqual(
            [feature.status for feature in x86.features[:2]],
            [CoverageStatus.FULL, CoverageStatus.FULL],
        )

        aarch64 = next(
            report
            for report in inventory.architectures
            if report.machine == "EM_AARCH64"
        )
        self.assertEqual(aarch64.declared_intersection, 0x3)
        self.assertEqual(
            [feature.status for feature in aarch64.features],
            [CoverageStatus.FULL, CoverageStatus.FULL],
        )

        # PT_NOTE and SHT_NOTE point at the same bytes.  They are one proof.
        x86_artifacts = [
            artifact
            for artifact in inventory.artifacts
            if artifact.machine == "EM_X86_64"
        ]
        self.assertEqual(len(x86_artifacts[0].notes), 1)
        self.assertEqual(
            set(x86_artifacts[0].notes[0].views),
            {"section", "program"},
        )
        self.assertIn(files[0], render_text(inventory))

    def test_missing_declaration_downgrades_x86_but_not_aarch64(self) -> None:
        files, inventory = self._scenario(remove_declaration=True)
        dependency = files[1]

        x86 = next(
            report
            for report in inventory.architectures
            if report.machine == "EM_X86_64"
        )
        self.assertEqual(x86.declaration_missing_from, (dependency,))
        by_name = {feature.name: feature for feature in x86.features}
        self.assertEqual(by_name["IBT"].status, CoverageStatus.PENDING)
        self.assertEqual(by_name["SHSTK"].status, CoverageStatus.PENDING)
        self.assertEqual(by_name["IBT"].missing_declaration_by, (dependency,))
        self.assertEqual(by_name["SHSTK"].missing_declaration_by, (dependency,))

        # The missing x86 declaration says nothing about the AArch64 artifact.
        aarch64 = next(
            report
            for report in inventory.architectures
            if report.machine == "EM_AARCH64"
        )
        self.assertEqual(
            {feature.name: feature.status for feature in aarch64.features},
            {
                "BTI": CoverageStatus.FULL,
                "PAC": CoverageStatus.FULL,
            },
        )

        report = render_text(inventory)
        self.assertIn("IBT: 待确认 (pending)", report)
        self.assertIn("SHSTK: 待确认 (pending)", report)
        self.assertIn("BTI: 全覆盖 (full)", report)
        self.assertIn("PAC: 全覆盖 (full)", report)
        self.assertIn(dependency, report)

    def test_unknown_machine_is_reported_separately(self) -> None:
        path = self._copy_x86("vendor-machine.elf")
        self._make_unknown_machine(path)

        inventory = build_property_inventory([path])
        self.assertEqual(len(inventory.uninterpretable_artifacts), 1)
        artifact = inventory.uninterpretable_artifacts[0]
        self.assertEqual(artifact.machine, 0x1234)
        self.assertEqual(
            artifact.raw_properties[0].property_type,
            _UNRECOGNIZED_NOTE_TYPE,
        )
        self.assertEqual(artifact.raw_properties[0].data, b"\x03\x00\x00\x00")
        self.assertEqual(inventory.architectures, ())

        report = render_text(inventory)
        self.assertIn("Uninterpretable machine architectures", report)
        self.assertIn("excluded from all intersections", report)

        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli_main(["--json", path]), 0)
        self.assertIn('"machine": 4660', output.getvalue())
        self.assertIn('"data": "03 00 00 00"', output.getvalue())

    def test_same_file_argument_is_counted_once(self) -> None:
        path = self._copy_x86("main-x86.elf")
        inventory = build_property_inventory([path, path])
        self.assertEqual(len(inventory.artifacts), 1)


if __name__ == "__main__":
    unittest.main()
