import json
import os
import unittest

from elftools.elf.elffile import ELFFile
from elftools.elf.note_evidence import collect_note_evidence
from elftools.elf.note_types import (
    NoteTypeEntry,
    NoteTypeNamespace,
    NoteTypeVocabulary,
    iter_note_type_conflicts,
    iter_shared_note_type_symbols,
    legacy_note_type_name,
    resolve_note_type,
    resolve_note_type_name,
)
from elftools.elf.sections import NoteSection


def _entry(owner, value, name, description=None, version="test-v1"):
    return NoteTypeEntry(
        owner=owner,
        value=value,
        name=name,
        description=description or name,
        source=f"{owner} test note type table",
        vocabulary_version=version,
    )


def _namespace(owner, entries, *, core_only=False):
    return NoteTypeNamespace(
        owner=owner,
        source=f"{owner} test note type table",
        vocabulary_version="test-v1",
        entries=tuple(entries),
        core_only=core_only,
    )


def _vocabulary(*namespaces):
    return NoteTypeVocabulary(
        version="test-vocabulary",
        namespaces={namespace.owner: namespace for namespace in namespaces},
    )


class TestNoteTypeProvenance(unittest.TestCase):
    def test_raw_code_and_legacy_output_are_both_preserved(self):
        with ELFFile.load_from_path(
            os.path.join("test", "testfiles_for_readelf", "note_owners.o.elf")
        ) as elf:
            notes = []
            for section in elf.iter_sections():
                if isinstance(section, NoteSection):
                    notes.extend(section.iter_notes())

        vendor = next(note for note in notes if note["n_name"] == "Vendor")
        gnu = next(note for note in notes if note["n_name"] == "GNU")
        android = next(note for note in notes if note["n_name"] == "Android")

        self.assertEqual(vendor["n_type_raw"], 3)
        self.assertEqual(vendor["n_type"], 3)
        self.assertIsNone(vendor["n_type_name"])
        self.assertIsNone(vendor["n_type_source"])

        self.assertEqual(gnu["n_type_raw"], 3)
        self.assertEqual(gnu["n_type"], "NT_GNU_BUILD_ID")
        self.assertEqual(gnu["n_type_name"], "NT_GNU_BUILD_ID")
        self.assertIn("GNU", gnu["n_type_source"])
        self.assertEqual(gnu["n_type_vocabulary_version"], "binutils-2.47")

        self.assertEqual(android["n_type_raw"], 1)
        self.assertEqual(android["n_type"], "NT_VERSION")
        self.assertEqual(android["n_type_name"], "NT_VERSION")
        self.assertIn("Android", android["n_type_source"])

    def test_same_code_is_resolved_by_owner_not_display_name(self):
        gnu = resolve_note_type("GNU", 1, e_type="ET_EXEC")
        android = resolve_note_type("Android", 1, e_type="ET_EXEC")
        self.assertEqual(gnu.name, "NT_GNU_ABI_TAG")
        self.assertEqual(android.name, "NT_VERSION")
        self.assertNotEqual(gnu.source, android.source)
        self.assertNotEqual(gnu.vocabulary_version, android.vocabulary_version)

        self.assertEqual(
            legacy_note_type_name("GNU", 1, e_type="ET_EXEC"), "NT_GNU_ABI_TAG"
        )
        self.assertEqual(
            legacy_note_type_name("Android", 1, e_type="ET_EXEC"), "NT_VERSION"
        )

    def test_core_namespace_requires_a_core_file(self):
        core = resolve_note_type("CORE", 1, e_type="ET_CORE")
        self.assertEqual(core.name, "NT_PRSTATUS")
        self.assertEqual(
            legacy_note_type_name("CORE", 1, e_type="ET_CORE"), "NT_PRSTATUS"
        )

        regular = resolve_note_type("CORE", 1, e_type="ET_REL")
        self.assertFalse(regular.resolved)
        self.assertIsNone(regular.source)
        self.assertEqual(regular.legacy, 1)

    def test_historical_name_lookup_is_owner_scoped(self):
        gnu = resolve_note_type_name("GNU", "NT_GNU_BUILD_ID")
        self.assertEqual(gnu.values, (3,))
        self.assertFalse(gnu.ambiguous)
        self.assertIn("GNU", gnu.source)

        android = resolve_note_type_name("Android", "NT_VERSION")
        self.assertEqual(android.values, (1,))
        self.assertEqual(android.owner, "Android")
        self.assertIn("Android", android.source)

        # Looking up the abbreviation without an owner must not rewrite it
        # into some other owner's namespace.
        unowned = resolve_note_type_name(None, "NT_VERSION")
        self.assertEqual(unowned.owner, None)
        self.assertEqual(unowned.values, (1,))

    def test_shared_abbreviation_is_not_a_conflict(self):
        vocabulary = _vocabulary(
            _namespace("GNU", [_entry("GNU", 1, "SHARED")]),
            _namespace("Android", [_entry("Android", 2, "SHARED")]),
        )
        self.assertEqual(list(iter_note_type_conflicts(vocabulary)), [])

        groups = list(iter_shared_note_type_symbols(vocabulary))
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].name, "SHARED")
        self.assertEqual(groups[0].owners, ("Android", "GNU"))

        self.assertEqual(
            resolve_note_type_name("GNU", "SHARED", vocabulary=vocabulary).values,
            (1,),
        )
        self.assertEqual(
            resolve_note_type_name("Android", "SHARED", vocabulary=vocabulary).values,
            (2,),
        )
        self.assertTrue(
            resolve_note_type_name(None, "SHARED", vocabulary=vocabulary).ambiguous
        )

    def test_two_local_codes_may_share_one_abbreviation(self):
        vocabulary = _vocabulary(
            _namespace(
                "GNU",
                [
                    _entry("GNU", 1, "LOCAL_NAME"),
                    _entry("GNU", 2, "LOCAL_NAME"),
                ],
            )
        )
        self.assertEqual(list(iter_note_type_conflicts(vocabulary)), [])
        groups = list(iter_shared_note_type_symbols(vocabulary))
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].owners, ("GNU",))

        lookup = resolve_note_type_name("GNU", "LOCAL_NAME", vocabulary=vocabulary)
        self.assertEqual(lookup.values, (1, 2))
        self.assertTrue(lookup.ambiguous)

    def test_same_owner_same_code_conflict_is_reported(self):
        vocabulary = _vocabulary(
            _namespace(
                "GNU",
                [
                    _entry("GNU", 7, "FIRST"),
                    _entry("GNU", 7, "SECOND"),
                ],
            )
        )
        conflicts = list(iter_note_type_conflicts(vocabulary))
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].owner, "GNU")
        self.assertEqual(conflicts[0].value, 7)

        interpretation = resolve_note_type("GNU", 7, vocabulary=vocabulary)
        self.assertTrue(interpretation.disputed)
        self.assertIsNone(interpretation.name)
        self.assertEqual(interpretation.names, ("FIRST", "SECOND"))

    def test_custom_vocabulary_does_not_rewrite_historical_n_type(self):
        vocabulary = _vocabulary(
            _namespace("GNU", [_entry("GNU", 3, "CUSTOM_BUILD_ID")])
        )
        with ELFFile.load_from_path(
            os.path.join("test", "testfiles_for_readelf", "note_owners.o.elf")
        ) as elf:
            notes = []
            for section in elf.iter_sections():
                if isinstance(section, NoteSection):
                    notes.extend(section.iter_notes(vocabulary=vocabulary))

        gnu = next(note for note in notes if note["n_name"] == "GNU")
        self.assertEqual(gnu["n_type"], "NT_GNU_BUILD_ID")
        self.assertEqual(gnu["n_type_name"], "CUSTOM_BUILD_ID")
        self.assertEqual(gnu["n_type_vocabulary_version"], "test-v1")


class TestNoteEvidenceReport(unittest.TestCase):
    def test_pt_note_and_sht_note_are_one_observation_with_two_views(self):
        report = collect_note_evidence(
            os.path.join("test", "testfiles_for_readelf", "aarch64-pac-bti.so.elf")
        )
        self.assertEqual(len(report.observations), 3)
        for observation in report.observations:
            self.assertEqual(len(observation.views), 2)
            self.assertEqual(
                {view.kind for view in observation.views},
                {"section", "segment"},
            )

    def test_core_notes_keep_raw_values_and_core_provenance(self):
        report = collect_note_evidence(
            os.path.join("test", "testfiles_for_unittests", "core_linux64.elf")
        )
        prstatus = next(
            obs
            for obs in report.observations
            if obs.owner == "CORE" and obs.raw_type == 1
        )
        self.assertEqual(prstatus.legacy_type, "NT_PRSTATUS")
        self.assertEqual(prstatus.interpretation.name, "NT_PRSTATUS")
        self.assertIn("Linux", prstatus.interpretation.source)
        self.assertEqual(prstatus.interpretation.vocabulary_version, "linux-uapi")

    def test_report_is_json_serializable(self):
        report = collect_note_evidence(
            os.path.join("test", "testfiles_for_readelf", "note_owners.o.elf")
        )
        encoded = json.dumps(report.as_dict())
        decoded = json.loads(encoded)
        self.assertEqual(decoded["vocabulary_version"], report.vocabulary.version)
        self.assertEqual(len(decoded["observations"]), 6)
        self.assertEqual(decoded["observations"][0]["n_type_raw"], 3)


if __name__ == "__main__":
    unittest.main()
