import json
import os
import tempfile
import unittest
import warnings
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from LnkParse3.lineage import build_lineage
from LnkParse3.lineage import extract_identity
from LnkParse3.lineage import KIND_DUPLICATE
from LnkParse3.lineage import KIND_MIGRATION
from LnkParse3.lineage import KIND_SNAPSHOT
from LnkParse3.lineage import TRACKER_BLOCK_NAME
from LnkParse3.lineage import TrackerIdentity
from tests.lineage.generate_samples import CONTEXT
from tests.lineage.generate_samples import SAMPLE_DIR


def load_local_identities():
    identities = []
    for name, context in sorted(CONTEXT.items(), key=lambda item: item[1]["collection_order"]):
        identity = extract_identity(path=os.path.join(SAMPLE_DIR, name), sample=name, **context)
        identities.append(identity)
    return identities


def make_identity(sample, current, birth, order, generation, created=None, written=None):
    return TrackerIdentity(
        sample=sample,
        machine_id="MACHINE",
        volume_id=current[0],
        file_id=current[1],
        birth_volume_id=birth[0],
        birth_file_id=birth[1],
        collection_order=order,
        hardware_generation=generation,
        creation_time=created,
        write_time=written,
    )


class TestExtractIdentity(unittest.TestCase):
    def test_extracts_current_and_birth_identifiers(self):
        identities = {identity.sample: identity for identity in load_local_identities()}
        self.assertEqual(len(identities), 4)

        backup = identities["backup1_oldpc.lnk"]
        self.assertEqual(backup.machine_id, "PC-OLD")
        self.assertEqual(backup.current_ids, backup.birth_ids)
        self.assertEqual(backup.creation_time, datetime(2023, 6, 15, 12, 0, tzinfo=timezone.utc))

        migrated = identities["migrated_newpc.lnk"]
        self.assertEqual(migrated.machine_id, "PC-NEW")
        self.assertEqual(migrated.birth_ids, backup.current_ids)
        self.assertNotEqual(migrated.current_ids, migrated.birth_ids)

    def test_missing_tracker_block_returns_none(self):
        header = b"\x4c\x00\x00\x00" + bytes(72)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            identity = extract_identity(indata=header, sample="no_tracker")
        self.assertIsNone(identity)
        self.assertTrue(any(TRACKER_BLOCK_NAME in str(warning.message) for warning in caught))


class TestLocalSampleLineage(unittest.TestCase):
    def setUp(self):
        self.lineage = build_lineage(load_local_identities())

    def edges_by_kind(self, kind):
        return {(edge.source, edge.target) for edge in self.lineage.edges if edge.kind == kind}

    def test_duplicate_recollection_edge(self):
        self.assertEqual(
            self.edges_by_kind(KIND_DUPLICATE),
            {("backup1_oldpc.lnk", "backup2_oldpc.lnk")},
        )

    def test_migration_edges(self):
        self.assertEqual(
            self.edges_by_kind(KIND_MIGRATION),
            {
                ("backup1_oldpc.lnk", "migrated_newpc.lnk"),
                ("backup2_oldpc.lnk", "migrated_newpc.lnk"),
                ("migrated_newpc.lnk", "copied_newpc.lnk"),
            },
        )

    def test_parallel_predecessors_are_kept(self):
        parallel = self.lineage.parallel_predecessors()
        self.assertEqual(
            parallel,
            {"migrated_newpc.lnk": ["backup1_oldpc.lnk", "backup2_oldpc.lnk"]},
        )

    def test_export_contains_provenance(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "lineage.json")
            self.lineage.export(path)
            with open(path) as fp:
                exported = json.load(fp)

        self.assertEqual(exported["format"], "LnkParse3-lineage/1.0")
        self.assertEqual(len(exported["nodes"]), 4)
        for node in exported["nodes"]:
            self.assertTrue(node["source"].endswith(".lnk"))

        edge = next(
            edge
            for edge in exported["edges"]
            if edge["target"] == "migrated_newpc.lnk" and edge["source"] == "backup1_oldpc.lnk"
        )
        self.assertEqual(edge["kind"], KIND_MIGRATION)
        evidence = edge["evidence"][0]
        self.assertEqual(evidence["source_block"], TRACKER_BLOCK_NAME)
        self.assertEqual(evidence["rule"], "birth_matches_predecessor_current")
        self.assertIn("volume_id", evidence["matched_fields"])
        self.assertTrue(edge["constraints"]["collection_order"]["satisfied"])
        self.assertTrue(edge["constraints"]["hardware_generation"]["satisfied"])
        self.assertTrue(edge["constraints"]["header_timestamps"]["satisfied"])

        self.assertEqual(
            exported["parallel_predecessors"],
            {"migrated_newpc.lnk": ["backup1_oldpc.lnk", "backup2_oldpc.lnk"]},
        )
        self.assertTrue(exported["rejected_candidates"])


class TestConstraints(unittest.TestCase):
    def test_collection_order_prunes(self):
        pred = make_identity("newer", ("V", "F"), ("V", "F"), order=2, generation=1)
        succ = make_identity("older", ("V2", "F2"), ("V", "F"), order=1, generation=1)
        lineage = build_lineage([pred, succ])
        self.assertFalse(
            any(edge.source == "newer" and edge.target == "older" for edge in lineage.edges)
        )
        rejected = {
            (candidate.source, candidate.target): candidate.reason for candidate in lineage.rejected
        }
        self.assertEqual(
            rejected[("newer", "older")], "predecessor was not collected before successor"
        )

    def test_hardware_generation_prunes(self):
        pred = make_identity("gen2", ("V", "F"), ("V", "F"), order=1, generation=2)
        succ = make_identity("gen1", ("V2", "F2"), ("V", "F"), order=2, generation=1)
        lineage = build_lineage([pred, succ])
        self.assertFalse(
            any(edge.source == "gen2" and edge.target == "gen1" for edge in lineage.edges)
        )
        rejected = {
            (candidate.source, candidate.target): candidate.reason for candidate in lineage.rejected
        }
        self.assertEqual(rejected[("gen2", "gen1")], "successor is on an older hardware generation")

    def test_header_timestamps_only_constrain(self):
        moment = datetime(2024, 1, 1, tzinfo=timezone.utc)
        # Timestamps contradict the identifier evidence -> edge pruned.
        pred = make_identity("pred", ("V", "F"), ("V", "F"), order=1, generation=1, written=moment)
        succ = make_identity(
            "succ",
            ("V2", "F2"),
            ("V", "F"),
            order=2,
            generation=1,
            created=moment - timedelta(days=1),
        )
        lineage = build_lineage([pred, succ])
        self.assertFalse(
            any(edge.source == "pred" and edge.target == "succ" for edge in lineage.edges)
        )
        rejected = {
            (candidate.source, candidate.target): candidate.reason for candidate in lineage.rejected
        }
        self.assertEqual(
            rejected[("pred", "succ")],
            "successor header creation time predates predecessor write time",
        )

        # Consistent timestamps alone never create an edge.
        unrelated = make_identity(
            "unrelated",
            ("VX", "FX"),
            ("VX", "FX"),
            order=2,
            generation=1,
            created=moment + timedelta(days=1),
        )
        lineage = build_lineage([pred, unrelated])
        self.assertEqual(lineage.edges, [])
        self.assertEqual(lineage.rejected, [])

    def test_shared_birth_kept_as_snapshot_branch(self):
        pred = make_identity("base", ("V", "F"), ("V", "F"), order=1, generation=1)
        succ = make_identity("clone", ("V2", "F2"), ("V", "F"), order=2, generation=1)
        other = make_identity("other", ("V3", "F3"), ("V", "F"), order=3, generation=1)
        lineage = build_lineage([pred, succ, other])

        snapshot_edges = {
            (edge.source, edge.target) for edge in lineage.edges if edge.kind == KIND_SNAPSHOT
        }
        # "succ" and "other" share their birth identity with each other and
        # descend from "base"; the shared-birth branches are kept alongside
        # the stronger continuation edges.
        self.assertIn(("clone", "other"), snapshot_edges)
        kinds = {edge.kind for edge in lineage.edges if edge.target == "other"}
        self.assertEqual(kinds, {KIND_MIGRATION, KIND_SNAPSHOT})


if __name__ == "__main__":
    unittest.main()
