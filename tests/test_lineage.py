import base64
import json
import struct
import tempfile
import unittest
from datetime import datetime
from datetime import timezone
from pathlib import Path

from LnkParse3.lineage import build_lineage
from LnkParse3.lineage import export_lineage
from LnkParse3.lineage import export_lineage_edges
from LnkParse3.lineage import parse_tracker_identity


HERE = Path(__file__).resolve().parent
FOUR_SAMPLES = HERE / "lineage" / "four_samples.json"
FOUR_SAMPLES_LNK = HERE / "lineage" / "four_samples_lnk.json"
SAMPLE9 = HERE / "samples" / "sample9"


def sample_bytes(name="sample9"):
    return base64.b64decode((HERE / "samples" / name).read_bytes())


def pack_guid(value):
    first, second, third, fourth, tail = value.split("-")
    return struct.pack("<LHH", int(first, 16), int(second, 16), int(third, 16)) + struct.pack(
        ">HHI", int(fourth, 16), int(tail[:4], 16), int(tail[4:], 16)
    )


def filetime(value):
    return int(value.timestamp() * 10_000_000) + 116444736000000000


def patch_lnk(original, current, birth, timestamp):
    data = bytearray(original)
    signature = data.find(struct.pack("<I", 0xA0000003))
    block = signature - 4
    data[block + 32 : block + 48] = pack_guid(current[0])
    data[block + 48 : block + 64] = pack_guid(current[1])
    data[block + 64 : block + 80] = pack_guid(birth[0])
    data[block + 80 : block + 96] = pack_guid(birth[1])
    value = filetime(timestamp)
    for offset in (28, 36, 44):
        data[offset : offset + 8] = struct.pack("<q", value)
    return bytes(data)


IDENTITY_A = (
    "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
    "11111111-1111-1111-1111-111111111111",
)
IDENTITY_B = (
    "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
    "22222222-2222-2222-2222-222222222222",
)
IDENTITY_C = (
    "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC",
    "33333333-3333-3333-3333-333333333333",
)


def local_lnk_samples():
    original = sample_bytes()
    first = datetime(2020, 1, 1, tzinfo=timezone.utc)
    second = datetime(2021, 1, 1, tzinfo=timezone.utc)
    third = datetime(2022, 1, 1, tzinfo=timezone.utc)
    return [
        {
            "sample_id": "backup-a",
            "data": patch_lnk(original, IDENTITY_A, IDENTITY_A, first),
            "machine_identifier": "desk-old",
        },
        {
            "sample_id": "backup-b",
            "data": patch_lnk(original, IDENTITY_A, IDENTITY_A, first),
            "machine_identifier": "desk-old",
        },
        {
            "sample_id": "backup-c",
            "data": patch_lnk(original, IDENTITY_B, IDENTITY_A, second),
            "machine_identifier": "desk-new",
        },
        {
            "sample_id": "backup-d",
            "data": patch_lnk(original, IDENTITY_C, IDENTITY_B, third),
            "machine_identifier": "desk-new",
        },
    ]


class TestDistributedTrackerLineage(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(FOUR_SAMPLES.read_text(encoding="utf-8"))

    def test_manifest_has_four_samples_and_a_tied_predecessor(self):
        result = build_lineage(self.manifest)

        self.assertEqual(len(result.nodes), 4)
        self.assertEqual(
            [node.sample_id for node in result.nodes],
            ["backup-a", "backup-b", "backup-c", "backup-d"],
        )

        tied = [tie for tie in result.ties if tie["target"] == "backup-c"]
        self.assertEqual(len(tied), 1)
        self.assertEqual(set(tied[0]["predecessors"]), {"backup-a", "backup-b"})

        incoming = {
            (edge.source, edge.target): edge for edge in result.edges if edge.target == "backup-c"
        }
        self.assertEqual(set(incoming), {("backup-a", "backup-c"), ("backup-b", "backup-c")})
        for edge in incoming.values():
            self.assertEqual(edge.relation, "migration")
            self.assertTrue(edge.tied)
            self.assertEqual(edge.support, 1.0)
            self.assertTrue(edge.provenance["evidence"])

    def test_identifier_sharing_is_retained_as_snapshot_reuse(self):
        result = build_lineage(self.manifest)
        edge = next(
            edge for edge in result.edges if edge.source == "backup-a" and edge.target == "backup-b"
        )
        self.assertEqual(edge.relation, "snapshot_reuse")
        self.assertFalse(edge.lineage)
        self.assertIn("continuation", edge.possible_relations)
        self.assertTrue(edge.provenance["identifiers"]["source_current"])

    def test_header_time_can_only_remove_edges(self):
        samples = json.loads(json.dumps(self.manifest))
        samples["samples"][2]["header"]["modified_time"] = "2019-01-01T00:00:00+00:00"
        result = build_lineage(samples)

        self.assertFalse(
            [
                edge
                for edge in result.edges
                if edge.target == "backup-c" and edge.evidence_kind == "birth_identifier"
            ]
        )
        self.assertFalse(
            [
                edge
                for edge in result.edges
                if edge.source == "backup-a" and edge.target == "backup-d"
            ]
        )

    def test_collection_order_and_generation_are_constraints(self):
        reversed_order = {
            "backup-a": 3,
            "backup-b": 4,
            "backup-c": 1,
            "backup-d": 2,
        }
        result = build_lineage(self.manifest, collection_order=reversed_order)
        self.assertFalse(
            [
                edge
                for edge in result.edges
                if edge.target == "backup-c" and edge.evidence_kind == "birth_identifier"
            ]
        )

        reversed_generation = {
            "backup-a": 2,
            "backup-b": 2,
            "backup-c": 1,
            "backup-d": 1,
        }
        result = build_lineage(
            self.manifest,
            hardware_generations=reversed_generation,
        )
        self.assertFalse(
            [
                edge
                for edge in result.edges
                if edge.target == "backup-c" and edge.evidence_kind == "birth_identifier"
            ]
        )

    def test_export_keeps_provenance(self):
        result = build_lineage(self.manifest)
        serialized = export_lineage(result)
        self.assertEqual(len(serialized["edges"]), len(result.edges))
        self.assertTrue(all(edge["provenance"] for edge in serialized["edges"]))

        with tempfile.TemporaryDirectory(dir=str(HERE)) as directory:
            json_path = Path(directory) / "lineage.json"
            jsonl_path = Path(directory) / "edges.jsonl"
            export_lineage(result, json_path)
            export_lineage_edges(result, jsonl_path, format="jsonl")

            exported = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertTrue(exported["edges"][0]["provenance"])
            self.assertTrue(exported["ties"])

            lines = jsonl_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), len(result["lineage_edges"]))
            self.assertTrue(all(json.loads(line)["provenance"] for line in lines))

    def test_binary_local_samples_manifest_keeps_tie(self):
        result = build_lineage(FOUR_SAMPLES_LNK)
        self.assertEqual(len(result.nodes), 4)
        self.assertEqual(len(result.ties), 1)
        self.assertEqual(set(result.ties[0]["predecessors"]), {"backup-a", "backup-b"})
        self.assertEqual(result.nodes[0].identity_status, "original")
        self.assertEqual(result.nodes[2].identity_status, "derived")

    def test_manifest_path_and_package_exports(self):
        import LnkParse3

        result = LnkParse3.build_lineage(FOUR_SAMPLES)
        self.assertIn("edges", result)
        self.assertEqual(result["tie_count"], 1)
        self.assertEqual(len(result["lineage_edges"]), 3)
        self.assertEqual(len(result["snapshot_reuse_edges"]), 1)

        parsed = LnkParse3.parse_tracker_identity(str(SAMPLE9))
        self.assertEqual(parsed["status"], "original")

    def test_raw_lnk_tracker_identity_and_tie(self):
        parsed = parse_tracker_identity(sample_bytes())
        self.assertEqual(parsed.status, "original")
        self.assertEqual(parsed.current.key, parsed.birth.key)
        self.assertEqual(parsed.machine_identifier, "desktop-73cl5qt")

        result = build_lineage(
            local_lnk_samples(),
            hardware_generations={"desk-old": 1, "desk-new": 2},
            collection_order=["backup-a", "backup-b", "backup-c", "backup-d"],
        )
        tied = [tie for tie in result.ties if tie["target"] == "backup-c"]
        self.assertEqual(len(tied), 1)
        self.assertEqual(set(tied[0]["predecessors"]), {"backup-a", "backup-b"})
        self.assertEqual(result.nodes[0].identity_status, "original")
        self.assertEqual(result.nodes[2].identity_status, "derived")

    def test_raw_lnk_header_time_rejects_contradictory_edge(self):
        samples = local_lnk_samples()
        samples[2]["data"] = patch_lnk(
            sample_bytes(),
            IDENTITY_B,
            IDENTITY_A,
            datetime(2019, 1, 1, tzinfo=timezone.utc),
        )
        result = build_lineage(
            samples,
            hardware_generations={"desk-old": 1, "desk-new": 2},
            collection_order=["backup-a", "backup-b", "backup-c", "backup-d"],
        )
        self.assertFalse([edge for edge in result.edges if edge.target == "backup-c"])


if __name__ == "__main__":
    unittest.main()
