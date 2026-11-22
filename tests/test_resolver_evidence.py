"""Regression tests for material resolution evidence."""

import hashlib
import json
import os
import sys
import tempfile
import unittest

from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from in_toto.resolver import (
    RESOLVER_FOR_URI_SCHEME,
    FileResolver,
    Resolver,
)
from in_toto.resolver.evidence import (
    CHANGED,
    CONSISTENT,
    UNVERIFIED,
    EvidenceReport,
)
from in_toto.runlib import (
    in_toto_run,
    record_artifacts_as_dict,
    record_artifacts_with_evidence,
)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


class _ScriptedResolver(Resolver):
    """A controllable local resolver with scripted source identities."""

    SCHEME = "scripted"

    def __init__(self, generations=None, contents=None):
        self._generations = list(generations or [0, 0])
        self._contents = contents or {"resource": b"same"}
        self._hash_calls = 0

    def artifact_identity(self, uri):
        index = min(self._hash_calls, len(self._generations) - 1)
        return {
            "source": uri,
            "generation": self._generations[index],
        }

    def artifact_source(self, uri):
        return uri

    def hash_artifacts(self, uris):
        self._hash_calls += 1
        return {
            uri: {"sha256": _sha256(self._contents.get(uri, b"same"))}
            for uri in uris
        }


class TestResolverEvidence(unittest.TestCase):
    def tearDown(self):
        RESOLVER_FOR_URI_SCHEME.clear()

    def test_same_content_at_multiple_paths_is_not_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = os.path.join(tmp, "first")
            second = os.path.join(tmp, "second")
            with open(first, "wb") as handle:
                handle.write(b"identical")
            with open(second, "wb") as handle:
                handle.write(b"identical")

            report = FileResolver().hash_artifacts_with_evidence(
                [first, second]
            )

        self.assertEqual(len(report.entries), 2)
        self.assertEqual(
            report.entries[0].hashes, report.entries[1].hashes
        )
        self.assertNotEqual(
            report.entries[0].source, report.entries[1].source
        )
        self.assertNotEqual(
            report.entries[0].before["stat"]["inode"],
            report.entries[1].before["stat"]["inode"],
        )
        self.assertTrue(all(entry.status == CONSISTENT for entry in report.entries))
        self.assertFalse(report.mixed_snapshot)

    def test_replacement_during_read_is_affected_and_names_resolver(self):
        resolver = _ScriptedResolver(generations=[1, 2])
        report = resolver.resolve(["scripted:resource"])

        self.assertEqual(len(report.entries), 1)
        entry = report.entries[0]
        self.assertEqual(entry.status, CHANGED)
        self.assertTrue(entry.affected)
        self.assertEqual(entry.resolver, "scripted")
        self.assertEqual(report.affected_names, ["scripted:resource"])
        self.assertEqual(report.affected_resolvers, ["scripted"])
        self.assertTrue(report.mixed_snapshot)
        self.assertFalse(report.consistent)

    def test_stable_read_is_proven_consistent(self):
        resolver = _ScriptedResolver(generations=[7, 7])
        report = resolver.resolve(["scripted:resource"])

        entry = report.entries[0]
        self.assertEqual(entry.status, CONSISTENT)
        self.assertTrue(entry.is_consistent)
        self.assertEqual(entry.before, entry.after)
        self.assertTrue(report.consistent)
        self.assertFalse(report.mixed_snapshot)

    def test_legacy_resolver_entries_are_unverified(self):
        class Legacy(Resolver):
            SCHEME = "legacy"

            def hash_artifacts(self, uris):
                return {uri: {"sha256": _sha256(b"x")} for uri in uris}

        report = Legacy().resolve(["legacy:resource"])
        self.assertEqual(report.entries[0].status, UNVERIFIED)
        self.assertFalse(report.consistent)
        self.assertFalse(report.mixed_snapshot)

    def test_record_artifacts_merges_resolvers_and_reports_affected(self):
        RESOLVER_FOR_URI_SCHEME["scripted"] = _ScriptedResolver(
            generations=[1, 2]
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "material")
            with open(path, "wb") as handle:
                handle.write(b"material")

            report = record_artifacts_with_evidence(
                [path, "scripted:resource"]
            )

        self.assertEqual(set(report.hashes), {path, "scripted:resource"})
        self.assertEqual(report.resolver_for(path), "file")
        self.assertEqual(report.resolver_for("scripted:resource"), "scripted")
        self.assertEqual(report.affected_resolvers, ["scripted"])
        affected = report.affected_with_resolvers
        self.assertEqual(len(affected), 1)
        self.assertEqual(affected[0][0].name, "scripted:resource")
        self.assertEqual(affected[0][1], "scripted")

    def test_record_artifacts_as_dict_can_return_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "material")
            with open(path, "wb") as handle:
                handle.write(b"material")

            hashes, report = record_artifacts_as_dict(
                [path], return_evidence=True
            )

        self.assertEqual(hashes, report.hashes)
        self.assertTrue(report.consistent)

    def test_record_with_explicit_local_resolver(self):
        resolver = _ScriptedResolver(generations=[1, 2])
        report = record_artifacts_with_evidence(
            ["scripted:resource"], resolver=resolver
        )

        self.assertEqual(report.affected_names, ["scripted:resource"])
        self.assertEqual(report.affected_resolvers, ["scripted"])


class TestLinkEvidence(unittest.TestCase):
    def test_run_attaches_material_report_to_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "material")
            with open(path, "wb") as handle:
                handle.write(b"x")

            metadata = in_toto_run(
                "step",
                [path],
                [],
                [sys.executable, "-c", "pass"],
            )

        report = metadata.get_materials_report()
        self.assertEqual(report.hashes, metadata.get_payload().materials)
        self.assertTrue(report.consistent)
        self.assertEqual(report.entries[0].resolver, "file")

    def test_link_roundtrip_preserves_report(self):
        entry_report = EvidenceReport.from_dict(
            {
                "entries": [
                    {
                        "name": "material",
                        "resolver": "file",
                        "hashes": {"sha256": _sha256(b"x")},
                        "source": "material",
                        "before": {"generation": 1},
                        "after": {"generation": 2},
                        "status": CHANGED,
                    }
                ]
            }
        )

        link = Link(
            materials={"material": {"sha256": _sha256(b"x")}},
            materials_evidence=entry_report.to_dict(),
        )
        dumped = json.loads(json.dumps(Metablock(signed=link).to_dict()))
        loaded = Metablock.from_dict(dumped).signed
        report = loaded.get_materials_report()

        self.assertEqual(report.affected_names, ["material"])
        self.assertEqual(report.affected_resolvers, ["file"])
        self.assertEqual(report.hashes, link.materials)

    def test_old_link_without_evidence_still_reads(self):
        data = {
            "_type": "link",
            "name": "old",
            "materials": {"material": {"sha256": _sha256(b"x")}},
            "products": {},
            "byproducts": {},
            "command": [],
            "environment": {},
        }
        link = Link.read(data)

        self.assertIsNone(link.materials_evidence)
        self.assertNotIn("materials_evidence", link.to_dict())
        report = link.get_materials_report()
        self.assertEqual(report.hashes, link.materials)
        self.assertEqual(report.entries[0].status, UNVERIFIED)
        self.assertEqual(report.entries[0].resolver, "file")


if __name__ == "__main__":
    unittest.main()
