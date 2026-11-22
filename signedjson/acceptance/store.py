"""Persistent, offline state for repeated acceptance runs.

The store keeps the admitted events, the material registry, the verify keys
and the node summaries of the most recent three acceptance runs.  Everything
is plain JSON, so a run can be restarted on an air-gapped machine and late
predecessors can be reconciled against earlier summaries.
"""

import json
from typing import Any, Dict, List, Optional

from signedjson.acceptance.verifier import AcceptanceVerifier

SNAPSHOT_LIMIT = 3


class AcceptanceStore:
    """JSON-file backed wrapper around :class:`AcceptanceVerifier`."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.data: Dict[str, Any] = {
            "materials": {},
            "keys": {},
            "events": {},
            "fingerprints": {},
            "run_counter": 0,
            "snapshots": [],
        }

    @classmethod
    def open(cls, path: str) -> "AcceptanceStore":
        store = cls(path)
        try:
            with open(path, encoding="utf-8") as stream:
                store.data = json.load(stream)
        except FileNotFoundError:
            pass
        return store

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as stream:
            json.dump(self.data, stream, ensure_ascii=False, indent=2, sort_keys=True)

    def load_verifier(self) -> AcceptanceVerifier:
        return AcceptanceVerifier.from_key_config(
            materials=self.data["materials"], key_config=self.data["keys"]
        )

    def register_materials(
        self, materials: Dict[str, Dict[str, Any]]
    ) -> None:
        self.data["materials"].update(materials)

    def register_keys(self, keys: Dict[str, Dict[str, str]]) -> None:
        self.data["keys"].update(keys)

    def run(self, batch: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ingest one batch, persist state and append a node summary."""

        verifier = self.load_verifier()
        verifier.events = dict(self.data["events"])
        verifier._fingerprints = dict(self.data["fingerprints"])
        verifier._seen_fingerprints = set(self.data["fingerprints"].values())

        report = verifier.ingest(batch)
        self.data["events"] = verifier.events
        self.data["fingerprints"] = verifier._fingerprints

        self.data["run_counter"] += 1
        run = self.data["run_counter"]
        snapshot = verifier.snapshot(run)
        snapshot["ingest_report"] = report.as_dict()
        self.data["snapshots"].append(snapshot)
        del self.data["snapshots"][:-SNAPSHOT_LIMIT]
        self.save()
        return snapshot

    @property
    def snapshots(self) -> List[Dict[str, Any]]:
        return list(self.data["snapshots"])

    def latest_snapshot(self) -> Optional[Dict[str, Any]]:
        return self.data["snapshots"][-1] if self.data["snapshots"] else None
