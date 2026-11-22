import json
import os

import pytest

from custody_audit.audit import AuditConfig, ExternalManifest, reconcile
from custody_audit.evtx_records import RecordRange, summarize_evtx

SAMPLE_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "custody_audit", "sample_data"))
EVTX_DIR = os.path.join(SAMPLE_DIR, "evtx")


def _load(name):
    with open(os.path.join(SAMPLE_DIR, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def sample_paths():
    return {
        "evtx_dir": EVTX_DIR,
        "config": os.path.join(SAMPLE_DIR, "audit_config.json"),
        "roster": os.path.join(SAMPLE_DIR, "custodian_roster.json"),
        "manifest": os.path.join(SAMPLE_DIR, "external_manifest.json"),
        "receipts": os.path.join(SAMPLE_DIR, "handover_receipts.json"),
    }


@pytest.fixture
def loaded():
    return {
        "config": _load("audit_config.json"),
        "roster": _load("custodian_roster.json"),
        "manifest": _load("external_manifest.json"),
        "receipts": _load("handover_receipts.json"),
    }


def build_record_index(config):
    index = {}
    for evtx_file, ranges in config["scope"].items():
        merged = []
        seen = set()
        for raw in ranges:
            rng = RecordRange.from_dict(raw)
            for summary in summarize_evtx(os.path.join(EVTX_DIR, evtx_file), rng):
                if summary.record_num not in seen:
                    seen.add(summary.record_num)
                    merged.append(summary)
        index[evtx_file] = merged
    return index


def run_reconcile(loaded, manifest_override=None, receipts_override=None, config_override=None):
    config_data = config_override or loaded["config"]
    manifest_data = manifest_override or loaded["manifest"]
    receipts_data = receipts_override or loaded["receipts"]
    config = AuditConfig(str(config_data["archive_cutoff"]), dict(config_data["scope"]))
    manifest = ExternalManifest.from_dict(manifest_data)
    index = build_record_index(config_data)
    return reconcile(config, loaded["roster"], manifest, receipts_data["receipts"], index)


@pytest.fixture
def sample_result(loaded):
    return run_reconcile(loaded)
