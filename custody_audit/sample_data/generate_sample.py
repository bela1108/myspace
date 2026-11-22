"""
Regenerate the offline custody-audit sample materials.

The EVTX files are checked in alongside this script; this helper only writes
the four JSON inputs (scope config, internal roster, external manifest,
receipts) and derives record hashes directly from the source evidence, so
the manifest never contains raw event XML or sensitive fields.
"""
from __future__ import annotations

import json
import os

from custody_audit.evtx_records import RecordRange, file_sha256, summarize_evtx

HERE = os.path.dirname(os.path.abspath(__file__))
EVTX_DIR = os.path.join(HERE, "evtx")
ARCHIVE_CUTOFF = "2017-12-31T23:59:59+08:00"

SECURITY_FILE = "security_short.evtx"
DNS_FILE = "dns_short.evtx"


def _write(name: str, payload: dict) -> None:
    with open(os.path.join(HERE, name), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def _record_hashes(evtx_file: str, first: int, last):
    path = os.path.join(EVTX_DIR, evtx_file)
    summaries = summarize_evtx(path, RecordRange(first, last))
    return [summary.sha256 for summary in summaries], len(summaries)


def main() -> None:
    config = {
        "archive_cutoff": ARCHIVE_CUTOFF,
        "scope": {
            SECURITY_FILE: [{"first_record": 1, "last_record": 1}],
            DNS_FILE: [
                {"first_record": 1, "last_record": 1},
                {"first_record": 2, "last_record": 3},
                {"first_record": 4, "last_record": 5},
            ],
        },
    }
    _write("audit_config.json", config)

    roster = {
        "custodians": [
            {
                "custodian_id": "C001",
                "display_name": "张调查（前任保管人）",
                "permissions": ["evtx.full_review"],
                "responsibility_start": "2017-01-01T00:00:00+08:00",
                "responsibility_end": "2017-06-30T23:59:59+08:00",
            },
            {
                "custodian_id": "C002",
                "display_name": "李长期（长期保管人）",
                "permissions": ["evtx.full_review", "evtx.summary"],
                "responsibility_start": "2017-07-01T00:00:00+08:00",
                "responsibility_end": None,
            },
            {
                "custodian_id": "C003",
                "display_name": "王归档（摘要保管人）",
                "permissions": ["evtx.summary"],
                "responsibility_start": "2017-07-01T00:00:00+08:00",
                "responsibility_end": None,
            },
        ]
    }
    _write("custodian_roster.json", roster)

    sec_hashes, sec_count = _record_hashes(SECURITY_FILE, 1, 1)
    dns_head_hashes, dns_head_count = _record_hashes(DNS_FILE, 1, 1)
    dns_mid_hashes, dns_mid_count = _record_hashes(DNS_FILE, 2, 3)
    dns_tail_hashes, dns_tail_count = _record_hashes(DNS_FILE, 4, 5)

    manifest = {
        "manifest_id": "EXT-MANIFEST-2017-009",
        "evtx_files": [SECURITY_FILE, DNS_FILE],
        "entries": [
            {
                "evtx_file": SECURITY_FILE,
                "first_record": 1,
                "last_record": 1,
                "mode": "full",
                "record_count": sec_count,
                "record_sha256": sec_hashes,
                "file_sha256": file_sha256(os.path.join(EVTX_DIR, SECURITY_FILE)),
                "handover_due": ARCHIVE_CUTOFF,
            },
            {
                "evtx_file": DNS_FILE,
                "first_record": 1,
                "last_record": 1,
                "mode": "summary",
                "record_count": dns_head_count,
                "record_sha256": dns_head_hashes,
                "file_sha256": file_sha256(os.path.join(EVTX_DIR, DNS_FILE)),
                "handover_due": ARCHIVE_CUTOFF,
            },
            {
                "evtx_file": DNS_FILE,
                "first_record": 2,
                "last_record": 3,
                "mode": "full",
                "record_count": dns_mid_count,
                "record_sha256": dns_mid_hashes,
                "file_sha256": file_sha256(os.path.join(EVTX_DIR, DNS_FILE)),
                "handover_due": ARCHIVE_CUTOFF,
            },
            {
                "evtx_file": DNS_FILE,
                "first_record": 4,
                "last_record": 5,
                "mode": "full",
                "record_count": dns_tail_count,
                "record_sha256": dns_tail_hashes,
                "file_sha256": file_sha256(os.path.join(EVTX_DIR, DNS_FILE)),
                "handover_due": ARCHIVE_CUTOFF,
            },
        ],
    }
    _write("external_manifest.json", manifest)

    receipts = {
        "receipts": [
            {
                "receipt_id": "R-01",
                "receipt_type": "shift_change",
                "evtx_file": SECURITY_FILE,
                "first_record": 1,
                "last_record": 1,
                "mode": "full",
                "signer_id": "C002",
                "signed_at": "2017-07-03T09:30:00+08:00",
                "predecessor_id": "C001",
            },
            {
                "receipt_id": "R-02",
                "receipt_type": "shift_change",
                "evtx_file": DNS_FILE,
                "first_record": 1,
                "last_record": 1,
                "mode": "summary",
                "signer_id": "C003",
                "signed_at": "2017-07-03T10:00:00+08:00",
                "predecessor_id": "C001",
            },
            {
                "receipt_id": "R-03",
                "receipt_type": "retroactive",
                "evtx_file": DNS_FILE,
                "first_record": 2,
                "last_record": 3,
                "mode": "full",
                "signer_id": "C001",
                "signed_at": "2017-08-15T14:00:00+08:00",
                "predecessor_id": "C001",
            },
            {
                "receipt_id": "R-04",
                "receipt_type": "retroactive",
                "evtx_file": DNS_FILE,
                "first_record": 4,
                "last_record": 5,
                "mode": "full",
                "signer_id": "C002",
                "signed_at": "2017-08-16T09:00:00+08:00",
                "predecessor_id": "C001",
            },
        ]
    }
    _write("handover_receipts.json", receipts)


if __name__ == "__main__":
    main()
