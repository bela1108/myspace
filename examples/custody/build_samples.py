#!/usr/bin/env python3
"""Build the small offline custody sample used by the reconciliation example.

The sample logs are one-chunk EVTX files trimmed to three records.  The chunk
and file checksums are recalculated so that python-evtx can read them exactly
like ordinary EVTX files.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from Evtx.Evtx import Evtx

HEADER_SIZE = 0x1000
CHUNK_SIZE = 0x10000


def _records(path, count):
    with Evtx(path) as log:
        records = []
        for record in log.records():
            records.append(record)
            if len(records) == count:
                break
        return [(int(record.record_num()), int(record.offset()), bytes(record.data())) for record in records]


def _put(buf, offset, data):
    buf[offset : offset + len(data)] = data


def _trim(source, output, count):
    with open(source, "rb") as handle:
        source_bytes = handle.read()
    records = _records(source, count)
    chunk_offset = HEADER_SIZE
    first_num = records[0][0]
    last_num = records[-1][0]
    last_offset = records[-1][1] - chunk_offset
    next_offset = last_offset + len(records[-1][2])

    buf = bytearray(source_bytes[: HEADER_SIZE + CHUNK_SIZE])
    if len(buf) < HEADER_SIZE + CHUNK_SIZE:
        raise RuntimeError("source file is too short")
    _put(buf, chunk_offset + 0x08, first_num.to_bytes(8, "little"))
    _put(buf, chunk_offset + 0x10, last_num.to_bytes(8, "little"))
    _put(buf, chunk_offset + 0x18, first_num.to_bytes(8, "little"))
    _put(buf, chunk_offset + 0x20, last_num.to_bytes(8, "little"))
    _put(buf, chunk_offset + 0x2C, last_offset.to_bytes(4, "little"))
    _put(buf, chunk_offset + 0x30, next_offset.to_bytes(4, "little"))
    data_checksum = binascii.crc32(bytes(buf[chunk_offset + 0x200 : chunk_offset + next_offset])) & 0xFFFFFFFF
    _put(buf, chunk_offset + 0x34, data_checksum.to_bytes(4, "little"))
    header_checksum = binascii.crc32(
        bytes(buf[chunk_offset : chunk_offset + 0x78]) + bytes(buf[chunk_offset + 0x80 : chunk_offset + 0x200])
    ) & 0xFFFFFFFF
    _put(buf, chunk_offset + 0x7C, header_checksum.to_bytes(4, "little"))

    _put(buf, 0x08, (0).to_bytes(8, "little"))
    _put(buf, 0x10, (0).to_bytes(8, "little"))
    _put(buf, 0x18, (last_num + 1).to_bytes(8, "little"))
    _put(buf, 0x2A, (1).to_bytes(2, "little"))
    file_checksum = binascii.crc32(bytes(buf[0:0x78])) & 0xFFFFFFFF
    _put(buf, 0x7C, file_checksum.to_bytes(4, "little"))
    with open(output, "wb") as handle:
        handle.write(buf)


def _range_digest(path, start, end):
    digest = hashlib.sha256()
    with Evtx(path) as log:
        for record in log.records():
            if start <= int(record.record_num()) <= end:
                digest.update(bytes(record.data()))
    return digest.hexdigest()


def main():
    system_out = os.path.join(HERE, "system-short.evtx")
    security_out = os.path.join(HERE, "security-short.evtx")
    _trim(os.path.join(REPO, "tests", "data", "system.evtx"), system_out, 3)
    _trim(os.path.join(REPO, "tests", "data", "security.evtx"), security_out, 3)

    system_digest_1 = _range_digest(system_out, 12049, 12050)
    system_digest_2 = _range_digest(system_out, 12051, 12051)
    security_digest_1 = _range_digest(security_out, 1, 2)
    security_digest_2 = _range_digest(security_out, 3, 3)

    case = {
        "case_id": "CASE-2026-11-EVTX-001",
        "archive_deadline": "2026-11-30T23:59:59Z",
        "as_of": "2026-11-30T23:59:59Z",
        "generated_at": "2026-11-30T23:59:59Z",
        "custodian": {
            "id": "archive-team",
            "role": "long-term custodian",
            "permissions": [
                {"evidence_id": "system-short.evtx", "start": 12049, "end": 12050, "access": "full"},
                {"evidence_id": "system-short.evtx", "start": 12051, "end": 12051, "access": "summary"},
                {"evidence_id": "security-short.evtx", "start": 1, "end": 2, "access": "full"},
                {"evidence_id": "security-short.evtx", "start": 3, "end": 3, "access": "full"},
            ],
        },
        "evidence": [
            {
                "evidence_id": "system-short.evtx",
                "path": "system-short.evtx",
                "ranges": [
                    {"start": 12049, "end": 12050, "sensitivity": "internal"},
                    {"start": 12051, "end": 12051, "sensitivity": "restricted"},
                ],
            },
            {
                "evidence_id": "security-short.evtx",
                "path": "security-short.evtx",
                "ranges": [
                    {"start": 1, "end": 2, "sensitivity": "internal"},
                    {"start": 3, "end": 3, "sensitivity": "restricted"},
                ],
            },
        ],
        "previous_holder": {"id": "u-a", "still_holds_copy": True},
        "external_manifest": "external_manifest.json",
        "responsibility": "responsibility.json",
        "receipts": "receipts.json",
    }
    external = {
        "case_id": case["case_id"],
        "entries": [
            {
                "evidence_id": "system-short.evtx",
                "record_start": 12049,
                "record_end": 12050,
                "receipt_id": "R2",
                "sha256": system_digest_1,
            },
            {
                "evidence_id": "system-short.evtx",
                "record_start": 12051,
                "record_end": 12051,
                "receipt_id": "R2",
                "digest": "sha256:" + system_digest_2,
            },
            {
                "evidence_id": "security-short.evtx",
                "record_start": 1,
                "record_end": 2,
                "receipt_id": "R1",
                "sha256": security_digest_1,
            },
            {
                "evidence_id": "security-short.evtx",
                "record_start": 3,
                "record_end": 3,
                "receipt_id": "R4",
                "sha256": security_digest_2,
            },
        ],
    }
    receipts = {
        "receipts": [
            {
                "receipt_id": "R1",
                "kind": "handover",
                "from_principal": "u-a",
                "to_principal": "u-b",
                "signer_id": "u-a",
                "status": "unsigned",
                "event_at": "2026-10-20T09:00:00Z",
                "scope": [{"evidence_id": "security-short.evtx", "start": 1, "end": 2}],
            },
            {
                "receipt_id": "R2",
                "kind": "shift_change",
                "from_principal": "u-a",
                "to_principal": "u-b",
                "signer_id": "u-b",
                "signed_at": "2026-10-25T09:00:00Z",
                "status": "signed",
                "scope": [{"evidence_id": "system-short.evtx", "start": 12049, "end": 12051}],
            },
            {
                "receipt_id": "R3",
                "kind": "supplemental",
                "amends": "R1",
                "signer_id": "u-b",
                "signed_at": "2026-11-05T10:00:00Z",
                "status": "signed",
                "scope": [{"evidence_id": "security-short.evtx", "start": 1, "end": 2}],
            },
            {
                "receipt_id": "R4",
                "kind": "handover",
                "from_principal": "u-a",
                "to_principal": "u-b",
                "signer_id": "u-b",
                "signed_at": "2026-12-01T10:00:00Z",
                "status": "signed",
                "scope": [{"evidence_id": "security-short.evtx", "start": 3, "end": 3}],
            },
        ]
    }
    responsibility = {
        "case_id": case["case_id"],
        "roles": [
            {
                "principal_id": "u-a",
                "actual_name": "Zhang Wei",
                "role": "investigation custodian",
                "authorized_from": "2026-09-01T00:00:00Z",
                "authorized_to": "2026-10-25T09:00:00Z",
            },
            {
                "principal_id": "u-b",
                "actual_name": "Li Na",
                "role": "long-term custodian",
                "authorized_from": "2026-10-25T09:00:00Z",
                "authorized_to": "2027-01-01T00:00:00Z",
            },
        ],
    }

    for name, payload in (
        ("case.json", case),
        ("external_manifest.json", external),
        ("receipts.json", receipts),
        ("responsibility.json", responsibility),
    ):
        with open(os.path.join(HERE, name), "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")


if __name__ == "__main__":
    main()
