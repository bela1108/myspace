"""
Command line entry point for the offline custody audit.
"""
from __future__ import annotations

import argparse
import json
import sys

from custody_audit.audit import AuditConfig, ExternalManifest, reconcile
from custody_audit.evtx_records import RecordRange, summarize_evtx
from custody_audit.report import render_report


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_result(evtx_dir: str, config_path: str, roster_path: str, manifest_path: str, receipts_path: str):
    config_data = _load_json(config_path)
    roster_data = _load_json(roster_path)
    manifest = ExternalManifest.from_dict(_load_json(manifest_path))
    receipts_data = _load_json(receipts_path)
    config = AuditConfig(
        archive_cutoff=str(config_data["archive_cutoff"]),
        scope=dict(config_data["scope"]),
    )

    import os

    record_index: dict = {}
    for evtx_file, ranges in config.scope.items():
        path = os.path.join(evtx_dir, evtx_file)
        merged: list = []
        seen: set = set()
        for raw_range in ranges:
            rng = RecordRange.from_dict(raw_range)
            for summary in summarize_evtx(path, rng):
                if summary.record_num not in seen:
                    seen.add(summary.record_num)
                    merged.append(summary)
        record_index[evtx_file] = merged

    return reconcile(config, roster_data, manifest, receipts_data["receipts"], record_index)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="离线 EVTX 保管核对：区分可复查、仅剩摘要与未承接范围。")
    parser.add_argument("--evtx-dir", required=True, help="存放源证物 EVTX 的目录")
    parser.add_argument("--config", required=True, help="调用方记录范围与销档日期 JSON")
    parser.add_argument("--roster", required=True, help="内部保管责任表 JSON")
    parser.add_argument("--manifest", required=True, help="外部交接清单 JSON（不得含敏感字段）")
    parser.add_argument("--receipts", required=True, help="换岗/补签回执 JSON")
    parser.add_argument("--report", help="可选：报告写入路径，默认打印到标准输出")
    args = parser.parse_args(argv)

    result = build_result(args.evtx_dir, args.config, args.roster, args.manifest, args.receipts)
    text = render_report(result)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        print(text)
    return 1 if result.has_blocking_errors else 0


if __name__ == "__main__":
    sys.exit(main())
