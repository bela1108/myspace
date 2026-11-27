"""Command-line entry point for symbol evidence reports."""

import argparse
import json
import sys

from .report import build_report


def _parser():
    parser = argparse.ArgumentParser(
        prog="symbol_evidence",
        description="只读解析 PE 调试记录，按证据等级复核符号库声明。",
    )
    parser.add_argument("image", nargs="?", help="PE 映像路径")
    parser.add_argument("--pe", dest="pe_option", help="PE 映像路径（与位置参数等价）")
    parser.add_argument("--signoff", help="符号库签收表（JSON/CSV/TSV/Markdown）")
    parser.add_argument("--claims", help="源定位声明文件（JSON/CSV/TSV）")
    parser.add_argument("--pdb", help="可选 PDB 文件，用于重新计算符号文件摘要")
    parser.add_argument(
        "--output-dir",
        default="symbol_evidence_out",
        help="导出目录（默认 symbol_evidence_out）",
    )
    parser.add_argument(
        "--formats",
        default="json,md,csv",
        help="导出格式，逗号分隔（json,md,csv）",
    )
    parser.add_argument("--basename", default="symbol_evidence", help="导出文件名前缀")
    parser.add_argument(
        "--print-json", action="store_true", help="将 JSON 报告打印到标准输出"
    )
    parser.add_argument(
        "--fail-unverified",
        action="store_true",
        help="存在未证实记录时返回退出码 2",
    )
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    pe_path = args.pe_option or args.image
    if not pe_path:
        parser.error("必须提供 PE 映像路径")

    formats = tuple(item.strip() for item in args.formats.split(",") if item.strip())
    try:
        report = build_report(
            pe_path=pe_path,
            signoff=args.signoff,
            claims=args.claims,
            pdb_path=args.pdb,
        )
        written = report.write(args.output_dir, formats=formats, basename=args.basename)
    except Exception as exc:  # noqa: BLE001 - CLI should present a concise error
        print("error: %s" % exc, file=sys.stderr)
        return 2

    summary = report.summary()
    print(
        "claims=%d verified=%d name_only=%d debug_record_match=%d digest_verified=%d"
        % (
            summary["total"],
            summary["verified"],
            summary["by_level"].get("name_only", 0),
            summary["by_level"].get("debug_record_match", 0),
            summary["by_level"].get("digest_verified", 0),
        )
    )
    for path in written:
        print("wrote %s" % path)
    if args.print_json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str))
    if args.fail_unverified and summary["unverified"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
