from __future__ import annotations

from pathlib import Path

from .checker import audit_file

CONTRACTS = {
    "hal_protected_write": {
        "role": "change",
        "resource_arg": 0,
        "success_return": 0,
        "description": "protected device setting write",
    },
    "cfg_withdraw": {
        "role": "withdraw",
        "resource_arg": 0,
        "description": "compensate a successful write",
    },
    "audit_commit": {
        "role": "credential",
        "resource_arg": 0,
        "description": "commit one audit credential",
    },
}

CASES = [
    ("漏记", "demo_missing"),
    ("重复记", "demo_duplicate"),
    ("回滚干净", "demo_rollback_clean"),
    ("无法判定", "demo_undecidable"),
]

VERDICT_ZH = {
    "missing_credential": "漏记",
    "duplicate_credential": "重复记",
    "missing_and_duplicate": "漏记且重复记",
    "rollback_clean": "回滚干净",
    "undecidable": "无法判定",
    "clean": "干净",
}


def _print_finding(finding: dict) -> None:
    location = finding.get("exit_line")
    code = finding.get("code")
    print(f"  - 出口行 {location} / {code}: {finding.get('message_zh', '')}")
    if finding.get("resource"):
        print(f"    资源: {finding['resource']}")
    if finding.get("boundaries"):
        for boundary in finding["boundaries"]:
            print(
                "    证明中断: "
                f"第 {boundary.get('line')} 行 [{boundary.get('function', '?')}] "
                f"{boundary.get('callee')} - {boundary.get('reason')}"
            )
    print("    可读路径:")
    for line in finding.get("path_text", "").splitlines():
        print(f"      {line}")


def run_demo() -> None:
    source = Path(__file__).with_name("synthetic_config.c")
    for expected, function_name in CASES:
        report = audit_file(source, CONTRACTS, function=function_name)
        verdict = VERDICT_ZH.get(report["verdict"], report["verdict"])
        print("=" * 78)
        print(f"{expected}样例: {function_name} => {verdict}")
        status_counts: dict[tuple[object, str], int] = {}
        for exit_report in report["exits"]:
            key = (exit_report["exit_line"], exit_report["status"])
            status_counts[key] = status_counts.get(key, 0) + 1
        exit_summary = [
            f"L{line}:{VERDICT_ZH.get(status, status)}×{count}"
            for (line, status), count in sorted(status_counts.items(), key=lambda item: (item[0][0] or 0, str(item[0][1])))
        ]
        print("出口结论: " + "; ".join(exit_summary))

        shown: set[tuple[object, str]] = set()
        for finding in report["findings"]:
            key = (finding.get("exit_line"), finding.get("code"))
            if key in shown:
                continue
            shown.add(key)
            _print_finding(finding)

        if expected == "回滚干净":
            for exit_report in report["exits"]:
                if exit_report["status"] != "rollback_clean":
                    continue
                print(f"  - 已验证出口行 {exit_report['exit_line']}: 变更已撤回，凭据数为 0")
                print("    可读路径:")
                for line in exit_report["path_text"].splitlines():
                    print(f"      {line}")
                break


if __name__ == "__main__":
    run_demo()
