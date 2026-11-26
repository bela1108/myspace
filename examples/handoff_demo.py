from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from msoffcrypto.handoff import (  # noqa: E402
    ExhibitAuthorization,
    HandoffPlanner,
    HandoffStage,
    Recipient,
    inspect_protection_file,
)


def main() -> None:
    sample_a = ROOT / "tests" / "inputs" / "rc4cryptoapi_password.doc"
    sample_b = ROOT / "tests" / "inputs" / "rc4cryptoapi_password.doc"

    profile_a = inspect_protection_file(sample_a)
    profile_b = inspect_protection_file(sample_b)

    backup_team = Recipient(
        department_id="backup-verify",
        department_name="备份核验组",
        protection_types=frozenset({"rc4_cryptoapi", "rc4", "xor_obfuscation"}),
        stages=frozenset({HandoffStage.VERIFY_PROTECTION}),
    )
    legacy_team_a = Recipient(
        department_id="legacy-office-a",
        department_name="旧 Office 处理一组",
        protection_types=frozenset({"rc4_cryptoapi", "rc4", "xor_obfuscation"}),
        stages=frozenset(
            {HandoffStage.VERIFY_PROTECTION, HandoffStage.CONVERT}
        ),
    )
    legacy_team_b = Recipient(
        department_id="legacy-office-b",
        department_name="旧 Office 处理二组",
        protection_types=frozenset({"rc4_cryptoapi", "rc4", "xor_obfuscation"}),
        stages=frozenset({HandoffStage.CONVERT}),
    )

    planner = HandoffPlanner(
        recipients=[legacy_team_a, legacy_team_b],
        backup_team=backup_team,
        authorizations=[
            ExhibitAuthorization(
                exhibit_id="EX-DOC-701",
                protection_type="rc4_cryptoapi",
                stages=frozenset(
                    {HandoffStage.VERIFY_PROTECTION, HandoffStage.CONVERT}
                ),
            ),
            ExhibitAuthorization(
                exhibit_id="EX-DOC-702",
                protection_type="rc4_cryptoapi",
                stages=frozenset({HandoffStage.VERIFY_PROTECTION}),
            ),
        ],
    )

    decisions = [
        planner.plan("EX-DOC-701", sample_a, profile_a),
        planner.plan("EX-DOC-702", sample_b, profile_b),
    ]

    for decision in decisions:
        print(f"证物: {decision.exhibit_id}")
        print(f"文件: {Path(decision.path).relative_to(ROOT)}")
        print(
            "保护识别: "
            f"{decision.profile.format}/{decision.profile.protection_type}, "
            f"encrypted={decision.profile.encrypted}"
        )
        print(f"队列: {decision.queue.value}")
        if decision.plans:
            print("可执行计划:")
            for plan in decision.plans:
                print(
                    f"- {plan.recipient.department_name} "
                    f"({plan.recipient.department_id}): {plan.stage.value} / {plan.action}"
                )
        else:
            print("可执行计划: 无")
        if decision.missing_conditions:
            print("缺少的不可替代条件:")
            for condition in decision.missing_conditions:
                print(f"- {condition.code}: {condition.description}")
        else:
            print("缺少的不可替代条件: 无")
        print()


if __name__ == "__main__":
    main()
