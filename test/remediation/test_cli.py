import json
import subprocess
import sys
from pathlib import Path

ASSETS = Path(__file__).parent.parent / "assets" / "remediation"

BASE_ARGS = [
    "--before-lock",
    str(ASSETS / "pylock.before.toml"),
    "--after-lock",
    str(ASSETS / "pylock.after.toml"),
    "--before-audit",
    str(ASSETS / "audit.before.json"),
    "--after-audit",
    str(ASSETS / "audit.after.json"),
]


def _run(*extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pip_audit._remediation", *BASE_ARGS, *extra],
        capture_output=True,
        text=True,
        check=False,
    )


class TestRemediationCli:
    def test_columns_run_reports_all_statuses(self):
        result = _run()
        assert result.returncode == 1
        assert "[base]" in result.stdout
        assert "moved-chain" in result.stdout
        assert "incomplete-evidence" in result.stdout

    def test_json_run_is_parseable(self):
        result = _run("-f", "json")
        payload = json.loads(result.stdout)
        assert [group["group"] for group in payload["groups"]] == ["base", "plugins"]

    def test_group_filter(self):
        result = _run("-g", "plugins", "-f", "json")
        payload = json.loads(result.stdout)
        assert [group["group"] for group in payload["groups"]] == ["base", "plugins"]

    def test_missing_input_exits_nonzero(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip_audit._remediation",
                "--before-lock",
                str(ASSETS / "missing.toml"),
                "--after-lock",
                str(ASSETS / "pylock.after.toml"),
                "--before-audit",
                str(ASSETS / "audit.before.json"),
                "--after-audit",
                str(ASSETS / "audit.after.json"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0
        assert "does not exist" in result.stderr

    def test_output_to_file(self, tmp_path):
        output = tmp_path / "report.json"
        result = _run("-f", "json", "-o", str(output))
        assert result.returncode == 1
        assert output.is_file()
        json.loads(output.read_text())
