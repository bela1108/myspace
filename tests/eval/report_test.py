import json

from detect_secrets.eval import load_dataset
from detect_secrets.eval.cli import evaluate_one
from detect_secrets.eval.cli import main
from detect_secrets.eval.report import render_failure_table
from detect_secrets.eval.report import render_json_report
from detect_secrets.eval.report import render_text_report


PYTHON_HEAVY = "test_data/eval/python_heavy"
PLUGINS = ["AWSKeyDetector", "GitHubTokenDetector", "KeywordDetector"]


def test_text_report_keeps_family_granularity():
    dataset = load_dataset(PYTHON_HEAVY)
    report = evaluate_one(dataset, PLUGINS)
    text = render_text_report(report)

    assert "Plugin x family effectiveness" in text
    assert "Family coverage and unmeasurable labels" in text
    assert "python" in text and "config" in text and "docs" in text


def test_json_report_round_trips():
    dataset = load_dataset(PYTHON_HEAVY)
    report = evaluate_one(dataset, PLUGINS)
    payload = json.loads(render_json_report(report))

    assert payload["dataset"] == "python-heavy"
    assert payload["plugin_order"]
    families = {row["family"] for row in payload["plugin_family_metrics"]}
    assert families == {"python", "config", "docs"}


def test_failed_plugins_listed_separately():
    dataset = load_dataset(PYTHON_HEAVY)
    report = evaluate_one(dataset, PLUGINS + ["NotInstalledDetector"])

    failure_text = render_failure_table(report)
    assert "NotInstalledDetector" in failure_text
    healthy = {row.plugin for row in report.plugin_family_metrics}
    assert "NotInstalledDetector" not in healthy
    assert report.failures[0].plugin == "NotInstalledDetector"


def test_cli_main_text(capsys):
    exit_code = main([
        "--dataset", PYTHON_HEAVY,
        "--plugin", "AWSKeyDetector",
        "--plugin", "GitHubTokenDetector",
    ])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "python-heavy" in captured.out
    assert "Failed plugins" in captured.out


def test_cli_main_json(capsys):
    exit_code = main([
        "--dataset", PYTHON_HEAVY,
        "--plugin", "AWSKeyDetector",
        "--json",
    ])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dataset"] == "python-heavy"


def test_cli_main_requires_plugins(capsys):
    exit_code = main(["--dataset", PYTHON_HEAVY])

    assert exit_code == 2
    assert "error" in capsys.readouterr().err


def test_cli_comparison_surfaces_family_regression(capsys):
    exit_code = main([
        "--dataset", PYTHON_HEAVY,
        "--baseline", "KeywordDetector",
        "--candidate", "GitHubTokenDetector",
    ])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Baseline vs candidate" in output
    assert "REGRESSED" in output
