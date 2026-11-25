import pytest

from detect_secrets.eval.dataset import load_dataset
from detect_secrets.eval.engine import run_all
from detect_secrets.eval.engine import run_plugin
from detect_secrets.eval.engine import resolve_plugin_class
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.github_token import GitHubTokenDetector


PYTHON_HEAVY = "test_data/eval/python_heavy"


def test_resolve_plugin_class_by_name():
    assert resolve_plugin_class("AWSKeyDetector") is AWSKeyDetector


def test_resolve_unknown_plugin_raises():
    with pytest.raises(KeyError):
        resolve_plugin_class("NotInstalledDetector")


def test_run_plugin_finds_aws_label_with_span():
    dataset = load_dataset(PYTHON_HEAVY)
    hits = run_plugin(AWSKeyDetector(), dataset)

    paths = {hit.path for hit in hits}
    assert "python/settings.py" in paths
    located = [hit for hit in hits if hit.start is not None and hit.end is not None]
    assert located
    assert all(hit.family == "python" for hit in located)


def test_github_plugin_detects_correct_length_token():
    dataset = load_dataset(PYTHON_HEAVY)
    hits = run_plugin(GitHubTokenDetector(), dataset)

    assert any(hit.path == "python/settings.py" for hit in hits)


def test_run_all_isolates_failed_plugins():
    dataset = load_dataset(PYTHON_HEAVY)
    plugin_hits, failures = run_all(
        dataset,
        [
            {"name": "AWSKeyDetector"},
            {"name": "NotInstalledDetector"},
        ],
    )

    assert "AWSKeyDetector" in plugin_hits
    assert plugin_hits["AWSKeyDetector"]
    assert "NotInstalledDetector" not in plugin_hits
    assert "NotInstalledDetector" in failures


def test_run_all_supports_plugin_options():
    dataset = load_dataset(PYTHON_HEAVY)
    plugin_hits, failures = run_all(
        dataset,
        [{"name": "Base64HighEntropyString", "options": {"limit": 4.5}}],
    )

    assert not failures
    assert "Base64HighEntropyString" in plugin_hits
