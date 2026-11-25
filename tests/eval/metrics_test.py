from pathlib import Path

from detect_secrets.eval.dataset import LabeledDataset
from detect_secrets.eval.dataset import LabeledFile
from detect_secrets.eval.dataset import TruthLabel
from detect_secrets.eval.matching import Hit
from detect_secrets.eval.matching import match_dataset
from detect_secrets.eval.metrics import compare_configurations
from detect_secrets.eval.metrics import evaluate

from detect_secrets.eval.dataset import load_dataset
from detect_secrets.eval.metrics import evaluate_dataset

PYTHON_HEAVY = "test_data/eval/python_heavy"


def _dataset():
    labels_py = [
        TruthLabel("P1", "a.py", "python", 1, 0, 4, "k"),
        TruthLabel("P2", "a.py", "python", 2, 0, 4, "k"),
    ]
    labels_cfg = [TruthLabel("C1", "b.env", "config", 1, 0, 4, "k")]
    return LabeledDataset(
        name="synthetic",
        root=Path("."),
        files=[
            LabeledFile("a.py", "python", labels_py),
            LabeledFile("b.env", "config", labels_cfg),
        ],
    )


def _hits():
    return {
        "First": [
            Hit("First", "a.py", "python", 1, "v", 0, 4),
            Hit("First", "a.py", "python", 1, "dup", 1, 3),
            Hit("First", "b.env", "config", 1, "v", 0, 4),
        ],
        "Second": [
            Hit("Second", "a.py", "python", 1, "v", 0, 4),
            Hit("Second", "a.py", "python", 2, "v", 0, 4),
        ],
    }


def test_incremental_credit_follows_plugin_order():
    dataset = _dataset()
    result = match_dataset(dataset, _hits())
    report = evaluate(dataset, result, plugin_order=["First", "Second"])

    rows = {(row.plugin, row.family): row for row in report.plugin_family_metrics}

    first_py = rows[("First", "python")]
    assert first_py.found == 1
    assert first_py.incremental == 1
    assert first_py.duplicate_hits == 1

    second_py = rows[("Second", "python")]
    assert second_py.found == 2
    assert second_py.incremental == 1
    assert second_py.missed == 0


def test_unmeasurable_labels_are_listed_per_family():
    dataset = _dataset()
    hits = {"First": [Hit("First", "a.py", "python", 1, "v", 0, 4)]}
    report = evaluate(dataset, match_dataset(dataset, hits))

    summaries = {row.family: row for row in report.family_summaries}
    assert summaries["python"].unmeasurable == 1
    assert summaries["config"].unmeasurable == 1
    assert summaries["config"].unmeasurable_ids == ["C1"]


def test_compare_flags_regressing_family():
    dataset = _dataset()
    baseline = match_dataset(
        dataset, {"B": [Hit("B", "a.py", "python", 1, "v", 0, 4)]},
    )
    candidate = match_dataset(
        dataset, {"C": [Hit("C", "b.env", "config", 1, "v", 0, 4)]},
    )

    comparisons = compare_configurations(dataset, baseline, candidate)
    by_family = {row.family: row for row in comparisons}

    assert by_family["python"].regressed is True
    assert by_family["python"].delta < 0
    assert by_family["config"].regressed is False
    assert by_family["config"].delta > 0


def test_evaluate_dataset_convenience_wrapper():
    dataset = load_dataset(PYTHON_HEAVY)
    report = evaluate_dataset(
        dataset,
        [
            {"name": "AWSKeyDetector"},
            {"name": "NotInstalledDetector"},
        ],
    )

    healthy = {row.plugin for row in report.plugin_family_metrics}
    assert healthy == {"AWSKeyDetector"}
    assert report.failures[0].plugin == "NotInstalledDetector"
