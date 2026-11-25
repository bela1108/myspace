from pathlib import Path

from detect_secrets.eval.dataset import LabeledDataset
from detect_secrets.eval.dataset import LabeledFile
from detect_secrets.eval.dataset import TruthLabel
from detect_secrets.eval.matching import Hit
from detect_secrets.eval.matching import match_dataset


def _dataset():
    labels = [
        TruthLabel("L1", "a.py", "python", 1, 10, 30, "k"),
        TruthLabel("L2", "a.py", "python", 2, 0, 8, "k"),
        TruthLabel("L3", "b.env", "config", 1, 5, 12, "k"),
    ]
    return LabeledDataset(
        name="synthetic",
        root=Path("."),
        files=[
            LabeledFile("a.py", "python", labels[:2]),
            LabeledFile("b.env", "config", labels[2:]),
        ],
    )


def test_overlapping_hits_count_as_one_truth():
    dataset = _dataset()
    hits = {
        "P": [
            Hit("P", "a.py", "python", 1, "inner", 12, 20),
            Hit("P", "a.py", "python", 1, "super", 5, 25),
            Hit("P", "a.py", "python", 2, "v2", 0, 8),
        ]
    }

    result = match_dataset(dataset, hits)
    family = result.metrics["P"].by_family["python"]

    assert family.found_labels == {"L1", "L2"}
    assert family.duplicate_labels == {"L1"}
    assert family.false_positives == []
    assert family.raw_hit_count == 3


def test_non_overlapping_hit_is_false_positive():
    dataset = _dataset()
    hits = {
        "P": [Hit("P", "a.py", "python", 3, "fp", 0, 4)],
    }

    result = match_dataset(dataset, hits)
    family = result.metrics["P"].by_family["python"]

    assert family.found_labels == set()
    assert len(family.false_positives) == 1


def test_families_are_scored_independently():
    dataset = _dataset()
    hits = {
        "P": [
            Hit("P", "a.py", "python", 1, "v", 10, 20),
            Hit("P", "b.env", "config", 1, "v", 5, 10),
        ]
    }

    result = match_dataset(dataset, hits)
    by_family = result.metrics["P"].by_family

    assert by_family["python"].found_labels == {"L1"}
    assert by_family["config"].found_labels == {"L3"}


def test_failures_are_kept_out_of_metrics():
    dataset = _dataset()
    result = match_dataset(
        dataset,
        {"P": [Hit("P", "a.py", "python", 1, "v", 10, 20)]},
        failures={"Broken": "RuntimeError: boom"},
    )

    assert "Broken" not in result.metrics
    assert result.failures == {"Broken": "RuntimeError: boom"}
    assert set(result.metrics) == {"P"}
