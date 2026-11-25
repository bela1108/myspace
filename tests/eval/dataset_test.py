import pytest

from detect_secrets.eval.dataset import find_truth_at
from detect_secrets.eval.dataset import load_dataset
from detect_secrets.eval.dataset import TruthLabel


PYTHON_HEAVY = "test_data/eval/python_heavy"
DOC_HEAVY = "test_data/eval/doc_heavy"


def test_load_dataset_groups_files_by_family():
    dataset = load_dataset(PYTHON_HEAVY)

    assert dataset.name == "python-heavy"
    assert len(dataset.files) == 4
    assert set(dataset.families) == {"config", "docs", "python"}
    assert len(dataset.files) == 4


def test_datasets_are_intentionally_imbalanced():
    python_heavy = load_dataset(PYTHON_HEAVY)
    doc_heavy = load_dataset(DOC_HEAVY)

    python_counts = {
        family: len(python_heavy.truths_for_family(family))
        for family in python_heavy.families
    }
    doc_counts = {
        family: len(doc_heavy.truths_for_family(family))
        for family in doc_heavy.families
    }

    assert python_counts["python"] > sum(
        count for family, count in python_counts.items() if family != "python"
    )
    assert doc_counts["docs"] > sum(
        count for family, count in doc_counts.items() if family != "docs"
    )


def test_label_span_points_at_the_embedded_value():
    dataset = load_dataset(PYTHON_HEAVY)
    settings = next(item for item in dataset.files if item.path.endswith("settings.py"))
    aws_label = next(label for label in settings.labels if label.kind == "aws-id")
    lines = dataset.read_lines(settings)

    sliced = lines[aws_label.line - 1][aws_label.start:aws_label.end]
    assert sliced == "AKIAIOSFODNN7EXAMPLE"


def test_invalid_span_is_rejected(tmp_path):
    import json
    (tmp_path / "a.py").write_text("token = abc\n")
    manifest = {
        "name": "bad",
        "files": [
            {
                "path": "a.py",
                "family": "python",
                "labels": [
                    {"id": "x", "line": 1, "start": 99, "end": 120, "kind": "k"},
                ],
            }
        ],
    }
    (tmp_path / "labels.json").write_text(json.dumps(manifest))

    with pytest.raises(ValueError):
        load_dataset(str(tmp_path))


def test_find_truth_at_uses_span_overlap():
    truth = TruthLabel("L1", "a.py", "python", 1, 10, 20, "k")

    assert find_truth_at([truth], "a.py", 1, 15, 18).identifier == "L1"
    assert find_truth_at([truth], "other.py", 1, 15, 18) is None
    assert find_truth_at([truth], "a.py", 2, 15, 18) is None
    # Without character spans, a same-line match still attributes to the truth.
    assert find_truth_at([truth], "a.py", 1).identifier == "L1"
