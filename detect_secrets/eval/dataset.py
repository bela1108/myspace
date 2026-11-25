"""
Synthetic, fully-labelled offline evaluation datasets.

A dataset is a directory of labelled source files plus a labels.json
manifest. Every label describes one ground-truth secret, including the file
it lives in, the line it sits on, and the exact character span of the secret
value on that line. Nothing here touches the network or performs
verification. The data is synthetic and the labels are authoritative.
"""
import json
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Dict
from typing import List
from typing import Optional

@dataclass(frozen=True)
class TruthLabel:
    """A single labelled secret occurrence, identified by identifier."""

    identifier: str
    path: str
    family: str
    line: int
    start: int
    end: int
    kind: str

    @property
    def identity(self) -> tuple:
        """Location identity shared by overlapping hits for one truth."""
        return (self.path, self.line, self.start, self.end)


@dataclass
class LabeledFile:
    path: str
    family: str
    labels: List[TruthLabel] = field(default_factory=list)


@dataclass
class LabeledDataset:
    name: str
    root: Path
    files: List[LabeledFile]

    @property
    def families(self) -> List[str]:
        seen: Dict[str, None] = {}
        for labeled_file in self.files:
            seen.setdefault(labeled_file.family, None)
        return list(seen.keys())

    @property
    def truths(self) -> List[TruthLabel]:
        return [truth for labeled_file in self.files for truth in labeled_file.labels]

    def truths_for_family(self, family: str) -> List[TruthLabel]:
        return [
            truth
            for labeled_file in self.files
            if labeled_file.family == family
            for truth in labeled_file.labels
        ]

    def read_lines(self, labeled_file: LabeledFile) -> List[str]:
        return (self.root / labeled_file.path).read_text().splitlines()


def load_dataset(directory: str) -> LabeledDataset:
    """Load a labelled dataset from a directory that contains labels.json.

    Label spans are validated against the on-disk files so a manifest typo
    fails loudly instead of silently scoring every plugin as a miss.
    """
    root = Path(directory)
    manifest = json.loads((root / "labels.json").read_text())

    files: List[LabeledFile] = []
    for file_index, entry in enumerate(manifest["files"]):
        path = entry["path"]
        family = entry["family"]
        labeled_file = LabeledFile(path=path, family=family)
        lines = (root / path).read_text().splitlines()

        for label_index, raw_label in enumerate(entry.get("labels", [])):
            truth = TruthLabel(
                identifier=raw_label.get("id", f"{path}#{label_index}"),
                path=path,
                family=family,
                line=raw_label["line"],
                start=raw_label["start"],
                end=raw_label["end"],
                kind=raw_label.get("kind", "unknown"),
            )
            _validate_span(truth, lines, file_index)
            labeled_file.labels.append(truth)

        files.append(labeled_file)

    return LabeledDataset(
        name=manifest.get("name", root.name),
        root=root,
        files=files,
    )


def _validate_span(truth: TruthLabel, lines: List[str], file_index: int) -> None:
    if truth.line < 1 or truth.line > len(lines):
        raise ValueError(
            "label {} in file {} references line {} but the file has {} lines".format(
                truth.identifier, file_index, truth.line, len(lines),
            ),
        )

    line = lines[truth.line - 1]
    if truth.start < 0 or truth.end > len(line) or truth.start >= truth.end:
        raise ValueError(
            "label {} has invalid span [{}:{}] on line {}".format(
                truth.identifier, truth.start, truth.end, truth.line,
            ),
        )


def find_truth_at(
    truths: List[TruthLabel],
    path: str,
    line: int,
    start: Optional[int] = None,
    end: Optional[int] = None,
) -> Optional[TruthLabel]:
    """Return the ground truth that owns a hit location.

    With character spans, any overlap attributes the hit, since plugins
    commonly return slightly different spans for one embedded secret.
    Without spans, a same-line match counts as overlapping too.
    """
    for truth in truths:
        if truth.path != path or truth.line != line:
            continue
        if start is None or end is None:
            return truth
        if start < truth.end and end > truth.start:
            return truth
    return None
