import hashlib
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import Enum


"""
READ-ONLY EXISTENCE AUDIT:
An exported StringData field (e.g. the shortcut "description") is only a
string, so an empty export cannot distinguish "not set" from "not captured".
This module audits *existence* without mutating or re-parsing the LNK file.
It combines four evidence sources:

  1. the ShellLinkHeader LinkFlags (which StringData structures are declared),
  2. the parsed StringData values,
  3. the parsed ExtraData block names,
  4. the caller's collection scopes and the file identity of each pass.

Each capture pass is described by a CollectionSheet whose scope states which
evidence channels ("header", "strings", "extras") that pass collected. Two
sheets may complete each other only when their file identities match and
their overlapping evidence is compatible. The report distinguishes
NOT_DECLARED (header flag unset), DECLARED_EMPTY (flag set, captured value
is "") and INCOMPLETE (the collected material cannot decide). The coverage
matrix shows which pair of partial sheets jointly completes a field and
which pass stays without conclusion because the file version differs.
"""

STRING_DATA_FIELDS = (
    "description",
    "relative_path",
    "working_directory",
    "command_line_arguments",
    "icon_location",
)

FIELD_DECLARATION_FLAGS = {
    "description": "HasName",
    "relative_path": "HasRelativePath",
    "working_directory": "HasWorkingDir",
    "command_line_arguments": "HasArguments",
    "icon_location": "HasIconLocation",
}

EVIDENCE_CHANNELS = ("header", "strings", "extras")


class FieldStatus(Enum):
    NOT_DECLARED = "not_declared"
    DECLARED_EMPTY = "declared_empty"
    PRESENT = "present"
    INCOMPLETE = "incomplete_material"
    NO_CONCLUSION = "no_conclusion"

    def is_conclusive(self):
        return self in (
            FieldStatus.NOT_DECLARED,
            FieldStatus.DECLARED_EMPTY,
            FieldStatus.PRESENT,
        )


@dataclass(frozen=True)
class FileIdentity:
    """Content-based identity of the captured file version."""

    digest: str
    size: int

    @classmethod
    def from_bytes(cls, indata):
        return cls(digest=hashlib.sha256(indata).hexdigest(), size=len(indata))

    def short_digest(self):
        return self.digest[:12]


@dataclass(frozen=True)
class FieldObservation:
    field: str
    status: FieldStatus
    value: object
    detail: str


class CollectionSheet:
    """One capture pass: which channels were collected and what they yielded.

    `declared` maps each StringData field to its header LinkFlag (None if the
    "header" channel was not collected), `values` maps each field to the
    captured string or None (None for the whole dict if "strings" was not
    collected), and `extras` holds the ExtraData block names (None if the
    "extras" channel was not collected).
    """

    def __init__(self, label, identity, declared=None, values=None, extras=None):
        self.label = label
        self.identity = identity
        self.declared = dict(declared) if declared is not None else None
        self.values = dict(values) if values is not None else None
        self.extras = frozenset(extras) if extras is not None else None

    @classmethod
    def from_lnk(cls, label, lnk, scope=EVIDENCE_CHANNELS):
        """Build a sheet by reading an already-parsed LnkFile (read-only).

        `scope` names the evidence channels this pass collected; any subset
        of "header", "strings" and "extras".
        """
        scope = frozenset(scope)
        unknown = scope - set(EVIDENCE_CHANNELS)
        if unknown:
            raise ValueError(f"Unknown evidence channels in scope: {sorted(unknown)}")

        declared = None
        if "header" in scope:
            flags = lnk.header.link_flags()
            declared = {f: flag in flags for f, flag in FIELD_DECLARATION_FLAGS.items()}

        values = None
        if "strings" in scope:
            getters = {
                "description": lnk.string_data.description,
                "relative_path": lnk.string_data.relative_path,
                "working_directory": lnk.string_data.working_directory,
                "command_line_arguments": lnk.string_data.command_line_arguments,
                "icon_location": lnk.string_data.icon_location,
            }
            values = {f: getters[f]() for f in STRING_DATA_FIELDS}

        extras = None
        if "extras" in scope:
            extras = frozenset(lnk.extras.as_dict())

        return cls(
            label=label,
            identity=FileIdentity.from_bytes(lnk.indata),
            declared=declared,
            values=values,
            extras=extras,
        )

    def scope(self):
        channels = set()
        if self.declared is not None:
            channels.add("header")
        if self.values is not None:
            channels.add("strings")
        if self.extras is not None:
            channels.add("extras")
        return frozenset(channels)

    def observe(self, field):
        if field not in STRING_DATA_FIELDS:
            raise ValueError(f"Unknown StringData field: {field!r}")
        if self.declared is None:
            return FieldObservation(
                field, FieldStatus.INCOMPLETE, None, "header was not collected"
            )
        if not self.declared[field]:
            flag = FIELD_DECLARATION_FLAGS[field]
            return FieldObservation(
                field, FieldStatus.NOT_DECLARED, None, f"header flag {flag} not set"
            )
        if self.values is None:
            return FieldObservation(
                field, FieldStatus.INCOMPLETE, None, "string data was not collected"
            )
        value = self.values.get(field)
        if value is None:
            return FieldObservation(
                field, FieldStatus.INCOMPLETE, None, "declared but not captured"
            )
        if value == "":
            return FieldObservation(
                field, FieldStatus.DECLARED_EMPTY, value, "declared and captured as empty"
            )
        return FieldObservation(field, FieldStatus.PRESENT, value, "declared and captured")

    def compatible_with(self, other):
        """Two sheets may complete each other only if the file identity
        matches and the overlapping evidence does not conflict."""
        if self.identity != other.identity:
            return False
        if (
            self.declared is not None
            and other.declared is not None
            and self.declared != other.declared
        ):
            return False
        if self.values is not None and other.values is not None:
            for field in STRING_DATA_FIELDS:
                mine = self.values.get(field)
                theirs = other.values.get(field)
                if mine is not None and theirs is not None and mine != theirs:
                    return False
        return not (
            self.extras is not None
            and other.extras is not None
            and self.extras != other.extras
        )


def _merge_observations(field, sheets):
    """Merge observations of mutually compatible sheets of one file version."""
    declared = [sheet.declared[field] for sheet in sheets if sheet.declared is not None]
    if not declared:
        return FieldObservation(
            field, FieldStatus.INCOMPLETE, None, "header was not collected"
        )
    if not any(declared):
        return FieldObservation(field, FieldStatus.NOT_DECLARED, None, "header flag not set")

    captured = [
        sheet.values.get(field)
        for sheet in sheets
        if sheet.values is not None and sheet.values.get(field) is not None
    ]
    if not captured:
        return FieldObservation(
            field, FieldStatus.INCOMPLETE, None, "declared but not captured"
        )
    if any(value != "" for value in captured):
        value = next(value for value in captured if value != "")
        return FieldObservation(field, FieldStatus.PRESENT, value, "declared and captured")
    return FieldObservation(
        field, FieldStatus.DECLARED_EMPTY, "", "declared and captured as empty"
    )


@dataclass
class FieldVerdict:
    field: str
    status: FieldStatus
    value: object
    evidence: list = dataclass_field(default_factory=list)


class ExistenceAudit:
    """Read-only audit over one or more CollectionSheets."""

    def __init__(self, sheets):
        self.sheets = list(sheets)
        if not self.sheets:
            raise ValueError("ExistenceAudit requires at least one CollectionSheet")
        labels = [sheet.label for sheet in self.sheets]
        if len(labels) != len(set(labels)):
            raise ValueError("CollectionSheet labels must be unique")

        self._clusters = []
        for sheet in self.sheets:
            for cluster in self._clusters:
                if all(sheet.compatible_with(member) for member in cluster):
                    cluster.append(sheet)
                    break
            else:
                self._clusters.append([sheet])

    def _cluster_verdicts(self, field):
        return [
            (_merge_observations(field, cluster), cluster) for cluster in self._clusters
        ]

    def verdict(self, field):
        """Overall conclusion for one StringData field across all sheets."""
        conclusive = {}
        for observation, cluster in self._cluster_verdicts(field):
            if observation.status.is_conclusive():
                key = (observation.status, observation.value)
                conclusive.setdefault(key, []).extend(sheet.label for sheet in cluster)

        if len(conclusive) > 1:
            return FieldVerdict(field, FieldStatus.NO_CONCLUSION, None, [])
        if conclusive:
            (status, value), evidence = next(iter(conclusive.items()))
            return FieldVerdict(field, status, value, sorted(evidence))

        identities = {sheet.identity for sheet in self.sheets}
        if len(identities) == 1:
            return FieldVerdict(field, FieldStatus.INCOMPLETE, None, [])
        return FieldVerdict(field, FieldStatus.NO_CONCLUSION, None, [])

    def report(self):
        """Per-field verdicts plus the evidence sheets behind them."""
        return {
            field: {
                "status": (verdict := self.verdict(field)).status.value,
                "value": verdict.value,
                "evidence": verdict.evidence,
            }
            for field in STRING_DATA_FIELDS
        }

    def coverage_matrix(self):
        """For each field: which pair of partial sheets completes it, and
        which pass stays unresolved because the file version differs."""
        matrix = {}
        identities = {sheet.identity for sheet in self.sheets}
        for field in STRING_DATA_FIELDS:
            completions = []
            for i, first in enumerate(self.sheets):
                for second in self.sheets[i + 1 :]:
                    if not first.compatible_with(second):
                        continue
                    pair = [first, second]
                    if any(
                        sheet.observe(field).status.is_conclusive() for sheet in pair
                    ):
                        continue
                    merged = _merge_observations(field, pair)
                    if merged.status.is_conclusive():
                        completions.append(
                            {
                                "sheets": [first.label, second.label],
                                "status": merged.status.value,
                                "value": merged.value,
                            }
                        )

            unresolved = []
            for sheet in self.sheets:
                if sheet.observe(field).status.is_conclusive():
                    continue
                cluster = next(c for c in self._clusters if sheet in c)
                merged = _merge_observations(field, cluster)
                if merged.status.is_conclusive():
                    continue
                reason = (
                    "file_version_differs" if len(identities) > 1 else "incomplete_material"
                )
                unresolved.append({"sheet": sheet.label, "reason": reason})

            matrix[field] = {"completions": completions, "unresolved": unresolved}
        return matrix

    def render_matrix(self):
        """Human-readable coverage matrix for the reviewer."""
        matrix = self.coverage_matrix()
        labels = [sheet.label for sheet in self.sheets]

        header = ["field", *labels, "verdict"]
        rows = []
        for field in STRING_DATA_FIELDS:
            cells = [sheet.observe(field).status.value for sheet in self.sheets]
            rows.append([field, *cells, self.verdict(field).status.value])

        widths = [max(len(row[i]) for row in [header, *rows]) for i in range(len(header))]
        lines = [" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(header))]
        lines.append("-+-".join("-" * width for width in widths))
        lines.extend(
            " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) for row in rows
        )

        for field in STRING_DATA_FIELDS:
            lines.extend(
                f"completion: {field}: {' + '.join(c['sheets'])} -> {c['status']}"
                for c in matrix[field]["completions"]
            )
            lines.extend(
                f"unresolved: {field}: {item['sheet']} ({item['reason']})"
                for item in matrix[field]["unresolved"]
            )
        return "\n".join(lines)
