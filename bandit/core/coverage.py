#
# SPDX-License-Identifier: Apache-2.0
"""Rule x file coverage ledger.

Two offline scans can both report zero issues for very different
reasons: one may have skipped rules entirely while the other hit parse
errors. This module provides a ledger sitting between the manager and
the metrics collector that records, for every (rule, file) cell, whether
the rule was selected, completed, failed, or skipped, along with the
shard that produced the cell.

Cells carry a digest of the scanned source and of the selected-rule
configuration. Cells are only merged when both digests match; re-running
the same shard replaces its old cells, while any conflicting overwrite
raises CoverageConflictError instead of being silently applied.
"""
import hashlib
import logging

LOG = logging.getLogger(__name__)

SELECTED = "selected"
COMPLETED = "completed"
FAILED = "failed"
SKIPPED = "skipped"
STATES = (SELECTED, COMPLETED, FAILED, SKIPPED)


class CoverageConflictError(Exception):
    """Raised when a coverage cell would be silently overwritten."""


class CoverageCell:
    """A single (rule, file) coverage record."""

    __slots__ = (
        "rule_id",
        "fname",
        "state",
        "source_digest",
        "config_digest",
        "shards",
        "detail",
    )

    def __init__(
        self,
        rule_id,
        fname,
        state,
        source_digest,
        config_digest,
        shards,
        detail="",
    ):
        self.rule_id = rule_id
        self.fname = fname
        self.state = state
        self.source_digest = source_digest
        self.config_digest = config_digest
        self.shards = set(shards)
        self.detail = detail

    @property
    def key(self):
        return (self.rule_id, self.fname)

    def copy(self):
        return CoverageCell(
            self.rule_id,
            self.fname,
            self.state,
            self.source_digest,
            self.config_digest,
            set(self.shards),
            self.detail,
        )


class CoverageLedger:
    """Tracks per-rule, per-file scan coverage with shard provenance."""

    def __init__(self, config_digest="", shard="default"):
        self.config_digest = config_digest
        self.shard = shard
        self._cells = {}
        self._file_digests = {}

    @staticmethod
    def digest_source(data):
        """Digest the raw bytes of a scanned source file."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def digest_config(rule_ids):
        """Digest the set of selected rule ids forming the scan config."""
        blob = ",".join(sorted(rule_ids)).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def begin_file(self, fname, source_digest):
        """Register the source digest for a file about to be scanned."""
        known = self._file_digests.get(fname)
        if known is not None and known != source_digest:
            raise CoverageConflictError(
                "coverage conflict for %s: source changed within ledger"
                % fname
            )
        self._file_digests[fname] = source_digest

    def record(
        self, rule_id, fname, state, detail="", source_digest=None, shard=None
    ):
        """Record the state of one (rule, file) cell for this shard."""
        if state not in STATES:
            raise ValueError("unknown coverage state: %s" % state)
        if source_digest is None:
            source_digest = self._file_digests.get(fname)
        if source_digest is None:
            raise KeyError("no source digest registered for %s" % fname)
        cell = CoverageCell(
            rule_id,
            fname,
            state,
            source_digest,
            self.config_digest,
            {shard or self.shard},
            detail,
        )
        self._merge_cell(cell)

    def transition_file(self, fname, from_state, to_state, detail=""):
        """Move all cells of a file in from_state to to_state."""
        for cell in self._cells.values():
            if cell.fname == fname and cell.state == from_state:
                cell.state = to_state
                if detail:
                    cell.detail = detail

    def merge(self, other):
        """Merge another ledger, only where digests and configs match."""
        for fname, digest in other._file_digests.items():
            self.begin_file(fname, digest)
        for cell in other.cells():
            self._merge_cell(cell.copy())

    def _merge_cell(self, cell):
        existing = self._cells.get(cell.key)
        if existing is None:
            self._cells[cell.key] = cell
            return
        if (
            existing.source_digest != cell.source_digest
            or existing.config_digest != cell.config_digest
        ):
            raise CoverageConflictError(
                "coverage conflict for %s: source or config digest "
                "mismatch, refusing to overwrite" % (cell.key,)
            )
        if existing.shards & cell.shards:
            # re-run of the same shard replaces its old cell
            cell.shards |= existing.shards
            self._cells[cell.key] = cell
            return
        if existing.state == cell.state:
            # same outcome from another shard: join provenance
            existing.shards |= cell.shards
            return
        raise CoverageConflictError(
            "coverage conflict for %s: %s from shards %s vs %s from "
            "shards %s, refusing to overwrite"
            % (
                cell.key,
                existing.state,
                sorted(existing.shards),
                cell.state,
                sorted(cell.shards),
            )
        )

    def get(self, rule_id, fname):
        return self._cells.get((rule_id, fname))

    def cells(self):
        return sorted(
            self._cells.values(), key=lambda c: (c.fname, c.rule_id)
        )

    def cells_by_state(self, state):
        return [c for c in self.cells() if c.state == state]

    def failures(self):
        return self.cells_by_state(FAILED)

    def summary(self):
        counts = {state: 0 for state in STATES}
        for cell in self._cells.values():
            counts[cell.state] += 1
        return counts

    def report(self):
        """Render a text report pointing at incomplete coverage cells."""
        counts = self.summary()
        lines = [
            "coverage: %s cells=%d"
            % (
                " ".join("%s=%d" % (s, counts[s]) for s in STATES),
                len(self._cells),
            )
        ]
        for state in (FAILED, SKIPPED):
            for cell in self.cells_by_state(state):
                line = "%s %s %s shard=%s" % (
                    state.upper(),
                    cell.rule_id,
                    cell.fname,
                    "+".join(sorted(cell.shards)),
                )
                if cell.detail:
                    line += " detail=%s" % cell.detail
                lines.append(line)
        return "\n".join(lines)
