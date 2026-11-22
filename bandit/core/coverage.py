"""Offline-mergeable coverage ledger for Bandit runs.

A coverage ledger records, at rule x file granularity, what actually
happened during a scan:

- ``selected``: the rule was selected by the profile for the run, but
  no execution outcome was recorded for the file (a coverage gap).
- ``completed``: the rule executed to completion on the file.
- ``failed``: the rule raised an error while executing on the file.
- ``not_applicable``: the rule was skipped because none of the AST node
  types it checks appeared in the file.

Ledgers are plain JSON so they can be stitched together offline. Two
ledgers may only fill each other's gaps when their source digest and
config (rule selection) digest match. Re-running the same shard may
replace the cells that shard owns; conflicting cells reported by
different shards are kept and surfaced as conflicts.
"""
import argparse
import hashlib
import json
import logging
import sys

LOG = logging.getLogger(__name__)

LEDGER_VERSION = 1

STATE_SELECTED = "selected"
STATE_COMPLETED = "completed"
STATE_FAILED = "failed"
STATE_NOT_APPLICABLE = "not_applicable"
STATE_CONFLICT = "conflict"

STATES = (
    STATE_SELECTED,
    STATE_COMPLETED,
    STATE_FAILED,
    STATE_NOT_APPLICABLE,
)

# states that mean "this cell is genuinely covered" for gate purposes
COVERING_STATES = (STATE_COMPLETED, STATE_NOT_APPLICABLE)

_STATE_SYMBOLS = {
    STATE_SELECTED: "?",
    STATE_COMPLETED: "ok",
    STATE_FAILED: "FAIL",
    STATE_NOT_APPLICABLE: "-",
    STATE_CONFLICT: "CONFLICT",
}


def _digest_lines(lines):
    """Stable sha256 digest over an iterable of strings."""
    digest = hashlib.sha256()
    for line in lines:
        digest.update(line.encode("utf-8"))
        digest.update(b"\n")
    return f"sha256:{digest.hexdigest()}"


def file_digest(data):
    """Digest of a single source file's bytes."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def source_digest(file_digests):
    """Digest over the sorted (name, digest) pairs of all source files."""
    lines = [
        f"{digest}  {fname}" for fname, digest in sorted(file_digests.items())
    ]
    return _digest_lines(lines)


def config_digest(rule_ids):
    """Digest over the sorted set of selected rule ids."""
    return _digest_lines(sorted(rule_ids))


def _is_blacklist_config(config):
    """Detect a blacklist-style config: node -> list of dicts with ids."""
    if not isinstance(config, dict) or not config:
        return False
    for value in config.values():
        if not isinstance(value, list):
            return False
        for item in value:
            if not isinstance(item, dict) or "id" not in item:
                return False
    return True


def rule_ids_for_test(test, checktype):
    """Return the rule ids a test function covers for a node type.

    Regular plugins cover exactly their own test id. The blacklist
    plugin (B001) covers each individual blacklist id registered for
    the given node type.
    """
    config = getattr(test, "_config", None)
    if _is_blacklist_config(config):
        return [item["id"] for item in config.get(checktype, [])]
    return [getattr(test, "_test_id", "B000")]


def extract_rules(testset):
    """Map every selected rule id to the node types it checks.

    :param testset: a bandit.core.test_set.BanditTestSet instance
    :return: dict of rule id -> set of node type names
    """
    rules = {}
    for checktype, tests in testset.tests.items():
        for test in tests:
            for rule_id in rule_ids_for_test(test, checktype):
                rules.setdefault(rule_id, set()).add(checktype)
    return rules


class CoverageLedger:
    """Records rule x file coverage for one shard of one run."""

    def __init__(self, shard_id="default"):
        self.shard_id = shard_id
        self.rules = []
        self.files = {}
        self.cells = {}

    def set_rules(self, rule_ids):
        """Record the selected rule set (the config selection)."""
        self.rules = sorted(rule_ids)

    def begin_file(self, fname, digest):
        """Start coverage for a file; every selected rule starts selected."""
        self.files[fname] = digest
        for rule_id in self.rules:
            self.cells.setdefault((rule_id, fname), STATE_SELECTED)

    def note_completed(self, rule_id, fname):
        """Record a rule that ran to completion on a file."""
        key = (rule_id, fname)
        if self.cells.get(key) != STATE_FAILED:
            self.cells[key] = STATE_COMPLETED

    def note_failed(self, rule_id, fname):
        """Record a rule that raised while running on a file."""
        self.cells[(rule_id, fname)] = STATE_FAILED

    def end_file(self, fname, checktypes_seen, rule_checks):
        """Close out a file after its AST has been fully visited.

        Rules that were selected but never executed are marked
        ``not_applicable`` when none of the node types they check
        appeared in the file. Anything left in ``selected`` state is a
        genuine coverage gap.
        """
        for rule_id in self.rules:
            key = (rule_id, fname)
            if self.cells.get(key) != STATE_SELECTED:
                continue
            checks = rule_checks.get(rule_id, set())
            if not checks.intersection(checktypes_seen):
                self.cells[key] = STATE_NOT_APPLICABLE

    def record_outcomes(self, fname, outcomes, checktypes_seen, rule_checks):
        """Apply per-rule outcomes collected by a BanditTester."""
        for rule_id, state in outcomes.items():
            if state == STATE_FAILED:
                self.note_failed(rule_id, fname)
            else:
                self.note_completed(rule_id, fname)
        self.end_file(fname, checktypes_seen, rule_checks)

    @property
    def source_digest(self):
        return source_digest(self.files)

    @property
    def config_digest(self):
        return config_digest(self.rules)

    def compatibility_key(self):
        """Ledgers may only fill each other's gaps within the same key."""
        return (self.source_digest, self.config_digest)

    def to_dict(self):
        cells = [
            {"rule": rule_id, "file": fname, "state": state}
            for (rule_id, fname), state in sorted(self.cells.items())
        ]
        return {
            "version": LEDGER_VERSION,
            "shard_id": self.shard_id,
            "source_digest": self.source_digest,
            "config_digest": self.config_digest,
            "rules": list(self.rules),
            "files": dict(sorted(self.files.items())),
            "cells": cells,
        }

    @classmethod
    def from_dict(cls, data):
        if data.get("version") != LEDGER_VERSION:
            raise ValueError(
                f"unsupported coverage ledger version: {data.get('version')}"
            )
        ledger = cls(shard_id=data.get("shard_id", "default"))
        ledger.rules = sorted(data.get("rules", []))
        ledger.files = dict(data.get("files", {}))
        for cell in data.get("cells", []):
            state = cell["state"]
            if state not in STATES:
                raise ValueError(f"unknown coverage state: {state}")
            ledger.cells[(cell["rule"], cell["file"])] = state
        return ledger

    def save(self, path):
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(self.to_dict(), fp, indent=2, sort_keys=True)
            fp.write("\n")

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fp:
            return cls.from_dict(json.load(fp))


class MergedCoverage:
    """Offline merge of several ledgers.

    Ledgers are grouped by (source digest, config digest); only ledgers
    in the same group may fill each other's gaps. Within a group a
    shard may replace its own cells (a re-run), while disagreeing cells
    from different shards are recorded as conflicts.

    A cell left in ``selected`` state is an unknown: another shard in
    the same group may fill it without conflict. Only differing
    definitive states (completed/failed/not_applicable) reported by
    different shards count as conflicts.
    """

    def __init__(self):
        self.groups = {}
        self.incompatible = []
        self._conflict_logged = set()

    def add(self, ledger):
        key = ledger.compatibility_key()
        group = self.groups.setdefault(
            key,
            {
                "rules": set(),
                "files": {},
                "cell_states": {},
            },
        )
        group["rules"].update(ledger.rules)
        group["files"].update(ledger.files)
        for cell_key, state in ledger.cells.items():
            shard = ledger.shard_id
            states = group["cell_states"].setdefault(cell_key, {})
            # a re-run of the same shard replaces its own cell
            states[shard] = state
            definitive = {
                s for s in states.values() if s != STATE_SELECTED
            }
            if len(definitive) > 1 and cell_key not in self._conflict_logged:
                self._conflict_logged.add(cell_key)
                rule_id, fname = cell_key
                LOG.warning(
                    "coverage conflict for %s on %s: %s",
                    rule_id,
                    fname,
                    states,
                )

    @staticmethod
    def _resolve(states):
        """Collapse per-shard states of a cell into one merged state."""
        definitive = {s for s in states.values() if s != STATE_SELECTED}
        if not definitive:
            return STATE_SELECTED
        if len(definitive) == 1:
            return definitive.pop()
        return STATE_CONFLICT

    @classmethod
    def _group_cells(cls, group):
        return {
            cell_key: cls._resolve(states)
            for cell_key, states in group["cell_states"].items()
        }

    @property
    def conflicts(self):
        """Cells where shards report differing definitive states."""
        result = []
        for group in self.groups.values():
            for cell_key, states in sorted(group["cell_states"].items()):
                definitive = {
                    shard: state
                    for shard, state in states.items()
                    if state != STATE_SELECTED
                }
                if len(set(definitive.values())) > 1:
                    rule_id, fname = cell_key
                    result.append(
                        {
                            "rule": rule_id,
                            "file": fname,
                            "states": dict(sorted(definitive.items())),
                        }
                    )
        return result

    def evaluate(self):
        """Return a list of gate failure reasons; empty means pass."""
        reasons = []
        for conflict in self.conflicts:
            reasons.append(
                "conflicting coverage for rule "
                f"{conflict['rule']} on {conflict['file']}: "
                + ", ".join(
                    f"{shard}={state}"
                    for shard, state in sorted(conflict["states"].items())
                )
            )
        for (src_digest, cfg_digest), group in sorted(self.groups.items()):
            label = f"source {src_digest[:19]}... config {cfg_digest[:19]}..."
            cells = self._group_cells(group)
            for (rule_id, fname), state in sorted(cells.items()):
                if state in COVERING_STATES:
                    continue
                if state == STATE_FAILED:
                    reasons.append(
                        f"rule {rule_id} failed on {fname} ({label})"
                    )
                elif state == STATE_CONFLICT:
                    continue  # already reported above
                else:
                    reasons.append(
                        f"coverage gap: rule {rule_id} on {fname} "
                        f"is '{state}' ({label})"
                    )
        return reasons

    def to_dict(self):
        groups = []
        for (src_digest, cfg_digest), group in sorted(self.groups.items()):
            cells = [
                {"rule": rule_id, "file": fname, "state": state}
                for (rule_id, fname), state in sorted(
                    self._group_cells(group).items()
                )
            ]
            groups.append(
                {
                    "source_digest": src_digest,
                    "config_digest": cfg_digest,
                    "rules": sorted(group["rules"]),
                    "files": dict(sorted(group["files"].items())),
                    "cells": cells,
                }
            )
        return {
            "version": LEDGER_VERSION,
            "groups": groups,
            "conflicts": self.conflicts,
        }


def merge_ledgers(ledgers):
    """Merge ledgers, keeping incompatible digest groups separate."""
    merged = MergedCoverage()
    keys = set()
    for ledger in ledgers:
        key = ledger.compatibility_key()
        if keys and key not in keys:
            merged.incompatible.append(ledger.shard_id)
            LOG.warning(
                "ledger shard %s has a different source/config digest; "
                "it cannot fill gaps of the other shards",
                ledger.shard_id,
            )
        keys.add(key)
        merged.add(ledger)
    return merged


def render_table(merged):
    """Render a rule x file coverage table for a merged coverage view."""
    lines = []
    legend = (
        "legend: ok=completed FAIL=failed -=not-applicable "
        "?=selected(gap) CONFLICT=shards disagree .=no data"
    )
    for (src_digest, cfg_digest), group in sorted(merged.groups.items()):
        rules = sorted(group["rules"])
        files = sorted(group["files"])
        cells = MergedCoverage._group_cells(group)
        lines.append(f"source digest: {src_digest}")
        lines.append(f"config digest: {cfg_digest}")
        name_width = max([len(fname) for fname in files] + [4])
        header = "rule".ljust(10) + "".join(
            fname.rjust(name_width + 2) for fname in files
        )
        lines.append(header)
        for rule_id in rules:
            row = rule_id.ljust(10)
            for fname in files:
                state = cells.get((rule_id, fname))
                symbol = _STATE_SYMBOLS.get(state, ".")
                row += symbol.rjust(name_width + 2)
            lines.append(row)
        lines.append("")
    if merged.conflicts:
        lines.append("conflicts:")
        for conflict in merged.conflicts:
            states = ", ".join(
                f"{shard}={state}"
                for shard, state in sorted(conflict["states"].items())
            )
            lines.append(
                f"  {conflict['rule']} on {conflict['file']}: {states}"
            )
        lines.append("")
    lines.append(legend)
    return "\n".join(lines) + "\n"


def _cmd_merge(args):
    ledgers = [CoverageLedger.load(path) for path in args.ledgers]
    merged = merge_ledgers(ledgers)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fp:
            json.dump(merged.to_dict(), fp, indent=2, sort_keys=True)
            fp.write("\n")
    table = render_table(merged)
    if args.table:
        with open(args.table, "w", encoding="utf-8") as fp:
            fp.write(table)
    else:
        sys.stdout.write(table)
    reasons = merged.evaluate()
    return _report_gate(reasons)


def _cmd_gate(args):
    ledger = CoverageLedger.load(args.ledger)
    merged = merge_ledgers([ledger])
    if args.table:
        sys.stdout.write(render_table(merged))
    reasons = merged.evaluate()
    return _report_gate(reasons)


def _cmd_table(args):
    ledgers = [CoverageLedger.load(path) for path in args.ledgers]
    merged = merge_ledgers(ledgers)
    sys.stdout.write(render_table(merged))
    return 0


def _report_gate(reasons):
    if reasons:
        print("coverage gate: FAIL")
        for reason in reasons:
            print(f"  - {reason}")
        return 1
    print("coverage gate: PASS")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="bandit-coverage",
        description="Merge and evaluate Bandit coverage ledgers offline",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    merge_parser = subparsers.add_parser(
        "merge", help="merge ledgers and evaluate the coverage gate"
    )
    merge_parser.add_argument("ledgers", nargs="+", help="ledger JSON files")
    merge_parser.add_argument(
        "-o", "--output", help="write merged coverage JSON to this file"
    )
    merge_parser.add_argument(
        "--table", help="write the rule x file coverage table to this file"
    )
    merge_parser.set_defaults(func=_cmd_merge)

    gate_parser = subparsers.add_parser(
        "gate", help="evaluate the coverage gate for a single ledger"
    )
    gate_parser.add_argument("ledger", help="ledger JSON file")
    gate_parser.add_argument(
        "--table",
        action="store_true",
        help="also print the rule x file coverage table",
    )
    gate_parser.set_defaults(func=_cmd_gate)

    table_parser = subparsers.add_parser(
        "table", help="print the rule x file coverage table"
    )
    table_parser.add_argument("ledgers", nargs="+", help="ledger JSON files")
    table_parser.set_defaults(func=_cmd_table)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
