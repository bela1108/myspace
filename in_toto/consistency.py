# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Module Name>
  in_toto/consistency.py

<Purpose>
  Post-verification ordering consistency check.

  in-toto verification proves that every link is authentic and that its
  recorded materials and products match the signed digests.  It does
  not prove that the links tell one coherent story: three parallel
  build steps may each carry a perfectly valid signature and still have
  read mutually incompatible versions of the release history.

  This module checks whether the steps of a finite layout could have
  executed in at least one order such that

    * every step's materials hold in the state that precedes it,
    * every step's products take effect together when the step ends,
    * the known ordering constraints are respected, and
    * the state after the last step equals the final summary exactly.

  A path may legitimately return to an older digest (e.g. a revert
  step); only the state at each step boundary matters.

  If at least one complete order exists, it is returned and the
  presence of further orders is flagged.  Otherwise a replayable
  report lists, for every reachable prefix, which step is blocked on
  which material, or which final summary entry mismatches.
"""

import itertools
from collections import deque
from dataclasses import dataclass, field


def _normalize_digest(digest):
    """Return a hashable canonical form for a digest value.

    Accepts a plain string or an in-toto style algorithm-to-hash dict.
    """
    if isinstance(digest, dict):
        return tuple(sorted(digest.items()))
    return digest


def _format_digest(digest):
    """Render a canonical digest for human-readable reports."""
    if digest is None:
        return "<absent>"
    if isinstance(digest, tuple):
        return ", ".join(f"{alg}:{hexdigest}" for alg, hexdigest in digest)
    return str(digest)


def _normalize_record(record, what):
    """Normalize a path-to-digest mapping, rejecting non-dict input."""
    if not isinstance(record, dict):
        raise ValueError(f"{what} must be a dict of path to digest")
    return {path: _normalize_digest(digest) for path, digest in record.items()}


@dataclass(frozen=True)
class Step:
    """One build step with the digests it requires and produces."""

    name: str
    materials: dict
    products: dict


class Problem:
    """A finite step-ordering consistency problem.

    Attributes:
      initial: Dict of path to canonical digest holding before any step.
      steps: List of Step; each step executes exactly once.
      predecessors: Dict of step index to set of indexes that must
        complete earlier (the known ordering constraints).
      final: Dict of path to canonical digest expected after the last
        step.  The final summary is matched exactly: every path of the
        resulting state must appear in it and vice versa.
    """

    def __init__(self, initial, steps, constraints, final):
        names = [step.name for step in steps]
        if len(set(names)) != len(names):
            raise ValueError("step names must be unique")
        index_of = {name: i for i, name in enumerate(names)}
        predecessors = {i: set() for i in range(len(steps))}
        for before, after in constraints:
            if before not in index_of or after not in index_of:
                raise ValueError(
                    f"constraint ({before!r}, {after!r}) names an unknown step"
                )
            if before == after:
                raise ValueError(f"step {before!r} cannot precede itself")
            predecessors[index_of[after]].add(index_of[before])
        self.initial = initial
        self.steps = list(steps)
        self.predecessors = predecessors
        self.final = final


def load_problem(spec):
    """Build a Problem from a plain dict, e.g. decoded JSON.

    The spec maps "initial" and "final" to path-to-digest records,
    "steps" to a list of {"name", "materials", "products"} dicts, and
    "constraints" to a list of [before, after] step-name pairs.
    Digests are strings or in-toto {algorithm: hexdigest} dicts.
    """
    try:
        initial = _normalize_record(spec["initial"], "initial")
        final = _normalize_record(spec["final"], "final")
        steps = [
            Step(
                name=entry["name"],
                materials=_normalize_record(
                    entry.get("materials", {}), "materials"
                ),
                products=_normalize_record(
                    entry.get("products", {}), "products"
                ),
            )
            for entry in spec["steps"]
        ]
        constraints = [tuple(pair) for pair in spec.get("constraints", [])]
    except KeyError as error:
        raise ValueError(f"missing spec key: {error}") from error
    for pair in constraints:
        if len(pair) != 2:
            raise ValueError("constraints must be [before, after] pairs")
    return Problem(initial, steps, constraints, final)


def _state_key(state):
    return tuple(sorted(state.items()))


def _apply(step, state):
    """Return a new state with the step's products in effect."""
    next_state = dict(state)
    next_state.update(step.products)
    return next_state


def _material_mismatches(state, step):
    """List (path, expected, actual) for each material not holding."""
    return [
        (path, expected, state.get(path))
        for path, expected in step.materials.items()
        if state.get(path) != expected
    ]


def _final_mismatches(problem, state):
    """List (path, expected, actual) where state and final disagree."""
    mismatches = [
        (path, expected, state.get(path))
        for path, expected in problem.final.items()
        if state.get(path) != expected
    ]
    mismatches += [
        (path, None, actual)
        for path, actual in state.items()
        if path not in problem.final
    ]
    return mismatches


def _successors(problem, state, done):
    """Indexes of steps that may run next from state/done."""
    return [
        i
        for i, step in enumerate(problem.steps)
        if i not in done
        and problem.predecessors[i] <= done
        and not _material_mismatches(state, step)
    ]


def _solution_counts(problem, limit):
    """Map (state key, done) to number of completions, capped at limit."""
    counts = {}

    def rec(state, done):
        key = (_state_key(state), done)
        if key in counts:
            return counts[key]
        if len(done) == len(problem.steps):
            total = 1 if not _final_mismatches(problem, state) else 0
        else:
            total = 0
            for i in _successors(problem, state, done):
                total += rec(_apply(problem.steps[i], state), done | {i})
                if total >= limit:
                    total = limit
                    break
        counts[key] = total
        return total

    rec(dict(problem.initial), frozenset())
    return counts


def find_orders(problem, limit=2):
    """Return up to limit complete orders (lists of step names).

    Every returned order replays from the initial state to exactly the
    final summary while respecting the known ordering constraints.
    Pass limit=None to enumerate all orders (exponential in general).
    """
    cap = limit if limit is not None else len(problem.steps) + 1
    counts = _solution_counts(problem, cap)
    orders = []

    def rec(state, done, prefix):
        if limit is not None and len(orders) >= limit:
            return
        if len(done) == len(problem.steps):
            orders.append([problem.steps[i].name for i in prefix])
            return
        for i in _successors(problem, state, done):
            next_state = _apply(problem.steps[i], state)
            next_done = done | {i}
            if counts.get((_state_key(next_state), next_done), 0) > 0:
                rec(next_state, next_done, prefix + (i,))

    rec(dict(problem.initial), frozenset(), ())
    return orders


def brute_force_orders(problem):
    """All valid complete orders by exhaustive permutation.

    Intended as a reference to cross-check find_orders on small inputs.
    """
    valid = []
    for perm in itertools.permutations(range(len(problem.steps))):
        position = {step: pos for pos, step in enumerate(perm)}
        if any(
            position[pre] > position[i]
            for i, preds in problem.predecessors.items()
            for pre in preds
        ):
            continue
        state = dict(problem.initial)
        for i in perm:
            step = problem.steps[i]
            if _material_mismatches(state, step):
                break
            state = _apply(step, state)
        else:
            if not _final_mismatches(problem, state):
                valid.append([problem.steps[i].name for i in perm])
    return valid


class ReplayError(Exception):
    """A prefix cannot be replayed from the initial state as claimed."""


def replay(problem, prefix):
    """Replay step names from the initial state; return the end state.

    Raises ReplayError if a step is unknown, repeated, misses a
    predecessor, or finds a material that does not hold.
    """
    state = dict(problem.initial)
    done = set()
    by_name = {step.name: i for i, step in enumerate(problem.steps)}
    for name in prefix:
        if name not in by_name:
            raise ReplayError(f"unknown step {name!r}")
        i = by_name[name]
        if i in done:
            raise ReplayError(f"step {name!r} executed twice")
        unmet = [
            problem.steps[pre].name
            for pre in problem.predecessors[i]
            if pre not in done
        ]
        if unmet:
            raise ReplayError(
                f"step {name!r} misses predecessors: {', '.join(unmet)}"
            )
        failing = _material_mismatches(state, problem.steps[i])
        if failing:
            details = "; ".join(
                f"{path}: expected {_format_digest(expected)}, "
                f"found {_format_digest(actual)}"
                for path, expected, actual in failing
            )
            raise ReplayError(f"step {name!r} blocked on: {details}")
        state = _apply(problem.steps[i], state)
        done.add(i)
    return state


@dataclass
class StepBlocker:
    """Why one remaining step cannot run after a prefix."""

    step: str
    unmet_predecessors: list = field(default_factory=list)
    failing_materials: list = field(default_factory=list)


@dataclass
class PrefixReport:
    """One reachable prefix and what can or cannot happen next.

    Attributes:
      prefix: Step names replayable from the initial state.
      next_steps: Steps that may run immediately after this prefix.
      blockers: StepBlocker for each remaining step that cannot run.
      final_mismatches: (path, expected, actual) entries; only set on
        complete prefixes, where every step has executed.
    """

    prefix: list
    next_steps: list = field(default_factory=list)
    blockers: list = field(default_factory=list)
    final_mismatches: list = field(default_factory=list)


def build_unsat_report(problem):
    """List every reachable prefix with its continuations or blockers.

    Prefixes that lead to the same state and completed-step set are
    merged; the recorded prefix is one replayable representative.
    """
    reports = []
    seen = set()
    queue = deque([(dict(problem.initial), frozenset(), ())])
    while queue:
        state, done, prefix = queue.popleft()
        key = (_state_key(state), done)
        if key in seen:
            continue
        seen.add(key)
        names = [problem.steps[i].name for i in prefix]
        if len(done) == len(problem.steps):
            reports.append(
                PrefixReport(
                    prefix=names,
                    final_mismatches=_final_mismatches(problem, state),
                )
            )
            continue
        next_steps = []
        blockers = []
        for i, step in enumerate(problem.steps):
            if i in done:
                continue
            unmet = [
                problem.steps[pre].name
                for pre in problem.predecessors[i]
                if pre not in done
            ]
            if unmet:
                blockers.append(StepBlocker(step.name, unmet, []))
                continue
            failing = _material_mismatches(state, step)
            if failing:
                blockers.append(StepBlocker(step.name, [], failing))
            else:
                next_steps.append(step.name)
                queue.append((_apply(step, state), done | {i}, prefix + (i,)))
        reports.append(PrefixReport(names, next_steps, blockers, []))
    return reports


def format_report(problem, report):
    """Render an unsat report as replayable, human-readable lines."""
    lines = []
    for entry in report:
        head = " -> ".join(entry.prefix) or "(initial state)"
        if len(entry.prefix) == len(problem.steps):
            lines.append(
                f"[{head}]: all steps executed, final summary mismatches:"
            )
            for path, expected, actual in entry.final_mismatches:
                lines.append(
                    f"  {path}: expected {_format_digest(expected)}, "
                    f"found {_format_digest(actual)}"
                )
        elif not entry.next_steps:
            lines.append(f"[{head}]: stuck, no remaining step can run")
        else:
            lines.append(
                f"[{head}]: can continue with " + ", ".join(entry.next_steps)
            )
        for blocker in entry.blockers:
            if blocker.unmet_predecessors:
                lines.append(
                    f"  {blocker.step}: waits for "
                    + ", ".join(blocker.unmet_predecessors)
                )
            for path, expected, actual in blocker.failing_materials:
                lines.append(
                    f"  {blocker.step}: material {path} expected "
                    f"{_format_digest(expected)}, "
                    f"found {_format_digest(actual)}"
                )
    return "\n".join(lines)


@dataclass
class ConsistencyResult:
    """Outcome of check_consistency.

    Attributes:
      satisfiable: Whether at least one complete order exists.
      orders: Up to order_limit complete orders (empty if unsat).
      multiple: Whether more than one complete order exists.
      report: Replayable per-prefix blocker report (only when unsat).
    """

    satisfiable: bool
    orders: list = field(default_factory=list)
    multiple: bool = False
    report: list = field(default_factory=list)


def check_consistency(problem, order_limit=2):
    """Check whether the steps admit a consistent complete order.

    Accepts a Problem or a plain spec dict (see load_problem).  Finds
    at least one complete order and flags whether more exist; if none
    exists, attaches a replayable report of every reachable prefix.
    """
    if not isinstance(problem, Problem):
        problem = load_problem(problem)
    orders = find_orders(problem, limit=order_limit)
    if orders:
        return ConsistencyResult(
            satisfiable=True, orders=orders, multiple=len(orders) > 1
        )
    return ConsistencyResult(
        satisfiable=False, report=build_unsat_report(problem)
    )
