#
# SPDX-License-Identifier: Apache-2.0
r"""
=================================================
B114: Restricted export missing match authorization
=================================================

Data export entry points commonly dispatch on a closed set of inputs (for
example a department identifier and an action name) using a Python 3.10
structural pattern matching statement::

    match (department, action):
        case ("dept_a", "export") if is_admin(user):
            export_customer_pii()
        case ("dept_a", _):
            ...

The order of the ``case`` clauses matters: a broad earlier clause shadows
everything below it, an ``or`` pattern may silently widen a clause, capture
patterns bind any value, and a guard makes a clause conditional.  Reviewing
this coverage by eye is error prone.

This plugin is given a *closed* input domain in its configuration: the
subjects (the names matched on), the finite value set for each subject, the
calls that perform restricted exports, and the authorization predicates that
satisfy a restricted export.  It then enumerates every concrete input
combination and, for each one, walks the ``match`` statement exactly as the
interpreter does.

An issue is only raised when a concrete witness input can be proven to reach a
restricted export call without a satisfied authorization predicate.  The
issue text names the winning ``case`` clause (including its line number), so
the clause that shadows a later authorization condition is identified
directly.  Guards that cannot be evaluated from the closed configuration are
never guessed: they produce a separate, low confidence analysis-gap finding
instead.

Files that do not use ``match`` (including source written in older Python
dialects) are untouched and continue through the usual checks.

**Config Options:**

.. code-block:: yaml

    match_export_authorization:
      # Names of the matched-on variables, in the order used in the match
      # subject tuple.
      subjects:
        - department
        - action
      # The finite, closed set of values each subject may take.
      domains:
        department:
          - dept_a
          - dept_b
        action:
          - view
          - export
          - bulk_export
      # Calls whose execution moves data across the export boundary.  Names
      # are matched against the call's function name and qualified name.
      restricted_calls:
          - export_customer_pii
          - bulk_export_customer_pii
      # Predicate calls that count as an authorization check.  A restricted
      # export is authorized only when one of these holds on the winning
      # path (a guard on the winning case or an ``if`` in its body).
      authorization_calls:
          - is_admin
          - has_export_grant

:Example:

.. code-block:: none

    >> Issue: [B114:match_export_authorization] Restricted export call
       'export_customer_pii' reachable without authorization for witness
       department='dept_a', action='bulk_export'; matched by case on line 8
       ('case ("dept_a", _)' shadows the later authorization case)
       Severity: High   Confidence: High
       CWE: CWE-284 (https://cwe.mitre.org/data/definitions/284.html)
       Location: ./examples/match_export_authorization.py:9

.. seealso::

 - https://docs.python.org/3/reference/compound_stmts.html#the-match-statement
 - https://cwe.mitre.org/data/definitions/284.html

.. versionadded:: 1.8.6
"""
import ast
import itertools

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


def gen_config(name):
    if name == "match_export_authorization":
        return {
            "subjects": ["department", "action"],
            "domains": {
                "department": ["dept_a", "dept_b"],
                "action": ["view", "export", "bulk_export"],
            },
            "restricted_calls": [
                "export_customer_pii",
                "bulk_export_customer_pii",
            ],
            "authorization_calls": ["is_admin", "has_export_grant"],
        }
    return None


class _UnknownGuard(Exception):
    """Raised when a guard cannot be evaluated against the closed domain."""


def _constant(node):
    """Return the literal value of an ast.Constant, else ``None``."""
    if isinstance(node, ast.Constant):
        return node.value
    return None


def _call_name(node):
    """Best-effort readable name for a call node."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _pattern_matches(pattern, value, bindings):
    """Evaluate a match pattern against a concrete value.

    ``bindings`` maps capture names to the values they are bound to.  The
    closed input domain only contains literals, so value patterns compare
    literals, sequence patterns require equal length, and wildcard/capture
    patterns accept anything.  Unsupported pattern shapes (mappings, class
    patterns) cannot be reasoned about on a literal domain and therefore do
    not match.
    """
    if isinstance(pattern, ast.MatchValue):
        return _constant(pattern.value) == value
    if isinstance(pattern, ast.MatchSingleton):
        return value is pattern.value
    if isinstance(pattern, ast.MatchAs):
        if pattern.pattern is not None and not _pattern_matches(
            pattern.pattern, value, bindings
        ):
            return False
        if pattern.name is not None:
            bindings[pattern.name] = value
        return True
    if isinstance(pattern, ast.MatchOr):
        return any(
            _pattern_matches(alternative, value, bindings)
            for alternative in pattern.patterns
        )
    if isinstance(pattern, ast.MatchSequence):
        if not isinstance(value, tuple) or len(pattern.patterns) != len(
            value
        ):
            return False
        return all(
            _pattern_matches(sub_pattern, sub_value, bindings)
            for sub_pattern, sub_value in zip(pattern.patterns, value)
        )
    return False


def _eval_authorized(node, bindings, config):
    """Evaluate an authorization expression on a fully bound witness.

    Only ``and``/``or``/``not`` expressions and calls to configured
    authorization predicates with literal or capture-bound arguments are
    understood.  Anything else raises :class:`_UnknownGuard`.
    """
    if isinstance(node, ast.BoolOp):
        values = [
            _eval_authorized(value, bindings, config) for value in node.values
        ]
        if isinstance(node.op, ast.And):
            return all(values)
        return any(values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_authorized(node.operand, bindings, config)
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name not in set(config["authorization_calls"]):
            raise _UnknownGuard(name)
        keyword_values = (kw.value for kw in node.keywords)
        for arg in itertools.chain(node.args, keyword_values):
            if _resolved_value(arg, bindings) is _UNKNOWN:
                raise _UnknownGuard(name)
        return True
    raise _UnknownGuard(ast.dump(node))


_UNKNOWN = object()


def _resolved_value(node, bindings):
    """Resolve an expression to a literal using capture bindings.

    Returns the sentinel :data:`_UNKNOWN` when the expression is outside the
    closed vocabulary.
    """
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return bindings.get(node.id, _UNKNOWN)
    if isinstance(node, ast.UnaryOp) and isinstance(
        node.op, ast.USub
    ):
        operand = _resolved_value(node.operand, bindings)
        if operand is _UNKNOWN:
            return _UNKNOWN
        return -operand
    return _UNKNOWN


def _contains_restricted_call(node, restricted_names):
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Call)
            and _call_name(child) in restricted_names
        ):
            return child
    return None


def _nested_authorization(stmt, bindings, config):
    """Whether a guarded ``if`` authorizes every restricted call beneath it.

    A restricted call nested in a case body is authorized when it is guarded
    by an authorizing ``if`` test.  Unresolved tests are reported as analysis
    gaps rather than being treated as a pass or failure.
    """
    unknown = []

    def walk(current, authorized):
        if isinstance(current, ast.If):
            try:
                granted = _eval_authorized(
                    current.test, bindings, config
                )
            except _UnknownGuard:
                unknown.append(current)
                granted = False
            for child in current.body:
                walk(child, authorized or granted)
            for child in current.orelse:
                walk(child, authorized)
            return
        if (
            authorized
            and isinstance(current, ast.Call)
            and _call_name(current) in restricted
        ):
            authorized_calls.add(id(current))
        for child in ast.iter_child_nodes(current):
            walk(child, authorized)

    restricted = set(config["restricted_calls"])
    authorized_calls = set()
    walk(stmt, False)
    return authorized_calls, unknown


def _subject_names(match_node):
    """Names of a tuple-shaped match subject, or a single name."""
    subject = match_node.subject
    if isinstance(subject, ast.Tuple):
        names = []
        for element in subject.elts:
            if not isinstance(element, ast.Name):
                return None
            names.append(element.id)
        return names
    if isinstance(subject, ast.Name):
        return [subject.id]
    return None


def _witness_label(subjects, witness):
    return ", ".join(
        f"{name}={value!r}" for name, value in zip(subjects, witness)
    )


def _case_signature(case_node):
    """Compact source-like description of a case pattern."""
    signature = "case " + ast.unparse(case_node.pattern)
    if case_node.guard is not None:
        signature += " if " + ast.unparse(case_node.guard)
    return signature


@test.takes_config
@test.checks("Match")
@test.test_id("B114")
def match_export_authorization(context, config):
    match_node = context.node
    subjects = _subject_names(match_node)
    configured_subjects = list(config.get("subjects", []))
    if subjects is None or subjects != configured_subjects:
        return None

    domains = config.get("domains", {})
    if any(subject not in domains for subject in subjects):
        return None
    restricted = set(config["restricted_calls"])

    violations = []
    gap_lines = set()
    witness_space = itertools.product(
        *(domains[subject] for subject in subjects)
    )
    for witness in witness_space:
        value = witness[0] if len(witness) == 1 else tuple(witness)
        bindings = dict(zip(subjects, witness))
        for case_node in match_node.cases:
            case_bindings = dict(bindings)
            if not _pattern_matches(
                case_node.pattern, value, case_bindings
            ):
                continue
            if case_node.guard is not None:
                try:
                    guard_passed = _eval_authorized(
                        case_node.guard, case_bindings, config
                    )
                except _UnknownGuard:
                    gap_lines.add(case_node.guard.lineno)
                    break
                if not guard_passed:
                    continue
            else:
                guard_passed = False
            restricted_call = _contains_restricted_call(
                case_node, restricted
            )
            if restricted_call is None:
                break
            authorized_calls, unknown_ifs = _nested_authorization(
                case_node, case_bindings, config
            )
            for unknown_if in unknown_ifs:
                gap_lines.add(unknown_if.test.lineno)
            if (
                not guard_passed
                and id(restricted_call) not in authorized_calls
            ):
                violations.append(
                    {
                        "witness": _witness_label(subjects, witness),
                        "call": _call_name(restricted_call),
                        "case_line": case_node.pattern.lineno,
                        "case": _case_signature(case_node),
                    }
                )
            break

    if not violations and not gap_lines:
        return None

    lines = []
    for violation in violations:
        lines.append(
            "Restricted export call "
            f"'{violation['call']}' reachable without authorization for "
            f"witness {violation['witness']}; matched by case on line "
            f"{violation['case_line']} ('{violation['case']}' shadows the "
            "later authorization condition)"
        )
    for line in sorted(gap_lines):
        lines.append(
            "Analysis gap: guard on line "
            f"{line} cannot be evaluated from the configured closed "
            "vocabulary; authorization coverage for inputs passing this "
            "guard is undecided"
        )

    if violations:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
            text="; ".join(lines),
        )
    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.LOW,
        cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
        text="; ".join(lines),
    )
