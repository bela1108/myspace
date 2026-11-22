#
# SPDX-License-Identifier: Apache-2.0
"""Local scan-budget accounting for bandit.

This module sits between bandit's rule registry
(:mod:`bandit.core.extension_loader`) and its scan statistics
(:mod:`bandit.core.metrics`).  It answers a question the regular scanner
cannot answer when a run is cut short by a fixed budget: which minimum
checks of each audit domain were actually proven, and which were never
examined?

Accounting rules
----------------

* Every audit domain owns a fixed quota.  A rule skipped on one file
  because that domain's quota is exhausted is simply never executed and
  no budget is borrowed from, or pre-charged to, another domain.
* Parsing a file into an AST is shared infrastructure.  Each frozen
  source is parsed at most once per run, no matter how many domains or
  rules inspect it.
* A rule execution costs one budget unit the first time a domain applies
  it to a file.  Domains sharing a rule each pay for their own
  application, but proven coverage is de-duplicated globally so a rule
  shared across domains is never counted twice.
* Scheduling is canonical (domain name, file name, rule id), therefore
  replaying the same frozen sources with the same quotas yields an
  identical ledger regardless of the order the sources were supplied.
"""
from __future__ import annotations

import ast
import dataclasses
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple


class BudgetError(ValueError):
    """Base class for budget configuration errors."""


class QuotaExceeded(BudgetError):
    """Raised when an operation cannot be covered by remaining quota."""


@dataclasses.dataclass(frozen=True)
class BudgetRule:
    """A registered check that can be scheduled against source files.

    :param rule_id: bandit test id, for example ``"B102"``.
    :param check_types: AST node types the rule is registered for
        (``"Call"``, ``"Import"`` ...) or ``"File"`` for whole-file
        checks.
    """

    rule_id: str
    check_types: Tuple[str, ...]

    def __post_init__(self):
        if not self.rule_id:
            raise BudgetError("BudgetRule requires a non-empty rule_id")
        if not self.check_types:
            raise BudgetError(
                f"rule {self.rule_id!r} must register at least one check "
                "type"
            )


@dataclasses.dataclass(frozen=True)
class AuditDomain:
    """An audit domain with its minimum required checks.

    :param name: unique domain name.
    :param minimum_rules: rule ids that must be proven for the domain to
        be fully covered.  Each id must be known to the budget.
    :param quota: fixed number of rule applications the domain may pay
        for.  Must be non-negative.
    """

    name: str
    minimum_rules: Tuple[str, ...]
    quota: int

    def __post_init__(self):
        if not self.name:
            raise BudgetError("AuditDomain requires a non-empty name")
        if self.quota < 0:
            raise BudgetError(
                f"domain {self.name!r} quota must be non-negative"
            )
        if not self.minimum_rules:
            raise BudgetError(
                f"domain {self.name!r} requires at least one minimum check"
            )


@dataclasses.dataclass(frozen=True)
class SourceFile:
    """A frozen source unit offered to the budget.

    :param name: unique file name used in the ledger.
    :param source: bytes or text of the frozen source.
    """

    name: str
    source: bytes

    def __init__(self, name, source):
        if isinstance(source, str):
            source = source.encode("utf-8")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "source", source)


@dataclasses.dataclass
class DomainLedger:
    """Per-domain bookkeeping for one budget replay.

    ``spent`` never exceeds the domain quota.  ``skipped`` and
    ``unparseable`` list ``(file_name, rule_id, reason)`` triples for
    minimum checks that were not proven; their budget was never spent.
    """

    name: str
    quota: int
    spent: int = 0
    covered: List[Tuple[str, str]] = dataclasses.field(default_factory=list)
    not_applicable: List[Tuple[str, str]] = dataclasses.field(
        default_factory=list
    )
    skipped: List[Tuple[str, str, str]] = dataclasses.field(
        default_factory=list
    )
    unparseable: List[Tuple[str, str, str]] = dataclasses.field(
        default_factory=list
    )

    @property
    def remaining(self):
        return self.quota - self.spent

    def as_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass
class BudgetReport:
    """Result of one budget replay.

    Cross-domain overlap is de-duplicated: both ``proven_coverage`` and
    ``unexamined`` are global sets of ``(file_name, rule_id)`` pairs, so
    a shared rule proven by one domain is never reported twice and never
    appears as unexamined.
    """

    rules: Tuple[BudgetRule, ...]
    files: Tuple[str, ...]
    domain_ledgers: Dict[str, DomainLedger]
    proven_coverage: List[Tuple[str, str]]
    unexamined: List[Tuple[str, str]]
    parsed_files: List[str]
    unparseable_files: List[Tuple[str, str]]
    ast_reuses: int

    @property
    def total_quota(self):
        return sum(ledger.quota for ledger in self.domain_ledgers.values())

    @property
    def total_spent(self):
        return sum(ledger.spent for ledger in self.domain_ledgers.values())

    def as_dict(self):
        data = dataclasses.asdict(self)
        data["total_quota"] = self.total_quota
        data["total_spent"] = self.total_spent
        return data


# A skip predicate returns a human-readable reason when the rule must be
# skipped for the file, or None when the rule may run.
SkipPredicate = Callable[[str, BudgetRule], Optional[str]]


class CoverageBudget:
    """Replay fixed quotas against frozen sources.

    :param rules: registered rules, shared by every domain.
    :param domains: audit domains with minimum checks and quotas.
    :param files: frozen sources to scan.
    :param skip_predicate: optional callback used to model a plugin that
        refuses to examine a file.  A returned reason records the
        minimum check as skipped without spending budget.
    :param parser: optional ``(bytes) -> ast.AST`` callable, defaulting
        to :func:`ast.parse`.  Injected parsers make the budget testable
        without writing fixtures to disk.
    """

    def __init__(
        self,
        rules: Iterable[BudgetRule],
        domains: Iterable[AuditDomain],
        files: Iterable[SourceFile],
        skip_predicate: Optional[SkipPredicate] = None,
        parser: Optional[Callable[[bytes], ast.AST]] = None,
    ):
        self.rules: Dict[str, BudgetRule] = {}
        for rule in rules:
            if rule.rule_id in self.rules:
                raise BudgetError(
                    f"duplicate rule id registered: {rule.rule_id!r}"
                )
            self.rules[rule.rule_id] = rule

        self.domains: Dict[str, AuditDomain] = {}
        for domain in domains:
            if domain.name in self.domains:
                raise BudgetError(
                    f"duplicate audit domain name: {domain.name!r}"
                )
            unknown = set(domain.minimum_rules) - set(self.rules)
            if unknown:
                raise BudgetError(
                    f"domain {domain.name!r} references unknown rules: "
                    f"{sorted(unknown)}"
                )
            self.domains[domain.name] = domain

        if not self.domains:
            raise BudgetError("at least one audit domain is required")

        self.files: Dict[str, SourceFile] = {}
        for source_file in files:
            if source_file.name in self.files:
                raise BudgetError(
                    f"duplicate source file name: {source_file.name!r}"
                )
            self.files[source_file.name] = source_file

        self.skip_predicate = skip_predicate
        self.parser = parser or ast.parse

    def replay(self) -> BudgetReport:
        """Run every domain under its fixed quota and return the ledger."""
        ast_cache, parse_failures = self._parse_all()
        ledgers = {
            domain.name: DomainLedger(domain.name, domain.quota)
            for domain in self.domains.values()
        }

        ordered_domains = sorted(
            self.domains.values(), key=lambda item: item.name
        )
        for domain in ordered_domains:
            ledger = ledgers[domain.name]
            for file_name in sorted(self.files):
                if file_name in parse_failures:
                    self._record_unparseable(
                        ledger, domain, file_name,
                        parse_failures[file_name],
                    )
                    continue
                tree = ast_cache[file_name]
                for rule_id in sorted(domain.minimum_rules):
                    self._apply_rule(
                        domain,
                        ledger,
                        self.rules[rule_id],
                        file_name,
                        tree,
                    )

        return self._build_report(ledgers, ast_cache, parse_failures)

    def _parse_all(self):
        """Parse every source once, sharing the AST across all domains."""
        ast_cache: Dict[str, ast.AST] = {}
        parse_failures: Dict[str, str] = {}
        reuses = 0
        for name in sorted(self.files):
            try:
                ast_cache[name] = self.parser(self.files[name].source)
            except SyntaxError as error:
                parse_failures[name] = error.msg
        # Every domain after the first reuses the cached AST.
        if len(self.domains) > 1 and ast_cache:
            reuses = len(ast_cache) * (len(self.domains) - 1)
        self._ast_reuses = reuses
        return ast_cache, parse_failures

    def _apply_rule(self, domain, ledger, rule, file_name, tree):
        pair = (file_name, rule.rule_id)
        if not self._is_applicable(rule, tree):
            ledger.not_applicable.append(pair)
            return

        if ledger.remaining <= 0:
            ledger.skipped.append(
                (file_name, rule.rule_id, "domain quota exhausted")
            )
            return

        if self.skip_predicate is not None:
            reason = self.skip_predicate(file_name, rule)
            if reason is not None:
                # The plugin refused this file; nothing is pre-charged.
                ledger.skipped.append((file_name, rule.rule_id, reason))
                return

        ledger.spent += 1
        ledger.covered.append(pair)

    @staticmethod
    def _record_unparseable(ledger, domain, file_name, reason):
        for rule_id in sorted(domain.minimum_rules):
            ledger.unparseable.append((file_name, rule_id, reason))

    @staticmethod
    def _is_applicable(rule, tree):
        """A rule applies when its node type occurs in the cached AST."""
        wanted = set(rule.check_types)
        if "File" in wanted:
            return True
        for node in ast.walk(tree):
            if type(node).__name__ in wanted:
                return True
        return False

    def _build_report(self, ledgers, ast_cache, parse_failures):
        proven = set()
        unexamined = set()
        for ledger in ledgers.values():
            proven.update(ledger.covered)
            unexamined.update(ledger.skipped)
            unexamined.update(ledger.unparseable)
        # Coverage proven by one domain removes the gap for every domain.
        unexamined -= proven

        return BudgetReport(
            rules=tuple(self.rules.values()),
            files=tuple(sorted(self.files)),
            domain_ledgers=ledgers,
            proven_coverage=sorted(proven),
            unexamined=sorted(
                (file_name, rule_id)
                for file_name, rule_id, _reason in unexamined
            ),
            parsed_files=sorted(ast_cache),
            unparseable_files=sorted(parse_failures.items()),
            ast_reuses=self._ast_reuses,
        )


def rules_from_registry(
    manager, rule_ids: Optional[Sequence[str]] = None
) -> List[BudgetRule]:
    """Build :class:`BudgetRule` objects from a loaded bandit registry.

    Both entry-point plugins (``manager.plugins``) and blacklist entries
    (``manager.blacklist``) are mapped.  Blacklist checks run against the
    AST node their blacklist group is keyed on.

    :param manager: a :class:`bandit.core.extension_loader.Manager`.
    :param rule_ids: optional ids to keep.  Defaults to every registered
        id.
    """
    check_types: Dict[str, set] = {}
    for plugin in manager.plugins:
        check_types.setdefault(
            plugin.plugin._test_id, set()
        ).update(getattr(plugin.plugin, "_checks", ()))
    for node_type, entries in manager.blacklist.items():
        for entry in entries:
            check_types.setdefault(entry["id"], set()).add(node_type)

    if rule_ids is not None:
        wanted = set(rule_ids)
        unknown = wanted - set(check_types)
        if unknown:
            raise BudgetError(f"unknown registry rule ids: {sorted(unknown)}")
        ids = wanted
    else:
        ids = set(check_types)

    return [
        BudgetRule(rule_id, tuple(sorted(check_types[rule_id])))
        for rule_id in sorted(ids)
    ]
