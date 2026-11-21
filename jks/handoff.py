# vim: set et ai ts=4 sts=4 sw=4:
"""
Handoff pre-checks for keystore backups.

This module only reasons about the *identity* of keystore entries (i.e. their
aliases). It never reads, decrypts or otherwise touches certificate or key
material, and it does not modify the keystore that is being inspected; the
normal :class:`~jks.jks.KeyStore` read path is left untouched.

Different receiving systems apply different "alias folding" conventions when
importing a backup: some treat aliases as case-sensitive, some fold them to
lower case, some apply full Unicode case folding, and some legacy systems only
know how to map a fixed set of aliases. Importing a backup into such a system
can therefore overwrite an already trusted entry whenever the effective alias
of a backup entry matches an alias that is already present on the target.

Typical usage::

    import jks
    from jks.handoff import CaseFoldRule, ExactRule, MappedRule, precheck_handoff

    ks = jks.KeyStore.load("backup.jks", "storepass")
    report = precheck_handoff(ks, [
        ("legacy", MappedRule({"rootca": "rootca"}), ["rootca"]),
        ("modern", CaseFoldRule(),                  ["rootca"]),
        ("exact",  ExactRule(),                     ["RootCA"]),
    ])
    for target in report.targets:
        print(target.name, target.conflicts, target.unconfirmed, target.conflict_free)

Each target is evaluated independently: a backup alias that is safe for one
target must never cause another target to be reported as conflict-free.
"""

from __future__ import print_function

import unicodedata

from .util import AbstractKeystore, py23basestring

try:
    _casefold = getattr(str, "casefold")   # Python 3.3+
except AttributeError:                    # pragma: no cover - Python 2 fallback
    _casefold = None


class HandoffException(Exception):
    """Superclass for all handoff pre-check exceptions."""
    pass


class AliasNotMappableException(HandoffException):
    """Raised by an alias rule when an alias cannot be translated into an
    effective alias on the target system.

    The pre-check catches this exception and records the offending backup
    alias as *unconfirmed* rather than treating it as conflict-free."""
    pass


class DuplicateBackupAliasException(HandoffException):
    """Signifies that the backup being handed off contains the same alias
    more than once."""
    pass


def _normalize(alias):
    if not isinstance(alias, py23basestring):
        raise TypeError("Aliases must be strings, found: %r" % type(alias))
    return unicodedata.normalize("NFC", alias)


class AbstractAliasRule(object):
    """Abstract superclass for target-specific alias folding conventions.

    A rule maps a backup alias to the *effective alias* under which the entry
    would be stored on the receiving system. Subclasses implement
    :meth:`fold`; plain callables taking a single alias argument are also
    accepted anywhere a rule is expected."""

    def fold(self, alias):
        """
        :param str alias: A backup alias.
        :returns: The effective alias on the target system.
        :raises AliasNotMappableException: If the alias cannot be mapped to
            an effective alias on the target system.
        """
        raise NotImplementedError("Abstract method")

    def __call__(self, alias):
        return self.fold(alias)


class ExactRule(AbstractAliasRule):
    """Alias rule for case-sensitive targets: aliases are compared exactly
    and are never folded. Two aliases only collide when they are identical
    after Unicode NFC normalization."""

    def fold(self, alias):
        return _normalize(alias)


class LowerCaseRule(AbstractAliasRule):
    """Alias rule for targets that fold every alias to its lower-case form
    (``alias.lower()``)."""

    def fold(self, alias):
        return _normalize(alias).lower()


class CaseFoldRule(AbstractAliasRule):
    """Alias rule for targets that apply full Unicode case folding
    (``alias.casefold()``), collapsing e.g. ``"RootCA"`` and ``"rootca"``,
    or ``"stra\\u00dfe"`` and ``"strasse"`` onto the same effective alias.

    On Python 2, where :meth:`str.casefold` does not exist, this falls back
    to :meth:`str.lower`."""

    def fold(self, alias):
        normalized = _normalize(alias)
        if _casefold is not None:
            return _casefold(normalized)
        return normalized.lower()


class MappedRule(AbstractAliasRule):
    """Alias rule for legacy systems that only recognize a fixed set of
    aliases.

    :param dict mapping: A dictionary mapping known backup aliases to the
        effective alias on the target system.

    Any alias that is not present in ``mapping`` cannot be resolved and
    causes :class:`AliasNotMappableException` to be raised from :meth:`fold`,
    which makes the pre-check report that identity as *unconfirmed*."""

    def __init__(self, mapping):
        self.mapping = dict(
            (_normalize(backup_alias), target_alias)
            for backup_alias, target_alias in mapping.items()
        )

    def fold(self, alias):
        normalized = _normalize(alias)
        if normalized not in self.mapping:
            raise AliasNotMappableException(
                "Alias '%s' is not covered by the target's alias mapping" % alias
            )
        return self.mapping[normalized]


class CallableRule(AbstractAliasRule):
    """Adapter that wraps a user-supplied callable as an alias rule.

    The wrapped callable receives a backup alias and must either return the
    effective alias on the target system, or raise
    :class:`AliasNotMappableException` to mark the identity as unconfirmed."""

    def __init__(self, func):
        if not callable(func):
            raise TypeError("An alias rule must be callable")
        self._func = func

    def fold(self, alias):
        return self._func(alias)


class TargetPrecheckResult(object):
    """Pre-check outcome for a single receiving system.

    The three alias lists are mutually exclusive and together cover every
    backup alias exactly once."""

    def __init__(self, name, conflicts, unconfirmed, conflict_free):
        self.name = name
        """Name of the receiving system, as supplied by the caller."""
        self.conflicts = list(conflicts)
        """Backup aliases that would overwrite an existing trusted entry on
        this target."""
        self.unconfirmed = list(unconfirmed)
        """Backup aliases whose effective alias on this target could not be
        determined, so their safety cannot be asserted. This also covers
        backup aliases that collapse onto the same effective alias as one
        another, where the surviving identity would depend on import order."""
        self.conflict_free = list(conflict_free)
        """Backup aliases that are guaranteed not to overwrite anything on
        this target."""

    @property
    def is_clear(self):
        """``True`` only when every backup alias is conflict-free for this
        target, i.e. there are no conflicts and no unconfirmed identities."""
        return not self.conflicts and not self.unconfirmed

    def __repr__(self):
        return "TargetPrecheckResult(name=%r, conflicts=%r, unconfirmed=%r, conflict_free=%r)" % (
            self.name, self.conflicts, self.unconfirmed, self.conflict_free
        )


class HandoffPrecheckReport(object):
    """Aggregate pre-check result across all requested targets."""

    def __init__(self, backup_aliases, targets):
        self.backup_aliases = list(backup_aliases)
        """Sorted list of the backup aliases that were evaluated."""
        self.targets = list(targets)
        """List of :class:`TargetPrecheckResult` instances, one per target,
        in the order in which the targets were supplied."""

    def get(self, name):
        """Return the :class:`TargetPrecheckResult` for the target with the
        given name."""
        for target in self.targets:
            if target.name == name:
                return target
        raise KeyError("No pre-check result for target '%s'" % name)

    @property
    def all_clear(self):
        """``True`` only when *every* target is fully conflict-free."""
        return all(target.is_clear for target in self.targets)

    def __iter__(self):
        return iter(self.targets)

    def __len__(self):
        return len(self.targets)


def precheck_handoff(keystore_or_aliases, targets):
    """Run a handoff pre-check of a keystore backup against one or more
    receiving systems.

    The pre-check is purely an identity check: it only folds and compares
    aliases. It never reads certificate or key data and never modifies the
    supplied keystore.

    :param keystore_or_aliases: Either a loaded
        :class:`~jks.jks.KeyStore`/:class:`~jks.bks.BKSKeystore` instance, or
        an iterable of backup alias strings.
    :param targets: An iterable of ``(name, rule, existing_aliases)``
        triples, one per receiving system. ``rule`` is an
        :class:`AbstractAliasRule` instance or any callable that maps a
        backup alias to its effective target alias (raising
        :class:`AliasNotMappableException` when it cannot).
        ``existing_aliases`` is the public list of aliases already present
        on that target.
    :returns: A :class:`HandoffPrecheckReport` containing one
        :class:`TargetPrecheckResult` per target.

    Each backup alias is classified per target as:

      * **conflict** -- its folded alias matches an existing target alias;
      * **unconfirmed** -- the rule cannot map the alias, or multiple backup
        entries fold onto the same effective alias (so which one would
        survive import cannot be determined);
      * **conflict-free** -- the folded alias is unique within the backup and
        absent from the target's existing aliases.

    Targets are evaluated independently; a safe result for one target never
    influences the result for another target.
    """
    backup_aliases = _extract_aliases(keystore_or_aliases)
    _check_duplicate_backup_aliases(backup_aliases)

    target_results = []
    for target in targets:
        name, rule, existing_aliases = target
        target_results.append(
            _precheck_target(name, _as_rule(rule), backup_aliases, existing_aliases)
        )

    return HandoffPrecheckReport(sorted(backup_aliases), target_results)


def _precheck_target(name, rule, backup_aliases, existing_aliases):
    folded_existing = set()
    for existing_alias in existing_aliases:
        folded_existing.add(rule.fold(existing_alias))

    unconfirmed = set()
    folded_by_alias = {}
    for alias in backup_aliases:
        try:
            folded_by_alias[alias] = rule.fold(alias)
        except AliasNotMappableException:
            unconfirmed.add(alias)

    # Backup aliases that collapse onto the same effective alias cannot be
    # assigned a unique slot on the target; import order would decide which
    # one survives, so treat them as unconfirmed identities.
    seen_folded = set()
    ambiguous_folded = set()
    for folded in folded_by_alias.values():
        if folded in seen_folded:
            ambiguous_folded.add(folded)
        seen_folded.add(folded)

    conflicts = set()
    for alias, folded in folded_by_alias.items():
        if folded in ambiguous_folded:
            unconfirmed.add(alias)
        elif folded in folded_existing:
            conflicts.add(alias)

    conflict_free = [
        alias for alias in backup_aliases
        if alias not in conflicts and alias not in unconfirmed
    ]
    return TargetPrecheckResult(
        name,
        sorted(conflicts),
        sorted(unconfirmed),
        conflict_free,
    )


def _extract_aliases(keystore_or_aliases):
    if isinstance(keystore_or_aliases, AbstractKeystore):
        return list(keystore_or_aliases.entries.keys())

    aliases = list(keystore_or_aliases)
    for alias in aliases:
        if not isinstance(alias, py23basestring):
            raise TypeError("Backup aliases must be strings, found: %r" % type(alias))
    return aliases


def _check_duplicate_backup_aliases(backup_aliases):
    seen = set()
    for alias in backup_aliases:
        normalized = _normalize(alias)
        if normalized in seen:
            raise DuplicateBackupAliasException(
                "Backup contains duplicate alias '%s'" % alias
            )
        seen.add(normalized)


def _as_rule(rule):
    if isinstance(rule, AbstractAliasRule):
        return rule
    if callable(rule):
        return CallableRule(rule)
    raise TypeError(
        "Alias rule must be an AbstractAliasRule instance or a callable, got: %r" % type(rule)
    )
