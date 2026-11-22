from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from sigma.evidence.provenance import RAW_LOG_FIELD

ProjectionValue = Any


@dataclass(frozen=True)
class PublicProjection:
    """
    Declares how a fact may be rendered for an external audience.

    ``statement`` can contain ``{field}``, ``{value}``, ``{statement}`` and
    ``{fact_id}`` placeholders.  A callable receives the fact and returns its public
    wording (or ``None`` to withhold it).
    """

    statement: str | Callable[[Any], str | None]
    fields: frozenset[str] | None = None

    def render(self, fact: Any) -> str | None:
        if callable(self.statement):
            return self.statement(fact)
        return _render_template(
            self.statement,
            fact=fact,
        )


@dataclass(frozen=True)
class Audience:
    """
    Describes what one audience is allowed to see.

    Args:
        name: Human-readable audience name.
        allowed_fields: Fields that may be cited outside the SOC.  ``None`` means every
            field is allowed (normally only the case for the internal audience).
        public_facts: Facts that may be projected into a public explanation.  This can
            be ``"*"``/``True`` for all facts, a set of fact ids / kinds / field names,
            or a mapping from such a selector to public wording (a string, ``True``,
            ``None`` or :class:`PublicProjection`).
        allow_raw: Whether raw-log keyword evidence may be used externally.
        internal_only: Marks the audience as an internal review audience.
    """

    name: str
    allowed_fields: frozenset[str] | None = None
    public_facts: Any = field(default_factory=dict)
    allow_raw: bool = False
    internal_only: bool = False

    def __post_init__(self) -> None:
        if self.allowed_fields is not None:
            fields = (
                (self.allowed_fields,)
                if isinstance(self.allowed_fields, str)
                else self.allowed_fields
            )
            object.__setattr__(self, "allowed_fields", frozenset(fields))
        if isinstance(self.public_facts, (set, frozenset, list, tuple)):
            object.__setattr__(self, "public_facts", frozenset(self.public_facts))
        if self.internal_only:
            object.__setattr__(self, "allowed_fields", None)
            object.__setattr__(self, "public_facts", "*")
            object.__setattr__(self, "allow_raw", True)

    @classmethod
    def internal(cls, name: str = "soc-internal") -> Audience:
        """Create an unrestricted internal review audience."""
        return cls(name=name, internal_only=True)

    @classmethod
    def external(
        cls,
        name: str,
        allowed_fields: Iterable[str],
        public_facts: Any,
        *,
        allow_raw: bool = False,
    ) -> Audience:
        """Create a restricted external audience."""
        return cls(
            name=name,
            allowed_fields=allowed_fields,
            public_facts=public_facts,
            allow_raw=allow_raw,
        )

    @property
    def is_internal(self) -> bool:
        return self.internal_only

    def field_allowed(self, field_name: str) -> bool:
        """Return True when ``field_name`` may be cited for this audience."""
        if self.internal_only or self.allowed_fields is None:
            return True
        if field_name == RAW_LOG_FIELD:
            return self.allow_raw
        return field_name in self.allowed_fields

    def project(self, fact: Any) -> str | None:
        """Return public wording for ``fact``, or ``None`` when it must be withheld."""
        if self.internal_only:
            return fact.public_statement or fact.statement

        rules = self.public_facts
        if callable(rules):
            return rules(fact)
        if rules is True or rules == "*":
            return fact.public_statement or fact.statement

        keys = self._selectors(fact)
        if isinstance(rules, Mapping):
            for key in keys:
                if key in rules:
                    return _projection_value(rules[key], fact)
            return None
        if isinstance(rules, (set, frozenset)):
            if any(key in rules for key in keys):
                return fact.public_statement or fact.statement
            return None
        if isinstance(rules, str):
            # A single selector is also accepted.
            if rules in keys:
                return fact.public_statement or fact.statement
        return None

    @staticmethod
    def _selectors(fact: Any) -> list[str]:
        selectors = [fact.id, fact.kind]
        for source in sorted(fact.sources):
            selectors.append(source)
            selectors.append(f"field:{source}")
        return selectors


def _projection_value(value: ProjectionValue, fact: Any) -> str | None:
    if value is None or value is False:
        return None
    if value is True:
        return fact.public_statement or fact.statement
    if isinstance(value, PublicProjection):
        return value.render(fact)
    if callable(value):
        return value(fact)
    if isinstance(value, str):
        return _render_template(value, fact=fact)
    return None


def _render_template(template: str, fact: Any) -> str:
    try:
        return template.format(
            field=", ".join(sorted(fact.sources)),
            value=fact.value,
            statement=fact.statement,
            fact_id=fact.id,
        )
    except (KeyError, IndexError, ValueError):
        return template


# Names used by some integrations.
AudiencePolicy = Audience
EvidenceAudience = Audience
EvidencePolicy = Audience
FactProjection = PublicProjection
