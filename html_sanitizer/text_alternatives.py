"""Safe text alternatives for elements whose accessible name was stripped.

The sanitizer is deliberately attribute-driven: an element may remain in the
allowlist while the ARIA attributes which gave it an accessible name do not.
This module turns an *existing*, unambiguous text reference into either an
allowed text-alternative attribute or plain text next to the element.  It
never adds a tag or an attribute which the sanitizer policy did not allow.
"""

from dataclasses import dataclass


# Element types which have a text alternative in HTML and which can be kept
# while losing the author-supplied name or description.  This is intentionally
# a short, explicit list instead of every element which happens to accept an
# ARIA attribute.
TEXT_ALTERNATIVE_TAGS = frozenset({"area", "embed", "iframe", "img", "input", "object"})

# ``aria-labelledby`` supplies the accessible name; ``aria-describedby``
# supplies the longer description.  The attributes are treated separately so
# that a policy may keep one and remove the other.
NAME_REFERENCE_ATTRIBUTES = ("aria-labelledby",)
DESCRIPTION_REFERENCE_ATTRIBUTES = ("aria-describedby",)
REFERENCE_ATTRIBUTES = (
    *NAME_REFERENCE_ATTRIBUTES,
    *DESCRIPTION_REFERENCE_ATTRIBUTES,
)

# Preferred attributes to fill when the policy allows them.  A derived name is
# never written to an attribute which is not in the element's allowlist.
TEXT_ALTERNATIVE_ATTRIBUTES = {
    "area": ("alt",),
    "embed": ("title", "aria-label"),
    "iframe": ("title", "aria-label"),
    "img": ("alt",),
    "input": ("alt", "aria-label", "title"),
    "object": ("title", "aria-label"),
}

# Elements which cannot have text children.  These are never modified by
# inserting text into the element itself; a visible alternative is placed in
# the element's tail instead.
VOID_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

_NAME_ATTRIBUTES = ("alt", "aria-label", "title")
_SAFE_TEXT_ATTRIBUTES = frozenset(_NAME_ATTRIBUTES)


@dataclass(frozen=True)
class TextAlternativeDecision:
    """One reviewable decision about an element's lost accessible text."""

    tag: str
    attribute: str
    references: tuple[str, ...]
    status: str
    reason: str | None = None
    output: str | None = None
    text: str | None = None

    def as_dict(self):
        return {
            "tag": self.tag,
            "attribute": self.attribute,
            "references": list(self.references),
            "status": self.status,
            "reason": self.reason,
            "output": self.output,
            "text": self.text,
        }


@dataclass(frozen=True)
class SanitizeResult:
    """Sanitized HTML together with text-alternative decisions."""

    html: str
    text_alternatives: tuple[TextAlternativeDecision, ...] = ()
    manual: tuple[TextAlternativeDecision, ...] = ()

    def __str__(self):
        return self.html

    def as_dict(self):
        return {
            "html": self.html,
            "text_alternatives": [item.as_dict() for item in self.text_alternatives],
            "manual": [item.as_dict() for item in self.manual],
        }


@dataclass(frozen=True)
class _Candidate:
    element: object
    references: dict[str, str]


def build_id_index(root):
    """Index IDs before attributes are filtered out."""

    index = {}
    for node in root.iter():
        identifier = node.get("id")
        if identifier:
            index.setdefault(identifier, []).append(node)
    return index


def _is_in_tree(element, root):
    node = element
    while node is not None:
        if node is root:
            return True
        node = node.getparent()
    return False


def _is_ancestor(possible_ancestor, element):
    node = element.getparent()
    while node is not None:
        if node is possible_ancestor:
            return True
        node = node.getparent()
    return False


def _normalized_text(element, whitespace_re):
    text = element.text_content().strip()
    if not text:
        return ""
    return whitespace_re.sub(" ", text).strip()


def _target_text(element, allowed_attributes, whitespace_re):
    """Return text which is legal under the target element's policy."""

    text = _normalized_text(element, whitespace_re)
    if text:
        return text
    for attribute in _NAME_ATTRIBUTES:
        value = element.get(attribute) if attribute in allowed_attributes else None
        if value and value.strip():
            return whitespace_re.sub(" ", value).strip()
    return ""


def _existing_name_attribute(element, allowed_attributes, preferred):
    for attribute in (*preferred, *_NAME_ATTRIBUTES):
        if (
            attribute in _SAFE_TEXT_ATTRIBUTES
            and attribute in allowed_attributes
            and attribute in element.attrib
            # alt="" is an intentional decorative marker.  Empty title or
            # aria-label values do not supply a name, so they do not count.
            and (attribute == "alt" or (element.get(attribute) or "").strip())
        ):
            return attribute
    return None


def _append_visible_text(element, text):
    """Place a visible alternative next to an element without adding a tag."""

    existing = element.tail or ""
    if not existing:
        element.tail = f" {text}"
    elif existing[:1].isspace() or existing[:1] in ",.;:!?":
        element.tail = f" {text}{existing}"
    else:
        element.tail = f" {text} {existing}"


def _join_texts(values):
    result = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return " ".join(result)


def _dedupe_substrings(values):
    """Drop a text which another resolved reference already contains.

    Adjacent sanitized elements may be merged.  In that case one reference can
    resolve to the merged text while another resolves to the part which was
    merged into it.  Keeping both would duplicate words in the fallback.
    """

    return [
        value
        for index, value in enumerate(values)
        if not any(
            index != other_index and value != other and value in other
            for other_index, other in enumerate(values)
        )
    ]


def decide_text_alternatives(  # noqa: C901 -- explicit review path.
    root,
    candidates,
    id_index,
    *,
    allowed_attributes,
    eligible_tags,
    output_attributes,
    whitespace_re,
):
    """Resolve candidates and return ``(decisions, plans)``.

    ``plans`` contains the changes to apply.  A candidate which has any
    duplicate, unresolved, out-of-scope or empty reference is reported as
    ``manual`` and is not changed at all.
    """

    decisions = []
    plans = []
    root_text = _normalized_text(root, whitespace_re)

    for candidate in candidates:
        element = candidate.element
        if element.tag not in eligible_tags or not _is_in_tree(element, root):
            continue

        allowed = allowed_attributes.get(element.tag, ())
        preferred = output_attributes.get(element.tag, ())
        existing_name = _existing_name_attribute(element, allowed, preferred)

        lost = []
        manual_reason = None
        manual_attribute = None
        manual_references = ()
        for attribute in REFERENCE_ATTRIBUTES:
            raw_references = candidate.references.get(attribute)
            if raw_references is None:
                continue

            references = tuple(raw_references.split())

            if not references:
                manual_reason = "empty-reference"
                manual_attribute = attribute
                manual_references = ()
                break
            if len(set(references)) != len(references):
                manual_reason = "duplicate-reference"
                manual_attribute = attribute
                manual_references = references
                break

            resolved = []
            for reference in references:
                targets = id_index.get(reference, ())
                if not targets:
                    manual_reason = "unresolved-reference"
                    manual_attribute = attribute
                    manual_references = references
                    break
                if len(targets) > 1:
                    manual_reason = "duplicate-id"
                    manual_attribute = attribute
                    manual_references = references
                    break

                target = targets[0]
                if target is root or target is element or _is_ancestor(target, element):
                    manual_reason = "out-of-scope-reference"
                    manual_attribute = attribute
                    manual_references = references
                    break

                in_tree = _is_in_tree(target, root)
                text = (
                    _target_text(
                        target,
                        allowed_attributes.get(target.tag, ()),
                        whitespace_re,
                    )
                    if in_tree
                    else _normalized_text(target, whitespace_re)
                )
                if not in_tree:
                    # A sanitizer normalization may unwrap or merge the
                    # target.  The reference element is gone, but the same
                    # text may still be present in the sanitized output.
                    if not text or text not in root_text:
                        manual_reason = "out-of-scope-reference"
                        manual_attribute = attribute
                        manual_references = references
                        break
                elif not text:
                    manual_reason = "empty-text"
                    manual_attribute = attribute
                    manual_references = references
                    break
                resolved.append((reference, target, text))

            if manual_reason:
                break
            # Keeping the ARIA attribute is only useful if the target ID also
            # survives sanitization. Otherwise the relationship is broken.
            retained = attribute in allowed and all(
                _is_in_tree(target, root) and target.get("id") == reference
                for reference, target, _ in resolved
            )
            if not retained:
                texts = _dedupe_substrings([text for _, _, text in resolved])
                lost.append((attribute, references, texts))

        if manual_reason:
            decisions.append(
                TextAlternativeDecision(
                    tag=element.tag,
                    attribute=manual_attribute,
                    references=manual_references,
                    status="manual",
                    reason=manual_reason,
                )
            )
            continue

        if not lost:
            continue

        name_text = _join_texts(
            text
            for attribute, _, texts in lost
            if attribute in NAME_REFERENCE_ATTRIBUTES
            for text in texts
        )
        description_text = _join_texts(
            text
            for attribute, _, texts in lost
            if attribute in DESCRIPTION_REFERENCE_ATTRIBUTES
            for text in texts
        )

        has_content_name = element.tag not in VOID_TAGS and bool(
            _normalized_text(element, whitespace_re)
        )

        name_attribute = None
        if name_text and existing_name is None and not has_content_name:
            for attribute in (*preferred, *_NAME_ATTRIBUTES):
                if attribute in _SAFE_TEXT_ATTRIBUTES and attribute in allowed:
                    name_attribute = attribute
                    break

        visible_parts = []
        if (
            name_text
            and existing_name is None
            and not has_content_name
            and name_attribute is None
        ):
            visible_parts.append(name_text)
        if description_text:
            visible_parts.append(description_text)
        visible_text = _join_texts(visible_parts)

        if name_attribute is None and not visible_text:
            continue

        decisions.append(
            TextAlternativeDecision(
                tag=element.tag,
                attribute="+".join(attribute for attribute, _, _ in lost),
                references=tuple(
                    reference for _, references, _ in lost for reference in references
                ),
                status="applied",
                output=name_attribute or "text",
                text=_join_texts([name_text if name_attribute else None, visible_text]),
            )
        )
        plans.append((element, name_attribute, name_text, visible_text))

    return decisions, plans


def apply_text_alternative_plans(plans):
    for element, name_attribute, name_text, visible_text in plans:
        if name_attribute:
            element.set(name_attribute, name_text)
        if visible_text:
            _append_visible_text(element, visible_text)
