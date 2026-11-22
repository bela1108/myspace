import re
import unicodedata
from collections import deque
from dataclasses import dataclass
from typing import NamedTuple

import lxml.etree
import lxml.html
import lxml.html.clean

from .ledger import (
    STAGE_PARSE,
    STAGE_POLICY,
    STAGE_STRUCTURE,
    STATUS_APPLIED,
    STATUS_PENDING,
    ChangeLedger,
    document_digest,
)


__all__ = ("Sanitizer", "SanitizeResult", "sanitize_with_ledger")


def sanitize_href(href):
    """
    Verify that a given href is benign and allowed.

    This is a stupid check, which probably should be much more elaborate
    to be safe.
    """
    if href.startswith(("/", "mailto:", "http:", "https:", "#", "tel:")):
        return href
    return "#"


typographic_whitespace_names = [
    "NO-BREAK SPACE",
    "EN QUAD",
    "EM QUAD",
    "EN SPACE",
    "EM SPACE",
    "THREE-PER-EM SPACE",
    "FOUR-PER-EM SPACE",
    "SIX-PER-EM SPACE",
    "FIGURE SPACE",
    "PUNCTUATION SPACE",
    "THIN SPACE",
    "HAIR SPACE",
    "NARROW NO-BREAK SPACE",
    "MEDIUM MATHEMATICAL SPACE",
    "IDEOGRAPHIC SPACE",
]

typographic_whitespace = "".join(
    {unicodedata.lookup(n) for n in typographic_whitespace_names}
)


def bold_span_to_strong(element):
    if element.tag == "span" and "bold" in element.get("style", ""):
        element.tag = "strong"
    return element


def italic_span_to_em(element):
    if element.tag == "span" and "italic" in element.get("style", ""):
        element.tag = "em"
    return element


def tag_replacer(from_, to_):
    def replacer(element):
        if element.tag == from_:
            element.tag = to_
        return element

    return replacer


def target_blank_noopener(element):
    if (
        element.tag == "a"
        and element.attrib.get("target") == "_blank"
        and "noopener" not in element.attrib.get("rel", "")
    ):
        element.attrib["rel"] = " ".join(
            part for part in (element.attrib.get("rel", ""), "noopener") if part
        )
    return element


def anchor_id_to_name(element):
    if (
        element.tag == "a"
        and element.attrib.get("id")
        and not element.attrib.get("name")
    ):
        element.attrib["name"] = element.attrib["id"]
    return element


def filter_control_characters(text):
    """Filter out control characters that lxml cannot handle."""
    if not text:
        return text
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)


def normalize_whitespace_in_text_or_tail(
    element,
    *,
    whitespace_re=None,
    keep_typographic_whitespace=False,
    normalize_text=True,
    normalize_tail=True,
):
    # Always filter control characters regardless of whitespace settings
    if element.text:
        element.text = filter_control_characters(element.text)
    if element.tail:
        element.tail = filter_control_characters(element.tail)

    if keep_typographic_whitespace:
        return element

    if whitespace_re is None:
        whitespace_re = re.compile(r"\s+")
    if element.text and normalize_text:
        while True:
            text = whitespace_re.sub(" ", element.text)
            if element.text == text:
                break
            element.text = text

    if element.tail and normalize_tail:
        while True:
            text = whitespace_re.sub(" ", element.tail)
            if element.tail == text:
                break
            element.tail = text

    return element


DEFAULT_SETTINGS = {
    "tags": {
        "a",
        "h1",
        "h2",
        "h3",
        "strong",
        "em",
        "p",
        "ul",
        "ol",
        "li",
        "br",
        "sub",
        "sup",
        "hr",
    },
    "attributes": {"a": ("href", "name", "target", "title", "rel")},
    "empty": {"hr", "a", "br"},
    "separate": {"a", "p", "li"},
    "whitespace": {"br"},
    "preserve_whitespace": {"pre"},
    "keep_typographic_whitespace": False,
    "drop_disallowed_contents": False,
    "add_nofollow": False,
    "autolink": False,
    "embedded_hosts": set(),
    "sanitize_href": sanitize_href,
    "element_preprocessors": [
        # convert span elements into em/strong if a matching style rule
        # has been found. strong has precedence, strong & em at the same
        # time is not supported
        bold_span_to_strong,
        italic_span_to_em,
        tag_replacer("b", "strong"),
        tag_replacer("i", "em"),
        tag_replacer("form", "p"),
        target_blank_noopener,
        anchor_id_to_name,
    ],
    "element_postprocessors": [],
}


def coerce_to_set(value):
    if isinstance(value, set):
        return value
    elif isinstance(value, tuple | list):
        return set(value)
    raise TypeError(f"Expected a set but got value {value!r} of type {type(value)}")


_CONTROL_CHARACTERS_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def _tag_name(tag):
    if isinstance(tag, str):
        return tag
    if tag is lxml.etree.Comment:
        return "#comment"
    if tag is lxml.etree.ProcessingInstruction:
        return "#processing-instruction"
    return "#node"


def _is_known_html_tag(tag):
    return isinstance(tag, str) and tag.lower() in lxml.html.defs.tags


@dataclass
class _Snapshot:
    element: object
    alias: str | None
    tag: object
    attrib: dict
    text: str | None
    tail: str | None


class _SanitizerAudit:
    """Instrument one sanitize pass and feed a :class:`ChangeLedger`."""

    # Tags which lxml's cleaner kills together with their contents.
    _kill_tags = {
        "applet",
        "base",
        "frame",
        "frameset",
        "link",
        "meta",
        "noframes",
        "script",
        "style",
    }
    # Tags which lxml's cleaner unwraps, keeping any fallback contents.
    _unwrap_tags = {
        "blink",
        "embed",
        "form",
        "iframe",
        "layer",
        "marquee",
        "object",
        "param",
    }

    def __init__(self, ledger, sanitizer, *, policy=None):
        self.ledger = ledger
        self.sanitizer = sanitizer
        self.policy = policy
        self.document_id = ""
        self.round = 0
        self.raw_html = ""
        self.root = None
        self._aliases = {}
        self._xpaths = {}
        self._elements = {}
        self._generated_count = 0

    # -- setup ----------------------------------------------------------

    def begin(self, html):
        self.raw_html = html
        self.document_id = document_digest(html)
        self.round, self.policy = self.ledger.begin_round(
            policy=self.policy, document_id=self.document_id
        )
        self.ledger.remember_document(self.document_id, html)

    def index(self, doc):
        self.root = doc
        self._assign(doc, "#fragment")

    def _assign(self, element, alias):
        self._bind(element, alias)
        counters = {}
        for child in element:
            tag = child.tag
            if isinstance(tag, str):
                key = tag.lower()
                segment = key
            elif tag is lxml.etree.Comment:
                key = "#comment"
                segment = "#comment"
            elif tag is lxml.etree.ProcessingInstruction:
                key = "#processing-instruction"
                segment = "#processing-instruction"
            else:
                key = "#node"
                segment = "#node"

            counters[key] = counters.get(key, 0) + 1
            self._assign(child, f"{alias}/{segment}[{counters[key]}]")

    def _bind(self, element, alias, *, xpath=None):
        self._aliases[id(element)] = alias
        if xpath is None and self.root is not None:
            try:
                xpath = self.root.getroottree().getpath(element)
            except Exception:
                xpath = None
        self._xpaths[id(element)] = xpath
        self._elements[id(element)] = element

    def alias_for(self, element):
        alias = self._aliases.get(id(element))
        if alias is not None:
            return alias

        parent = element.getparent()
        parent_alias = self._aliases.get(id(parent)) if parent is not None else None
        self._generated_count += 1
        alias = f"{parent_alias or '#fragment'}/#generated[{self._generated_count}]"
        self._bind(element, alias)
        return alias

    def mark_generated(self, doc, before_ids):
        for element in doc.iter():
            if id(element) in before_ids:
                continue
            self.alias_for(element)

    def fragment(self, element):
        try:
            return lxml.html.tostring(element, encoding="unicode")
        except Exception:
            return None

    # -- generic recording ---------------------------------------------

    def record(
        self,
        *,
        element=None,
        alias=None,
        stage,
        operation,
        reason,
        status=STATUS_APPLIED,
        fragment=None,
        tag=None,
        details=None,
    ):
        if alias is None and element is not None:
            alias = self.alias_for(element)
        if alias is None:
            alias = "#fragment"
        if tag is None and element is not None:
            tag = _tag_name(element.tag)
        if fragment is None and element is not None:
            fragment = self.fragment(element)

        entry, _ = self.ledger.record(
            alias=alias,
            stage=stage,
            status=status,
            round=self.round,
            policy=self.policy,
            document_id=self.document_id,
            operation=operation,
            reason=reason,
            source_xpath=(
                self._xpaths.get(id(element)) if element is not None else None
            ),
            fragment=fragment,
            tag=tag,
            details=details or {},
            source_node=element,
        )
        return entry

    # -- parsing decisions ---------------------------------------------

    def record_unicode_normalization(self, form):
        self.record(
            element=self.root,
            stage=STAGE_PARSE,
            operation=f"parse:unicode:{form}",
            reason=f"input text was Unicode-normalized to {form} before parsing",
            fragment=self.raw_html,
            tag="#document",
        )

    def record_parse_fallback(self):
        self.record(
            element=self.root,
            stage=STAGE_PARSE,
            operation="parse:fallback:soupparser",
            reason=(
                "lxml could not parse the fragment; BeautifulSoup recovery was"
                " used, so repaired nodes are kept for confirmation"
            ),
            status=STATUS_PENDING,
            fragment=self.raw_html,
            tag="#document",
        )

    def record_parser_errors(self, doc):
        try:
            parser = doc.getroottree().parser
        except Exception:
            return
        if parser is None:
            return

        for error in parser.error_log:
            message = getattr(error, "message", str(error))
            line = getattr(error, "line", None)
            column = getattr(error, "column", None)
            location = f" at {line}:{column}" if line else ""
            self.record(
                element=self.root,
                stage=STAGE_PARSE,
                operation=(
                    f"parse:repair:{getattr(error, 'type_name', 'error')}:"
                    f"{line}:{column}:{message}"
                ),
                reason=(
                    f"HTML parser repaired malformed markup ({message}{location});"
                    " the repaired node could not be aligned with the source and"
                    " is kept for confirmation"
                ),
                status=STATUS_PENDING,
                fragment=self.raw_html,
                tag="#document",
                details={
                    "message": message,
                    "line": line,
                    "column": column,
                    "type": getattr(error, "type_name", None),
                },
            )

    # -- cleaner decisions ---------------------------------------------

    def snapshot(self, doc):
        snapshot = {}
        for element in doc.iter():
            snapshot[id(element)] = _Snapshot(
                element=element,
                alias=self._aliases.get(id(element)),
                tag=element.tag,
                attrib=dict(element.attrib),
                text=element.text,
                tail=element.tail,
            )
        return snapshot

    def record_cleaner_changes(self, snapshot, doc, *, phase):
        alive = {id(element) for element in doc.iter()}

        for item in snapshot.values():
            element = item.element
            if id(element) in alive:
                self._record_attribute_changes(item, element)
                continue

            parent = element.getparent()
            if parent is not None and id(parent) not in alive:
                # A removed ancestor already accounts for this node.
                continue
            if item.alias is not None and self.ledger.has_node_decision(
                self.document_id, item.alias
            ):
                continue

            stage, status, reason = self._cleaner_removal_reason(
                item, alive, phase=phase
            )
            self.record(
                element=element,
                alias=item.alias,
                stage=stage,
                operation="node-removal",
                reason=reason,
                status=status,
                tag=_tag_name(item.tag),
            )

    def _record_attribute_changes(self, item, element):
        before = item.attrib
        after = element.attrib
        tag = _tag_name(element.tag)

        for key, old_value in before.items():
            if key in after:
                continue
            self.record(
                element=element,
                stage=STAGE_POLICY,
                operation=f"attribute:{key}",
                reason=self._attribute_reason(tag, key),
                details={"attribute": key, "old_value": old_value},
            )

        for key, new_value in after.items():
            old_value = before.get(key)
            if old_value is None:
                if key == "rel" and (
                    "nofollow" in new_value or "noopener" in new_value
                ):
                    reason = (
                        "safe-link attribute 'rel' was added to an external or"
                        " new-window link by policy"
                    )
                else:
                    reason = f"attribute '{key}' was added by the sanitizer policy"
                self.record(
                    element=element,
                    stage=STAGE_POLICY,
                    operation=f"attribute-add:{key}",
                    reason=reason,
                    details={"attribute": key, "new_value": new_value},
                )
            elif old_value != new_value:
                self.record(
                    element=element,
                    stage=STAGE_POLICY,
                    operation=f"attribute:{key}",
                    reason=self._attribute_reason(tag, key, rewritten=True),
                    details={
                        "attribute": key,
                        "old_value": old_value,
                        "new_value": new_value,
                    },
                )

        if item.tag != element.tag:
            self.record(
                element=element,
                stage=STAGE_STRUCTURE,
                operation=(
                    f"rewrite:tag:{_tag_name(item.tag)}->{_tag_name(element.tag)}"
                ),
                reason=(
                    f"<{_tag_name(item.tag)}> was rewritten to"
                    f" <{_tag_name(element.tag)}> during structural normalization"
                ),
                details={
                    "old_tag": _tag_name(item.tag),
                    "new_tag": _tag_name(element.tag),
                },
            )

    def _cleaner_removal_reason(self, item, alive, *, phase):
        tag = item.tag
        label = _tag_name(tag)
        has_live_descendants = any(
            id(descendant) in alive for descendant in item.element.iterdescendants()
        )
        action = (
            "the tag was unwrapped and its contents kept"
            if has_live_descendants or item.text
            else "the tag was unwrapped"
        )

        if tag is lxml.etree.Comment:
            return (
                STAGE_POLICY,
                STATUS_APPLIED,
                "HTML comments are valid markup but are not exposed in public"
                " output; the comment was removed",
            )

        if label in {"script", "style"}:
            return (
                STAGE_POLICY,
                STATUS_APPLIED,
                f"tag <{label}> is valid HTML but is active content and is not"
                " approved for public output; the tag and its contents were"
                " removed",
            )

        if label in {"embed", "iframe", "layer", "param"}:
            if (
                phase == "final"
                and isinstance(tag, str)
                and tag.lower() not in self.sanitizer.tags
            ):
                return (
                    STAGE_POLICY,
                    STATUS_APPLIED,
                    f"embedded element <{label}> is valid HTML but is not"
                    " approved for public output; the tag was unwrapped and any"
                    " fallback contents kept",
                )
            return (
                STAGE_POLICY,
                STATUS_APPLIED,
                f"embedded element <{label}> is valid HTML but its source or"
                " host is not approved by the embedded-host policy; the tag was"
                " unwrapped and any fallback contents kept",
            )

        if label in {"applet", "object"}:
            content_action = (
                "the tag was unwrapped and its contents kept"
                if label == "object"
                else "the tag and its contents were removed"
            )
            return (
                STAGE_POLICY,
                STATUS_APPLIED,
                f"embedded element <{label}> is valid HTML but is not approved"
                f" for public output; {content_action}",
            )

        if label in self._kill_tags:
            return (
                STAGE_POLICY,
                STATUS_APPLIED,
                f"tag <{label}> is valid HTML but is not approved for public"
                " output; the tag and its contents were removed",
            )

        if label in self._unwrap_tags:
            return (
                STAGE_POLICY,
                STATUS_APPLIED,
                f"tag <{label}> is valid HTML but is not approved for public"
                f" output; {action}",
            )

        if isinstance(tag, str) and tag.lower() not in self.sanitizer.tags:
            if _is_known_html_tag(tag):
                prefix = (
                    f"tag <{label}> is valid HTML but is not approved for public output"
                )
            else:
                prefix = f"tag <{label}> is not an approved public tag"
            return (STAGE_POLICY, STATUS_APPLIED, f"{prefix}; {action}")

        return (
            STAGE_POLICY,
            STATUS_PENDING,
            f"element <{label}> was removed by the cleaner but could not be"
            " aligned to a recorded policy decision; kept for confirmation",
        )

    def _attribute_reason(self, tag, key, *, rewritten=False):
        action = "rewritten" if rewritten else "removed"
        if key.lower().startswith("on"):
            return (
                f"attribute '{key}' is valid HTML but is an event handler and"
                f" is not approved on <{tag}>; the attribute was {action}"
            )
        if key.lower() == "style":
            return (
                f"inline style is valid HTML but is not approved on <{tag}>;"
                f" the attribute was {action}"
            )
        if key.lower() == "href":
            if rewritten:
                return (
                    "link target is valid markup but did not match the approved"
                    " link policy; href was rewritten"
                )
            return (
                f"attribute 'href' is valid HTML but is not approved on <{tag}>;"
                " the attribute was removed"
            )
        if key.lower() == "rel":
            return f"link relationship attribute 'rel' was {action} by policy"
        if rewritten:
            return f"attribute '{key}' was rewritten by the sanitizer policy"
        return (
            f"attribute '{key}' is valid HTML but is not approved on <{tag}>;"
            " the attribute was removed"
        )

    # -- element processor decisions -----------------------------------

    def record_processor(
        self, before_element, after_element, *, before_tag, before_attrib, processor
    ):
        if after_element is None:
            return

        name = getattr(processor, "__name__", type(processor).__name__)
        alias = self.alias_for(before_element)
        xpath = self._xpaths.get(id(before_element))

        if after_element is not before_element:
            self._bind(after_element, alias, xpath=xpath)
            self.record(
                element=before_element,
                alias=alias,
                stage=STAGE_STRUCTURE,
                operation=f"rewrite:replacement:{name}",
                reason=(f"element was replaced by structural preprocessor '{name}'"),
            )
            return

        if before_tag != after_element.tag:
            self.record(
                element=after_element,
                stage=STAGE_STRUCTURE,
                operation=(
                    f"rewrite:tag:{_tag_name(before_tag)}"
                    f"->{_tag_name(after_element.tag)}"
                ),
                reason=(
                    f"<{_tag_name(before_tag)}> was rewritten to"
                    f" <{_tag_name(after_element.tag)}> during structural"
                    " normalization"
                ),
                details={
                    "old_tag": _tag_name(before_tag),
                    "new_tag": _tag_name(after_element.tag),
                    "processor": name,
                },
            )

        after_attrib = dict(after_element.attrib)
        for key, old_value in before_attrib.items():
            if key in after_attrib:
                continue
            self.record(
                element=after_element,
                stage=STAGE_STRUCTURE,
                operation=f"attribute:{key}",
                reason=(
                    f"attribute '{key}' was removed by structural preprocessor '{name}'"
                ),
                details={
                    "attribute": key,
                    "old_value": old_value,
                    "processor": name,
                },
            )

        for key, new_value in after_attrib.items():
            old_value = before_attrib.get(key)
            if old_value == new_value:
                continue

            if key == "rel" and ("noopener" in new_value or "nofollow" in new_value):
                stage = STAGE_POLICY
                reason = (
                    "safe-link attribute 'rel' was added to a target=_blank or"
                    " external link by policy"
                )
            elif key == "name" and "id" in before_attrib:
                stage = STAGE_STRUCTURE
                reason = (
                    "anchor name was derived from its id during structural"
                    " normalization"
                )
            elif old_value is None:
                stage = STAGE_STRUCTURE
                reason = (
                    f"attribute '{key}' was added by structural preprocessor '{name}'"
                )
            else:
                stage = STAGE_STRUCTURE
                reason = (
                    f"attribute '{key}' was rewritten by structural"
                    f" preprocessor '{name}'"
                )

            self.record(
                element=after_element,
                stage=stage,
                operation=(
                    f"attribute-add:{key}" if old_value is None else f"attribute:{key}"
                ),
                reason=reason,
                details={
                    "attribute": key,
                    "old_value": old_value,
                    "new_value": new_value,
                    "processor": name,
                },
            )

    # -- structural decisions ------------------------------------------

    def record_text_changes(self, element, before_text, before_tail):
        if before_text and _CONTROL_CHARACTERS_RE.search(before_text):
            self.record(
                element=element,
                alias=f"{self.alias_for(element)}/#text",
                stage=STAGE_STRUCTURE,
                operation="text:control:#text",
                reason=(
                    "control characters were removed from text during"
                    " structural cleanup"
                ),
            )
        if before_tail and _CONTROL_CHARACTERS_RE.search(before_tail):
            self.record(
                element=element,
                alias=f"{self.alias_for(element)}/#tail",
                stage=STAGE_STRUCTURE,
                operation="text:control:#tail",
                reason=(
                    "control characters were removed from trailing text during"
                    " structural cleanup"
                ),
            )

    def record_structure_removal(self, element, reason):
        self.record(
            element=element,
            stage=STAGE_STRUCTURE,
            operation="node-removal",
            reason=reason,
        )

    def record_merge(self, element, removed_element):
        self.record(
            element=removed_element,
            stage=STAGE_STRUCTURE,
            operation="node-removal",
            reason=(
                f"adjacent <{_tag_name(removed_element.tag)}> elements were"
                " merged during structural repair"
            ),
            details={"merged_into": self.alias_for(element)},
        )

    def record_list_marker(self, element, before_text):
        self.record(
            element=element,
            alias=f"{self.alias_for(element)}/#text",
            stage=STAGE_STRUCTURE,
            operation="text:list-marker",
            reason=(
                f"redundant list marker was removed from <{_tag_name(element.tag)}>"
                " during structural cleanup"
            ),
            details={"old_text": before_text, "new_text": element.text},
        )

    # -- explicit policy decisions -------------------------------------

    def record_policy_removal(self, element, *, drop_contents):
        tag = element.tag
        label = _tag_name(tag)
        if label in {"script", "style"}:
            reason = (
                f"tag <{label}> is valid HTML but is active content and is not"
                " approved for public output; the tag and its contents were"
                " removed"
            )
        elif _is_known_html_tag(tag):
            reason = (
                f"tag <{label}> is valid HTML but is not approved for public output"
            )
            if drop_contents:
                reason += "; the tag and its contents were removed by policy"
            else:
                reason += "; the tag was unwrapped"
        else:
            reason = f"tag <{label}> is not an approved public tag"
            if drop_contents:
                reason += "; the tag and its contents were removed by policy"
            else:
                reason += "; the tag was unwrapped"

        self.record(
            element=element,
            stage=STAGE_POLICY,
            operation="node-removal",
            reason=reason,
        )

    def record_attribute_removal(self, element, key, value, allowed):
        self.record(
            element=element,
            stage=STAGE_POLICY,
            operation=f"attribute:{key}",
            reason=self._attribute_reason(_tag_name(element.tag), key),
            details={
                "attribute": key,
                "value": value,
                "allowed": sorted(allowed),
            },
        )

    def record_href_rewrite(self, element, old_value, new_value):
        self.record(
            element=element,
            stage=STAGE_POLICY,
            operation="attribute:href",
            reason=(
                "link target is valid markup but did not match the approved"
                " link policy; href was rewritten"
            ),
            details={"old_value": old_value, "new_value": new_value},
        )

    # -- final reconciliation ------------------------------------------

    def reconcile(self, doc):
        alive = {id(element) for element in doc.iter()}
        for element in list(self._elements.values()):
            if id(element) in alive:
                continue

            parent = element.getparent()
            if parent is not None and id(parent) not in alive:
                continue

            alias = self._aliases.get(id(element))
            if alias is None or alias == "#fragment":
                continue
            if self.ledger.has_node_disposition(self.document_id, alias):
                continue

            tag = element.tag
            label = _tag_name(tag)
            stage = (
                STAGE_POLICY
                if isinstance(tag, str) and tag.lower() not in self.sanitizer.tags
                else STAGE_STRUCTURE
            )
            self.record(
                element=element,
                stage=stage,
                operation="node-removal",
                reason=(
                    f"element <{label}> disappeared during sanitization and"
                    " could not be aligned to a recorded decision; kept for"
                    " confirmation"
                ),
                status=STATUS_PENDING,
            )


class Sanitizer:
    def __init__(self, settings=None):
        self.__dict__.update(DEFAULT_SETTINGS)
        self.__dict__.update(settings or {})

        # Allow iterables of any kind, not just sets.
        self.tags = coerce_to_set(self.tags)
        self.empty = coerce_to_set(self.empty)
        self.separate = coerce_to_set(self.separate)
        self.whitespace = coerce_to_set(self.whitespace)
        self.embedded_hosts = coerce_to_set(self.embedded_hosts)
        # Preserving whitespace inside tags which are removed later would
        # leak unnormalized whitespace into the output.
        self.preserve_whitespace = coerce_to_set(self.preserve_whitespace) & self.tags
        self.attributes = {
            tag: coerce_to_set(attributes)
            for tag, attributes in self.attributes.items()
        }

        if self.keep_typographic_whitespace:
            re_whitespace = r"[^\S%s]" % typographic_whitespace
        else:
            re_whitespace = r"\s"

        self.only_whitespace_re = re.compile(rf"^{re_whitespace}*$")
        self.whitespace_re = re.compile(rf"{re_whitespace}+")

        # Validate the settings.
        if not self.tags:
            raise TypeError(
                "Empty list of allowed tags is not supported by the underlying"
                " lxml cleaner. If you really do not want to pass any tags"
                " pass a made-up tag name which will never exist in your"
                " document."
            )
        if not self.tags.issuperset(self.empty):
            raise TypeError(
                f'Tags in "empty", but not allowed: {self.empty - self.tags!r}'
            )
        if not self.tags.issuperset(self.separate):
            raise TypeError(
                f'Tags in "separate", but not allowed: {self.separate - self.tags!r}'
            )
        if not self.tags.issuperset(self.attributes.keys()):
            raise TypeError(
                f'Tags in "attributes", but not allowed: {set(self.attributes.keys()) - self.tags!r}'
            )

        anchor_attributes = self.attributes.get("a", ())
        if "target" in anchor_attributes and "rel" not in anchor_attributes:
            raise TypeError(
                'Always allow "rel" when allowing "target" as anchor attribute'
            )

    @staticmethod
    def is_mergeable(e1, e2):
        """
        Decide if the adjacent elements of the same type e1 and e2 can be
        merged. This can be overriden to honouring distinct classes etc.
        """
        return True

    def normalize_whitespace(self, element, *, audit=None):
        before_text = element.text
        before_tail = element.tail
        inside = any(e.tag in self.preserve_whitespace for e in element.iterancestors())
        result = normalize_whitespace_in_text_or_tail(
            element,
            whitespace_re=self.whitespace_re,
            keep_typographic_whitespace=self.keep_typographic_whitespace,
            normalize_text=not inside and element.tag not in self.preserve_whitespace,
            normalize_tail=not inside,
        )
        if audit is not None:
            audit.record_text_changes(element, before_text, before_tail)
        return result

    def sanitize(  # noqa: C901 -- I know.
        self,
        html,
        *,
        ledger=None,
        audit_log=None,
        change_ledger=None,
        policy=None,
    ):
        """
        Clean HTML code from ugly copy-pasted CSS and empty elements

        Removes everything not explicitly allowed in ``self.allowed_tags``.

        Requires ``lxml`` and, for especially broken HTML, ``beautifulsoup4``.

        Passing a :class:`html_sanitizer.ledger.ChangeLedger` as ``ledger``
        turns on the optional audit trail. The returned HTML is unchanged; the
        ledger receives parse, structural and explicit-policy decisions.
        ``audit_log`` and ``change_ledger`` are accepted as aliases for
        ``ledger``.
        """

        provided_ledgers = [
            item for item in (ledger, audit_log, change_ledger) if item is not None
        ]
        if len({id(item) for item in provided_ledgers}) > 1:
            raise TypeError("Pass only one of ledger, audit_log or change_ledger")
        ledger = provided_ledgers[0] if provided_ledgers else None

        audit = None
        if ledger is not None:
            audit = _SanitizerAudit(ledger, self, policy=policy)
            audit.begin(html)

        # normalize unicode
        normalization_form = "NFC" if self.keep_typographic_whitespace else "NFKC"
        normalized_html = unicodedata.normalize(normalization_form, html)
        normalization_changed = normalized_html != html
        html = normalized_html

        html = "<div>%s</div>" % html
        parsed_with_fallback = False
        try:
            doc = lxml.html.fromstring(html)
            lxml.html.tostring(doc, encoding="utf-8")
        except Exception:
            from lxml.html import soupparser  # noqa: PLC0415

            doc = soupparser.fromstring(html)
            parsed_with_fallback = True

        if audit is not None:
            audit.index(doc)
            if normalization_changed:
                audit.record_unicode_normalization(normalization_form)
            if parsed_with_fallback:
                audit.record_parse_fallback()
            audit.record_parser_errors(doc)

        cleaner_snapshot = audit.snapshot(doc) if audit is not None else None
        lxml.html.clean.Cleaner(
            remove_unknown_tags=False,
            # Remove style *tags* if not explicitly allowed
            style="style" not in self.tags,
            # Do not strip out style attributes; we still need the style
            # information to convert spans into em/strong tags
            safe_attrs_only=False,
            inline_style=False,
            # Do not strip all form tags; we will filter them below
            forms=False,
            host_whitelist=self.embedded_hosts,
        )(doc)
        if audit is not None:
            audit.record_cleaner_changes(cleaner_snapshot, doc, phase="initial")

        # walk the tree recursively, because we want to be able to remove
        # previously emptied elements completely
        backlog = deque(doc.iterdescendants())

        doc = self.normalize_whitespace(doc, audit=audit)

        while True:
            try:
                element = backlog.pop()
            except IndexError:
                break

            for processor in self.element_preprocessors:
                before_tag = element.tag
                before_attrib = dict(element.attrib)
                processed = processor(element)
                if audit is not None:
                    audit.record_processor(
                        element,
                        processed,
                        before_tag=before_tag,
                        before_attrib=before_attrib,
                        processor=processor,
                    )
                element = processed

            if self.drop_disallowed_contents and element.tag not in self.tags:
                if audit is not None:
                    audit.record_policy_removal(element, drop_contents=True)
                element.drop_tree()
                continue

            element = self.normalize_whitespace(element, audit=audit)

            # remove empty tags if they are not explicitly allowed
            if (
                (not element.text or self.only_whitespace_re.match(element.text))
                and element.tag not in self.empty
                and not len(element)
            ):
                if audit is not None:
                    audit.record_structure_removal(
                        element,
                        (
                            f"empty <{_tag_name(element.tag)}> element was"
                            " removed during structural cleanup"
                        ),
                    )
                element.drop_tag()
                continue

            # remove tags which only contain whitespace and/or <br>s
            if (
                element.tag not in self.empty
                and self.only_whitespace_re.match(element.text or "")
                and {e.tag for e in element} <= self.whitespace
                and all(self.only_whitespace_re.match(e.tail or "") for e in element)
            ):
                if audit is not None:
                    audit.record_structure_removal(
                        element,
                        (
                            f"whitespace-only <{_tag_name(element.tag)}> element"
                            " was removed during structural cleanup"
                        ),
                    )
                element.drop_tree()
                continue

            if element.tag in {"li", "p"}:
                # remove p-in-li and p-in-p tags
                for p in element.findall("p"):
                    if audit is not None:
                        audit.record_structure_removal(
                            p,
                            (
                                f"nested <p> was unwrapped from"
                                f" <{_tag_name(element.tag)}> during structural"
                                " repair"
                            ),
                        )
                    if getattr(p, "text", None):
                        p.text = " " + p.text + " "
                    p.drop_tag()

                # remove list markers, maybe copy-pasted from word or whatever
                if element.text:
                    before_text = element.text
                    new_text = filter_control_characters(
                        re.sub(r"^\s*(-|\*|&#183;)\s+", "", element.text)
                    )
                    if audit is not None and new_text != before_text:
                        element.text = new_text
                        audit.record_list_marker(element, before_text)
                    else:
                        element.text = new_text

            elif element.tag in self.whitespace:
                # Drop the next element if
                # 1. it is a <br> too and 2. there is no content in-between
                nx = element.getnext()
                if (
                    nx is not None
                    and nx.tag == element.tag
                    and (
                        not element.tail or self.only_whitespace_re.match(element.tail)
                    )
                ):
                    if audit is not None:
                        audit.record_structure_removal(
                            nx,
                            (
                                f"redundant <{_tag_name(nx.tag)}> element was"
                                " removed during structural cleanup"
                            ),
                        )
                    nx.drop_tag()

            if not element.text:
                # No text before first child and first child is a <br>: Drop it
                first = next(iter(element), None)
                if first is not None and first.tag in self.whitespace:
                    if audit is not None:
                        audit.record_structure_removal(
                            first,
                            (
                                f"leading <{_tag_name(first.tag)}> element was"
                                " removed during structural cleanup"
                            ),
                        )
                    first.drop_tag()
                    # Maybe we have more than one <br>
                    backlog.append(element)
                    continue

            if element.tag in (self.tags - self.separate):
                # Check whether we should merge adjacent elements of the same
                # tag type
                nx = element.getnext()
                if (
                    self.only_whitespace_re.match(element.tail or "")
                    and nx is not None
                    and nx.tag == element.tag
                    and self.is_mergeable(element, nx)
                ):
                    # Yes, we should. Tail is empty, that is, no text between
                    # tags of a mergeable type.
                    if audit is not None:
                        audit.record_merge(element, nx)
                    if nx.text:
                        if len(element):
                            list(element)[-1].tail = "{}{}".format(
                                list(element)[-1].tail or "",
                                nx.text,
                            )
                        else:
                            element.text = "{}{}{}".format(
                                element.text or "", element.tail or "", nx.text
                            )

                    for child in nx:
                        element.append(child)

                    # tail is merged with previous element.
                    element.tail = nx.tail
                    nx.getparent().remove(nx)

                    # Process element again
                    backlog.append(element)
                    continue

            for processor in self.element_postprocessors:
                before_tag = element.tag
                before_attrib = dict(element.attrib)
                processed = processor(element)
                if audit is not None:
                    audit.record_processor(
                        element,
                        processed,
                        before_tag=before_tag,
                        before_attrib=before_attrib,
                        processor=processor,
                    )
                element = processed

            # remove all attributes which are not explicitly allowed
            allowed = self.attributes.get(element.tag, [])
            for key in list(element.keys()):
                if key not in allowed:
                    if audit is not None:
                        audit.record_attribute_removal(
                            element, key, element.get(key), allowed
                        )
                    del element.attrib[key]
                elif not self.keep_typographic_whitespace:
                    element.set(key, self.whitespace_re.sub(" ", element.get(key)))

            # Clean hrefs so that they are benign
            href = element.get("href")
            if href is not None:
                sanitized_href = self.sanitize_href(href)
                if audit is not None and sanitized_href != href:
                    audit.record_href_rewrite(element, href, sanitized_href)
                element.set("href", sanitized_href)

            element = self.normalize_whitespace(element, audit=audit)

        autolink_before_ids = (
            {id(element) for element in doc.iter()} if audit is not None else None
        )
        if self.autolink is True:
            lxml.html.clean.autolink(doc)
        elif isinstance(self.autolink, dict):
            lxml.html.clean.autolink(doc, **self.autolink)
        if audit is not None:
            audit.mark_generated(doc, autolink_before_ids)

        # Run cleaner again, but this time with even more strict settings
        cleaner_snapshot = audit.snapshot(doc) if audit is not None else None
        lxml.html.clean.Cleaner(
            allow_tags=self.tags,
            remove_unknown_tags=False,
            safe_attrs_only=False,  # Our attributes allowlist is sufficient.
            add_nofollow=self.add_nofollow,
            forms=False,
            host_whitelist=self.embedded_hosts,
        )(doc)
        if audit is not None:
            audit.record_cleaner_changes(cleaner_snapshot, doc, phase="final")
            audit.reconcile(doc)

        html = lxml.html.tostring(doc, encoding="unicode")

        # add a space before the closing slash in empty tags
        html = re.sub(r"<([^/>]+)/>", r"<\1 />", html)

        # remove wrapping tag needed by XML parser
        html = re.sub(r"^<div>|</div>$", "", html)

        return html

    def sanitize_with_ledger(self, html, *, ledger=None, policy=None):
        """Sanitize and return the output together with a change ledger."""

        if ledger is None:
            ledger = ChangeLedger()
        sanitized = self.sanitize(html, ledger=ledger, policy=policy)
        return SanitizeResult(html=sanitized, ledger=ledger)


class SanitizeResult(NamedTuple):
    """Result of :meth:`Sanitizer.sanitize_with_ledger`."""

    html: str
    ledger: ChangeLedger

    @property
    def sanitized(self):
        return self.html


def sanitize_with_ledger(html, *, settings=None, ledger=None, policy=None):
    """Convenience wrapper around :meth:`Sanitizer.sanitize_with_ledger`."""

    sanitizer = Sanitizer(settings) if settings is not None else Sanitizer()
    return sanitizer.sanitize_with_ledger(html, ledger=ledger, policy=policy)
