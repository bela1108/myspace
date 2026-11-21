import re
import unicodedata
from collections import deque

import lxml.html
import lxml.html.clean

from .text_alternatives import (
    REFERENCE_ATTRIBUTES,
    TEXT_ALTERNATIVE_ATTRIBUTES,
    TEXT_ALTERNATIVE_TAGS,
    SanitizeResult,
    TextAlternativeDecision,
    _Candidate,
    apply_text_alternative_plans,
    build_id_index,
    decide_text_alternatives,
)


__all__ = (
    "TEXT_ALTERNATIVE_ATTRIBUTES",
    "TEXT_ALTERNATIVE_TAGS",
    "SanitizeResult",
    "Sanitizer",
    "TextAlternativeDecision",
)


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
    "text_alternative_tags": set(TEXT_ALTERNATIVE_TAGS),
    "text_alternative_attributes": dict(TEXT_ALTERNATIVE_ATTRIBUTES),
}


def coerce_to_set(value):
    if isinstance(value, set):
        return value
    elif isinstance(value, tuple | list):
        return set(value)
    raise TypeError(f"Expected a set but got value {value!r} of type {type(value)}")


class Sanitizer:
    def __init__(self, settings=None):
        self.__dict__.update(DEFAULT_SETTINGS)
        self.__dict__.update(settings or {})

        self._configure_text_alternatives(settings or {})

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
        self.text_alternative_tags = coerce_to_set(self.text_alternative_tags)
        self.text_alternative_attributes = {
            tag: tuple(attributes)
            for tag, attributes in self.text_alternative_attributes.items()
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

    def _configure_text_alternatives(self, settings):  # noqa: C901
        """Accept the documented setting and a few convenient aliases."""

        unset = object()
        configured = unset
        for key in (
            "text_alternative",
            "text_alternatives",
            "accessible_text_alternatives",
            "accessible_text_alternative_tags",
            "aria_text_alternatives",
            "aria_text_fallbacks",
            "accessible_name_fallbacks",
        ):
            if key in settings and "text_alternative_tags" not in settings:
                configured = settings[key]
                break

        # The attributes map is always copied so instances do not share it.
        configured_attributes = self.text_alternative_attributes
        self.text_alternative_attributes = {
            tag: tuple(attributes) for tag, attributes in configured_attributes.items()
        }

        if configured is not unset:
            if configured is True:
                self.text_alternative_tags = set(TEXT_ALTERNATIVE_TAGS)
            elif configured is False or configured is None:
                self.text_alternative_tags = set()
            elif isinstance(configured, dict):
                tags = set()
                for tag, value in configured.items():
                    if value is False:
                        continue
                    tags.add(tag)
                    if isinstance(value, str):
                        self.text_alternative_attributes[tag] = (value,)
                    elif isinstance(value, tuple | list | set | frozenset):
                        self.text_alternative_attributes[tag] = tuple(value)
                    elif isinstance(value, dict):
                        if value.get("enabled") is False:
                            tags.discard(tag)
                            continue
                        attributes = value.get("attributes", value.get("attribute"))
                        if isinstance(attributes, str):
                            self.text_alternative_attributes[tag] = (attributes,)
                        elif attributes:
                            self.text_alternative_attributes[tag] = tuple(attributes)
                self.text_alternative_tags = tags
            else:
                self.text_alternative_tags = coerce_to_set(configured)

        if isinstance(self.text_alternative_tags, bool):
            self.text_alternative_tags = (
                set(TEXT_ALTERNATIVE_TAGS) if self.text_alternative_tags else set()
            )
        else:
            self.text_alternative_tags = set(coerce_to_set(self.text_alternative_tags))

        if not isinstance(self.text_alternative_attributes, dict):
            raise TypeError("text_alternative_attributes must be a dict")

        self.text_alternative_attributes = {
            tag: (attributes,) if isinstance(attributes, str) else tuple(attributes)
            for tag, attributes in self.text_alternative_attributes.items()
        }

    @staticmethod
    def is_mergeable(e1, e2):
        """
        Decide if the adjacent elements of the same type e1 and e2 can be
        merged. This can be overriden to honouring distinct classes etc.
        """
        return True

    def normalize_whitespace(self, element):
        inside = any(e.tag in self.preserve_whitespace for e in element.iterancestors())
        return normalize_whitespace_in_text_or_tail(
            element,
            whitespace_re=self.whitespace_re,
            keep_typographic_whitespace=self.keep_typographic_whitespace,
            normalize_text=not inside and element.tag not in self.preserve_whitespace,
            normalize_tail=not inside,
        )

    def sanitize(self, html):
        """
        Clean HTML code from ugly copy-pasted CSS and empty elements

        Removes everything not explicitly allowed in ``self.allowed_tags``.

        Requires ``lxml`` and, for especially broken HTML, ``beautifulsoup4``.
        """
        html, _decisions = self._sanitize(html)
        return html

    def sanitize_with_report(self, html):
        """Sanitize and return the accessible-text decisions as well."""

        html, decisions = self._sanitize(html)
        return SanitizeResult(
            html=html,
            text_alternatives=tuple(
                decision for decision in decisions if decision.status == "applied"
            ),
            manual=tuple(
                decision for decision in decisions if decision.status == "manual"
            ),
        )

    def _sanitize(self, html):  # noqa: C901 -- I know.

        # normalize unicode
        if self.keep_typographic_whitespace:
            html = unicodedata.normalize("NFC", html)
        else:
            html = unicodedata.normalize("NFKC", html)

        html = "<div>%s</div>" % html
        try:
            doc = lxml.html.fromstring(html)
            lxml.html.tostring(doc, encoding="utf-8")
        except Exception:
            from lxml.html import soupparser  # noqa: PLC0415

            doc = soupparser.fromstring(html)

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

        # walk the tree recursively, because we want to be able to remove
        # previously emptied elements completely
        backlog = deque(doc.iterdescendants())
        id_index = build_id_index(doc)
        candidates = []
        seen_candidates = set()

        doc = self.normalize_whitespace(doc)

        while True:
            try:
                element = backlog.pop()
            except IndexError:
                break

            for processor in self.element_preprocessors:
                element = processor(element)

            if (
                element.tag in self.text_alternative_tags
                and element.tag in self.tags
                and id(element) not in seen_candidates
            ):
                references = {
                    attribute: value
                    for attribute in REFERENCE_ATTRIBUTES
                    if (value := element.get(attribute))
                }
                if references:
                    seen_candidates.add(id(element))
                    candidates.append(_Candidate(element, references))

            if self.drop_disallowed_contents and element.tag not in self.tags:
                element.drop_tree()
                continue

            element = self.normalize_whitespace(element)

            # remove empty tags if they are not explicitly allowed
            if (
                (not element.text or self.only_whitespace_re.match(element.text))
                and element.tag not in self.empty
                and not len(element)
            ):
                element.drop_tag()
                continue

            # remove tags which only contain whitespace and/or <br>s
            if (
                element.tag not in self.empty
                and self.only_whitespace_re.match(element.text or "")
                and {e.tag for e in element} <= self.whitespace
                and all(self.only_whitespace_re.match(e.tail or "") for e in element)
            ):
                element.drop_tree()
                continue

            if element.tag in {"li", "p"}:
                # remove p-in-li and p-in-p tags
                for p in element.findall("p"):
                    if getattr(p, "text", None):
                        p.text = " " + p.text + " "
                    p.drop_tag()

                # remove list markers, maybe copy-pasted from word or whatever
                if element.text:
                    element.text = filter_control_characters(
                        re.sub(r"^\s*(-|\*|&#183;)\s+", "", element.text)
                    )

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
                    nx.drop_tag()

            if not element.text:
                # No text before first child and first child is a <br>: Drop it
                first = next(iter(element), None)
                if first is not None and first.tag in self.whitespace:
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
                element = processor(element)

            # remove all attributes which are not explicitly allowed
            allowed = self.attributes.get(element.tag, [])
            for key in element.keys():  # noqa: SIM118 (do not remove .keys())
                if key not in allowed:
                    del element.attrib[key]
                elif not self.keep_typographic_whitespace:
                    element.set(key, self.whitespace_re.sub(" ", element.get(key)))

            # Clean hrefs so that they are benign
            href = element.get("href")
            if href is not None:
                element.set("href", self.sanitize_href(href))

            element = self.normalize_whitespace(element)

        if self.autolink is True:
            lxml.html.clean.autolink(doc)
        elif isinstance(self.autolink, dict):
            lxml.html.clean.autolink(doc, **self.autolink)

        # Run cleaner again, but this time with even more strict settings
        lxml.html.clean.Cleaner(
            allow_tags=self.tags,
            remove_unknown_tags=False,
            safe_attrs_only=False,  # Our attributes allowlist is sufficient.
            add_nofollow=self.add_nofollow,
            forms=False,
            host_whitelist=self.embedded_hosts,
        )(doc)

        if candidates:
            document_order = {node: index for index, node in enumerate(doc.iter())}
            candidates.sort(
                key=lambda candidate: document_order.get(
                    candidate.element, len(document_order)
                )
            )

        decisions, plans = decide_text_alternatives(
            doc,
            candidates,
            id_index,
            allowed_attributes=self.attributes,
            eligible_tags=self.text_alternative_tags & self.tags,
            output_attributes=self.text_alternative_attributes,
            whitespace_re=self.whitespace_re,
        )
        apply_text_alternative_plans(plans)

        html = lxml.html.tostring(doc, encoding="unicode")

        # add a space before the closing slash in empty tags
        html = re.sub(r"<([^/>]+)/>", r"<\1 />", html)

        # remove wrapping tag needed by XML parser
        html = re.sub(r"^<div>|</div>$", "", html)

        return html, decisions
