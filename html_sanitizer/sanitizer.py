import re
import unicodedata
from collections import deque
from urllib.parse import urlparse

import lxml.html
import lxml.html.clean

from .audit import Category, ChangeLedger, Reason, Status


__all__ = ("Sanitizer",)


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

    def normalize_whitespace(self, element):
        inside = any(e.tag in self.preserve_whitespace for e in element.iterancestors())
        return normalize_whitespace_in_text_or_tail(
            element,
            whitespace_re=self.whitespace_re,
            keep_typographic_whitespace=self.keep_typographic_whitespace,
            normalize_text=not inside and element.tag not in self.preserve_whitespace,
            normalize_tail=not inside,
        )


    def sanitize_with_ledger(self, html, *, previous=None):
        ledger = ChangeLedger(previous=previous)
        return self.sanitize(html, ledger=ledger), ledger

    def _record_tag_rewrite(self, element, before, ledger):
        if ledger is None or before == element.tag:
            return
        ledger.record(
            element,
            Category.STRUCTURE,
            Reason.TAG_REWRITTEN,
            detail=f"{before}->{element.tag}",
        )

    def _normalize_with_ledger(self, element, ledger):
        if ledger is None:
            return self.normalize_whitespace(element)
        had_control = bool(
            (element.text and re.search(r"[\x00-\x1f\x7f]", element.text))
            or (element.tail and re.search(r"[\x00-\x1f\x7f]", element.tail))
        )
        element = self.normalize_whitespace(element)
        if had_control:
            ledger.record(
                element,
                Category.STRUCTURE,
                Reason.CONTROL_CHARACTERS_FILTERED,
            )
        return element

    @staticmethod
    def _prescan_disallowed(root, allowed_tags):
        """All elements whose tag is outside the allowlist.

        The parser wrapping element (the document root) is intentionally
        excluded -- it is scaffolding, never part of the fragment.
        """
        return [
            element
            for element in root.iter()
            if element is not root
            and isinstance(element.tag, str)
            and element.tag not in allowed_tags
        ]

    def sanitize(self, html, *, ledger=None):  # noqa: C901 -- I know.
        """
        Clean HTML code from ugly copy-pasted CSS and empty elements

        Removes everything not explicitly allowed in ``self.allowed_tags``.

        Requires ``lxml`` and, for especially broken HTML, ``beautifulsoup4``.

        When a :class:`~html_sanitizer.audit.ChangeLedger` is passed as
        ``ledger`` every parse, structural and explicit-policy decision is
        recorded there. Nodes which disappear without an attributable
        decision are kept as pending entries for later human confirmation.
        """

        # normalize unicode
        if self.keep_typographic_whitespace:
            html = unicodedata.normalize("NFC", html)
        else:
            html = unicodedata.normalize("NFKC", html)

        html = "<div>%s</div>" % html
        parser_fallback = False
        try:
            doc = lxml.html.fromstring(html)
            lxml.html.tostring(doc, encoding="utf-8")
        except Exception:  # noqa: BLE001 -- we could and maybe should be more specific
            from lxml.html import soupparser  # noqa: PLC0415

            doc = soupparser.fromstring(html)
            parser_fallback = True

        if ledger is not None:
            ledger.assign_aliases(doc)
            if parser_fallback:
                ledger.record(
                    doc,
                    Category.PARSE,
                    Reason.PARSER_FALLBACK,
                    detail="lxml parser failed; BeautifulSoup fallback used",
                )
            # Comments and style/script tags are removed by the first
            # cleaner. Prescan them so the decision is attributable.
            for element in doc.iter():
                # The first cleaner strips event-handler attributes;
                # record them before they disappear.
                if isinstance(element.tag, str):
                    for handler in [k for k in element.keys() if k.startswith("on")]:
                        ledger.record(
                            element,
                            Category.POLICY,
                            Reason.DISALLOWED_ATTRIBUTE_REMOVED,
                            detail=(
                                f"attribute {handler!r} not allowed on"
                                f" {element.tag!r}"
                            ),
                        )

                if not isinstance(element.tag, str):
                    ledger.record(
                        element, Category.PARSE, Reason.COMMENT_REMOVED
                    )
                elif element.tag == "style" and "style" not in self.tags:
                    ledger.record(
                        element, Category.PARSE, Reason.STYLE_TAG_REMOVED
                    )
                elif element.tag == "script":
                    ledger.record(
                        element, Category.PARSE, Reason.SCRIPT_TAG_REMOVED
                    )

                href = element.get("href") if isinstance(element.tag, str) else None
                if href is not None and self.sanitize_href(href) != href:
                    # The first cleaner neutralizes unsafe hrefs itself;
                    # record the explicit policy decision up-front.
                    ledger.record(
                        element,
                        Category.POLICY,
                        Reason.HREF_SANITIZED,
                        detail=(
                            f"href {href!r} replaced with"
                            f" {self.sanitize_href(href)!r}"
                        ),
                    )

                if element.tag in {"iframe", "embed", "object"} and (
                    element.tag not in self.tags
                    or urlparse(element.get("src", "")).hostname
                    not in self.embedded_hosts
                ):
                    # The first cleaner drops embedded content from hosts
                    # outside the allowlist (or with unsafe schemes).
                    ledger.record(
                        element,
                        Category.POLICY,
                        Reason.EMBEDDED_HOST_NOT_ALLOWED,
                    )

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

        if ledger is not None:
            ledger.reconcile(doc)

        # walk the tree recursively, because we want to be able to remove
        # previously emptied elements completely
        backlog = deque(doc.iterdescendants())

        doc = self._normalize_with_ledger(doc, ledger)

        while True:
            try:
                element = backlog.pop()
            except IndexError:
                break

            tag_before_processors = element.tag
            for processor in self.element_preprocessors:
                element = processor(element)
            self._record_tag_rewrite(element, tag_before_processors, ledger)

            if self.drop_disallowed_contents and element.tag not in self.tags:
                if ledger is not None:
                    ledger.record(
                        element,
                        Category.POLICY,
                        Reason.DISALLOWED_TAG_REMOVED,
                        detail=f"tag {element.tag!r} outside allowlist",
                    )
                element.drop_tree()
                continue

            element = self._normalize_with_ledger(element, ledger)

            # remove empty tags if they are not explicitly allowed
            if (
                (not element.text or self.only_whitespace_re.match(element.text))
                and element.tag not in self.empty
                and not len(element)
            ):
                if ledger is not None:
                    ledger.record(
                        element,
                        Category.STRUCTURE,
                        Reason.EMPTY_ELEMENT_REMOVED,
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
                if ledger is not None:
                    ledger.record(
                        element,
                        Category.STRUCTURE,
                        Reason.WHITESPACE_ELEMENT_REMOVED,
                    )
                element.drop_tree()
                continue

            if element.tag in {"li", "p"}:
                # remove p-in-li and p-in-p tags
                for p in element.findall("p"):
                    if ledger is not None:
                        ledger.record(
                            p,
                            Category.STRUCTURE,
                            Reason.NESTED_PARAGRAPH_UNWRAPPED,
                        )
                    if getattr(p, "text", None):
                        p.text = " " + p.text + " "
                    p.drop_tag()

                # remove list markers, maybe copy-pasted from word or whatever
                if element.text:
                    cleaned = filter_control_characters(
                        re.sub(r"^\s*(-|\*|&#183;)\s+", "", element.text)
                    )
                    if cleaned != element.text and ledger is not None:
                        ledger.record(
                            element,
                            Category.STRUCTURE,
                            Reason.LIST_MARKER_REMOVED,
                        )
                    element.text = cleaned

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
                    if ledger is not None:
                        ledger.record(
                            nx,
                            Category.STRUCTURE,
                            Reason.DUPLICATE_WHITESPACE_TAG,
                        )
                    nx.drop_tag()

            if not element.text:
                # No text before first child and first child is a <br>: Drop it
                first = next(iter(element), None)
                if first is not None and first.tag in self.whitespace:
                    if ledger is not None:
                        ledger.record(
                            first,
                            Category.STRUCTURE,
                            Reason.LEADING_WHITESPACE_TAG,
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
                    if ledger is not None:
                        ledger.record(
                            nx,
                            Category.STRUCTURE,
                            Reason.ELEMENTS_MERGED,
                            detail=f"merged into preceding {nx.tag!r}",
                        )
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
                    if ledger is not None:
                        ledger.record(
                            element,
                            Category.POLICY,
                            Reason.DISALLOWED_ATTRIBUTE_REMOVED,
                            detail=(
                                f"attribute {key!r} not allowed on"
                                f" {element.tag!r}"
                            ),
                        )
                    del element.attrib[key]
                elif not self.keep_typographic_whitespace:
                    element.set(key, self.whitespace_re.sub(" ", element.get(key)))
            # Clean hrefs so that they are benign. Unsafe hrefs may already
            # have been neutralized by the first cleaner (the decision is
            # recorded in the pre-scan); only record when the value changes
            # during this pass.
            href = element.get("href")
            if href is not None:
                sanitized = self.sanitize_href(href)
                if (
                    sanitized != href
                    and ledger is not None
                    and not ledger.was_seen(element, Reason.HREF_SANITIZED)
                ):
                    ledger.record(
                        element,
                        Category.POLICY,
                        Reason.HREF_SANITIZED,
                        detail=f"href {href!r} replaced with {sanitized!r}",
                    )
                element.set("href", sanitized)

            element = self._normalize_with_ledger(element, ledger)

        if self.autolink is True:
            lxml.html.clean.autolink(doc)
        elif isinstance(self.autolink, dict):
            lxml.html.clean.autolink(doc, **self.autolink)

        if ledger is not None:
            # Prescan the explicit-policy decisions the stricter cleaner is
            # about to take so they do not end up as unattributed removals.
            for disallowed in self._prescan_disallowed(doc, self.tags):
                ledger.record(
                    disallowed,
                    Category.POLICY,
                    Reason.DISALLOWED_TAG_UNWRAPPED,
                    detail=f"tag {disallowed.tag!r} outside allowlist",
                )
            for element in doc.iter():
                allowed = self.attributes.get(element.tag, ())
                for key in element.keys():
                    if key not in allowed:
                        ledger.record(
                            element,
                            Category.POLICY,
                            Reason.DISALLOWED_ATTRIBUTE_REMOVED,
                            detail=(
                                f"attribute {key!r} not allowed on"
                                f" {element.tag!r}"
                            ),
                        )
                if element.tag in {"iframe", "embed", "object"} and (
                    element.tag not in self.tags
                    or urlparse(element.get("src", "")).hostname
                    not in self.embedded_hosts
                ):
                    ledger.record(
                        element,
                        Category.POLICY,
                        Reason.EMBEDDED_HOST_NOT_ALLOWED,
                    )

        # Run cleaner again, but this time with even more strict settings
        lxml.html.clean.Cleaner(
            allow_tags=self.tags,
            remove_unknown_tags=False,
            safe_attrs_only=False,  # Our attributes allowlist is sufficient.
            add_nofollow=self.add_nofollow,
            forms=False,
            host_whitelist=self.embedded_hosts,
        )(doc)

        if ledger is not None:
            # Anything still unattributed remains open for confirmation.
            ledger.reconcile(doc)

        html = lxml.html.tostring(doc, encoding="unicode")

        # add a space before the closing slash in empty tags
        html = re.sub(r"<([^/>]+)/>", r"<\1 />", html)

        # remove wrapping tag needed by XML parser
        html = re.sub(r"^<div>|</div>$", "", html)

        return html
