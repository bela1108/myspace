from copy import deepcopy
from contextlib import ExitStack
from dataclasses import dataclass, replace
import random
import re
from random import Random
from unittest import TestCase
from unittest.mock import patch
import lxml.html

from . import sanitizer as sanitizer_module
from .sanitizer import Sanitizer


default_sanitizer = Sanitizer()


MUTATION_SEED = 20261125
MUTATION_COUNT = 24
FORBIDDEN_TAGS = (
    "script",
    "object",
    "iframe",
    "embed",
    "svg",
    "math",
    "template",
)
EVENT_ATTRIBUTES = ("onerror", "onload", "onclick", "onfocus", "onanimationstart")
DANGEROUS_PROTOCOLS = (
    "javascript:alert(1)",
    "JaVaScRiPt:alert(2)",
    "java\tscript:alert(3)",
    "vbscript:msgbox(4)",
    "data:text/html,<script>alert(5)</script>",
)
SAFE_TAGS = ("p", "div", "span", "strong", "em", "a")
COMMENT_PAYLOADS = (
    "--><img src=x onerror=alert(6)>",
    "[if IE]><img src=x onerror=alert(7)><![endif]",
    "<![CDATA[<img src=x onerror=alert(8)>]]>",
)


def encode_entities(value):
    replacements = {
        "a": ("&#97;", "&Aacute;"),
        "j": ("&#106;",),
        "v": ("&#118;",),
        "s": ("&#115;",),
        "c": ("&#99;",),
        "r": ("&#114;",),
        "i": ("&#105;",),
        "p": ("&#112;",),
        "t": ("&#116;",),
        ":": ("&#58;", "&colon;"),
        "/": ("&#47;",),
    }
    encoded = []
    for index, char in enumerate(value):
        options = replacements.get(char.lower())
        if options:
            encoded.append(options[index % len(options)])
        else:
            encoded.append(char)
    return "".join(encoded)


def normalize_scheme(value):
    return "".join(char for char in value.lower() if not char.isspace())


def has_dangerous_protocol(value):
    normalized = normalize_scheme(value)
    return normalized.startswith(
        (
            "javascript:",
            "vbscript:",
            "data:text/html",
            "file:",
        )
    )


@dataclass(frozen=True)
class TextNode:
    text: str

    def render(self):
        return self.text

    def contains_dangerous_mutation(self):
        return any(
            token in self.text.lower()
            for token in ("<script", "<img", "<svg", "onerror", "onload")
        )


@dataclass(frozen=True)
class CommentNode:
    text: str

    def render(self):
        return f"<!--{self.text}-->"

    def contains_dangerous_mutation(self):
        lowered = self.text.lower()
        return "<img" in lowered or "<script" in lowered or "onerror" in lowered


@dataclass(frozen=True)
class ElementNode:
    tag: str
    attributes: tuple = ()
    children: tuple = ()

    def render(self):
        attribute_text = ""
        for name, value in self.attributes:
            attribute_text += f' {name}="{value}"'
        children = "".join(child.render() for child in self.children)
        return f"<{self.tag}{attribute_text}>{children}</{self.tag.split()[0]}>"

    def contains_dangerous_mutation(self):
        lowered_tag = self.tag.lower()
        if lowered_tag in FORBIDDEN_TAGS:
            return True
        if any(name.lower().startswith("on") for name, _ in self.attributes):
            return True
        if any(
            name.lower() == "href" and has_dangerous_protocol(value)
            for name, value in self.attributes
        ):
            return True
        return any(child.contains_dangerous_mutation() for child in self.children)


@dataclass(frozen=True)
class StageEvent:
    stage: str
    detail: str


@dataclass(frozen=True)
class MutationReport:
    index: int
    payload: str
    minimized_payload: str
    sanitized: str
    resanitized: str
    trace: tuple


class FixedSeedMutator:
    def __init__(self, seed=MUTATION_SEED):
        self.random = Random(seed)

    def generate(self, count=MUTATION_COUNT):
        return [self.generate_mutation(index) for index in range(count)]

    def generate_mutation(self, index):
        random = self.random
        children = [
            self.protocol_anchor(),
            self.event_element(),
            self.forbidden_element(),
            CommentNode(random.choice(COMMENT_PAYLOADS)),
        ]
        depth = random.randrange(2, 5)
        nested = self.nest(children, depth)
        if index % 2:
            nested = (
                ElementNode("p", (), nested),
                TextNode("&lt;img src=x onerror=alert(9)&gt;"),
            )
        return ElementNode("div", (), nested)

    def nest(self, children, depth):
        if not depth:
            return tuple(children)
        wrapper = ElementNode(
            random_tag(self.random, SAFE_TAGS),
            (),
            self.nest(children, depth - 1),
        )
        return (wrapper,)

    def protocol_anchor(self):
        protocol = self.random.choice(DANGEROUS_PROTOCOLS)
        if self.random.randrange(2):
            protocol = encode_entities(protocol)
        return ElementNode("a", (("HREF", protocol),), (TextNode("link"),))

    def event_element(self):
        event = self.random.choice(EVENT_ATTRIBUTES)
        if self.random.randrange(2):
            event = mixed_case(event)
        tag = random_tag(self.random, SAFE_TAGS)
        return ElementNode(
            tag,
            ((event, "alert(10)"),),
            (TextNode("mutated"),),
        )

    def forbidden_element(self):
        tag = self.random.choice(FORBIDDEN_TAGS)
        if self.random.randrange(2):
            tag = mixed_case(tag)
        return ElementNode(
            tag,
            (("OnErRoR", "alert(11)"),),
            (TextNode("blocked"),),
        )


def random_tag(random, tags):
    tag = random.choice(tags)
    if random.randrange(2):
        return mixed_case(tag)
    return tag


def mixed_case(value):
    return "".join(
        char.upper() if index % 2 else char.lower()
        for index, char in enumerate(value)
    )


def tree_size(node):
    if isinstance(node, ElementNode):
        return 1 + sum(tree_size(child) for child in node.children)
    return 1


def with_children(element, children):
    return replace(element, children=tuple(children))


def minimize_tree(root):
    candidate = replace(root)
    while True:
        reduced = reduce_tree_once(candidate)
        if reduced == candidate:
            return candidate
        candidate = reduced


def reduce_tree_once(root):
    for index, child in enumerate(root.children):
        without = with_children(root, root.children[:index] + root.children[index + 1 :])
        if without.contains_dangerous_mutation():
            return without

        if isinstance(child, ElementNode):
            if child.contains_dangerous_mutation():
                unwrapped = with_children(
                    root,
                    root.children[:index] + child.children + root.children[index + 1 :],
                )
                if unwrapped.contains_dangerous_mutation():
                    return unwrapped

            reduced_child = reduce_tree_once(child)
            if reduced_child != child:
                return with_children(
                    root,
                    root.children[:index]
                    + (reduced_child,)
                    + root.children[index + 1 :],
                )
    return root


def describe_element(element):
    attributes = sorted((name, value) for name, value in element.attrib.items())
    return f"{element.tag} {attributes}"


def run_with_stage_trace(sanitizer, payload):
    trace = []
    configured = Sanitizer(sanitizer.__dict__.copy())

    def parse_hook(parser, *args, **kwargs):
        trace.append(StageEvent("parse", "lxml.html.fromstring"))
        return parser(*args, **kwargs)

    def soup_parse_hook(parser, *args, **kwargs):
        trace.append(StageEvent("parse", "soupparser.fromstring"))
        return parser(*args, **kwargs)

    def tostring_hook(*args, **kwargs):
        trace.append(StageEvent("serialize", "lxml.html.tostring"))
        return sanitizer_module.lxml.html.tostring(*args, **kwargs)

    def wrap_processor(name, processor):
        def tracked(element):
            result = processor(element)
            trace.append(StageEvent("callback", f"{name}:{describe_element(result)}"))
            return result

        return tracked

    configured.element_preprocessors = [
        wrap_processor("preprocessor", processor)
        for processor in configured.element_preprocessors
    ]
    configured.element_postprocessors = [
        wrap_processor("postprocessor", processor)
        for processor in configured.element_postprocessors
    ]
    configured.sanitize_href = wrap_href_callback(configured.sanitize_href, trace)

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                sanitizer_module.lxml.html,
                "fromstring",
                side_effect=lambda *args, **kwargs: parse_hook(
                    original_parse, *args, **kwargs
                ),
            )
        )
        stack.enter_context(
            patch.object(
                sanitizer_module.lxml.html,
                "tostring",
                side_effect=tostring_hook,
            )
        )
        original_parse = sanitizer_module.lxml.html.fromstring
        stack.enter_context(
            patch.object(
                sanitizer_module.lxml.html.soupparser,
                "fromstring",
                side_effect=lambda *args, **kwargs: soup_parse_hook(
                    original_soup_parse, *args, **kwargs
                ),
            )
        )
        original_soup_parse = sanitizer_module.lxml.html.soupparser.fromstring
        sanitized = configured.sanitize(payload)

    return sanitized, tuple(trace)


def wrap_href_callback(callback, trace):
    def tracked(href):
        result = callback(href)
        trace.append(StageEvent("callback", f"sanitize_href:{href}->{result}"))
        return result

    return tracked


def build_mutation_reports(sanitizer):
    reports = []
    for index, tree in enumerate(FixedSeedMutator().generate()):
        payload = tree.render()
        minimized_tree = minimize_tree(tree)
        minimized_payload = minimized_tree.render()
        sanitized, trace = run_with_stage_trace(sanitizer, minimized_payload)
        resanitized = sanitizer.sanitize(sanitized)
        reports.append(
            MutationReport(
                index=index,
                payload=payload,
                minimized_payload=minimized_payload,
                sanitized=sanitized,
                resanitized=resanitized,
                trace=trace,
            )
        )
    return reports


def assert_sanitized_output_is_allowed(test_case, sanitizer, html):
    parsed = sanitizer_module.lxml.html.fragment_fromstring(html, create_parent="div")
    for element in parsed.iter():
        if not isinstance(element.tag, str):
            continue
        test_case.assertIn(element.tag, sanitizer.tags)
        allowed_attributes = sanitizer.attributes.get(element.tag, set())
        for name, value in element.attrib.items():
            test_case.assertIn(name, allowed_attributes)
            test_case.assertFalse(name.lower().startswith("on"))
            test_case.assertFalse(has_dangerous_protocol(value))


class SanitizerTestCase(TestCase):
    def run_tests(self, entries, *, sanitizer=default_sanitizer, strip=False):
        for before, after in entries:
            with self.subTest(before=before, after=after):
                after = before if after is None else after  # noqa: PLW2901
                result = sanitizer.sanitize(before)
                self.assertEqual(
                    result.strip() if strip else result,
                    after.strip() if strip else after,
                    b"Cleaning '%s', expected '%s' but got '%s'"
                    % (
                        before.encode("unicode-escape"),
                        after.encode("unicode-escape"),
                        result.encode("unicode-escape"),
                    ),
                )

    def test_01_sanitize(self):
        entries = [
            ("<p>&nbsp;</p>", " "),
            ("<p>           </p>", " "),
            (
                '<span style="font-weight: bold;">Something</span><p></p>',
                "<strong>Something</strong>",
            ),
            (
                "<p>abc <span>def <em>ghi</em> jkl</span> mno</p>",
                "<p>abc def <em>ghi</em> jkl mno</p>",
            ),
            (
                '<span style="font-style: italic;">Something</span><p></p>',
                "<em>Something</em>",
            ),
            ('<h2 style="font-weight:bold">bla</h2>', "<h2>bla</h2>"),
            ('<h2 style="font-style:italic">bla</h2>', "<h2>bla</h2>"),
            ("<p>abc<br />def</p>", "<p>abc<br>def</p>"),
            ("<p><br/><br/><strong></strong>  <br/></p>", ""),
            ("<p><br/><strong></strong>  <br/> abc</p>", "<p> abc</p>"),
            ("<li><br>bla</li>", "<li>bla</li>"),
            (
                "<p><strong>just</strong> <em>testing</em></p>",
                "<p><strong>just</strong> <em>testing</em></p>",
            ),
            (
                "<p>Hallo<br>Welt<br><br>Hallo<br>Welt</p>",
                "<p>Hallo<br>Welt<br>Hallo<br>Welt</p>",
            ),
            (
                "<p><strong>Zeile 1</strong><br>Zeile 2<br>Zeile 3</p>",
                "<p><strong>Zeile 1</strong><br>Zeile 2<br>Zeile 3</p>",
            ),
            (
                "<p><strong>A</strong>, <strong>B</strong> und <strong>C</strong></p>",
                "<p><strong>A</strong>, <strong>B</strong> und <strong>C</strong></p>",
            ),
            ("<p><form>Zeile 1</form></p>", "<p>Zeile 1</p>"),
            # Suboptimal, should be cleaned further
            ("<form><p>Zeile 2</p></form>", "<p> Zeile 2 </p>"),
            ("1<p> </p>2", "1 2"),
            ("1<p></p>2", "12"),
            ("<p>son<strong>der</strong>bar</p>", "<p>son<strong>der</strong>bar</p>"),
            # Empty a tags are allowed...
            ("<a>  </a>", "<a> </a>"),
            # ...but breaks without any additional content are still removed
            ("<a><br />  </a>", "<a> </a>"),
            ("<p>blab<br hello='world' />blub<p>", "<p>blab<br>blub</p>"),
            ("<p>A & B</p>", "<p>A &amp; B</p>"),
            ("<p>A &lt; B</p>", "<p>A &lt; B</p>"),
        ]

        self.run_tests(entries)

    def test_02_a_tag(self):
        entries = (
            ('<a href="/foo">foo</a>', None),
            (
                (
                    '<a href="/foo" name="bar" target="some" title="baz"'
                    ' cookies="yesplease">foo</a>'
                ),
                '<a href="/foo" name="bar" target="some" title="baz">foo</a>',
            ),
            ('<a href="http://somewhere.else">foo</a>', None),
            ('<a href="https://somewhere.else">foo</a>', None),
            ('<a href="javascript:alert()">foo</a>', '<a href="#">foo</a>'),
            ('<a href="javascript%3Aalert()">foo</a>', '<a href="#">foo</a>'),
            ('<a href="mailto:foo@bar.com">foo</a>', None),
            ('<a href="tel:1-234-567-890">foo</a>', None),
        )

        self.run_tests(entries)

    def test_03_merge(self):
        entries = (
            ("<h2>foo</h2><h2>bar</h2>", "<h2>foobar</h2>"),
            ("<h2>foo  </h2>   <h2>   bar</h2>", "<h2>foo bar</h2>"),
        )

        self.run_tests(entries)

    def test_no_space_between_same_tags(self):
        entries = [
            ("<strong>Hel</strong><strong>lo</strong>", "<strong>Hello</strong>")
        ]
        self.run_tests(entries)

    def test_04_p_in_li(self):
        entries = (
            ("<li><p>foo</p></li>", "<li> foo </li>"),
            ("<li>&nbsp;<p>foo</p> &#160; </li>", "<li> foo </li>"),
            (
                (
                    "<li>foo<p>bar<strong>xx</strong>rab</p><strong>baz</strong>"
                    "a<p>b</p>c</li>"
                ),
                "<li>foo bar <strong>xx</strong>rab<strong>baz</strong>a b c</li>",
            ),
        )

        self.run_tests(entries)

    def test_05_p_in_p(self):
        entries = (
            ("<p><p>foo</p></p>", "<p>foo</p>"),
            ("<p><p><p>&nbsp;</p> </p><p><br /></p></p>", " "),
            # This is actually correct as the second <p> implicitely
            # closes the first paragraph, and the trailing </p> is
            # deleted because it has no matching opening <p>
            ("<p>foo<p>bar</p>baz</p>", "<p>foo</p><p>bar</p>baz"),
            ("<p>bla <p>blub</p> blaaa</p>", "<p>bla </p><p>blub</p> blaaa"),
            (
                "<p>text1 <p>text2</p> tail2 <p>text3</p> tail3 </p>tail1",
                "<p>text1 </p><p>text2</p> tail2 <p>text3</p> tail3 tail1",
            ),
        )

        self.run_tests(entries)

    def test_06_allowlist(self):
        entries = (
            ('<script src="http://abc">foo</script>', ""),
            ('<script type="text/javascript">foo</script>', ""),
        )

        self.run_tests(entries)

    def test_07_configuration(self):
        sanitizer = Sanitizer(
            {"tags": ["h1", "h2"], "empty": (), "separate": (), "attributes": {}}
        )

        entries = (
            ("<h1>foo</h1>", None),
            ("<h1>foo</h1><h2>bar</h2><h3>baz</h3>", "<h1>foo</h1><h2>bar</h2>baz"),
        )

        self.run_tests(entries, sanitizer=sanitizer)

    def test_08_li_with_marker(self):
        entries = (
            ("<li> - foo</li>", "<li>foo</li>"),
            ("<li>* foo</li>", "<li>foo</li>"),
            ("<li>*foo</li>", "<li>*foo</li>"),
        )

        self.run_tests(entries)

    def test_09_empty_p_text_in_li(self):
        # this results in an empty p.text
        entries = (
            ("<li><p><strong>foo</strong></p></li>", "<li><strong>foo</strong></li>"),
            ("<li><p><em>foo</em></p></li>", "<li><em>foo</em></li>"),
        )

        self.run_tests(entries)

    def test_10_broken_html(self):
        entries = (
            ("<p><strong>bla", "<p><strong>bla</strong></p>"),
            ("<p><strong>bla<>/dsiad<p/", "<p><strong>bla&lt;&gt;/dsiad</strong></p>"),
        )

        self.run_tests(entries)

    def test_11_nofollow(self):
        sanitizer = Sanitizer({"add_nofollow": True})

        entries = (
            (
                '<p><a href="http://example.com/">example.com</a></p>',
                '<p><a href="http://example.com/" rel="nofollow">example.com</a></p>',
            ),
        )

        self.run_tests(entries, sanitizer=sanitizer)

    def test_12_replacements(self):
        entries = (
            ("<b>Bla</b>", "<strong>Bla</strong>"),
            ("<i>Bla</i>", "<em>Bla</em>"),
        )

        self.run_tests(entries)

    def test_13_autolink(self):
        self.run_tests([("<p>https://github.com/</p>", "<p>https://github.com/</p>")])

        sanitizer = Sanitizer({"autolink": True})

        self.run_tests(
            [
                (
                    "<p>https://github.com/</p>",
                    '<p><a href="https://github.com/">https://github.com/</a></p>',
                ),
                (
                    # localhost is not autolinked by default by lxml
                    "<p>https://localhost/</p>",
                    "<p>https://localhost/</p>",
                ),
            ],
            sanitizer=sanitizer,
        )

        sanitizer = Sanitizer({"autolink": True, "add_nofollow": True})

        self.run_tests(
            [
                (
                    "<p>https://github.com/</p>",
                    (
                        '<p><a href="https://github.com/"'
                        ' rel="nofollow">https://github.com/</a></p>'
                    ),
                )
            ],
            sanitizer=sanitizer,
        )

        sanitizer = Sanitizer({"autolink": {"avoid_hosts": []}})

        self.run_tests(
            [
                (
                    "<p>https://github.com/</p>",
                    '<p><a href="https://github.com/">https://github.com/</a></p>',
                ),
                (
                    "<p>https://localhost/</p>",
                    '<p><a href="https://localhost/">https://localhost/</a></p>',
                ),
            ],
            sanitizer=sanitizer,
        )

    def test_14_classes(self):
        """Class attributes should not be treated specially"""
        sanitizer = Sanitizer(
            {
                "tags": {"h1", "h2", "p", "a", "span"},
                "attributes": {
                    "a": ("href", "name", "target", "title", "id", "rel"),
                    "h1": ("class",),
                    "p": ("class",),
                    "span": ("class",),
                },
                "empty": set(),
                "separate": {"a", "p"},
            }
        )

        self.run_tests(
            [
                ('<p class="centered">Test</p>', '<p class="centered">Test</p>'),
                (
                    '<p class="centered">Test <span class="bla">span</span></p>',
                    '<p class="centered">Test <span class="bla">span</span></p>',
                ),
                (
                    (
                        '<p class="centered">Test <span class="bla">span</span>'
                        '<span class="blub">span</span></p>'
                    ),
                    '<p class="centered">Test <span class="bla">spanspan</span></p>',
                ),
                ('<h1 class="centered">Test</h1>', '<h1 class="centered">Test</h1>'),
                ('<h2 class="centered">Test</h2>', "<h2>Test</h2>"),
            ],
            sanitizer=sanitizer,
        )

    def test_15_classes(self):
        """Class attributes may disable merging"""
        sanitizer = Sanitizer(
            {
                "tags": {"h1", "h2", "p", "a", "span"},
                "attributes": {
                    "a": ("href", "name", "target", "title", "id", "rel"),
                    "h1": ("class",),
                    "p": ("class",),
                    "span": ("class",),
                },
                "empty": set(),
                "separate": {"a", "p"},
                "is_mergeable": lambda e1, e2: e1.get("class") == e2.get("class"),
            }
        )

        self.run_tests(
            [
                (
                    (
                        '<p class="centered">Test <span class="bla">span</span>'
                        '<span class="blub">span</span></p>'
                    ),
                    (
                        '<p class="centered">Test <span class="bla">span</span>'
                        '<span class="blub">span</span></p>'
                    ),
                ),
                (
                    (
                        '<p class="centered">Test <span class="bla">span</span>'
                        '<span class="bla">span</span></p>'
                    ),
                    '<p class="centered">Test <span class="bla">spanspan</span></p>',
                ),
            ],
            sanitizer=sanitizer,
        )

    def test_16_emoji(self):
        self.run_tests([("<p>😂</p>", "<p>😂</p>"), ("<p>💕</p>", "<p>💕</p>")])

    def test_target_blank(self):
        self.run_tests(
            [
                (
                    '<a href="#" target="_blank">test</a>',
                    '<a href="#" target="_blank" rel="noopener">test</a>',
                )
            ]
        )

    def test_remove_everything(self):
        sanitizer = Sanitizer(
            {"tags": {"__never"}, "attributes": {}, "empty": set(), "separate": set()}
        )

        self.run_tests(
            [
                (
                    '<span style="color:#000000;font-weight:bold">11:44:14</span>',
                    "11:44:14",
                )
            ],
            sanitizer=sanitizer,
        )

    def test_more_merging(self):
        self.run_tests(
            [
                ("<p><hr></p>", "<hr>"),
                ("<hr><hr><hr>", "<hr>"),
                (
                    '<a name="a"></a><a name="b"></a>',
                    '<a name="a"></a><a name="b"></a>',
                ),
            ]
        )

    def test_keep_consecutive_br_tags(self):
        sanitizer = Sanitizer({"whitespace": set(), "separate": {"br"}})
        self.run_tests(
            [
                ("<p>Hello<br><br>World</p>", "<p>Hello<br><br>World</p>"),
                ("<p>Hello<br><br></p>", "<p>Hello<br><br></p>"),
                ("<p><br><br>World</p>", "<p><br><br>World</p>"),
                ("<p><br><br></p>", "<p><br><br></p>"),
                ("<p><br></p><hr><br></p>", "<p><br></p><hr><br>"),
            ],
            sanitizer=sanitizer,
        )

    def test_custom_allowed_attribute(self):
        sanitizer = Sanitizer({"attributes": {"a": ("href", "custom")}})
        self.run_tests(
            [
                (
                    '<a href="http://example.com" custom="1" abc="2">Test</a>',
                    '<a href="http://example.com" custom="1">Test</a>',
                )
            ],
            sanitizer=sanitizer,
        )

    def test_blob(self):
        source = """\
<p class="western" style="margin-left: 0.39in; text-indent: -0.39in; margin-top: 0.25in; margin-bottom: 0in; line-height: 0.19in" lang="de-DE" align="justify">
<font style="font-size: 12pt" size="3"><b>1.2.	Definition des
Spesenbegriffs</b></font></p>
<p class="western" style="margin-left: 0.39in; margin-top: 0.13in; margin-bottom: 0in; line-height: 0.19in" lang="de-DE" align="justify">
<font style="font-size: 12pt" size="3">Als Spesen im Sinne dieses
Reglements gelten die Auslagen, die einem Mitarbeitenden im Interesse
des Arbeitgebers angefallen sind. Sämtliche Mitarbeitende sind
verpflichtet, ihre Spesen im Rahmen dieses Reglements möglichst tief
zu halten. Aufwendungen, die für die Arbeitsausführung nicht
notwendig waren, werden von der Firma nicht übernommen, sondern sind
von den Mitarbeitenden selbst zu tragen.</font></p>
<p class="western" style="margin-left: 0.39in; margin-top: 0.13in; margin-bottom: 0in; line-height: 0.19in" lang="de-DE" align="justify">
<font style="font-size: 12pt" size="3">Im Wesentlichen werden den
Mitarbeitenden folgende geschäftlich bedingten Auslagen ersetzt:</font></p>
<ul><li><p class="western" style="margin-top: 0.13in; margin-bottom: 0in; line-height: 0.19in" lang="de-DE" align="justify"> <font style="font-size: 12pt" size="3">-	Fahrtkosten					(nachfolgend 2.)</font></p> </li><li><p class="western" style="margin-bottom: 0in; line-height: 0.19in" lang="de-DE" align="justify"> <font style="font-size: 12pt" size="3">-	Verpflegungskosten			(nachfolgend 3.)</font></p> </li><li><p class="western" style="margin-bottom: 0in; line-height: 0.19in" lang="de-DE" align="justify"> <font style="font-size: 12pt" size="3">-	Übernachtungskosten			(nachfolgend 4.)</font></p> </li><li><p class="western" style="margin-bottom: 0in; line-height: 0.19in" lang="de-DE" align="justify"> <font style="font-size: 12pt" size="3">-	Übrige Kosten				(nachfolgend 5.)</font></p> </li></ul>"""

        result = """\
<p> <strong>1.2. Definition des Spesenbegriffs</strong></p> <p> Als Spesen im Sinne dieses Reglements gelten die Auslagen, die einem Mitarbeitenden im Interesse des Arbeitgebers angefallen sind. Sämtliche Mitarbeitende sind verpflichtet, ihre Spesen im Rahmen dieses Reglements möglichst tief zu halten. Aufwendungen, die für die Arbeitsausführung nicht notwendig waren, werden von der Firma nicht übernommen, sondern sind von den Mitarbeitenden selbst zu tragen.</p> <p> Im Wesentlichen werden den Mitarbeitenden folgende geschäftlich bedingten Auslagen ersetzt:</p> <ul><li> - Fahrtkosten (nachfolgend 2.) </li><li> - Verpflegungskosten (nachfolgend 3.) </li><li> - Übernachtungskosten (nachfolgend 4.) </li><li> - Übrige Kosten (nachfolgend 5.) </li></ul>"""

        # XXX An exact match isn't really required. Using Django's
        # assertHTMLEqual would be great but we'd have to depend on Django in
        # the test suite for this (not a big problem really, because then we
        # could also test html_sanitizer.django but I didn't yet *have* to do
        # this)
        self.run_tests([(source, result)])

    def test_keep_typographic_whitespace(self):
        sanitizer = Sanitizer({"keep_typographic_whitespace": True})

        # Note some unicode normalization of typographic whitespace
        self.run_tests(
            [
                (
                    (
                        "\u200a\u2001\u202f\u2004\xa0\u2007\u2002\u2000"
                        "\u2003\u2009\u205f\u2005\u2006\u2008\u3000"
                    ),
                    (
                        "\u200a\u2003\u202f\u2004\xa0\u2007\u2002\u2002"
                        "\u2003\u2009\u205f\u2005\u2006\u2008\u3000"
                    ),
                ),
                (
                    (
                        "Hello This is a paragraph. \n"
                        "\tHello. This is a tabled line."
                        "Hello.This is beginning of the end.\r"
                    ),
                    (
                        "Hello This is a paragraph. \n"
                        "\tHello. This is a tabled line."
                        "Hello.This is beginning of the end.\n"
                    ),
                ),
                (
                    "something    <br>somethingelse    ",
                    "something    <br>somethingelse    ",
                ),
            ],
            sanitizer=sanitizer,
        )

    def test_strip_typographic_whitespace(self):
        sanitizer = Sanitizer({"keep_typographic_whitespace": False})

        self.run_tests(
            [
                (
                    (
                        "\u200a\u2001\u202f\u2004\xa0\u2007\u2002\u2000"
                        "\u2003\u2009\u205f\u2005\u2006\u2008\u3000"
                    ),
                    " ",
                )
            ],
            sanitizer=sanitizer,
        )

    def test_anchor_names(self):
        self.run_tests(
            [
                (
                    '<a name="test" id="test"></a>',
                    '<a name="test"></a>',
                ),
                (
                    '<a name="test"></a>',
                    '<a name="test"></a>',
                ),
                (
                    '<a id="test"></a>',
                    '<a name="test"></a>',
                ),
            ],
        )

    def test_style_tag(self):
        # don't allow style tag (default)
        self.run_tests(
            [("foo<style>*{color: red}</style>bar", "foobar")],
            sanitizer=Sanitizer(
                {
                    "tags": {"impossible tag"},
                    "attributes": {},
                    "empty": set(),
                    "separate": set(),
                }
            ),
        )

        # allow style tag but no style attribute
        self.run_tests(
            [
                (
                    "foo<style>*{color: red}</style>bar",
                    "foo<style>*{color: red}</style>bar",
                ),
                ('<h2 style="font-weight:bold">bla</h2>', "<h2>bla</h2>"),
            ],
            sanitizer=Sanitizer(
                {
                    "tags": {"h2", "style"},
                    "attributes": {},
                    "empty": set(),
                    "separate": set(),
                }
            ),
        )

        # allow style tag and style attribute
        self.run_tests(
            [
                (
                    "foo<style>*{color: red}</style>bar",
                    "foo<style>*{color: red}</style>bar",
                ),
                (
                    '<h2 style="font-weight:bold">bla</h2>',
                    '<h2 style="font-weight:bold">bla</h2>',
                ),
            ],
            sanitizer=Sanitizer(
                {
                    "tags": {"h2", "style"},
                    "attributes": {"h2": {"style"}},
                    "empty": set(),
                    "separate": set(),
                }
            ),
        )

    def test_billion_laughs(self):
        before = """\
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
"""

        external_entities = """\
 <?xml version="1.0"?>
  <!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>
"""

        self.run_tests(
            [
                (before, "]&gt; &amp;lol9;"),
                (external_entities, "]&gt;&amp;xxe;"),
            ],
            strip=True,
        )

    def test_data_attributes(self):
        sanitizer = Sanitizer(
            {
                "tags": ["span"],
                "empty": (),
                "separate": (),
                "attributes": {"span": {"data-title"}},
            }
        )

        entries = (
            (
                '<span data-title="Test">Content</span>',
                '<span data-title="Test">Content</span>',
            ),
            (
                '<span data-title="Test" data-other="Stuff">Content</span>',
                '<span data-title="Test">Content</span>',
            ),
        )

        self.run_tests(entries, sanitizer=sanitizer)

    def test_entities(self):
        self.run_tests(
            [
                ("&lsquo;", "\u2018"),
            ],
        )

    def test_invalid_attributes(self):
        with self.assertRaisesRegex(TypeError, "Expected a set but got"):
            Sanitizer({"attributes": {"p": ("class")}})

        with self.assertRaisesRegex(TypeError, "Expected a set but got"):
            Sanitizer({"tags": "blub"})

        with self.assertRaisesRegex(TypeError, 'Tags in "empty", but not allowed:'):
            Sanitizer({"tags": {"blub"}})

    def test_img_tag(self):
        sanitizer = Sanitizer(
            {
                "tags": {"p", "img"},
                "empty": {"img"},
                "separate": (),
                "attributes": {"img": {"alt", "src"}},
            }
        )

        entries = (
            (
                '<p><img src="hello.jpg" alt="hello" class="hello"></p>',
                '<p><img src="hello.jpg" alt="hello"></p>',
            ),
        )

        self.run_tests(entries, sanitizer=sanitizer)

    def test_code_whitespace(self):
        sanitizer = Sanitizer(
            {
                "tags": {"code"},
                "empty": set(),
                "separate": set(),
                "attributes": {},
                "keep_typographic_whitespace": True,
            }
        )

        html = """\
<code>
git status
git add
git commit
</code>
"""

        self.run_tests([(html, html)], sanitizer=sanitizer)

    def test_br_attribute_sanitization(self):
        """Attributes which aren't allowlisted are removed from br tags"""
        self.run_tests(
            [
                ("<p><br hello=\"alert('world');\"/><br></p>", ""),
                ('<p hello="world"></p>', ""),
                ("<br hello=\"alert('world');\"/><br>", "<br>"),
            ]
        )

    def test_normalize_early(self):
        self.run_tests(
            [
                (
                    "\uff1cimg src=x onerror=\uff02alert(window.location)\uff02\uff1e",
                    "",
                ),
            ]
        )

    def test_typographic_whitespace_tags_merging(self):
        sanitizer = Sanitizer(
            {
                "whitespace": set(),
                "keep_typographic_whitespace": True,
            }
        )
        self.run_tests(
            [
                (
                    "This is <strong>some</strong> <strong>text</strong> with adjacent tags.",
                    "This is <strong>some text</strong> with adjacent tags.",
                ),
                (
                    "This is <strong>some</strong> <strong>text</strong>with adjacent tags.",
                    "This is <strong>some text</strong>with adjacent tags.",
                ),
            ],
            sanitizer=sanitizer,
        )

    def test_control_characters(self):
        self.run_tests(
            [
                (
                    # Control characters are filtered out, leaving empty element which gets removed
                    "<p>\x01</p>",
                    "",
                ),
                (
                    "<p>Hallo \x01 Welt</p>",
                    "<p>Hallo Welt</p>",
                ),
            ]
        )

    def test_preserve_whitespace(self):
        sanitizer = Sanitizer(
            {
                "tags": {"p", "pre", "code", "strong"},
                "empty": set(),
                "separate": {"p", "pre"},
                "attributes": {},
            }
        )
        self.run_tests(
            [
                (
                    "<pre>git status\ngit  add\n\tgit commit\n</pre>",
                    "<pre>git status\ngit  add\n\tgit commit\n</pre>",
                ),
                (
                    "<p>a\n\n  b</p>\n\n<pre><code>if x:\n    <strong>y</strong>\n</code></pre>\n\n<p>c  d</p>",
                    "<p>a b</p> <pre><code>if x:\n    <strong>y</strong>\n</code></pre> <p>c d</p>",
                ),
                (
                    "<pre><span>a\n  b</span>\n</pre>",
                    "<pre>a\n  b\n</pre>",
                ),
                ("<code>a\n  b</code>", "<code>a b</code>"),
            ],
            sanitizer=sanitizer,
        )

        sanitizer = Sanitizer(
            {
                "tags": {"code"},
                "empty": set(),
                "separate": set(),
                "attributes": {},
                "preserve_whitespace": {"code"},
            }
        )
        self.run_tests(
            [("<code>a\n  b</code>", "<code>a\n  b</code>")],
            sanitizer=sanitizer,
        )

    def test_preserve_whitespace_disallowed_tag(self):
        # pre isn't allowed by default, therefore whitespace is normalized
        self.run_tests([("<pre>a\n\n  b</pre>", "a b")])

    def test_embedded_hosts(self):
        settings = {
            "tags": {"p", "iframe"},
            "empty": {"iframe"},
            "separate": {"p", "iframe"},
            "attributes": {"iframe": {"src", "width", "height"}},
        }
        entries = [
            (
                '<iframe src="https://www.youtube.com/embed/abc" width="560" onload="alert(1)"></iframe>',
                '<iframe src="https://www.youtube.com/embed/abc" width="560"></iframe>',
            ),
            ('<iframe src="https://evil.example.com/"></iframe>', ""),
            ('<iframe src="//www.youtube.com/embed/abc"></iframe>', ""),
            ('<iframe src="javascript:alert(1)"></iframe>', ""),
            ("<iframe></iframe>", ""),
            ('<p>a<embed src="https://www.youtube.com/x"></p>', "<p>a</p>"),
        ]
        self.run_tests(
            entries,
            sanitizer=Sanitizer({**settings, "embedded_hosts": {"www.youtube.com"}}),
        )

        # Without embedded_hosts no iframes are allowed at all
        self.run_tests(
            [
                ('<iframe src="https://www.youtube.com/embed/abc"></iframe>', ""),
            ],
            sanitizer=Sanitizer(settings),
        )

        # iframe has to be an allowed tag
        self.run_tests(
            [
                (
                    '<p>x<iframe src="https://www.youtube.com/embed/abc">y</iframe></p>',
                    "<p>xy</p>",
                ),
            ],
            sanitizer=Sanitizer({"embedded_hosts": {"www.youtube.com"}}),
        )

    def test_drop_disallowed_contents(self):
        sanitizer = Sanitizer({"drop_disallowed_contents": True})
        self.run_tests(
            [
                (
                    "<p>abc <span>def <em>ghi</em> jkl</span> mno</p>",
                    "<p>abc mno</p>",
                ),
                (
                    "<p>abc <b>def</b> <i>ghi</i></p>",
                    "<p>abc <strong>def</strong> <em>ghi</em></p>",
                ),
                ("<badtag>secret</badtag><p>public</p>", "<p>public</p>"),
                ("<p>a<badtag>b<em>c</em></badtag>d</p>", "<p>ad</p>"),
            ],
            sanitizer=sanitizer,
        )
