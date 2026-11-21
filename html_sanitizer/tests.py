from unittest import TestCase

from .sanitizer import Sanitizer
from .verification import ApprovalScope, ReviewRecord, StructuralSummary, verify


default_sanitizer = Sanitizer()


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


class VerificationTestCase(TestCase):
    def summary(self, html, policy_version="policy-a"):
        return StructuralSummary.from_html(html, policy_version=policy_version)

    def test_unchanged_edited_and_missing_are_distinct(self):
        reviewed = (
            "<h2>Introduction</h2><p>The quick brown fox jumps over the lazy dog.</p>"
        )
        summary = self.summary(reviewed)
        scope = ApprovalScope.from_sections({"introduction": summary.sections[0].id})

        unchanged = verify(
            reviewed,
            summary=summary,
            scope=scope,
            policy_version="policy-a",
        )
        entry = unchanged["introduction"]
        self.assertEqual(entry.status, "unchanged")
        self.assertTrue(entry.matched)
        self.assertTrue(entry.claimable)
        self.assertEqual(unchanged.claimable_keys, ("introduction",))

        edited = verify(
            (
                "<h2>Introduction</h2>"
                "<p>The quick brown fox jumped over the lazy dog.</p>"
            ),
            summary=summary,
            scope=scope,
            policy_version="policy-a",
        )
        entry = edited["introduction"]
        self.assertEqual(entry.status, "edited")
        self.assertTrue(entry.matched)
        self.assertFalse(entry.claimable)
        self.assertGreater(entry.similarity, 0.5)
        self.assertEqual(edited.counts["edited"], 1)

        # The new policy no longer allows headings, so the section identity is
        # gone even though the body text survives.
        sanitizer = Sanitizer(
            {"tags": {"p"}, "empty": set(), "separate": {"p"}, "attributes": {}}
        )
        missing_html = sanitizer.sanitize(reviewed)
        missing = verify(
            missing_html,
            summary=summary,
            scope=scope,
            policy_version="policy-a",
            current_policy_version="policy-b",
        )
        entry = missing["introduction"]
        self.assertEqual(entry.status, "missing")
        self.assertFalse(entry.matched)
        self.assertFalse(entry.claimable)
        self.assertIsNone(entry.current_path)

    def test_moving_two_same_named_sections_keeps_their_identity(self):
        reviewed = (
            "<h2>Overview</h2><p>intro</p>"
            "<h2>Notes</h2><p>alpha</p>"
            "<h2>Notes</h2><p>beta</p>"
        )
        summary = self.summary(reviewed)
        self.assertEqual(
            [section.id for section in summary.sections],
            [
                "section:0",
                "section:2",
                "section:4",
            ],
        )
        self.assertEqual(
            summary.sections[1].name_digest, summary.sections[2].name_digest
        )
        self.assertNotEqual(
            summary.sections[1].content_digest,
            summary.sections[2].content_digest,
        )

        scope = ApprovalScope.from_sections(
            {
                "notes-a": summary.sections[1].id,
                "notes-b": summary.sections[2].id,
            }
        )
        # Move both same-named subsections: the alpha section now follows the
        # beta section, and vice versa.
        final = (
            "<h2>Overview</h2><p>intro</p>"
            "<h2>Notes</h2><p>beta</p>"
            "<h2>Notes</h2><p>alpha</p>"
        )
        report = verify(
            final,
            summary=summary,
            scope=scope,
            policy_version="policy-a",
        )

        notes_a = report["notes-a"]
        notes_b = report["notes-b"]
        self.assertEqual(notes_a.status, "moved")
        self.assertEqual(notes_a.original_path, (2,))
        self.assertEqual(notes_a.current_path, (4,))
        self.assertEqual(notes_b.status, "moved")
        self.assertEqual(notes_b.original_path, (4,))
        self.assertEqual(notes_b.current_path, (2,))
        self.assertEqual(report.with_status("unchanged"), ())
        self.assertEqual(report.matched_keys, ("notes-a", "notes-b"))
        self.assertEqual(report.claimable_keys, ())
        self.assertEqual(report.counts["moved"], 2)

    def test_duplicate_at_the_old_path_is_not_claimed(self):
        reviewed = (
            "<h2>Overview</h2><p>intro</p>"
            "<h2>Notes</h2><p>alpha</p>"
            "<h2>Notes</h2><p>beta</p>"
        )
        summary = self.summary(reviewed)
        # Only the second, otherwise identically named section was approved.
        scope = ApprovalScope.from_sections({"notes-b": summary.sections[2].id})
        final = (
            "<h2>Overview</h2><p>intro</p>"
            "<h2>Notes</h2><p>beta</p>"
            "<h2>Notes</h2><p>alpha</p>"
        )
        report = verify(
            final,
            summary=summary,
            scope=scope,
            policy_version="policy-a",
        )

        entry = report["notes-b"]
        self.assertEqual(entry.status, "moved")
        self.assertEqual(entry.current_path, (2,))
        self.assertFalse(entry.claimable)
        # The unapproved duplicate now sits at the old path, but it must not
        # inherit the approval merely because its heading name matches.
        self.assertEqual(report.matched_keys, ("notes-b",))
        self.assertEqual(report.claimable_keys, ())
        self.assertEqual(len(report.entries), 1)

    def test_policy_version_is_bound_and_reported(self):
        reviewed = "<h2>Notes</h2><p>alpha</p>"
        summary = self.summary(reviewed, policy_version="policy-a")
        scope = ApprovalScope.from_sections({"notes": summary.sections[0].id})

        with self.assertRaisesRegex(ValueError, "recorded for policy version"):
            verify(
                reviewed,
                summary=summary,
                scope=scope,
                policy_version="policy-b",
            )

        report = verify(
            reviewed,
            summary=summary,
            scope=scope,
            policy_version="policy-a",
            current_policy_version="policy-b",
        )
        self.assertTrue(report.policy_changed)
        self.assertEqual(report.current_policy_version, "policy-b")
        self.assertEqual(report.claimable_keys, ("notes",))

        record = ReviewRecord(summary=summary, scope=scope, policy_version="policy-a")
        restored = ReviewRecord.from_dict(record.to_dict())
        self.assertEqual(restored.verify(reviewed).claimable_keys, ("notes",))

    def test_report_and_summary_do_not_contain_reviewed_text(self):
        reviewed = (
            "<h2>Reviewed heading 73c9</h2>"
            "<p>Reviewed body 4f1a that must never be copied into a report.</p>"
        )
        summary = self.summary(reviewed)
        scope = ApprovalScope.from_sections({"notes": summary.sections[0].id})
        report = verify(
            reviewed,
            summary=summary,
            scope=scope,
            policy_version="policy-a",
        )

        rendered = " ".join(
            (
                repr(summary),
                repr(report),
                str(summary.to_dict()),
                str(report.to_dict()),
            )
        )
        self.assertNotIn("Reviewed heading 73c9", rendered)
        self.assertNotIn("Reviewed body 4f1a", rendered)
        self.assertNotIn("must never be copied", rendered)
