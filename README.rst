==============
HTML sanitizer
==============

This is a allowlist-based and very opinionated HTML sanitizer that
can be used both for untrusted and trusted sources. It attempts to clean
up the mess made by various rich text editors and or copy-pasting to
make styling of webpages simpler and more consistent. It builds on the
excellent HTML cleaner in lxml_ to make the result both valid and safe.

HTML sanitizer goes further than e.g. bleach_ in that it not only
ensures that content is safe and tags and attributes conform to a given
allowlist, but also applies additional transforms to HTML fragments.

Goals
=====

- Clean up HTML fragments using a very restricted set of allowed tags
  and attributes.
- Convert *some* tags (such as ``<span style="...">``, ``<b>`` and
  ``<i>``) into either ``<strong>`` or ``<em>`` (but never both).
- Absolutely disallow all inline styles.
- Normalize whitespace by removing repeated line breaks, empty
  paragraphs and other empty elements.
- Merge adjacent tags of the same type (such as several ``<strong>`` or
  ``<h3>`` directly after each other.
- Automatically remove redundant list markers inside ``<li>`` tags.
- Clean up some uglyness such as paragraphs inside paragraphs or list
  elements etc.
- Normalize unicode.

Usage
=====

    >>> from html_sanitizer import Sanitizer
    >>> sanitizer = Sanitizer()  # default configuration
    >>> sanitizer.sanitize('<span style="font-weight:bold">some text</span>')
    '<strong>some text</strong>'

Settings
========

- Bold spans and ``b`` tags are converted into ``strong`` tags, italic
  spans and ``i`` tags into ``em`` tags (if ``strong`` and ``em`` are
  allowed at all)
- Inline styles and scripts will always be dropped.
- A ``div`` element is used to wrap the HTML fragment for the parser,
  therefore ``div`` tags are not allowed.

The default settings are::

    DEFAULT_SETTINGS = {
        "tags": {
            "a", "h1", "h2", "h3", "strong", "em", "p", "ul", "ol",
            "li", "br", "sub", "sup", "hr",
        },
        "attributes": {"a": ("href", "name", "target", "title", "id", "rel")},
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
        ],
        "element_postprocessors": [],
        "is_mergeable": lambda e1, e2: True,
    }

The keys' meaning is as follows:

- ``tags``: A ``set()`` of allowed tags.
- ``attributes``: A ``dict()`` mapping tags to their allowed attributes.
- ``empty``: Tags which are allowed to be empty. By default, empty tags
  (containing no text or only whitespace) are dropped.
- ``separate``: Tags which are not merged if they appear as siblings. By
  default, tags of the same type are merged.
- ``whitespace``: Tags which are treated as whitespace and removed from
  the beginning or end of other tags' content.
- ``preserve_whitespace``: Tags inside which whitespace isn't normalized,
  e.g. to keep line breaks in ``pre`` or ``code`` tags. Only has an
  effect for tags which are allowed.
- ``keep_typographic_whitespace``: Keep typographically used space
  characters like non-breaking space etc.
- ``drop_disallowed_contents``: Remove disallowed tags including their
  contents. By default, only the tags themselves are removed and their
  contents are kept. Element preprocessors run first, so e.g. ``b`` tags
  are still converted into ``strong`` tags instead of being dropped.
- ``add_nofollow``: Whether to add ``rel="nofollow"`` to all links.
- ``autolink``: Enable lxml_'s autolinker_. May be either a boolean or a
  dictionary; a dictionary is passed as keyword arguments to
  ``autolink``.
- ``embedded_hosts``: Hosts from which embedded content such as
  ``iframe`` elements is accepted (only ``http:`` and ``https:`` URLs).
  Embedded content is dropped by default. To allow YouTube embeds you also
  have to allow the tag and its attributes and allow it to be empty, e.g.
  ``"tags": {..., "iframe"}``, ``"attributes": {"iframe": {"src", "width",
  "height", "allowfullscreen"}}``, ``"empty": {..., "iframe"}`` and
  ``"embedded_hosts": {"www.youtube.com", "www.youtube-nocookie.com"}``.
- ``sanitize_href``: A callable that gets anchor's ``href`` value and
  returns a sanitized version. The default implementation checks whether
  links start with a few allowed prefixes, and if not, returns a single
  hash (``#``).
- ``element_preprocessors`` and ``element_postprocessors``: Additional
  filters that are called on all elements in the tree. The tree is
  processed in reverse depth-first order. Under certain circumstances
  elements are processed more than once (search the code for
  ``backlog.append``). Preprocessors are run before whitespace
  normalization, postprocessors afterwards.
- ``is_mergeable``: Adjacent elements which aren't kept ``separate`` are
  merged by default. This callable can be used to prevent merging of
  adjacent elements e.g. when their classes do not match
  (``lambda e1, e2: e1.get('class') == e2.get('class')``)

Settings can be specified partially when initializing a sanitizer
instance, but are still checked for consistency. For example, it is not
allowed to have tags in ``empty`` that are not in ``tags``, that is,
tags that are allowed to be empty but at the same time not allowed at
all. The ``Sanitizer`` constructor raises ``TypeError`` exceptions when
it detects inconsistencies.

An example for an even more restricted configuration might be::

    >>> from html_sanitizer import Sanitizer
    >>> sanitizer = Sanitizer({
    ...     'tags': ('h1', 'h2', 'p'),
    ...     'attributes': {},
    ...     'empty': set(),
    ...     'separate': set(),
    ... })

The rationale for such a restricted set of allowed tags (e.g. no
images) is documented in the `design decisions`_ section of
django-content-editor_'s documentation.

Publication boundary checks (own documents only)
================================================

Sanitizing a document can merge adjacent nodes and concatenate their text and
tail runs. If a document uses annotations for publication permissions, a clean
public citation can therefore end up containing text from an internal
annotation. ``PublicationBoundary`` adds a boundary check for this case. It
returns both the publishable HTML and a review queue with source provenance.

This helper is intended for documents owned and controlled by the application.
The permission annotations are trusted metadata, not a security boundary. It
does not make third-party HTML safe; sanitize untrusted input first.

Annotations are ordinary HTML attributes, classes or small semantic tags::

    <p data-publish="public">Monday, maths</p>
    <p data-publish="public">Tuesday, Chinese
      <span data-publish="internal">Remember the dictionary.</span>
    </p>

Supported permission values include ``public``, ``internal``, ``private``,
``draft``, ``teacher`` and the corresponding Chinese labels. Unlabelled content
is public by default. Use ``default_visibility="internal"`` for a fail-closed
document.

Usage::

    >>> from html_sanitizer import PublicationBoundary
    >>> boundary = PublicationBoundary({
    ...     "tags": {"p"},
    ...     "attributes": {},
    ...     "empty": set(),
    ...     "separate": {"p"},
    ... })
    >>> result = boundary.check(html)
    >>> result.public_html.strip()
    "<p>Monday, maths</p>"
    >>> result.review[0].text
    "Tuesday, Chinese Remember the dictionary."

The result has the following useful attributes:

- ``public_html``: sanitized HTML containing public-only blocks. Internal-only
  blocks are omitted; blocks mixing public and internal runs are omitted and
  sent to review as a whole.
- ``review``: a tuple of ``ReviewItem`` objects. Every item contains the
  sanitized ``html``, flattened ``text``, the affected ``sources`` and ``runs``.
- ``withheld``: internal-only segments. These are not published and are kept for
  audit purposes.
- ``text_runs``: the provenance artifact. Each run records the sanitized text,
  whether it came from the element text or tail, the output position and the
  source runs which contributed to it. ``merged`` is true when a run contains
  more than one source permission; such a run needs review.
- ``sources``: all annotated source runs with their tag, XPath, trust level and
  final status (``published``, ``withheld``, ``review`` or ``dropped``).

Blocks, paragraphs and table cells are the default publication units. Clean
public citations stay in public_html while a citation which absorbed an
internal annotation is sent to review as a whole. Use ``group_rows=True`` when
table rows must stay atomic; a mixed row is then reviewed as one row.

A convenient functional wrapper is also available::

    >>> from html_sanitizer import check_publication
    >>> check_publication(html, settings).public_html

Input may also be a sequence of annotated text segments. This is useful when a
pipeline has already split plain copy into runs::

    >>> boundary.check([
    ...     {"text": "Monday, maths", "visibility": "public", "tag": "p"},
    ...     {"text": "Remember the dictionary.", "visibility": "internal", "tag": "p"},
    ... ]).public_html
    "<p>Monday, maths</p>"

Django
======

HTML sanitizer does not depend on Django, but ships with a module which
makes configuring sanitizers using Django settings easier. Usage is as
follows::

    >>> from html_sanitizer.django import get_sanitizer
    >>> sanitizer = get_sanitizer([name=...])

Different sanitizers can be configured. The default configuration is
aptly named ``'default'``. Example settings follow::

    HTML_SANITIZERS = {
        'default': {
          'tags': ...,
        },
        ...
    }

The ``'default'`` configuration is special: If it isn't explicitly
defined, the default configuration above is used instead. Non-existing
configurations will lead to ``ImproperlyConfigured`` exceptions.

The ``get_sanitizer`` function caches sanitizer instances, so feel free
to call it as often as you want to.


Security issues
===============

Please report security issues to me directly at mk@feinheit.ch.


.. _bleach: https://bleach.readthedocs.io/
.. _Django: https://www.djangoproject.com/
.. _django-content-editor: http://django-content-editor.readthedocs.io/
.. _FeinCMS: https://pypi.python.org/pypi/FeinCMS
.. _feincms-cleanse: https://pypi.python.org/pypi/feincms-cleanse
.. _design decisions: http://django-content-editor.readthedocs.io/en/latest/#design-decisions
.. _lxml: http://lxml.de/
.. _autolinker: http://lxml.de/api/lxml.html.clean-module.html
