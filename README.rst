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
        "resource_resolver": None,
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
- ``resource_resolver``: An optional callable confirming automatically
  fetched resource references (``img``, ``iframe``, ``audio``, ``video``
  etc.) against caller-managed data, e.g. a table of reviewed assets. See
  the `resource constraints`_ section below.
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

Resource constraints
====================

External references come in two flavors: *interactive* references such as
``<a href>`` are only opened when the user clicks them, while *automatic*
references such as ``<img src>`` are fetched as soon as the page is
rendered. A system may therefore want to keep clickable links to external
pages while restricting embedded media to reviewed assets only.

When a ``resource_resolver`` is configured, each automatic reference in
the final tree is confirmed by the resolver. Unapproved elements are
dropped, but their human-readable description (the ``alt`` text) stays
visible. The resolver is a read-only callable receiving the URL and a
``ResourceReference`` (which includes the ``kind``, so the same address
can be judged differently as a link and as an image); it never has to
access the network. ``html_sanitizer.AssetTable`` is a ready-made
resolver backed by a local, read-only asset table::

    >>> from html_sanitizer import AssetTable, ResourceDecision, Sanitizer
    >>> asset_table = AssetTable({
    ...     "https://assets.example.test/banner.png": ResourceDecision(
    ...         license="CC-BY-4.0",
    ...         license_url="https://creativecommons.org/licenses/by/4.0/",
    ...     ),
    ... })
    >>> sanitizer = Sanitizer({
    ...     "tags": {"p", "img", "a"},
    ...     "empty": {"img", "a"},
    ...     "separate": {"a", "p"},
    ...     "attributes": {"img": {"src", "alt"}, "a": {"href"}},
    ...     "resource_resolver": asset_table,
    ... })
    >>> html, manifest = sanitizer.sanitize_with_manifest(
    ...     '<p><img src="https://assets.example.test/banner.png" alt="B"></p>'
    ...     '<p><img src="https://tracking.example.test/x.gif" alt="Nope"></p>'
    ...     '<p><a href="https://tracking.example.test/x.gif">source</a></p>'
    ... )
    >>> html
    '<p><img src="https://assets.example.test/banner.png" alt="B"></p><p>Nope</p><p><a href="https://tracking.example.test/x.gif">source</a></p>'
    >>> [(r.kind, r.url, r.decision) for r in manifest]  # doctest: +SKIP
    [('automatic', 'https://assets.example.test/banner.png', ResourceDecision(license='CC-BY-4.0', ...)), ('interactive', 'https://tracking.example.test/x.gif', None)]

``sanitize_with_manifest`` returns the sanitized HTML along with the
manifest of resource references generated from the final tree, so every
remaining automatically fetched reference can be traced back to its
license.

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
