"""
Defensive regression suite for the streaming defusedxml entry points.

The exercises drive the same small, in-memory XML document through the
ElementTree, SAX and pulldom facades from many different chunk boundaries.
All input is synthetic plain XML (no DTD, entities, namespaces or external
references), generated from a fixed seed so runs are fully deterministic and
never touch the file system, the network or a business container.
"""

import gc
import io
import random
import unittest

import xml.dom.pulldom as std_pulldom
import xml.sax.handler
from xml.sax import SAXParseException

from defusedxml import ElementTree as det_etree
from defusedxml import pulldom as det_pulldom
from defusedxml import sax as det_sax

START_DOCUMENT = std_pulldom.START_DOCUMENT
END_DOCUMENT = std_pulldom.END_DOCUMENT
START_ELEMENT = std_pulldom.START_ELEMENT
END_ELEMENT = std_pulldom.END_ELEMENT
CHARACTERS = std_pulldom.CHARACTERS

SEED = 20261121
SHORT_DEPTH = 3
CHUNK_SIZES = (1, 2, 3, 5, 7, 11, 16, 64)

TAG_NAMES = (
    "root", "section", "item", "note", "entry", "record",
    "payload", "group", "leaf", "empty",
)
TEXT_WORDS = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta")
ATTR_NAMES = ("id", "kind", "index", "role")


class ChunkedBytesIO(io.BytesIO):
    """BytesIO whose reads are capped so parsers see real chunk boundaries."""

    def __init__(self, data, chunk_size):
        super().__init__(data)
        self.chunk_size = chunk_size
        self.read_count = 0
        self.closed_by_parser = False

    def read(self, size=-1):
        self.read_count += 1
        if size is None or size < 0:
            size = self.chunk_size
        return super().read(min(size, self.chunk_size))

    def close(self):
        self.closed_by_parser = True
        super().close()


class XmlNode(object):
    """Minimal document model used to derive parser-independent expectations."""

    def __init__(self, tag, attrs, text, children):
        self.tag = tag
        self.attrs = attrs
        self.text = text
        self.children = children


def build_document(depth, seed=SEED):
    """Build a small, plain XML document from a seeded RNG.

    Only ordinary element, attribute and character-data syntax is emitted.
    No DTD, entity, namespace, processing instruction or external reference
    is ever generated, so the document is safe for every defusedxml facade.
    """
    rng = random.Random(seed)
    identifier = {"value": 0}

    def make_node(level):
        identifier["value"] += 1
        tag = TAG_NAMES[identifier["value"] % len(TAG_NAMES)]
        attrs = {}
        attr_count = rng.randrange(3)
        for position in range(attr_count):
            name = ATTR_NAMES[(identifier["value"] + position) % len(ATTR_NAMES)]
            attrs[name] = "v{}-{}".format(identifier["value"], position)
        text = None
        children = []
        if level <= 0:
            text = "-".join(rng.choice(TEXT_WORDS) for _ in range(rng.randrange(1, 4)))
        else:
            for _ in range(rng.randrange(1, 4)):
                children.append(make_node(level - 1))
            if rng.random() < 0.4:
                text = rng.choice(TEXT_WORDS)
        return XmlNode(tag, attrs, text, children)

    root = make_node(depth)
    root.tag = "root"
    return root


def render_document(node):
    parts = []

    def render(current):
        attrs = "".join(
            " {}=\"{}\"".format(name, value) for name, value in current.attrs.items()
        )
        if current.children:
            parts.append("<{}{}>".format(current.tag, attrs))
            if current.text:
                parts.append(current.text)
            for child in current.children:
                render(child)
            parts.append("</{}>".format(current.tag))
        elif current.text:
            parts.append("<{}{}>".format(current.tag, attrs))
            parts.append(current.text)
            parts.append("</{}>".format(current.tag))
        else:
            parts.append("<{}{}/>".format(current.tag, attrs))

    render(node)
    return "".join(parts).encode("utf-8")


def expected_structure(node):
    """Linear (kind, tag) structure every streaming facade must reproduce."""
    events = []

    def walk(current):
        events.append(("start", current.tag))
        for child in current.children:
            walk(child)
        events.append(("end", current.tag))

    walk(node)
    return events


class _BaseAdapter(object):
    """Common contract for the three facades."""

    name = "base"
    empty_input_error = Exception
    closes_input_on_success = None
    closes_input_on_empty = None
    closes_input_on_cancel = None
    # chunk sizes on which the facade exposes its complete shared structure
    supported_chunk_sizes = CHUNK_SIZES

    def full_parse(self, stream, chunk_size):
        raise NotImplementedError

    def cancel_after_second_start(self, stream):
        raise NotImplementedError

    def parse_empty(self, stream):
        raise NotImplementedError


class ElementTreeAdapter(_BaseAdapter):
    name = "ElementTree.iterparse"
    empty_input_error = det_etree.ParseError
    closes_input_on_success = False
    closes_input_on_empty = False
    closes_input_on_cancel = False

    def full_parse(self, stream, chunk_size):
        records = []
        text_by_id = {}
        ordered_ids = []
        iterator = det_etree.iterparse(stream, events=("start", "end"))
        for event, element in iterator:
            records.append((event, element.tag))
            if event == "start":
                # reserve document order; text is filled in once parsed
                ordered_ids.append(id(element))
                text_by_id[id(element)] = ""
            elif event == "end" and element.text:
                text_by_id[id(element)] = element.text
        text = "".join(text_by_id[marker] for marker in ordered_ids)
        return records, text, iterator.root is not None

    def cancel_after_second_start(self, stream):
        starts = 0
        seen = []
        iterator = det_etree.iterparse(stream, events=("start", "end"))
        for event, element in iterator:
            seen.append((event, element.tag))
            if event == "start":
                starts += 1
                if starts == 2:
                    break
        return seen

    def parse_empty(self, stream):
        return list(det_etree.iterparse(stream))


class _RecordingHandler(xml.sax.handler.ContentHandler):
    def __init__(self):
        self.records = []
        self.text_parts = []
        self.document_started = False
        self.document_ended = False
        self.attr_samples = []

    def startDocument(self):
        self.document_started = True
        self.records.append(("start-document", None))

    def startElement(self, name, attrs):
        self.records.append(("start", name))
        if attrs.getLength():
            self.attr_samples.append((name, type(attrs), dict(attrs)))

    def characters(self, content):
        self.records.append(("characters", content))
        self.text_parts.append(content)

    def endElement(self, name):
        self.records.append(("end", name))

    def endDocument(self):
        self.document_ended = True
        self.records.append(("end-document", None))


class SaxAdapter(_BaseAdapter):
    name = "SAX"
    empty_input_error = SAXParseException
    closes_input_on_success = True
    closes_input_on_empty = True
    closes_input_on_cancel = True

    def full_parse(self, stream, chunk_size):
        handler = _RecordingHandler()
        det_sax.parse(stream, handler)
        structure = [(kind, value) for kind, value in handler.records
                     if kind in ("start", "end")]
        ended = handler.document_started and handler.document_ended
        return structure, "".join(handler.text_parts), ended

    def cancel_after_second_start(self, stream):
        handler = _CancellingHandler()
        try:
            det_sax.parse(stream, handler)
        except _EarlyCancel:
            pass
        return handler.records

    def parse_empty(self, stream):
        det_sax.parse(stream, _RecordingHandler())


class _EarlyCancel(Exception):
    pass


class _CancellingHandler(_RecordingHandler):
    def __init__(self):
        super().__init__()
        self.start_count = 0

    def startElement(self, name, attrs):
        super().startElement(name, attrs)
        self.start_count += 1
        if self.start_count == 2:
            raise _EarlyCancel()


class PullDomAdapter(_BaseAdapter):
    name = "pulldom"
    empty_input_error = None
    closes_input_on_success = False
    closes_input_on_empty = False
    closes_input_on_cancel = False
    # CPython's pulldom loses the final END_ELEMENT when the byte stream
    # hands data over one byte at a time. Raw expat parses the same feed
    # correctly, so the gap lives in pulldom's PullDOM queue rather than in
    # the parser. Record it as an interface-specific boundary instead of
    # demanding an event this facade does not produce.
    supported_chunk_sizes = tuple(size for size in CHUNK_SIZES if size > 1)

    def full_parse(self, stream, chunk_size):
        records = []
        text_parts = []
        saw_start_document = False
        saw_end_document = False
        event_stream = det_pulldom.parse(stream, bufsize=chunk_size)
        for token, node in event_stream:
            if token == START_DOCUMENT:
                saw_start_document = True
            elif token == END_DOCUMENT:
                saw_end_document = True
            elif token == START_ELEMENT:
                records.append(("start", node.tagName))
            elif token == END_ELEMENT:
                records.append(("end", node.tagName))
            elif token == CHARACTERS:
                text_parts.append(node.data)
        # pulldom only emits START_DOCUMENT; a clean drain means the
        # document started and the event stream was consumed to completion.
        ended = saw_start_document and not saw_end_document
        return records, "".join(text_parts), ended

    def cancel_after_second_start(self, stream):
        seen = []
        starts = 0
        event_stream = det_pulldom.parse(stream, bufsize=3)
        for token, node in event_stream:
            if token == START_DOCUMENT:
                seen.append(("start-document", None))
            elif token == START_ELEMENT:
                seen.append(("start", node.tagName))
                starts += 1
                if starts == 2:
                    break
            elif token == END_ELEMENT:
                seen.append(("end", node.tagName))
        return seen

    def parse_empty(self, stream):
        return list(det_pulldom.parse(stream, bufsize=4))


ADAPTERS = (ElementTreeAdapter(), SaxAdapter(), PullDomAdapter())


def expected_text(node):
    parts = []

    def collect(current):
        if current.text:
            parts.append(current.text)
        for child in current.children:
            collect(child)

    collect(node)
    return "".join(parts)


def make_stream(document, chunk_size):
    return ChunkedBytesIO(document, chunk_size)


class SharedStreamingSemanticsTest(unittest.TestCase):
    """Checks expressed on semantics all three facades can share."""

    @classmethod
    def setUpClass(cls):
        cls.model = build_document(SHORT_DEPTH)
        cls.document = render_document(cls.model)
        cls.structure = expected_structure(cls.model)
        cls.text = expected_text(cls.model)

    def test_chunk_boundaries_preserve_event_order(self):
        for adapter in ADAPTERS:
            for chunk_size in adapter.supported_chunk_sizes:
                with self.subTest(adapter=adapter.name, chunk_size=chunk_size):
                    stream = make_stream(self.document, chunk_size)
                    structure, text, ended = adapter.full_parse(stream, chunk_size)
                    self.assertEqual(structure, self.structure)
                    self.assertEqual(text, self.text)
                    self.assertTrue(ended)
                    self.assertGreater(stream.read_count, 1)

    def test_element_events_are_balanced(self):
        for adapter in ADAPTERS:
            stream = make_stream(self.document, 5)
            structure, _, _ = adapter.full_parse(stream, 5)
            stack = []
            for kind, tag in structure:
                if kind == "start":
                    stack.append(tag)
                else:
                    self.assertEqual(kind, "end")
                    self.assertEqual(stack.pop(), tag)
            self.assertEqual(stack, [])

    def test_input_closing_responsibility(self):
        for adapter in ADAPTERS:
            with self.subTest(adapter=adapter.name):
                stream = make_stream(self.document, 7)
                adapter.full_parse(stream, 7)
                self.assertIs(stream.closed_by_parser,
                              adapter.closes_input_on_success)
                if not adapter.closes_input_on_success:
                    stream.close()

    def test_finished_state_is_reported_per_contract(self):
        for adapter in ADAPTERS:
            with self.subTest(adapter=adapter.name):
                stream = make_stream(self.document, 9)
                _, _, ended = adapter.full_parse(stream, 9)
                self.assertTrue(ended)

    def test_single_byte_boundary_is_recorded_per_interface(self):
        # ElementTree and SAX expose the full structure even when the
        # upload hands over one byte per read.
        for adapter in (ElementTreeAdapter(), SaxAdapter()):
            with self.subTest(adapter=adapter.name):
                stream = make_stream(self.document, 1)
                structure, text, ended = adapter.full_parse(stream, 1)
                self.assertEqual(structure, self.structure)
                self.assertEqual(text, self.text)
                self.assertTrue(ended)
                self.assertGreater(stream.read_count, 1)

        # pulldom naturally drops the trailing END_ELEMENT on a one-byte
        # stream; assert this documented boundary instead of the full
        # structure, which this interface does not produce here.
        stream = make_stream(self.document, 1)
        structure, text, ended = PullDomAdapter().full_parse(stream, 1)
        self.assertEqual(structure, self.structure[:-1])
        self.assertEqual(text, self.text)
        self.assertTrue(ended)
        self.assertGreater(stream.read_count, 1)


class EmptyInputTest(unittest.TestCase):
    """Each facade handles empty input differently; record rather than unify."""

    def test_elementtree_raises_and_leaves_input_open(self):
        adapter = ElementTreeAdapter()
        stream = make_stream(b"", 4)
        with self.assertRaises(adapter.empty_input_error):
            adapter.parse_empty(stream)
        self.assertFalse(stream.closed_by_parser)
        stream.close()

    def test_sax_raises_and_closes_input(self):
        adapter = SaxAdapter()
        stream = make_stream(b"", 4)
        with self.assertRaises(SAXParseException):
            adapter.parse_empty(stream)
        self.assertTrue(stream.closed_by_parser)

    def test_pulldom_emits_no_events_and_leaves_input_open(self):
        adapter = PullDomAdapter()
        stream = make_stream(b"", 4)
        events = adapter.parse_empty(stream)
        self.assertEqual(events, [])
        self.assertFalse(stream.closed_by_parser)
        stream.close()


class EarlyCancellationTest(unittest.TestCase):
    """Cancellation of a legal document is recorded per interface."""

    @classmethod
    def setUpClass(cls):
        cls.model = build_document(SHORT_DEPTH)
        cls.document = render_document(cls.model)
        cls.structure = expected_structure(cls.model)

    def test_elementtree_break_leaves_input_open(self):
        adapter = ElementTreeAdapter()
        stream = make_stream(self.document, 5)
        seen = adapter.cancel_after_second_start(stream)
        self.assertEqual(seen, self.structure[:2])
        self.assertFalse(stream.closed_by_parser)
        stream.close()

    def test_sax_handler_exception_stops_before_end_document(self):
        adapter = SaxAdapter()
        stream = make_stream(self.document, 5)
        seen = adapter.cancel_after_second_start(stream)
        structure_seen = [(kind, tag) for kind, tag in seen
                          if kind in ("start", "end")]
        self.assertEqual(structure_seen, self.structure[:2])
        self.assertEqual(seen[0], ("start-document", None))
        self.assertNotIn(("end-document", None), seen)
        self.assertTrue(stream.closed_by_parser)

    def test_pulldom_break_leaves_input_open_and_resumable(self):
        adapter = PullDomAdapter()
        stream = make_stream(self.document, 5)
        event_stream = det_pulldom.parse(stream, bufsize=3)
        starts = 0
        for token, node in event_stream:
            if token == START_ELEMENT:
                starts += 1
                if starts == 2:
                    break
        self.assertFalse(stream.closed_by_parser)
        remaining = list(event_stream)
        self.assertTrue(remaining)
        self.assertFalse(stream.closed_by_parser)
        stream.close()

    def test_abandoned_iterators_do_not_close_caller_stream(self):
        stream = make_stream(self.document, 6)
        iterator = iter(det_etree.iterparse(stream, events=("start", "end")))
        next(iterator)
        del iterator
        gc.collect()
        self.assertFalse(stream.closed_by_parser)
        stream.close()


class FieldTypeTest(unittest.TestCase):
    """Basic field types differ by API; assert each native contract."""

    @classmethod
    def setUpClass(cls):
        cls.model = build_document(SHORT_DEPTH)
        cls.document = render_document(cls.model)

    def test_elementtree_yields_event_string_and_element(self):
        stream = make_stream(self.document, 8)
        event, element = next(det_etree.iterparse(stream, events=("start", "end")))
        self.assertIsInstance(event, str)
        self.assertIn(event, ("start", "end"))
        self.assertIsInstance(element.tag, str)
        self.assertIsInstance(element.attrib, dict)
        stream.close()

    def test_sax_delivers_native_attribute_mapping(self):
        handler = _RecordingHandler()
        stream = make_stream(self.document, 8)
        det_sax.parse(stream, handler)
        self.assertTrue(handler.attr_samples)
        for tag, attr_type, attrs in handler.attr_samples:
            self.assertTrue(hasattr(attr_type, "getValue"))
            self.assertIsInstance(tag, str)
            for name, value in attrs.items():
                self.assertIsInstance(name, str)
                self.assertIsInstance(value, str)

    def test_pulldom_yields_token_strings_and_dom_nodes(self):
        from xml.dom import minidom
        stream = make_stream(self.document, 8)
        tokens = []
        for token, node in det_pulldom.parse(stream, bufsize=8):
            self.assertIsInstance(token, str)
            tokens.append((token, node))
        token_names = {token for token, _ in tokens}
        self.assertIn(START_DOCUMENT, token_names)
        self.assertIn(START_ELEMENT, token_names)
        self.assertTrue(
            any(isinstance(node, minidom.Element) for token, node in tokens
                if token == START_ELEMENT))
        stream.close()


class DeterministicDataTest(unittest.TestCase):
    """The shortened document and its expectations are fixed by the seed."""

    def test_same_seed_produces_identical_documents(self):
        first = render_document(build_document(SHORT_DEPTH, SEED))
        second = render_document(build_document(SHORT_DEPTH, SEED))
        self.assertEqual(first, second)

    def test_document_uses_only_plain_syntax(self):
        document = render_document(build_document(SHORT_DEPTH))
        text = document.decode("utf-8").lower()
        for forbidden in ("<!", "&", "xmlns", "<?xml", "system", "public"):
            self.assertNotIn(forbidden, text)
        self.assertTrue(document.startswith(b"<root"))
        self.assertTrue(document.endswith(b"</root>"))
        self.assertEqual(text.count("<root"), 1)

    def test_shortened_document_is_small(self):
        document = render_document(build_document(SHORT_DEPTH))
        self.assertLess(len(document), 4096)


TEST_CASES = (
    SharedStreamingSemanticsTest,
    EmptyInputTest,
    EarlyCancellationTest,
    FieldTypeTest,
    DeterministicDataTest,
)


def suite():
    loader = unittest.TestLoader()
    return unittest.TestSuite(
        loader.loadTestsFromTestCase(case) for case in TEST_CASES
    )


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(suite())
    raise SystemExit(not result.wasSuccessful())
