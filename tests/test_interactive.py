"""Tests for explicit interactive-action review and sanitization."""

from io import BytesIO
from pathlib import Path

import pytest

from pypdf import (
    ActionClassification,
    ActionDisposition,
    ActionFinding,
    PdfReader,
    PdfWriter,
    SanitizationPolicy,
    review_interactive_actions,
    sanitize_interactive_bytes,
    sanitize_interactive_pdf,
)
from pypdf.errors import SanitizationError
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    RectangleObject,
    TextStringObject,
)


def _action(action_type: str, **entries: object) -> DictionaryObject:
    action = DictionaryObject()
    action[NameObject("/S")] = NameObject(action_type)
    for key, value in entries.items():
        if not key.startswith("/"):
            key = "/" + key
        action[NameObject(key)] = value
    return action


def _link(rect: tuple[float, float, float, float], action_ref=None, dest=None) -> DictionaryObject:
    link = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): RectangleObject(rect),
        }
    )
    if action_ref is not None:
        link[NameObject("/A")] = action_ref
    if dest is not None:
        link[NameObject("/Dest")] = dest
    return link


def _build_shared_interactive_pdf() -> tuple[bytes, str]:
    writer = PdfWriter()
    pages = [writer.add_blank_page(200, 200) for _ in range(3)]
    external_uri = "https://example.invalid/archive-secret"

    shared_external = _action(
        "/URI",
        URI=TextStringObject(external_uri),
    )
    shared_external_ref = writer._add_object(shared_external)

    unknown_ref = writer._add_object(_action("/Mystery"))

    local = _action(
        "/GoTo",
        D=ArrayObject([pages[1].indirect_reference, NameObject("/Fit")]),
    )
    next_external = _action(
        "/URI",
        URI=TextStringObject("https://example.invalid/follow-up"),
    )
    local[NameObject("/Next")] = writer._add_object(next_external)
    local_ref = writer._add_object(local)

    writer.add_outline_item("Local bookmark", 0)
    writer.add_outline_item_dict(
        {
            NameObject("/Title"): TextStringObject("External bookmark"),
            NameObject("/A"): shared_external_ref,
        }
    )
    writer.add_outline_item_dict(
        {
            NameObject("/Title"): TextStringObject("Unknown bookmark"),
            NameObject("/A"): unknown_ref,
        }
    )

    link_external = writer._add_object(
        _link((0, 0, 20, 20), action_ref=shared_external_ref)
    )
    link_local = writer._add_object(
        _link((20, 20, 40, 40), action_ref=local_ref)
    )
    link_dest = writer._add_object(
        _link(
            (40, 40, 60, 60),
            dest=ArrayObject([pages[2].indirect_reference, NameObject("/Fit")]),
        )
    )

    widget = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Widget"),
            NameObject("/FT"): NameObject("/Tx"),
            NameObject("/T"): TextStringObject("shared_field"),
            NameObject("/Rect"): RectangleObject((60, 60, 80, 80)),
            NameObject("/P"): pages[0].indirect_reference,
            NameObject("/AA"): DictionaryObject(
                {NameObject("/K"): shared_external_ref}
            ),
        }
    )
    widget_ref = writer._add_object(widget)
    pages[0][NameObject("/Annots")] = ArrayObject(
        [link_external, link_local, link_dest, widget_ref]
    )
    writer.root_object[NameObject("/AcroForm")] = DictionaryObject(
        {
            NameObject("/Fields"): ArrayObject([widget_ref]),
        }
    )

    output = BytesIO()
    writer.write(output)
    return output.getvalue(), external_uri


def test_shared_external_actions_are_removed_and_reported():
    source, external_uri = _build_shared_interactive_pdf()
    derived, report = sanitize_interactive_bytes(source)

    assert b"https://example.invalid" not in derived
    assert report.applied is True
    assert report.output_verified is True
    assert report.output_counts["external_actions"] == 0
    assert report.counts == {
        "actions": 5,
        "retained_actions": 2,
        "removed_actions": 3,
        "unexplained_actions": 1,
        "external_actions": 2,
        "bookmarks": 3,
        "form_fields": 1,
    }
    assert all(
        action.disposition == ActionDisposition.REMOVED
        for action in report.actions
        if action.action_type == "/URI"
    )
    assert report.external_actions
    assert all(action.is_removed for action in report.external_actions)

    shared = next(
        action
        for action in report.external_actions
        if action.target == external_uri
    )
    assert shared.shared is True
    assert {owner.kind.value for owner in shared.owners} == {
        "outline",
        "annotation",
        "form_field",
    }
    assert shared.disposition == ActionDisposition.REMOVED
    assert "external resource" in shared.reason

    unexplained = report.unexplained_actions
    assert len(unexplained) == 1
    assert unexplained[0].action_type == "/Mystery"
    assert unexplained[0].disposition == ActionDisposition.REMOVED

    for action in report.removed_actions:
        assert action.reason
        assert action.disposition == ActionDisposition.REMOVED

    reader = PdfReader(BytesIO(derived))
    assert reader.pages[0]["/Annots"][0].get_object().get("/A") is None
    local_link = reader.pages[0]["/Annots"][1].get_object()
    assert local_link["/A"]["/S"] == "/GoTo"
    assert local_link["/A"]["/D"][0].get_object()["/Type"] == "/Page"
    assert local_link["/A"].get("/Next") is None
    assert reader.pages[0]["/Annots"][2].get_object()["/Dest"][0].get_object()["/Type"] == "/Page"

    fields = reader.get_fields()
    assert fields is not None
    assert list(fields) == ["shared_field"]
    widget = reader.pages[0]["/Annots"][3].get_object()
    assert "/AA" not in widget
    assert widget["/FT"] == "/Tx"

    bookmark_titles = [item.title for item in reader.outline if hasattr(item, "title")]
    assert bookmark_titles == ["Local bookmark", "External bookmark", "Unknown bookmark"]
    assert report.bookmarks[0].disposition == "retained"
    assert report.bookmarks[0].destination == "page:0"
    assert report.bookmarks[1].disposition == "retained_inert"
    assert report.bookmarks[1].removed_action_keys
    assert report.bookmarks[2].disposition == "retained_inert"
    assert report.bookmarks[2].removed_action_keys
    assert report.form_fields[0].name == "shared_field"
    assert report.form_fields[0].disposition == "retained_without_actions"
    assert report.form_fields[0].removed_action_keys == [shared.key]

    output_review = review_interactive_actions(reader)
    assert output_review.external_actions == []
    assert output_review.unexplained_actions == []


def test_review_is_non_mutating_and_local_navigation_can_be_denied():
    source, external_uri = _build_shared_interactive_pdf()
    reader = PdfReader(BytesIO(source))
    before = reader.pages[0]["/Annots"][0].get_object()["/A"]["/URI"]

    review = review_interactive_actions(reader)
    assert review.applied is False
    assert str(before) == external_uri
    assert reader.pages[0]["/Annots"][0].get_object()["/A"]["/URI"] == external_uri
    assert review.retained_actions
    assert all(
        action.classification != ActionClassification.LOCAL_NAVIGATION
        for action in review.removed_actions
    )

    denied = review_interactive_actions(
        reader,
        policy=SanitizationPolicy(allow_local_navigation=False),
    )
    assert not denied.retained_actions
    assert all(action.disposition == ActionDisposition.REMOVED for action in denied.actions)


def test_source_file_is_never_written(tmp_path: Path):
    source, _ = _build_shared_interactive_pdf()
    source_path = tmp_path / "source.pdf"
    target_path = tmp_path / "derived.pdf"
    source_path.write_bytes(source)
    source_hash = source_path.read_bytes()

    report = sanitize_interactive_pdf(source_path, target_path)

    assert source_path.read_bytes() == source_hash
    assert report.output == str(target_path)
    assert target_path.exists()
    assert b"https://example.invalid" not in target_path.read_bytes()

    with pytest.raises(SanitizationError, match="different output path"):
        sanitize_interactive_pdf(source_path, source_path)
    assert source_path.read_bytes() == source_hash


def test_javascript_name_tree_is_sanitized():
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    script = _action(
        "/JavaScript",
        JS=TextStringObject("app.launchURL(https://example.invalid)"),
    )
    second_script = _action(
        "/JavaScript",
        JS=TextStringObject("app.launchURL(https://example.invalid/two)"),
    )
    names = ArrayObject(
        [
            TextStringObject("script"),
            writer._add_object(script),
            TextStringObject("second"),
            writer._add_object(second_script),
        ]
    )
    writer.root_object[NameObject("/Names")] = DictionaryObject(
        {
            NameObject("/JavaScript"): DictionaryObject(
                {NameObject("/Names"): names}
            )
        }
    )
    writer.root_object[NameObject("/OpenAction")] = writer._add_object(
        _action("/URI", URI=TextStringObject("https://example.invalid/open"))
    )
    writer.add_outline_item("Page", 0)
    source = BytesIO()
    writer.write(source)

    derived, report = sanitize_interactive_bytes(source.getvalue())
    assert b"https://example.invalid" not in derived
    assert report.output_verified is True

    reader = PdfReader(BytesIO(derived))
    assert "/OpenAction" not in reader.root_object
    names = reader.root_object.get("/Names", DictionaryObject())
    javascript = names.get("/JavaScript")
    if javascript is not None:
        assert javascript.get("/Names", []) == []


def test_named_local_navigation_is_approved_by_policy():
    writer = PdfWriter()
    page = writer.add_blank_page(100, 100)
    named_ref = writer._add_object(_action("/Named", N=NameObject("/NextPage")))
    page[NameObject("/Annots")] = ArrayObject(
        [writer._add_object(_link((0, 0, 10, 10), action_ref=named_ref))]
    )
    source = BytesIO()
    writer.write(source)

    derived, report = sanitize_interactive_bytes(source.getvalue())
    assert b"/NextPage" in derived
    assert report.retained_actions[0].classification == ActionClassification.LOCAL_NAVIGATION
    assert reader_local_action(derived)[NameObject("/S")] == "/Named"

    denied, denied_report = sanitize_interactive_bytes(
        source.getvalue(),
        policy=SanitizationPolicy(allowed_named_actions=frozenset()),
    )
    assert b"/NextPage" not in denied
    assert not denied_report.retained_actions


def reader_local_action(pdf_bytes: bytes) -> DictionaryObject:
    reader = PdfReader(BytesIO(pdf_bytes))
    return reader.pages[0]["/Annots"][0].get_object()["/A"]


def test_writer_backend_does_not_touch_the_reader_clone_source():
    source, external_uri = _build_shared_interactive_pdf()
    reader = PdfReader(BytesIO(source))
    writer = PdfWriter()
    writer.clone_document_from_reader(reader)

    report = writer.sanitize_interactive()

    assert report.actions
    assert reader.pages[0]["/Annots"][0].get_object()["/A"]["/URI"] == external_uri
    assert writer.pages[0]["/Annots"][0].get_object().get("/A") is None


def test_reviewer_only_sees_policy_approved_local_actions():
    source, _ = _build_shared_interactive_pdf()
    seen: list[ActionFinding] = []

    def reviewer(finding) -> bool:
        seen.append(finding)
        return False

    derived, report = sanitize_interactive_bytes(source, reviewer=reviewer)

    assert seen
    assert all(
        finding.classification == ActionClassification.LOCAL_NAVIGATION
        for finding in seen
    )
    assert not report.retained_actions
    assert b"https://example.invalid" not in derived
    assert b"/GoTo" not in derived


def test_approved_action_after_rejected_action_is_promoted():
    writer = PdfWriter()
    pages = [writer.add_blank_page(100, 100) for _ in range(2)]
    external = _action("/URI", URI=TextStringObject("https://example.invalid/drop"))
    external[NameObject("/Next")] = writer._add_object(
        _action(
            "/GoTo",
            D=ArrayObject([pages[1].indirect_reference, NameObject("/Fit")]),
        )
    )
    external_ref = writer._add_object(external)
    pages[0][NameObject("/Annots")] = ArrayObject(
        [writer._add_object(_link((0, 0, 10, 10), action_ref=external_ref))]
    )
    source = BytesIO()
    writer.write(source)

    derived, report = sanitize_interactive_bytes(source.getvalue())
    assert b"https://example.invalid" not in derived
    assert report.retained_actions
    assert report.retained_actions[0].action_type == "/GoTo"

    link = PdfReader(BytesIO(derived)).pages[0]["/Annots"][0].get_object()
    assert link["/A"]["/S"] == "/GoTo"
    assert link["/A"]["/D"][0].get_object()["/Type"] == "/Page"


def test_open_destination_dictionary_is_retained_as_local_navigation():
    writer = PdfWriter()
    page = writer.add_blank_page(100, 100)
    writer.root_object[NameObject("/OpenAction")] = DictionaryObject(
        {
            NameObject("/D"): ArrayObject(
                [page.indirect_reference, NameObject("/Fit")]
            )
        }
    )
    source = BytesIO()
    writer.write(source)

    derived, report = sanitize_interactive_bytes(source.getvalue())

    assert report.destinations[0].target == "page:0"
    assert report.destinations[0].disposition == "retained"
    output = PdfReader(BytesIO(derived))
    assert output.root_object["/OpenAction"]["/D"][0].get_object()["/Type"] == "/Page"


def test_policy_can_approve_an_additional_named_action():
    writer = PdfWriter()
    page = writer.add_blank_page(100, 100)
    named = _action("/Named", N=NameObject("/ZoomIn"))
    page[NameObject("/Annots")] = ArrayObject(
        [
            writer._add_object(
                _link((0, 0, 10, 10), action_ref=writer._add_object(named))
            )
        ]
    )
    source = BytesIO()
    writer.write(source)

    derived, report = sanitize_interactive_bytes(
        source.getvalue(),
        policy=SanitizationPolicy(
            allowed_named_actions=frozenset({"/ZoomIn"})
        ),
    )

    assert report.retained_actions[0].target == "named:/ZoomIn"
    output = PdfReader(BytesIO(derived))
    assert output.pages[0]["/Annots"][0].get_object()["/A"]["/N"] == "/ZoomIn"
