"""Review and sanitize actions in interactive PDF documents.

The functions in this module are opt-in.  Reading a PDF with
:class:`~pypdf.PdfReader` or cloning it with :class:`~pypdf.PdfWriter` never
changes any action.  Callers must explicitly run a review or use one of the
sanitization entry points.

Only the local actions explicitly covered by a
:class:`SanitizationPolicy` are retained.  Actions that can reach a URI,
another file, an application, a media handler, or a script are removed.
Actions which cannot be interpreted are also removed and are reported as
unexplained.

The scanner deliberately follows the catalog, outline tree, page annotation
arrays, and the AcroForm field tree.  Action dictionaries are identified by
their object identity, so one action referenced by several of those surfaces
is reviewed once and all of its owners are reported.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, cast

from ._page import PageObject
from .constants import CatalogAttributes, Core
from .errors import SanitizationError
from .generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    is_null_or_none,
)

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:  # pragma: no cover - Python 3.10 compatibility
    class StrEnum(str, Enum):
        def __str__(self) -> str:
            return str(self.value)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._reader import PdfReader
    from ._utils import StrByteType
    from ._writer import PdfWriter


class SurfaceKind(StrEnum):
    """A place from which a PDF action can be reached."""

    CATALOG = "catalog"
    PAGE = "page"
    OUTLINE = "outline"
    ANNOTATION = "annotation"
    FORM_FIELD = "form_field"
    NAME_TREE = "name_tree"


class ActionClassification(StrEnum):
    """The security-relevant interpretation of an action."""

    LOCAL_NAVIGATION = "local_navigation"
    EXTERNAL_RESOURCE = "external_resource"
    NON_NAVIGATION = "non_navigation"
    UNEXPLAINED = "unexplained"


class ActionDisposition(StrEnum):
    """What happened to an action."""

    RETAINED = "retained"
    REMOVED = "removed"


class NavigationDisposition(StrEnum):
    """What happened to a destination attached to a surface."""

    RETAINED = "retained"
    REMOVED = "removed"
    NOT_PRESENT = "not_present"


_EXTERNAL_ACTION_TYPES = frozenset(
    {
        "/URI",
        "/GoToR",
        "/Launch",
        "/SubmitForm",
        "/ImportData",
        "/JavaScript",
        "/Sound",
        "/Movie",
        "/Rendition",
        "/RichMediaExecute",
    }
)

_NON_NAVIGATION_ACTION_TYPES = frozenset(
    {
        "/Thread",
        "/Hide",
        "/Trans",
        "/ResetForm",
        "/SetOCGState",
        "/GoTo3DView",
        "/GoToDp",
        "/GoToE",
    }
)

_DEFAULT_NAMED_ACTIONS = frozenset(
    {
        "/NextPage",
        "/PrevPage",
        "/FirstPage",
        "/LastPage",
    }
)

_ALL_SURFACES = frozenset(SurfaceKind)
_ALL_LOCAL_ACTION_TYPES = frozenset({"/GoTo", "/Named"})


@dataclass(frozen=True)
class ApprovalScope:
    """The actions and surfaces a policy is allowed to approve.

    A local action is retained only when all of its owners are in
    ``allowed_surfaces``, its action type is in
    ``allowed_local_action_types``, and (for ``/Named``) its name is in
    ``allowed_named_actions``.
    """

    allowed_surfaces: frozenset[SurfaceKind] = _ALL_SURFACES
    allowed_local_action_types: frozenset[str] = _ALL_LOCAL_ACTION_TYPES
    allowed_named_actions: frozenset[str] = _DEFAULT_NAMED_ACTIONS
    allow_local_navigation: bool = True
    remove_unexplained: bool = True
    reviewer_used: bool = False

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of the scope."""
        return {
            "allowed_surfaces": sorted(str(surface) for surface in self.allowed_surfaces),
            "allowed_local_action_types": sorted(self.allowed_local_action_types),
            "allowed_named_actions": sorted(self.allowed_named_actions),
            "allow_local_navigation": self.allow_local_navigation,
            "remove_unexplained": self.remove_unexplained,
            "reviewer_used": self.reviewer_used,
        }


@dataclass(frozen=True)
class SanitizationPolicy:
    """Explicit approval policy for interactive PDF sanitization.

    Args:
        allowed_surfaces: Surfaces whose local navigation may be retained.
        allow_local_navigation: Set to ``False`` to remove every action,
            including approved local page jumps.
        allowed_local_action_types: Local action types eligible for approval.
        allowed_named_actions: The ``/Named`` actions eligible for approval.
        remove_unexplained: Remove actions that cannot be interpreted.  This
            is enabled by default and should only be disabled for auditing.
    """

    allowed_surfaces: frozenset[SurfaceKind] = _ALL_SURFACES
    allow_local_navigation: bool = True
    allowed_local_action_types: frozenset[str] = _ALL_LOCAL_ACTION_TYPES
    allowed_named_actions: frozenset[str] = _DEFAULT_NAMED_ACTIONS
    remove_unexplained: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "allowed_surfaces", frozenset(self.allowed_surfaces)
        )
        object.__setattr__(
            self,
            "allowed_local_action_types",
            frozenset(self.allowed_local_action_types),
        )
        object.__setattr__(
            self, "allowed_named_actions", frozenset(self.allowed_named_actions)
        )

    @property
    def approval_scope(self) -> ApprovalScope:
        """Return the concrete scope used for a review."""
        return ApprovalScope(
            allowed_surfaces=self.allowed_surfaces,
            allowed_local_action_types=self.allowed_local_action_types,
            allowed_named_actions=self.allowed_named_actions,
            allow_local_navigation=self.allow_local_navigation,
            remove_unexplained=self.remove_unexplained,
        )


@dataclass(frozen=True)
class SurfaceRef:
    """A stable description of one owner of an action or destination."""

    kind: SurfaceKind
    path: str
    page_index: int | None = None
    bookmark_title: str | None = None
    field_name: str | None = None
    annotation_subtype: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of this owner."""
        result: dict[str, Any] = {
            "kind": str(self.kind),
            "path": self.path,
        }
        if self.page_index is not None:
            result["page_index"] = self.page_index
        if self.bookmark_title is not None:
            result["bookmark_title"] = self.bookmark_title
        if self.field_name is not None:
            result["field_name"] = self.field_name
        if self.annotation_subtype is not None:
            result["annotation_subtype"] = self.annotation_subtype
        return result


@dataclass
class ActionFinding:
    """The interpretation and outcome for one action dictionary."""

    key: str
    action_type: str | None
    classification: ActionClassification
    target: str | None
    owners: list[SurfaceRef]
    action_ref: str | None
    shared: bool
    disposition: ActionDisposition = ActionDisposition.REMOVED
    reason: str = ""
    page_index: int | None = None

    @property
    def is_removed(self) -> bool:
        """Whether the action is absent from the derived document."""
        return self.disposition == ActionDisposition.REMOVED

    @property
    def is_unexplained(self) -> bool:
        """Whether neither the action nor its target could be interpreted."""
        return self.classification == ActionClassification.UNEXPLAINED

    @property
    def owner_paths(self) -> list[str]:
        """The paths of every surface that referenced this action."""
        return [owner.path for owner in self.owners]

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of this finding."""
        return {
            "key": self.key,
            "action_ref": self.action_ref,
            "action_type": self.action_type,
            "classification": str(self.classification),
            "target": self.target,
            "page_index": self.page_index,
            "shared": self.shared,
            "disposition": str(self.disposition),
            "reason": self.reason,
            "owners": [owner.as_dict() for owner in self.owners],
        }


@dataclass
class DestinationFinding:
    """The outcome for a ``/Dest`` entry or an opening destination."""

    key: str
    target: str | None
    owners: list[SurfaceRef]
    disposition: NavigationDisposition
    reason: str
    page_index: int | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of this finding."""
        return {
            "key": self.key,
            "target": self.target,
            "page_index": self.page_index,
            "disposition": str(self.disposition),
            "reason": self.reason,
            "owners": [owner.as_dict() for owner in self.owners],
        }


@dataclass
class BookmarkFinding:
    """The outcome for one outline item (bookmark)."""

    title: str
    node_ref: str | None
    path: str
    page_index: int | None
    destination: str | None
    action_keys: list[str] = field(default_factory=list)
    destination_key: str | None = None
    removed_action_keys: list[str] = field(default_factory=list)
    navigation_retained: bool = False
    reason: str = ""

    @property
    def disposition(self) -> str:
        """A concise outcome for this bookmark."""
        if self.action_keys and self.navigation_retained:
            return "retained"
        if self.destination and self.navigation_retained:
            return "retained"
        if self.action_keys or self.destination_key is not None:
            return "retained_inert"
        return "retained_without_navigation"

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of this bookmark."""
        return {
            "title": self.title,
            "node_ref": self.node_ref,
            "page_index": self.page_index,
            "destination": self.destination,
            "action_keys": list(self.action_keys),
            "destination_key": self.destination_key,
            "removed_action_keys": list(self.removed_action_keys),
            "navigation_retained": self.navigation_retained,
            "disposition": self.disposition,
            "reason": self.reason,
        }


@dataclass
class FormFieldFinding:
    """The outcome for one AcroForm field."""

    name: str
    field_type: str | None
    pages: list[int]
    action_keys: list[str] = field(default_factory=list)
    removed_action_keys: list[str] = field(default_factory=list)

    @property
    def disposition(self) -> str:
        """A concise outcome for this form field."""
        if self.removed_action_keys:
            return "retained_without_actions"
        return "retained"

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of this form field."""
        return {
            "name": self.name,
            "field_type": self.field_type,
            "pages": list(self.pages),
            "action_keys": list(self.action_keys),
            "removed_action_keys": list(self.removed_action_keys),
            "disposition": self.disposition,
        }


@dataclass
class InteractiveReview:
    """A read-only review of interactive actions in a document."""

    actions: list[ActionFinding]
    destinations: list[DestinationFinding]
    bookmarks: list[BookmarkFinding]
    form_fields: list[FormFieldFinding]
    approval_scope: ApprovalScope
    applied: bool = False

    @property
    def retained_actions(self) -> list[ActionFinding]:
        """Actions which are (or would be) retained."""
        return [
            action
            for action in self.actions
            if action.disposition == ActionDisposition.RETAINED
        ]

    @property
    def removed_actions(self) -> list[ActionFinding]:
        """Actions which are (or would be) removed."""
        return [
            action
            for action in self.actions
            if action.disposition == ActionDisposition.REMOVED
        ]

    @property
    def unexplained_actions(self) -> list[ActionFinding]:
        """Actions which could not be interpreted."""
        return [
            action
            for action in self.actions
            if action.classification == ActionClassification.UNEXPLAINED
        ]

    @property
    def external_actions(self) -> list[ActionFinding]:
        """Actions which can reach an external resource."""
        return [
            action
            for action in self.actions
            if action.classification == ActionClassification.EXTERNAL_RESOURCE
        ]

    @property
    def counts(self) -> dict[str, int]:
        """Counts useful for audit logs."""
        return {
            "actions": len(self.actions),
            "retained_actions": len(self.retained_actions),
            "removed_actions": len(self.removed_actions),
            "unexplained_actions": len(self.unexplained_actions),
            "external_actions": len(self.external_actions),
            "bookmarks": len(self.bookmarks),
            "form_fields": len(self.form_fields),
        }

    def action_by_key(self, key: str) -> ActionFinding | None:
        """Return the action finding with ``key``, if present."""
        return next((action for action in self.actions if action.key == key), None)

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable audit report."""
        return {
            "applied": self.applied,
            "approval_scope": self.approval_scope.as_dict(),
            "counts": self.counts,
            "actions": [action.as_dict() for action in self.actions],
            "destinations": [
                destination.as_dict() for destination in self.destinations
            ],
            "bookmarks": [bookmark.as_dict() for bookmark in self.bookmarks],
            "form_fields": [
                form_field.as_dict() for form_field in self.form_fields
            ],
        }

    def to_dict(self) -> dict[str, Any]:
        """Alias for :meth:`as_dict` for audit integrations."""
        return self.as_dict()


@dataclass
class SanitizationReport(InteractiveReview):
    """An applied review with output verification details."""

    output: str | None = None
    output_verified: bool | None = None
    output_counts: dict[str, int] = field(default_factory=dict)
    output_external_actions: list[ActionFinding] = field(default_factory=list)

    def verify_dict(self) -> dict[str, Any]:
        """Return output verification details."""
        return {
            "output": self.output,
            "output_verified": self.output_verified,
            "output_counts": dict(self.output_counts),
            "output_external_actions": [
                action.as_dict() for action in self.output_external_actions
            ],
        }


@dataclass
class _ActionSlot:
    owner: Any
    key: Any
    chain: bool = False
    name_tree_pair: bool = False

    def remove(self) -> None:
        if self.name_tree_pair:
            # The key and value are adjacent in a PDF name tree array.  The
            # slot points at the value, so remove the pair backwards.
            del self.owner[self.key - 1 : self.key + 1]
        else:
            del self.owner[self.key]


@dataclass
class _DestinationRecord:
    owner: DictionaryObject
    key: str
    value: Any
    owner_ref: SurfaceRef


@dataclass
class _ActionRecord:
    action: DictionaryObject | None
    key: str
    action_ref: str | None
    slots: list[_ActionSlot] = field(default_factory=list)
    owners: list[SurfaceRef] = field(default_factory=list)
    classification: ActionClassification = ActionClassification.UNEXPLAINED
    target: str | None = None
    page_index: int | None = None
    reason: str = ""


@dataclass
class _FieldRecord:
    name: str
    field_type: str | None
    pages: list[int]
    action_keys: list[str] = field(default_factory=list)


def _resolve(value: Any) -> Any:
    """Resolve indirect objects repeatedly, with cycle protection."""
    seen: set[int] = set()
    while isinstance(value, IndirectObject):
        marker = id(value)
        if marker in seen:
            break
        seen.add(marker)
        value = value.get_object()
    return value


def _name(value: Any) -> str | None:
    if isinstance(value, NameObject):
        return str(value)
    if isinstance(value, str):
        return str(value)
    return None


def _display_text(value: Any, limit: int = 240) -> str:
    value = _resolve(value)
    if isinstance(value, (bytes, str)):
        text = str(value)
    else:
        text = repr(value)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _file_spec_target(value: Any) -> str | None:
    value = _resolve(value)
    if isinstance(value, DictionaryObject):
        for key in ("/UF", "/F", "/DOS", "/Mac", "/Unix"):
            if key in value:
                return _display_text(value[key])
        return None
    return _display_text(value) if value is not None else None


def _action_type(action: DictionaryObject | None) -> str | None:
    if action is None:
        return None
    return _name(_resolve(action.get("/S")))


def _action_key(action: DictionaryObject | None, owner: SurfaceRef) -> tuple[str, str | None]:
    if action is None:
        return f"invalid:{owner.kind}:{owner.path}", None
    reference = getattr(action, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        key = f"{reference.idnum} {reference.generation} R"
        return key, key
    return f"direct:{owner.kind}:{owner.path}", None


class _Scanner:
    def __init__(self, document: PdfReader | PdfWriter) -> None:
        self.document = document
        self.action_records: dict[int, _ActionRecord] = {}
        self.destination_records: list[_DestinationRecord] = []
        self.bookmarks: list[BookmarkFinding] = []
        self.fields: list[_FieldRecord] = []
        self.aa_containers: list[tuple[DictionaryObject, DictionaryObject]] = []
        self._scanned_annotations: set[int] = set()
        self._scanned_fields: set[int] = set()
        self._outline_visited: set[int] = set()
        self._page_refs: dict[tuple[int, int], int] = {}
        self._page_ids: dict[int, int] = {}
        self._named_destinations: dict[str, Any] | None = None
        for index, page in enumerate(document.pages):
            self._page_ids[id(page)] = index
            reference = getattr(page, "indirect_reference", None)
            if isinstance(reference, IndirectObject):
                self._page_refs[(reference.idnum, reference.generation)] = index

    def scan(self) -> None:
        root = self.document.root_object
        if not isinstance(root, DictionaryObject):
            return
        self._scan_catalog(root)
        self._scan_outlines(root)
        for index, page in enumerate(self.document.pages):
            self._scan_page(page, index)
        self._scan_acro_form(root)

    def _scan_catalog(self, root: DictionaryObject) -> None:
        if "/OpenAction" in root:
            open_action = _resolve(root["/OpenAction"])
            if isinstance(open_action, DictionaryObject):
                if "/S" not in open_action and "/D" in open_action:
                    self.destination_records.append(
                        _DestinationRecord(
                            owner=root,
                            key="/OpenAction",
                            value=open_action,
                            owner_ref=SurfaceRef(
                                SurfaceKind.CATALOG, "/OpenAction"
                            ),
                        )
                    )
                else:
                    self._scan_action_slot(
                        root,
                        "/OpenAction",
                        SurfaceRef(SurfaceKind.CATALOG, "/OpenAction"),
                    )
            elif isinstance(open_action, (ArrayObject, str, bytes)):
                self.destination_records.append(
                    _DestinationRecord(
                        owner=root,
                        key="/OpenAction",
                        value=open_action,
                        owner_ref=SurfaceRef(SurfaceKind.CATALOG, "/OpenAction"),
                    )
                )
            elif not is_null_or_none(open_action):
                self._scan_invalid_action(
                    root,
                    "/OpenAction",
                    SurfaceRef(SurfaceKind.CATALOG, "/OpenAction"),
                )
        if "/AA" in root:
            self._scan_additional_actions(
                root, SurfaceRef(SurfaceKind.CATALOG, "/AA")
            )
        self._scan_javascript_names(root)

    def _scan_javascript_names(self, root: DictionaryObject) -> None:
        names = _resolve(root.get("/Names"))
        if not isinstance(names, DictionaryObject):
            return
        javascript = _resolve(names.get("/JavaScript"))
        if not isinstance(javascript, DictionaryObject):
            return
        self._scan_name_tree_node(
            javascript,
            SurfaceRef(SurfaceKind.NAME_TREE, "/Names/JavaScript"),
            set(),
        )

    def _scan_name_tree_node(
        self,
        node: DictionaryObject,
        owner_ref: SurfaceRef,
        visited: set[int],
    ) -> None:
        marker = id(node)
        if marker in visited:
            return
        visited.add(marker)
        kids = _resolve(node.get("/Kids"))
        if isinstance(kids, ArrayObject):
            for index, kid in enumerate(kids):
                kid_object = _resolve(kid)
                if isinstance(kid_object, DictionaryObject):
                    self._scan_name_tree_node(
                        kid_object,
                        SurfaceRef(
                            SurfaceKind.NAME_TREE,
                            f"{owner_ref.path}/Kids[{index}]",
                        ),
                        visited,
                    )
            return
        names = _resolve(node.get("/Names"))
        if not isinstance(names, ArrayObject):
            return
        index = 0
        while index + 1 < len(names):
            value = _resolve(names[index + 1])
            action_owner = SurfaceRef(
                SurfaceKind.NAME_TREE,
                f"{owner_ref.path}/Names[{index + 1}]",
            )
            if isinstance(value, DictionaryObject):
                slot = _ActionSlot(names, index + 1, name_tree_pair=True)
                self._add_action(value, action_owner, slot)
                self._scan_next(value, action_owner)
            elif not is_null_or_none(value):
                slot = _ActionSlot(names, index + 1, name_tree_pair=True)
                self._add_invalid_action(action_owner, slot)
            index += 2

    def _scan_outlines(self, root: DictionaryObject) -> None:
        outlines = _resolve(root.get(Core.OUTLINES))
        if not isinstance(outlines, DictionaryObject):
            return
        first = outlines.get("/First")
        if first is not None:
            self._scan_outline_siblings(first, self._outline_visited)

    def _scan_outline_siblings(self, node: Any, visited: set[int]) -> None:
        current = node
        while current is not None:
            node_object = _resolve(current)
            if not isinstance(node_object, DictionaryObject):
                return
            marker = id(node_object)
            if marker in visited:
                return
            visited.add(marker)
            self._scan_outline_item(node_object)
            current = node_object.get("/Next")

    def _scan_outline_item(self, node: DictionaryObject) -> None:
        title_value = _resolve(node.get("/Title", ""))
        title = str(title_value)
        reference = getattr(node, "indirect_reference", None)
        node_ref = (
            f"{reference.idnum} {reference.generation} R"
            if isinstance(reference, IndirectObject)
            else None
        )
        owner_ref = SurfaceRef(
            SurfaceKind.OUTLINE,
            f"/Outlines/{node_ref or id(node)}",
            bookmark_title=title,
        )
        bookmark = BookmarkFinding(
            title=title,
            node_ref=node_ref,
            path=owner_ref.path,
            page_index=None,
            destination=None,
        )
        if "/A" in node:
            action = _resolve(node["/A"])
            if isinstance(action, DictionaryObject):
                record = self._scan_action_slot(node, "/A", owner_ref)
                bookmark.action_keys.append(record.key)
            else:
                record = self._scan_invalid_action(node, "/A", owner_ref)
                bookmark.action_keys.append(record.key)
        if "/Dest" in node:
            destination_record = _DestinationRecord(
                owner=node,
                key="/Dest",
                value=node["/Dest"],
                owner_ref=owner_ref,
            )
            self.destination_records.append(destination_record)
            bookmark.destination_key = f"dest:{owner_ref.path}"
        self.bookmarks.append(bookmark)
        first = node.get("/First")
        if first is not None:
            self._scan_outline_siblings(first, self._outline_visited)

    def _scan_page(self, page: PageObject, page_index: int) -> None:
        page_owner = SurfaceRef(
            SurfaceKind.PAGE, f"/Pages/{page_index}", page_index=page_index
        )
        if "/AA" in page:
            self._scan_additional_actions(page, page_owner)
        annotations = _resolve(page.get("/Annots"))
        if not isinstance(annotations, ArrayObject):
            return
        for index, annotation in enumerate(annotations):
            annotation_object = _resolve(annotation)
            if not isinstance(annotation_object, DictionaryObject):
                continue
            marker = id(annotation_object)
            if marker in self._scanned_annotations:
                continue
            self._scanned_annotations.add(marker)
            subtype = _name(_resolve(annotation_object.get("/Subtype")))
            annotation_owner = SurfaceRef(
                SurfaceKind.ANNOTATION,
                f"/Pages/{page_index}/Annots[{index}]",
                page_index=page_index,
                annotation_subtype=subtype,
            )
            self._scan_action_entry(annotation_object, "/A", annotation_owner)
            if "/AA" in annotation_object:
                self._scan_additional_actions(
                    annotation_object, annotation_owner
                )
            if "/Dest" in annotation_object:
                self.destination_records.append(
                    _DestinationRecord(
                        owner=annotation_object,
                        key="/Dest",
                        value=annotation_object["/Dest"],
                        owner_ref=annotation_owner,
                    )
                )

    def _scan_acro_form(self, root: DictionaryObject) -> None:
        acro_form = _resolve(root.get(CatalogAttributes.ACRO_FORM))
        if not isinstance(acro_form, DictionaryObject):
            return
        fields = _resolve(acro_form.get("/Fields"))
        if isinstance(fields, ArrayObject):
            self._scan_field_array(
                fields,
                "/AcroForm/Fields",
                parent=None,
                visited=set(),
            )

    def _scan_field_array(
        self,
        fields: ArrayObject,
        path: str,
        parent: DictionaryObject | None,
        visited: set[int],
    ) -> None:
        for index, field_ref in enumerate(fields):
            field_object = _resolve(field_ref)
            if not isinstance(field_object, DictionaryObject):
                continue
            marker = id(field_object)
            if marker in visited:
                continue
            visited.add(marker)
            self._scan_field(
                field_object,
                f"{path}[{index}]",
                parent,
                visited,
            )

    def _scan_field(
        self,
        field: DictionaryObject,
        path: str,
        parent: DictionaryObject | None,
        visited: set[int],
    ) -> None:
        field_name = self._qualified_field_name(field, parent)
        field_type: str | None = None
        current: DictionaryObject | None = field
        seen: set[int] = set()
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            field_type = _name(_resolve(current.get("/FT")))
            if field_type is not None:
                break
            parent_value = _resolve(current.get("/Parent"))
            current = parent_value if isinstance(parent_value, DictionaryObject) else None
        pages = self._field_pages(field)
        field_owner = SurfaceRef(
            SurfaceKind.FORM_FIELD,
            path,
            page_index=pages[0] if pages else None,
            field_name=field_name,
        )
        field_record: _FieldRecord | None = None
        if id(field) not in self._scanned_fields:
            self._scanned_fields.add(id(field))
            field_record = _FieldRecord(
                name=field_name,
                field_type=field_type,
                pages=pages,
            )
            self.fields.append(field_record)

        self._scan_action_entry(field, "/A", field_owner, field_record)
        if "/AA" in field:
            self._scan_additional_actions(field, field_owner, field_record)

        kids = _resolve(field.get("/Kids"))
        if isinstance(kids, ArrayObject):
            self._scan_field_array(
                kids,
                f"{path}/Kids",
                parent=field,
                visited=visited,
            )

    def _qualified_field_name(
        self, field: DictionaryObject, parent: DictionaryObject | None
    ) -> str:
        parts: list[str] = []
        visited: set[int] = set()
        current: DictionaryObject | None = field
        while current is not None:
            marker = id(current)
            if marker in visited:
                break
            visited.add(marker)
            if "/TM" in current:
                parts.append(str(_resolve(current["/TM"])))
            elif "/T" in current:
                parts.append(str(_resolve(current["/T"])))
            parent_value = _resolve(current.get("/Parent"))
            if isinstance(parent_value, DictionaryObject):
                current = parent_value
            elif current is field:
                current = parent
            else:
                current = None
        return ".".join(reversed([part for part in parts if part]))

    def _field_pages(self, field: DictionaryObject) -> list[int]:
        pages: list[int] = []
        parent = _resolve(field.get("/P"))
        if isinstance(parent, PageObject):
            pages.append(parent.page_number)
        for index, page in enumerate(self.document.pages):
            annotations = _resolve(page.get("/Annots"))
            if not isinstance(annotations, ArrayObject):
                continue
            if any(_resolve(annotation) is field for annotation in annotations):
                pages.append(index)
        return sorted(set(pages))

    def _scan_additional_actions(
        self,
        container: DictionaryObject,
        owner_ref: SurfaceRef,
        field_record: _FieldRecord | None = None,
    ) -> None:
        additional_actions = _resolve(container.get("/AA"))
        if not isinstance(additional_actions, DictionaryObject):
            return
        self.aa_containers.append((container, additional_actions))
        for trigger in list(additional_actions.keys()):
            self._scan_action_entry(
                additional_actions, trigger, owner_ref, field_record
            )

    def _scan_action_entry(
        self,
        owner: DictionaryObject,
        key: str,
        owner_ref: SurfaceRef,
        field_record: _FieldRecord | None = None,
    ) -> None:
        if key not in owner:
            return
        value = _resolve(owner[key])
        if isinstance(value, DictionaryObject):
            self._scan_action_slot(owner, key, owner_ref, field_record)
        elif value is not None and not is_null_or_none(value):
            slot = _ActionSlot(owner, key)
            record = self._add_invalid_action(owner_ref, slot)
            if field_record is not None:
                field_record.action_keys.append(record.key)

    def _scan_action_slot(
        self,
        owner: DictionaryObject,
        key: str,
        owner_ref: SurfaceRef,
        field_record: _FieldRecord | None = None,
    ) -> _ActionRecord:
        action = cast(DictionaryObject, _resolve(owner[key]))
        slot = _ActionSlot(owner, key)
        record = self._add_action(action, owner_ref, slot)
        if field_record is not None:
            field_record.action_keys.append(record.key)
        self._scan_next(action, owner_ref)
        return record

    def _scan_next(
        self,
        action: DictionaryObject,
        owner_ref: SurfaceRef,
        stack: set[int] | None = None,
    ) -> None:
        if "/Next" not in action:
            return
        if stack is None:
            stack = set()
        marker = id(action)
        if marker in stack:
            return
        stack.add(marker)
        try:
            next_value = _resolve(action["/Next"])
            if isinstance(next_value, DictionaryObject):
                slot = _ActionSlot(action, "/Next", chain=True)
                self._add_action(next_value, owner_ref, slot)
                self._scan_next(next_value, owner_ref, stack)
            elif isinstance(next_value, ArrayObject):
                for index, item in enumerate(next_value):
                    item_object = _resolve(item)
                    if not isinstance(item_object, DictionaryObject):
                        continue
                    slot = _ActionSlot(next_value, index, chain=True)
                    self._add_action(item_object, owner_ref, slot)
                    self._scan_next(item_object, owner_ref, stack)
        finally:
            stack.remove(marker)

    def _add_action(
        self,
        action: DictionaryObject,
        owner_ref: SurfaceRef,
        slot: _ActionSlot,
    ) -> _ActionRecord:
        marker = id(action)
        record = self.action_records.get(marker)
        if record is None:
            key, action_ref = _action_key(action, owner_ref)
            record = _ActionRecord(
                action=action,
                key=key,
                action_ref=action_ref,
            )
            self.action_records[marker] = record
        if owner_ref not in record.owners:
            record.owners.append(owner_ref)
        if not any(
            candidate.owner is slot.owner and candidate.key == slot.key
            for candidate in record.slots
        ):
            record.slots.append(slot)
        return record

    def _add_invalid_action(
        self,
        owner_ref: SurfaceRef,
        slot: _ActionSlot,
    ) -> _ActionRecord:
        key = f"invalid:{owner_ref.kind}:{owner_ref.path}:{slot.key}"
        record = self.action_records.get(id(slot))
        if record is None:
            record = _ActionRecord(
                action=None,
                key=key,
                action_ref=None,
            )
            self.action_records[id(slot)] = record
        if owner_ref not in record.owners:
            record.owners.append(owner_ref)
        record.slots.append(slot)
        return record

    def _scan_invalid_action(
        self,
        owner: DictionaryObject,
        key: str,
        owner_ref: SurfaceRef,
    ) -> _ActionRecord:
        return self._add_invalid_action(owner_ref, _ActionSlot(owner, key))


def _named_destination_map(document: PdfReader | PdfWriter) -> dict[str, Any]:
    try:
        return cast(dict[str, Any], document.named_destinations)
    except Exception:  # pragma: no cover - malformed destination trees
        return {}


def _destination_target(
    value: Any,
    scanner: _Scanner,
) -> tuple[bool, str | None, int | None, str]:
    value = _resolve(value)
    if isinstance(value, DictionaryObject) and "/D" in value:
        return _destination_target(value["/D"], scanner)
    if isinstance(value, (str, bytes)):
        if scanner._named_destinations is None:
            scanner._named_destinations = _named_destination_map(scanner.document)
        names = scanner._named_destinations
        candidate = value.decode() if isinstance(value, bytes) else value
        destination = names.get(candidate)
        if destination is None and not candidate.startswith("/"):
            destination = names.get("/" + candidate)
        if destination is None and candidate.startswith("/"):
            destination = names.get(candidate[1:])
        if destination is None:
            return False, f"named:{candidate}", None, "unresolved named destination"
        value = _resolve(destination.dest_array)
    if isinstance(value, ArrayObject) and len(value) >= 2:
        first = value[0]
        if isinstance(first, IndirectObject):
            key = (first.idnum, first.generation)
            if key in scanner._page_refs:
                page_index = scanner._page_refs[key]
                return True, f"page:{page_index}", page_index, "local page destination"
        resolved = _resolve(first)
        if isinstance(resolved, PageObject):
            page_index = resolved.page_number
            return True, f"page:{page_index}", page_index, "local page destination"
        if isinstance(resolved, NumberObject):
            page_index = int(resolved)
            if 0 <= page_index < len(scanner.document.pages):
                return True, f"page:{page_index}", page_index, "local page destination"
            return False, f"page:{page_index}", None, "page index out of range"
        if isinstance(resolved, DictionaryObject) and resolved.get("/Type") == "/Page":
            # Some readers expose page dictionaries without wrapping them in a
            # PageObject.  Locate the matching page through the page tree.
            for page_index, page in enumerate(scanner.document.pages):
                if page.get_object() is resolved:
                    return True, f"page:{page_index}", page_index, "local page destination"
        return False, None, None, "destination does not reference a local page"
    return False, None, None, "malformed destination"


def _classify_action(  # noqa: PLR0911
    record: _ActionRecord,
    scanner: _Scanner,
    policy: SanitizationPolicy,
) -> tuple[ActionClassification, str | None, int | None, str]:
    action = record.action
    if action is None:
        return (
            ActionClassification.UNEXPLAINED,
            None,
            None,
            "action entry is not an action dictionary",
        )
    action_type = _action_type(action)
    if action_type is None:
        return (
            ActionClassification.UNEXPLAINED,
            None,
            None,
            "action has no /S entry",
        )
    if action_type in _EXTERNAL_ACTION_TYPES:
        target: str | None = None
        if action_type == "/URI":
            target = _display_text(action.get("/URI", ""))
        elif action_type in {"/GoToR", "/Launch", "/SubmitForm", "/ImportData"}:
            target = _file_spec_target(action.get("/F"))
        elif action_type == "/JavaScript":
            target = _display_text(action.get("/JS", ""))
        elif action_type in {"/Sound", "/Movie", "/Rendition", "/RichMediaExecute"}:
            target = f"{action_type.lower()} handler"
        return (
            ActionClassification.EXTERNAL_RESOURCE,
            target,
            None,
            f"external resource action {action_type}",
        )
    if action_type == "/GoTo":
        destination = action.get("/D")
        if destination is None:
            return (
                ActionClassification.UNEXPLAINED,
                None,
                None,
                "GoTo action has no /D destination",
            )
        valid, target, page_index, reason = _destination_target(
            destination, scanner
        )
        if valid:
            return (
                ActionClassification.LOCAL_NAVIGATION,
                target,
                page_index,
                reason,
            )
        return (
            ActionClassification.UNEXPLAINED,
            target,
            None,
            reason,
        )
    if action_type == "/Named":
        named_action = _name(_resolve(action.get("/N")))
        if named_action is None:
            return (
                ActionClassification.UNEXPLAINED,
                None,
                None,
                "Named action has no /N entry",
            )
        if (
            named_action in _DEFAULT_NAMED_ACTIONS
            or named_action in policy.allowed_named_actions
        ):
            return (
                ActionClassification.LOCAL_NAVIGATION,
                f"named:{named_action}",
                None,
                "local named navigation",
            )
        return (
            ActionClassification.NON_NAVIGATION,
            f"named:{named_action}",
            None,
            "named action is not approved local navigation",
        )
    if action_type in _NON_NAVIGATION_ACTION_TYPES:
        return (
            ActionClassification.NON_NAVIGATION,
            action_type,
            None,
            f"{action_type} is not an approved local page navigation",
        )
    return (
        ActionClassification.UNEXPLAINED,
        action_type,
        None,
        f"unknown action type {action_type}",
    )


def _reviewer_accepts(
    reviewer: Callable[[ActionFinding], bool | ActionDisposition] | None,
    finding: ActionFinding,
) -> bool:
    if reviewer is None:
        return True
    result = reviewer(finding)
    if isinstance(result, ActionDisposition):
        return result == ActionDisposition.RETAINED
    return bool(result)


def _build_review(
    document: PdfReader | PdfWriter,
    *,
    policy: SanitizationPolicy | None = None,
    reviewer: Callable[[ActionFinding], bool | ActionDisposition] | None = None,
) -> tuple[InteractiveReview, _Scanner]:
    policy = policy or SanitizationPolicy()
    scanner = _Scanner(document)
    scanner.scan()

    actions: list[ActionFinding] = []
    for record in scanner.action_records.values():
        classification, target, page_index, reason = _classify_action(
            record, scanner, policy
        )
        finding = ActionFinding(
            key=record.key,
            action_type=_action_type(record.action),
            classification=classification,
            target=target,
            owners=list(record.owners),
            action_ref=record.action_ref,
            shared=len(record.owners) > 1,
            page_index=page_index,
        )
        if classification == ActionClassification.LOCAL_NAVIGATION:
            action_type = _action_type(record.action)
            named_action = (
                _name(_resolve(record.action.get("/N")))
                if record.action is not None
                else None
            )
            if not policy.allow_local_navigation:
                finding.disposition = ActionDisposition.REMOVED
                finding.reason = "local navigation is disabled by policy"
            elif any(
                owner.kind not in policy.allowed_surfaces
                for owner in finding.owners
            ):
                finding.disposition = ActionDisposition.REMOVED
                finding.reason = "one or more owners are outside the approved surfaces"
            elif action_type not in policy.allowed_local_action_types:
                finding.disposition = ActionDisposition.REMOVED
                finding.reason = f"action type {action_type} is not approved"
            elif (
                action_type == "/Named"
                and named_action not in policy.allowed_named_actions
            ):
                finding.disposition = ActionDisposition.REMOVED
                finding.reason = (
                    f"named action {named_action} is not approved"
                )
            elif reviewer is not None:
                finding.disposition = ActionDisposition.RETAINED
                finding.reason = "proposed local navigation for interactive review"
                if not _reviewer_accepts(reviewer, finding):
                    finding.disposition = ActionDisposition.REMOVED
                    finding.reason = "rejected by interactive reviewer"
                else:
                    finding.reason = "approved by interactive reviewer"
            else:
                finding.disposition = ActionDisposition.RETAINED
                finding.reason = "approved local navigation"
        else:
            finding.disposition = ActionDisposition.REMOVED
            if (
                classification == ActionClassification.UNEXPLAINED
                and not policy.remove_unexplained
            ):
                # Auditing mode: leave the action in place, but keep the
                # unexplained marker in the report.
                finding.disposition = ActionDisposition.RETAINED
                finding.reason = "unexplained action retained by audit policy"
            else:
                finding.reason = reason
        actions.append(finding)

    bookmarks = list(scanner.bookmarks)
    field_records = list(scanner.fields)
    review = InteractiveReview(
        actions=actions,
        destinations=[],
        bookmarks=bookmarks,
        form_fields=[
            FormFieldFinding(
                name=field.name,
                field_type=field.field_type,
                pages=field.pages,
                action_keys=list(field.action_keys),
            )
            for field in field_records
        ],
        approval_scope=ApprovalScope(
            allowed_surfaces=policy.allowed_surfaces,
            allowed_local_action_types=policy.allowed_local_action_types,
            allowed_named_actions=policy.allowed_named_actions,
            allow_local_navigation=policy.allow_local_navigation,
            remove_unexplained=policy.remove_unexplained,
            reviewer_used=reviewer is not None,
        ),
    )
    _evaluate_outcomes(review, scanner)
    return review, scanner


def _evaluate_outcomes(review: InteractiveReview, scanner: _Scanner) -> None:
    """Fill in proposed destination, bookmark, and form outcomes."""
    for record in scanner.destination_records:
        valid, target, page_index, reason = _destination_target(
            record.value, scanner
        )
        allowed = (
            valid
            and review.approval_scope.allow_local_navigation
            and record.owner_ref.kind in review.approval_scope.allowed_surfaces
        )
        review.destinations.append(
            DestinationFinding(
                key=f"dest:{record.owner_ref.path}",
                target=target,
                owners=[record.owner_ref],
                disposition=(
                    NavigationDisposition.RETAINED
                    if allowed
                    else NavigationDisposition.REMOVED
                ),
                reason=(
                    reason
                    if allowed or not valid
                    else "destination surface is not approved"
                ),
                page_index=page_index,
            )
        )

    destinations_by_key = {
        destination.key: destination for destination in review.destinations
    }
    for bookmark in review.bookmarks:
        destination = destinations_by_key.get(bookmark.destination_key or "")
        if destination is not None:
            bookmark.destination = destination.target
            bookmark.page_index = destination.page_index
            bookmark.navigation_retained = (
                destination.disposition == NavigationDisposition.RETAINED
            )
        for action_key in bookmark.action_keys:
            action = review.action_by_key(action_key)
            if action is None:
                continue
            if action.disposition == ActionDisposition.REMOVED:
                bookmark.removed_action_keys.append(action_key)
            elif action.classification == ActionClassification.LOCAL_NAVIGATION:
                bookmark.destination = action.target
                bookmark.page_index = action.page_index
                bookmark.navigation_retained = True
        if bookmark.navigation_retained:
            bookmark.reason = "approved local navigation retained"
        elif bookmark.removed_action_keys or bookmark.destination_key:
            bookmark.reason = (
                "bookmark retained without an approved local navigation target"
            )
        else:
            bookmark.reason = "bookmark has no action or destination"

    for form_field in review.form_fields:
        for action_key in form_field.action_keys:
            action = review.action_by_key(action_key)
            if action is not None and action.disposition == ActionDisposition.REMOVED:
                form_field.removed_action_keys.append(action_key)


def _record_for_action(
    scanner: _Scanner,
    action: DictionaryObject,
) -> _ActionRecord | None:
    return scanner.action_records.get(id(action))


def _sanitize_next_value(
    value: Any,
    scanner: _Scanner,
    review: InteractiveReview,
    seen: set[int],
) -> list[Any]:
    value = _resolve(value)
    if isinstance(value, DictionaryObject):
        record = _record_for_action(scanner, value)
        if record is None:
            return []
        finding = review.action_by_key(record.key)
        if finding is not None and finding.disposition == ActionDisposition.RETAINED:
            _sanitize_action_next(value, scanner, review, seen)
            return [value]
        marker = id(value)
        if marker in seen:
            return []
        seen.add(marker)
        if "/Next" in value:
            return _sanitize_next_value(value["/Next"], scanner, review, seen)
        return []
    if isinstance(value, ArrayObject):
        result: list[Any] = []
        for item in list(value):
            item_object = _resolve(item)
            if not isinstance(item_object, DictionaryObject):
                continue
            record = _record_for_action(scanner, item_object)
            if record is None:
                continue
            finding = review.action_by_key(record.key)
            if finding is not None and finding.disposition == ActionDisposition.RETAINED:
                _sanitize_action_next(item_object, scanner, review, seen)
                result.append(item_object)
            elif "/Next" in item_object:
                result.extend(
                    _sanitize_next_value(
                        item_object["/Next"], scanner, review, seen
                    )
                )
        return result
    return []


def _sanitize_action_next(
    action: DictionaryObject,
    scanner: _Scanner,
    review: InteractiveReview,
    seen: set[int],
) -> None:
    marker = id(action)
    if marker in seen:
        return
    seen.add(marker)
    if "/Next" not in action:
        return
    remaining = _sanitize_next_value(action["/Next"], scanner, review, seen)
    if not remaining:
        del action["/Next"]
    elif len(remaining) == 1:
        action[NameObject("/Next")] = remaining[0]
    else:
        action[NameObject("/Next")] = ArrayObject(remaining)


def _remove_slot(slot: _ActionSlot) -> None:
    try:
        slot.remove()
    except (IndexError, KeyError, TypeError, ValueError):
        return


def _apply_review(
    review: InteractiveReview,
    scanner: _Scanner,
) -> None:
    # First make action chains safe.  This also promotes approved actions which
    # followed an action that was removed.
    seen: set[int] = set()
    for record in scanner.action_records.values():
        if record.action is not None:
            _sanitize_action_next(record.action, scanner, review, seen)

    # Detach removed actions from every direct surface.  Chain slots are
    # handled by the chain sanitizer above.
    name_tree_slots: dict[int, tuple[ArrayObject, list[_ActionSlot]]] = {}
    for record in scanner.action_records.values():
        finding = review.action_by_key(record.key)
        if finding is None or finding.disposition == ActionDisposition.RETAINED:
            continue
        replacement = (
            record.action.get("/Next")
            if record.action is not None and "/Next" in record.action
            else None
        )
        for slot in record.slots:
            if slot.chain:
                continue
            if slot.name_tree_pair and isinstance(slot.owner, ArrayObject):
                _, grouped = name_tree_slots.setdefault(
                    id(slot.owner), (slot.owner, [])
                )
                grouped.append(slot)
            elif replacement is not None:
                # Keep an approved action which followed the rejected action.
                replacement_key = (
                    NameObject(slot.key)
                    if isinstance(slot.owner, DictionaryObject)
                    and isinstance(slot.key, str)
                    else slot.key
                )
                slot.owner[replacement_key] = replacement
            else:
                _remove_slot(slot)

    # Removing a name-tree pair shifts every later pair in that array.
    # Process each array from right to left.
    for _, slots in name_tree_slots.values():
        for slot in sorted(slots, key=lambda candidate: candidate.key, reverse=True):
            _remove_slot(slot)

    # Do not leave a reachable or orphaned copy of a rejected action payload
    # in the derived object table.
    for record in scanner.action_records.values():
        finding = review.action_by_key(record.key)
        if (
            finding is not None
            and finding.disposition == ActionDisposition.REMOVED
            and record.action is not None
        ):
            record.action.clear()

    # Remove empty additional-action dictionaries to avoid leaving an
    # interaction shell behind after all of its triggers were removed.
    for container, additional_actions in scanner.aa_containers:
        if not additional_actions:
            try:
                del container["/AA"]
            except KeyError:
                pass

    # Destinations are not actions, but an unapproved destination still moves
    # the reader to an object which is outside the approved navigation scope.
    for record in scanner.destination_records:
        finding = next(
            (
                destination
                for destination in review.destinations
                if destination.key == f"dest:{record.owner_ref.path}"
            ),
            None,
        )
        if (
            finding is not None
            and finding.disposition == NavigationDisposition.REMOVED
        ):
            _remove_slot(_ActionSlot(record.owner, record.key))

    review.applied = True


def review_interactive_actions(
    document: PdfReader | PdfWriter,
    *,
    policy: SanitizationPolicy | None = None,
    reviewer: Callable[[ActionFinding], bool | ActionDisposition] | None = None,
) -> InteractiveReview:
    """Inspect interactive actions without changing the document.

    The returned :class:`InteractiveReview` contains proposed dispositions.
    Use :meth:`PdfWriter.sanitize_interactive` or
    :func:`sanitize_interactive_pdf` to apply them to a derived document.
    """
    review, _ = _build_review(document, policy=policy, reviewer=reviewer)
    return review


def sanitize_writer(
    writer: PdfWriter,
    *,
    policy: SanitizationPolicy | None = None,
    reviewer: Callable[[ActionFinding], bool | ActionDisposition] | None = None,
) -> SanitizationReport:
    """Sanitize a writer in place and return an audit report.

    This is the backend used by ``PdfWriter.sanitize_interactive``.  It never
    writes a file and never touches the reader from which the writer was
    cloned.
    """
    if getattr(writer, "incremental", False):
        raise SanitizationError(
            "Incremental writers cannot be sanitized because that would modify "
            "the original file.  Use a non-incremental clone instead."
        )
    review, scanner = _build_review(
        writer, policy=policy, reviewer=reviewer
    )
    _apply_review(review, scanner)
    return SanitizationReport(
        actions=review.actions,
        destinations=review.destinations,
        bookmarks=review.bookmarks,
        form_fields=review.form_fields,
        approval_scope=review.approval_scope,
        applied=True,
    )


def _as_reader(source: PdfReader | StrByteType | Path | BinaryIO) -> tuple[PdfReader, bool]:
    from ._reader import PdfReader  # noqa: PLC0415

    if isinstance(source, PdfReader):
        return source, False
    if isinstance(source, (bytes, bytearray, memoryview)):
        return PdfReader(BytesIO(bytes(source))), True
    return PdfReader(source), True


def _clone_writer(reader: PdfReader) -> PdfWriter:
    from ._writer import PdfWriter  # noqa: PLC0415

    writer = PdfWriter()
    writer.clone_document_from_reader(reader)
    return writer


def _verify_output(
    data: bytes,
    report: SanitizationReport,
    policy: SanitizationPolicy,
) -> None:
    from ._reader import PdfReader  # noqa: PLC0415

    reader = PdfReader(BytesIO(data))
    try:
        output_review = review_interactive_actions(reader, policy=policy)
        external = output_review.external_actions
        report.output_counts = output_review.counts
        report.output_external_actions = external
        report.output_verified = not external
        if external:
            raise SanitizationError(
                "Derived PDF still contains external-resource actions: "
                + ", ".join(action.key for action in external)
            )
        if len(output_review.bookmarks) != len(report.bookmarks):
            raise SanitizationError(
                "Derived PDF changed the bookmark inventory during sanitization"
            )
        if len(output_review.form_fields) != len(report.form_fields):
            raise SanitizationError(
                "Derived PDF changed the form field inventory during sanitization"
            )
        if any(
            not bookmark.disposition or not bookmark.reason
            for bookmark in report.bookmarks
        ):
            raise SanitizationError(
                "Derived PDF contains a bookmark without a disposition"
            )
        if any(
            not form_field.disposition
            for form_field in report.form_fields
        ):
            raise SanitizationError(
                "Derived PDF contains a form field without a disposition"
            )
        if any(
            action.disposition != ActionDisposition.REMOVED
            for action in report.removed_actions
        ):
            raise SanitizationError(
                "Derived PDF report contains a removed action which was retained"
            )
    finally:
        reader.close()


def sanitize_interactive_bytes(
    source: PdfReader | StrByteType | Path | BinaryIO,
    *,
    policy: SanitizationPolicy | None = None,
    reviewer: Callable[[ActionFinding], bool | ActionDisposition] | None = None,
    verify: bool = True,
) -> tuple[bytes, SanitizationReport]:
    """Return a sanitized PDF as bytes together with its audit report.

    ``source`` may be a reader, path, or binary stream.  The source is only
    opened for reading.
    """
    policy = policy or SanitizationPolicy()
    reader, owned = _as_reader(source)
    try:
        writer = _clone_writer(reader)
        report = sanitize_writer(
            writer, policy=policy, reviewer=reviewer
        )
        output = BytesIO()
        writer.write(output)
        data = output.getvalue()
    finally:
        if owned:
            reader.close()
    if verify:
        _verify_output(data, report, policy)
    return data, report


def sanitize_interactive_pdf(
    source: PdfReader | StrByteType | Path | BinaryIO,
    target: StrByteType | Path | BinaryIO,
    *,
    policy: SanitizationPolicy | None = None,
    reviewer: Callable[[ActionFinding], bool | ActionDisposition] | None = None,
    verify: bool = True,
) -> SanitizationReport:
    """Write a sanitized derived PDF and return an audit report.

    The source path is never opened for writing.  Supplying the same path for
    ``source`` and ``target`` is rejected.
    """
    if source is target:
        raise SanitizationError(
            "The source PDF is read-only; choose a different output path or stream"
        )
    source_name = (
        source
        if isinstance(source, (str, Path))
        else getattr(getattr(source, "stream", source), "name", None)
    )
    target_name = target if isinstance(target, (str, Path)) else getattr(target, "name", None)
    if isinstance(source_name, (str, Path)) and isinstance(target_name, (str, Path)):
        source_path = Path(source_name).expanduser().resolve()
        target_path = Path(target_name).expanduser().resolve()
        if source_path == target_path:
            raise SanitizationError(
                "The source PDF is read-only; choose a different output path"
            )
        if target_path.exists() and source_path.samefile(target_path):
            raise SanitizationError(
                "The source PDF is read-only; choose a different output path"
            )
    data, report = sanitize_interactive_bytes(
        source,
        policy=policy,
        reviewer=reviewer,
        verify=verify,
    )
    if isinstance(target, (str, Path)):
        output_path = Path(target)
        output_path.write_bytes(data)
        report.output = str(output_path)
    else:
        target.write(data)
        report.output = getattr(target, "name", "<stream>")
    return report


__all__ = [
    "ActionClassification",
    "ActionDisposition",
    "ActionFinding",
    "ApprovalScope",
    "BookmarkFinding",
    "DestinationFinding",
    "FormFieldFinding",
    "InteractiveReview",
    "NavigationDisposition",
    "SanitizationPolicy",
    "SanitizationReport",
    "SurfaceKind",
    "SurfaceRef",
    "review_interactive_actions",
    "sanitize_interactive_bytes",
    "sanitize_interactive_pdf",
    "sanitize_writer",
]
