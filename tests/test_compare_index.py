from types import SimpleNamespace

from dnfile.compare import (
    TypeIdentity,
    TypeIndex,
    compare_type_tables,
)


def type_row(rid, name, namespace=""):
    return {
        "RowIndex": rid,
        "TypeName": name,
        "TypeNamespace": namespace,
    }


def nested_row(child, parent):
    return {"NestedClass": child, "EnclosingClass": parent}


def test_internal_row_reorder_preserves_parent_qualified_observations():
    old_types = [
        type_row(1, "<Module>"),
        type_row(2, "Container", "Archive"),
        type_row(3, "Worker", "Archive"),
        type_row(4, "Counter", "Archive"),
    ]
    new_types = [
        type_row(1, "<Module>"),
        type_row(2, "AddedOne", "Archive"),
        type_row(3, "AddedTwo", "Archive"),
        type_row(4, "Container", "Archive"),
        type_row(5, "Counter", "Archive"),
        type_row(6, "Worker", "Archive"),
    ]
    old_nested = [nested_row(3, 2), nested_row(4, 2)]
    new_nested = [nested_row(5, 4), nested_row(6, 4)]

    report = compare_type_tables(
        old_types,
        new_types,
        nested_old=old_nested,
        nested_new=new_nested,
        module_name="Archive.dll",
    )

    assert report.row_map[3] == 6
    assert report.row_map[4] == 5
    assert report.relocations[3] == 6
    assert report.relocations[4] == 5

    worker = next(
        item
        for item in report.matches
        if item.identity.full_name == "Archive.Container/Worker"
    )
    counter = next(
        item
        for item in report.matches
        if item.identity.full_name == "Archive.Container/Counter"
    )

    assert worker.status == "moved"
    assert worker.preservation == "relocated"
    assert worker.preserved is True
    assert worker.identity_preserved is True
    assert worker.can_carry_observations is True
    assert worker.old_rid == 3
    assert worker.new_rid == 6

    assert counter.old_rid == 4
    assert counter.new_rid == 5
    assert counter.preserved is True
    assert counter.can_carry_observations is True

    assert report.ambiguous == []
    assert report.parent_changes == []
    worker_entry = next(
        item
        for item in report.manifest
        if item.get("identity") == "Archive.Container/Worker"
    )
    assert worker_entry["kind"] == "moved"
    assert worker_entry["preservation"] == "relocated"
    assert worker_entry["preserved"] is True
    assert "move" in worker_entry["conclusion"]


def test_same_simple_name_under_different_parents_is_not_collapsed():
    old_types = [
        type_row(1, "<Module>"),
        type_row(2, "Alpha"),
        type_row(3, "Item"),
        type_row(4, "Beta"),
        type_row(5, "Item"),
    ]
    new_types = [
        type_row(1, "<Module>"),
        type_row(2, "Beta"),
        type_row(3, "Item"),
        type_row(4, "Alpha"),
        type_row(5, "Item"),
    ]
    old_nested = [nested_row(3, 2), nested_row(5, 4)]
    new_nested = [nested_row(3, 2), nested_row(5, 4)]

    old_index = TypeIndex.build(
        old_types, nested_rows=old_nested, module_name="Scopes.dll"
    )
    new_index = TypeIndex.build(
        new_types, nested_rows=new_nested, module_name="Scopes.dll"
    )
    report = old_index.compare(new_index)

    item_matches = [item for item in report.matches if item.name == "Item"]
    assert len(item_matches) == 2
    assert {item.identity.full_name for item in item_matches} == {
        "Alpha/Item",
        "Beta/Item",
    }
    assert report.row_map[3] == 5
    assert report.row_map[5] == 3
    assert report.ambiguous == []


def test_real_parent_type_change_has_different_preservation_conclusion():
    old_types = [
        type_row(1, "<Module>"),
        type_row(2, "OldParent"),
        type_row(3, "Child"),
    ]
    new_types = [
        type_row(1, "<Module>"),
        type_row(2, "AddedType"),
        type_row(3, "NewParent"),
        type_row(4, "Child"),
    ]
    old_nested = [nested_row(3, 2)]
    new_nested = [nested_row(4, 3)]

    report = compare_type_tables(
        old_types,
        new_types,
        nested_old=old_nested,
        nested_new=new_nested,
        module_name="Families.dll",
    )

    child_matches = [item for item in report.matches if item.name == "Child"]
    assert child_matches == []
    assert 3 not in report.relocations

    assert len(report.parent_changes) == 1
    change = report.parent_changes[0]
    assert change.status == "parent_changed"
    assert change.old_identity.full_name == "OldParent/Child"
    assert change.new_identity.full_name == "NewParent/Child"
    assert change.old_rid == 3
    assert change.new_rid == 4
    assert change.preserved is False
    assert change.identity_preserved is False
    assert change.can_carry_observations is False
    assert change.requires_review is True

    manifest_child = next(
        item for item in report.manifest if item.get("name") == "Child"
    )
    assert manifest_child["kind"] == "parent_changed"
    assert manifest_child["preservation"] == "not_preserved"
    assert manifest_child["preserved"] is False

    added_identities = {item.identity.full_name for item in report.new_definitions}
    assert "AddedType" in added_identities
    assert "NewParent" in added_identities
    assert "NewParent/Child" in added_identities


def test_multiple_same_name_parent_candidates_are_ambiguous():
    old_types = [
        type_row(1, "<Module>"),
        type_row(2, "OldParent"),
        type_row(3, "Child"),
    ]
    new_types = [
        type_row(1, "<Module>"),
        type_row(2, "CandidateA"),
        type_row(3, "Child"),
        type_row(4, "CandidateB"),
        type_row(5, "Child"),
    ]
    old_nested = [nested_row(3, 2)]
    new_nested = [nested_row(3, 2), nested_row(5, 4)]

    report = compare_type_tables(
        old_types,
        new_types,
        nested_old=old_nested,
        nested_new=new_nested,
        module_name="Ambiguous.dll",
    )

    assert report.parent_changes == []
    assert len(report.ambiguous_names) == 1
    ambiguity = report.ambiguous_names[0]
    assert ambiguity.name == "Child"
    assert ambiguity.old_rids == [3]
    assert ambiguity.new_rids == [3, 5]
    assert {identity.full_name for identity in ambiguity.identities} == {
        "OldParent/Child",
        "CandidateA/Child",
        "CandidateB/Child",
    }
    assert ambiguity.preservation == "ambiguous"
    assert ambiguity.can_carry_observations is False
    assert any(item["kind"] == "ambiguous" for item in report.manifest)


def test_duplicate_parent_qualified_rows_are_ambiguous():
    old_types = [type_row(1, "Dup"), type_row(2, "Dup")]
    new_types = [type_row(1, "Dup"), type_row(3, "Dup")]

    report = compare_type_tables(old_types, new_types, module_name="Dup.dll")

    assert len(report.ambiguous_identities) == 1
    ambiguity = report.ambiguous_identities[0]
    assert ambiguity.old_rids == [1, 2]
    assert ambiguity.new_rids == [1, 3]
    assert report.matches == []


def test_module_scope_participates_in_identity():
    old_identity = TypeIdentity(name="Item", module="OldModule.dll")
    new_identity = TypeIdentity(name="Item", module="NewModule.dll")
    assert old_identity.key != new_identity.key

    report = compare_type_tables(
        [type_row(1, "Item")],
        [type_row(1, "Item")],
        old_module_name="OldModule.dll",
        new_module_name="NewModule.dll",
    )
    assert report.matches == []
    assert len(report.parent_changes) == 1
    assert report.parent_changes[0].status == "scope_changed"
    assert report.parent_changes[0].old_identity.module == "OldModule.dll"
    assert report.parent_changes[0].new_identity.module == "NewModule.dll"


def test_builds_from_dnfile_like_namespace_objects():
    old_rows = [
        SimpleNamespace(TypeName="Outer", TypeNamespace="Scopes"),
        SimpleNamespace(TypeName="Inner", TypeNamespace="Scopes"),
    ]
    nested_rows = [
        SimpleNamespace(
            NestedClass=SimpleNamespace(row_index=2),
            EnclosingClass=SimpleNamespace(row_index=1),
        )
    ]
    mdtables = SimpleNamespace(
        Module=SimpleNamespace(rows=[SimpleNamespace(Name="Scopes.dll")]),
        TypeDef=SimpleNamespace(rows=old_rows),
        NestedClass=SimpleNamespace(rows=nested_rows),
    )
    source = SimpleNamespace(net=SimpleNamespace(mdtables=mdtables))

    index = TypeIndex.build(source)

    assert index.module_name == "Scopes.dll"
    inner = next(item for item in index.observations if item.name == "Inner")
    assert inner.rid == 2
    assert inner.identity.full_name == "Scopes.Outer/Inner"
    assert inner.parent is not None
    assert inner.parent.name == "Outer"


def test_direct_parent_name_is_identity_even_without_parent_row():
    report = compare_type_tables(
        [{"RowIndex": 7, "TypeName": "Child", "Parent": "OldParent"}],
        [{"RowIndex": 9, "TypeName": "Child", "Parent": "NewParent"}],
        module_name="Direct.dll",
    )

    assert report.matches == []
    assert len(report.parent_changes) == 1
    change = report.parent_changes[0]
    assert change.old_identity.full_name == "OldParent/Child"
    assert change.new_identity.full_name == "NewParent/Child"
    assert change.can_carry_observations is False
