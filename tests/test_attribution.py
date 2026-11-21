from types import SimpleNamespace

from dnfile.attribution import (
    AttributionStatus,
    MetadataSample,
    attribute_type_references,
)
from dnfile.utils import LazyList


class FakeTable:
    def __init__(self, name, rows, file_offset=0x100, row_size=16):
        self.name = name
        self.rows = rows
        self.num_rows = len(rows)
        self.file_offset = file_offset
        self.row_size = row_size


class FakeRow:
    def __init__(self, struct, **public):
        self.struct = SimpleNamespace(**struct)
        self.__dict__.update(public)


def make_row(public=None, **struct):
    return FakeRow(struct, **(public or {}))


def assembly_row(name, version):
    return make_row(
        {
            'Name': name,
            'MajorVersion': version[0],
            'MinorVersion': version[1],
            'BuildNumber': version[2],
            'RevisionNumber': version[3],
            'Culture': '',
        },
        Name_StringIndex=1,
        Culture_StringIndex=0,
        PublicKey_BlobIndex=0,
        Flags=0,
    )


def assembly_ref_row(name, version):
    return make_row(
        {
            'Name': name,
            'MajorVersion': version[0],
            'MinorVersion': version[1],
            'BuildNumber': version[2],
            'RevisionNumber': version[3],
            'Culture': '',
        },
        Name_StringIndex=1,
        Culture_StringIndex=0,
        PublicKey_BlobIndex=0,
        HashValue_BlobIndex=0,
        Flags=0,
    )


def type_def_row(namespace, name):
    return make_row(
        {'TypeNamespace': namespace, 'TypeName': name},
        TypeNamespace_StringIndex=1,
        TypeName_StringIndex=2,
        Extends_CodedIndex=0,
        FieldList_Index=1,
        MethodList_Index=1,
    )


def type_ref_row(namespace, name, scope):
    return make_row(
        {'TypeNamespace': namespace, 'TypeName': name},
        ResolutionScope_CodedIndex=scope,
        TypeNamespace_StringIndex=1,
        TypeName_StringIndex=2,
    )


def exported_type_row(namespace, name, implementation, type_def_id=1):
    return make_row(
        {'TypeNamespace': namespace, 'TypeName': name},
        Implementation_CodedIndex=implementation,
        TypeDefId=type_def_id,
        TypeNamespace_StringIndex=1,
        TypeName_StringIndex=2,
        Flags=0,
    )


def nested_row(nested, enclosing):
    return make_row({}, NestedClass_Index=nested, EnclosingClass_Index=enclosing)


def scope_assembly_ref(rid):
    return (rid << 2) | 2


def scope_type_ref(rid):
    return (rid << 2) | 3


def implementation_assembly_ref(rid):
    return (rid << 2) | 1


def implementation_exported_type(rid):
    return (rid << 2) | 2


def table_map(**tables):
    return {name: FakeTable(name, rows) for name, rows in tables.items()}


def sample(key, tables):
    return MetadataSample(key=key, metadata=tables)


def build_samples(lazy=False):
    lib1_tables = table_map(
        Assembly=[assembly_row('Lib', (1, 0, 0, 0))],
        TypeDef=[
            type_def_row('Lib', 'Helper'),
            type_def_row('Lib', 'Outer'),
            type_def_row('', 'Inner'),
        ],
        NestedClass=[nested_row(3, 2)],
    )
    lib2_tables = table_map(
        Assembly=[assembly_row('Lib', (2, 0, 0, 0))],
        TypeDef=[type_def_row('Lib', 'Helper')],
    )
    lib3_tables = table_map(
        Assembly=[assembly_row('Lib', (3, 0, 0, 0))],
        TypeDef=[type_def_row('Lib', 'Helper')],
    )
    facade_tables = table_map(
        Assembly=[assembly_row('Facade', (1, 0, 0, 0))],
        AssemblyRef=[assembly_ref_row('Lib', (1, 0, 0, 0))],
        ExportedType=[
            exported_type_row('Lib', 'Helper', implementation_assembly_ref(1)),
            exported_type_row('Lib', 'Outer', implementation_assembly_ref(1)),
            exported_type_row('', 'Inner', implementation_exported_type(2)),
        ],
    )
    ghost_tables = table_map(
        Assembly=[assembly_row('GhostFacade', (1, 0, 0, 0))],
        AssemblyRef=[assembly_ref_row('Absent', (1, 0, 0, 0))],
        ExportedType=[
            exported_type_row('Lib', 'Helper', implementation_assembly_ref(1)),
        ],
    )
    app_tables = table_map(
        Assembly=[assembly_row('App', (1, 0, 0, 0))],
        AssemblyRef=[
            assembly_ref_row('Lib', (1, 0, 0, 0)),
            assembly_ref_row('Absent', (1, 0, 0, 0)),
            assembly_ref_row('Facade', (1, 0, 0, 0)),
            assembly_ref_row('GhostFacade', (1, 0, 0, 0)),
        ],
        TypeRef=[
            type_ref_row('Lib', 'Helper', scope_assembly_ref(1)),
            type_ref_row('Lib', 'Outer', scope_assembly_ref(1)),
            type_ref_row('Lib', 'Inner', scope_type_ref(2)),
            type_ref_row('Absent', 'Helper', scope_assembly_ref(2)),
            type_ref_row('Lib', 'Helper', scope_assembly_ref(3)),
            type_ref_row('Lib', 'Outer', scope_assembly_ref(3)),
            type_ref_row('Lib', 'Inner', scope_type_ref(6)),
            type_ref_row('Lib', 'Helper', scope_assembly_ref(4)),
        ],
    )
    tables = [app_tables, lib1_tables, lib2_tables, lib3_tables, facade_tables, ghost_tables]
    if lazy:
        for table_set in tables:
            for table in table_set.values():
                rows = table.rows
                table.rows = LazyList(lambda index, value, rows=rows: rows[index], len(rows))
    return [
        sample('app.exe', app_tables),
        sample('lib-1.dll', lib1_tables),
        sample('lib-2.dll', lib2_tables),
        sample('lib-3.dll', lib3_tables),
        sample('facade.dll', facade_tables),
        sample('ghost-facade.dll', ghost_tables),
    ]


def results_for(report, full_name, assembly_name=None):
    return tuple(
        result
        for result in report.results
        if result.reference.full_name == full_name
        and (
            assembly_name is None
            or (result.reference.assembly is not None and result.reference.assembly.name == assembly_name)
        )
    )


def find_edge(report, kind, table, row_index):
    return next(
        edge
        for edge in report.graph.edges
        if edge.kind == kind and edge.table == table and edge.row_index == row_index
    )


def test_multi_candidate_and_nested_attribution():
    report = attribute_type_references(build_samples())

    candidates = results_for(report, 'Lib.Helper', 'Lib')
    assert len(candidates) == 3
    assert all(result.status == AttributionStatus.RESOLVED for result in candidates)
    assert {result.candidate.version for result in candidates} == {
        (1, 0, 0, 0),
        (2, 0, 0, 0),
        (3, 0, 0, 0),
    }
    assert sum(bool(result.version_match) for result in candidates) == 1

    nested = results_for(report, 'Lib.Outer+Inner', 'Lib')
    resolved = tuple(result for result in nested if result.resolved)
    assert len(resolved) == 1
    assert resolved[0].definition.table == 'TypeDef'
    assert resolved[0].definition.row_index == 3
    assert resolved[0].candidate.version == (1, 0, 0, 0)


def test_forwarded_and_nested_forwarded_types():
    report = attribute_type_references(build_samples())

    forwarded = results_for(report, 'Lib.Helper', 'Facade')
    assert len(forwarded) == 3
    assert all(result.resolved and result.forwarded for result in forwarded)
    assert {result.final_assembly.version for result in forwarded} == {
        (1, 0, 0, 0),
        (2, 0, 0, 0),
        (3, 0, 0, 0),
    }

    nested_forwarded = results_for(report, 'Lib.Outer+Inner', 'Facade')
    assert any(result.resolved and result.forwarded for result in nested_forwarded)
    edge = find_edge(report, 'exportedtype.implementation', 'ExportedType', 3)
    assert edge.target.table == 'ExportedType'
    assert edge.target.row_index == 2


def test_missing_assembly_keeps_source_evidence():
    report = attribute_type_references(build_samples())
    missing = results_for(report, 'Absent.Helper', 'Absent')
    assert len(missing) == 1
    result = missing[0]
    assert result.status == AttributionStatus.MISSING_ASSEMBLY
    assert result.candidate is None
    assert result.missing[0].expected_assembly.name == 'Absent'
    assert result.missing[0].source.table == 'AssemblyRef'
    assert result.missing[0].source.row_index == 2
    assert any(edge.table == 'TypeRef' and edge.row_index == 4 for edge in result.evidence)


def test_lazy_and_full_parsing_have_same_identities():
    full = attribute_type_references(build_samples(lazy=False))
    lazy = attribute_type_references(build_samples(lazy=True))
    assert full.references == lazy.references
    assert full.results == lazy.results
    assert full.graph.nodes == lazy.graph.nodes
    assert full.graph.edges == lazy.graph.edges


def test_every_graph_edge_points_back_to_original_row():
    inputs = build_samples()
    report = attribute_type_references(inputs)
    row_counts = {
        (provided.key, table.name): len(table.rows)
        for provided in inputs
        for table in provided.metadata.values()
    }

    report.graph.validate()
    assert report.graph.edges
    for edge in report.graph.edges:
        assert edge.row_index >= 1
        assert edge.row_index <= row_counts[(edge.sample, edge.table)]
        assert edge.provenance.sample == edge.sample
        assert edge.provenance.table == edge.table
        assert edge.provenance.row_index == edge.row_index

    nested_typeref = find_edge(report, 'typeref.scope', 'TypeRef', 3)
    assert nested_typeref.source.table == 'TypeRef'
    assert nested_typeref.source.row_index == 3
    assert nested_typeref.target.table == 'TypeRef'
    assert nested_typeref.target.row_index == 2

    nested_export = find_edge(report, 'exportedtype.implementation', 'ExportedType', 3)
    assert nested_export.source.row_index == 3
    assert nested_export.target.table == 'ExportedType'
    assert nested_export.target.row_index == 2

    nested_class = find_edge(report, 'typedef.nested-in', 'NestedClass', 1)
    assert nested_class.source.table == 'TypeDef'
    assert nested_class.source.row_index == 3
    assert nested_class.target.table == 'TypeDef'
    assert nested_class.target.row_index == 2

    forwarded = find_edge(report, 'exportedtype.implementation', 'ExportedType', 1)
    assert forwarded.target.table == 'AssemblyRef'
    assert forwarded.target.row_index == 1


def test_missing_after_forwarding_keeps_exported_type_evidence():
    report = attribute_type_references(build_samples())
    missing = results_for(report, 'Lib.Helper', 'GhostFacade')
    assert len(missing) == 1
    result = missing[0]
    assert result.status == AttributionStatus.MISSING_ASSEMBLY
    assert result.forwarded
    assert result.missing[0].expected_assembly.name == 'Absent'
    assert result.missing[0].source.table == 'ExportedType'
    assert result.missing[0].source.row_index == 1
    assert any(
        edge.kind == 'exportedtype.implementation' and edge.row_index == 1
        for edge in result.evidence
    )
