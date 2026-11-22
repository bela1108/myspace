import json
import sys
from pathlib import Path

import dnfile.abi as abi

sys.path.insert(0, str(Path(__file__).parent))
from synthetic_abi import SyntheticAssembly


def test_table_row_movement_is_not_an_interface_change():
    def old_assembly():
        builder = SyntheticAssembly('Demo')
        first = builder.add_type('Demo', 'A')
        builder.add_method(first, 'One')
        second = builder.add_type('Demo', 'G')
        builder.add_method(second, 'Two')
        return builder.build()

    def new_assembly():
        builder = SyntheticAssembly('Demo')
        extra = builder.add_type('Demo', 'Extra', visibility='internal')
        builder.add_method(extra, 'Hidden')
        moved = builder.add_type('Demo', 'G')
        builder.add_method(moved, 'Two')
        first = builder.add_type('Demo', 'A')
        builder.add_method(first, 'One')
        return builder.build()

    report = abi.audit_abi(
        old_assembly(),
        new_assembly(),
        entrypoints=['Demo.A::One', 'Demo.G::Two'],
    )
    assert report.counts == {'supported': 2, 'changed': 0, 'unresolved': 0, 'total': 2}
    assert all(result.status == abi.AbiStatus.SUPPORTED for result in report)
    assert not any('Extra' in result.old_identity for result in report if result.old_identity)


def test_member_moved_to_base_is_still_supported_and_explained():
    old = SyntheticAssembly('Demo')
    base = old.add_type('Demo', 'Base')
    derived = old.add_type('Demo', 'Derived', extends=base)
    old.add_method(derived, 'Keep')
    old_bytes = old.build()

    new = SyntheticAssembly('Demo')
    base = new.add_type('Demo', 'Base')
    new.add_method(base, 'Keep')
    new.add_type('Demo', 'Derived', extends=base)
    new_bytes = new.build()

    report = abi.audit_abi(old_bytes, new_bytes, entrypoints=['Demo.Derived::Keep'])
    result = report[0]
    assert result.status == abi.AbiStatus.SUPPORTED
    assert result.status == 'supported'
    assert result.details['inheritance']['moved_to_base'] is True
    assert result.details['inheritance']['old_declaring_type'] == 'Demo.Derived'
    assert result.details['inheritance']['new_declaring_type'] == 'Demo.Base'
    assert result.inherited_from == ['Demo.Derived']


def test_parameter_signature_change_changes_identity():
    old = SyntheticAssembly('Demo')
    api = old.add_type('Demo', 'Api')
    old.add_method(api, 'Sig', params=('System.String',))
    old_bytes = old.build()

    new = SyntheticAssembly('Demo')
    api = new.add_type('Demo', 'Api')
    new.add_method(api, 'Sig', params=('System.Int32',))
    new_bytes = new.build()

    report = abi.audit_abi(old_bytes, new_bytes, entrypoints=['Demo.Api::Sig'])
    result = report[0]
    assert result.status == abi.AbiStatus.CHANGED
    assert 'parameter_type' in result.reason
    change = [item for item in result.changes if item['kind'] == 'parameter_type'][0]
    assert change['parameter'] == 1
    assert change['old'] == 'System.String'
    assert change['new'] == 'System.Int32'
    assert result.details['parameters_old'] == ['System.String']
    assert result.details['parameters_new'] == ['System.Int32']


def test_return_signature_and_visibility_changes():
    old = SyntheticAssembly('Demo')
    api = old.add_type('Demo', 'Api')
    old.add_method(api, 'Return', return_type='System.String')
    old.add_method(api, 'Hide', visibility='public')
    old_bytes = old.build()

    new = SyntheticAssembly('Demo')
    api = new.add_type('Demo', 'Api')
    new.add_method(api, 'Return', return_type='System.Int32')
    new.add_method(api, 'Hide', visibility='private')
    new_bytes = new.build()

    report = abi.audit_abi(old_bytes, new_bytes, entrypoints=['Demo.Api::Return', 'Demo.Api::Hide'])
    assert report[0].status == abi.AbiStatus.CHANGED
    assert any(change['kind'] == 'return_type' for change in report[0].changes)
    assert report[1].status == abi.AbiStatus.CHANGED
    assert report[1].changes[0]['kind'] == 'visibility'
    assert report[1].changes[0]['narrowed'] is True
    assert report[1].old_visibility == 'public'
    assert report[1].new_visibility == 'private'


def test_property_setter_visibility_change():
    def build(setter_visibility):
        builder = SyntheticAssembly('Demo')
        api = builder.add_type('Demo', 'Api')
        builder.add_property(
            api,
            'Name',
            return_type='System.String',
            getter=True,
            setter=True,
            getter_visibility='public',
            setter_visibility=setter_visibility,
        )
        return builder.build()

    report = abi.audit_abi(build('public'), build('private'), entrypoints=['Demo.Api::Name'])
    result = report[0]
    assert result.status == abi.AbiStatus.CHANGED
    assert result.changes[0]['kind'] == 'accessor_visibility'
    assert result.changes[0]['accessor'] == 'set'


def test_missing_signature_component_is_unresolved_until_approved_source_supplied():
    source = SyntheticAssembly('Gone')
    source.add_type('Lost', 'Type')
    source_bytes = source.build()

    def app():
        builder = SyntheticAssembly('App')
        api = builder.add_type('Demo', 'Api')
        builder.add_method(api, 'Missing', params=('[Gone]Lost.Type',))
        return builder.build()

    unresolved = abi.audit_abi(app(), app(), entrypoints=['Demo.Api::Missing'])
    result = unresolved[0]
    assert result.status == abi.AbiStatus.UNRESOLVED
    assert any('Gone' in str(missing) for missing in result.unresolved)
    assert result.status.value == 'unresolved'

    supported = abi.audit_abi(
        app(),
        app(),
        entrypoints=['Demo.Api::Missing'],
        approved_sources=[source_bytes],
    )
    assert supported[0].status == abi.AbiStatus.SUPPORTED


def test_inheritance_from_missing_component_is_unresolved():
    external = SyntheticAssembly('Lib')
    base = external.add_type('Demo', 'Base')
    external.add_method(base, 'Keep')
    external_bytes = external.build()

    def app():
        builder = SyntheticAssembly('App')
        builder.add_type('Demo', 'Derived', extends='[Lib]Demo.Base')
        return builder.build()

    unresolved = abi.audit_abi(app(), app(), entrypoints=['Demo.Derived::Keep'])
    result = unresolved[0]
    assert result.status == abi.AbiStatus.UNRESOLVED
    assert any('Lib' in str(missing) for missing in result.unresolved)

    supported = abi.audit_abi(
        app(),
        app(),
        entrypoints=['Demo.Derived::Keep'],
        approved_sources=[external_bytes],
    )
    result = supported[0]
    assert result.status == abi.AbiStatus.SUPPORTED
    assert result.inherited_from == ['Demo.Derived']


def test_type_visibility_and_base_contract():
    old = SyntheticAssembly('Demo')
    old.add_type('Demo', 'Api', visibility='public')
    old_bytes = old.build()

    new = SyntheticAssembly('Demo')
    new.add_type('Demo', 'Api', visibility='internal')
    new_bytes = new.build()

    report = abi.audit_abi(old_bytes, new_bytes, entrypoints=['Demo.Api'])
    result = report[0]
    assert result.status == abi.AbiStatus.CHANGED
    assert result.old_visibility == 'public'
    assert result.new_visibility == 'internal'

    def with_missing_base():
        builder = SyntheticAssembly('App')
        builder.add_type('Demo', 'Derived', extends='[Gone]Missing.Base')
        return builder.build()

    unresolved = abi.audit_abi(with_missing_base(), with_missing_base(), entrypoints=['Demo.Derived'])
    assert unresolved[0].status == abi.AbiStatus.UNRESOLVED
    assert 'Gone' in str(unresolved[0].unresolved[0])

    approved = abi.audit_abi(
        with_missing_base(),
        with_missing_base(),
        entrypoints=['Demo.Derived'],
        approved_sources=['Gone'],
    )
    assert approved[0].status == abi.AbiStatus.SUPPORTED


def test_entry_forms_and_report_json():
    builder = SyntheticAssembly('Demo')
    api = builder.add_type('Demo', 'Api')
    builder.add_method(api, 'Run')
    data = builder.build()

    report = abi.audit_abi(
        data,
        data,
        entrypoints=[
            'Demo.Api',
            {'type': 'Demo.Api', 'member': 'Run'},
            ('Demo.Api', 'Run', 'method'),
        ],
        approved_sources=['mscorlib'],
    )
    assert len(report) == 3
    assert all(result.status == abi.AbiStatus.SUPPORTED for result in report)
    assert report.by_name('Demo.Api::Run') is report[1]
    payload = json.loads(report.to_json())
    assert payload['counts']['supported'] == 3
    assert payload['supported'][0]['status'] == 'supported'
