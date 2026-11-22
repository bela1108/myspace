import importlib.util
from pathlib import Path

import dnfile

import security_fixture
from dnfile.customattributes import analyze_custom_attributes


def _load_example():
    path = Path(__file__).parent.parent / "examples" / "custom-attribute-attribution.py"
    spec = importlib.util.spec_from_file_location("attribute_report", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_three_attribution_paths_and_offsets(tmp_path):
    sample = security_fixture.write_security_fixture(tmp_path / "security-fixture.dll")
    before = sample.read_bytes()
    pe = dnfile.dnPE(str(sample))
    records = analyze_custom_attributes(pe)
    after = sample.read_bytes()

    assert records
    assert [record.comparison for record in records] == [
        "assembly", "member_only", "insufficient"
    ]
    assert before == after

    assembly_record, member_record, unresolved_record = records
    assert assembly_record.parent.table == "Assembly"
    assert assembly_record.parent.token == 0x20000001
    assert assembly_record.constructor.owner is not None
    assert assembly_record.constructor.owner.assembly is not None
    assert assembly_record.constructor.owner.assembly.name == "Shared.Security"

    assert member_record.parent.table == "MethodDef"
    assert member_record.parent.token == 0x06000001
    assert member_record.parent.owner is not None
    assert member_record.parent.owner.display_name == "Fixture.MarkerHost"
    assert member_record.constructor.owner is not None
    assert member_record.constructor.owner.assembly is not None
    assert member_record.constructor.owner.assembly.name == "Vendor.Security"
    assert assembly_record.constructor.owner.identity_key != member_record.constructor.owner.identity_key

    assert unresolved_record.constructor.owner is not None
    assert unresolved_record.constructor.owner.assembly is None
    assert unresolved_record.constructor.owner.resolution_chain[-1].startswith("ModuleRef[1]")
    assert len(unresolved_record.blob.arguments) == 1
    assert unresolved_record.blob.arguments[0].value == "maybe"
    assert not unresolved_record.blob.complete
    assert unresolved_record.blob.error_offset == 8
    assert unresolved_record.blob.error_file_offset == unresolved_record.blob.payload_file_offset + 8


def test_parameter_offsets_and_named_arguments(tmp_path):
    sample = security_fixture.write_security_fixture(tmp_path / "security-fixture.dll")
    pe = dnfile.dnPE(str(sample))
    records = analyze_custom_attributes(pe)
    blob = records[0].blob
    fixed_string = blob.arguments[0]
    fixed_bool = blob.arguments[1]
    named = blob.arguments[2]

    assert blob.complete
    assert blob.prolog_hex == "0100"
    assert fixed_string.value == "assembly"
    assert fixed_string.blob_offset == 2
    assert fixed_string.file_offset == blob.payload_file_offset + 2
    assert fixed_bool.value is True
    assert named.name == "Level"
    assert named.value == 7
    assert named.end_blob_offset - named.blob_offset == len(bytes.fromhex(named.raw_hex))


def test_report_has_three_sections_and_separate_assemblies(tmp_path):
    sample = security_fixture.write_security_fixture(tmp_path / "security-fixture.dll")
    pe = dnfile.dnPE(str(sample))
    records = analyze_custom_attributes(pe)
    report = _load_example().render_markdown(records, "security-fixture.dll")

    assert "## 1. 标记挂在程序集上" in report
    assert "## 2. 只挂在成员上" in report
    assert "## 3. 一条引用不足以证明归属" in report
    assert "Shared.Security" in report
    assert "Vendor.Security" in report
    assert "0x0c000001" in report
    assert "0x0c000003" in report
    assert "raw offsets are retained" in report
