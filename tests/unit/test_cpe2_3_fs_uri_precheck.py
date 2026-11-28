from cpe.comp.cpecomp import CPEComponent
from cpe.cpe2_3_fs import (
    CPE2_3_FS,
    precheck_uri_conversion,
    uri_conversion_precheck,
)


def _field(result, attribute):
    return next(
        field for field in result["fields"]
        if field["attribute"] == attribute
    )


def test_any_and_not_applicable_remain_distinct_and_roundtrippable():
    fs = "cpe:2.3:a:vendor:product:1.0:-:*:*:*:*:*:*"
    result = CPE2_3_FS(fs).uri_conversion_precheck()

    assert result["uri"] == "cpe:/a:vendor:product:1.0:-"
    assert result["roundtrippable"] is True
    assert result["parseable_uri"] is True

    update = _field(result, CPEComponent.ATT_UPDATE)
    assert update["source"] == "-"
    assert update["target"] == "-"
    assert update["roundtripped"] == "-"
    assert update["status"] == CPE2_3_FS.URI_CHECK_EQUIVALENT
    assert update["roundtrippable"] is True
    assert update["logical"] == "not_applicable"

    edition = _field(result, CPEComponent.ATT_EDITION)
    assert edition["source"] == "*"
    assert edition["target"] == ""
    assert edition["roundtripped"] == "*"
    assert edition["status"] == CPE2_3_FS.URI_CHECK_EQUIVALENT
    assert edition["roundtrippable"] is True
    assert edition["logical"] == "any"


def test_escaped_hyphen_normalization_is_semantic_loss():
    fs = r"cpe:2.3:a:vendor:product:1.0:a\-b:*:*:*:*:*:*"
    result = CPE2_3_FS(fs).uri_conversion_precheck()
    field = _field(result, CPEComponent.ATT_UPDATE)

    assert result["roundtrippable"] is False
    assert result["lossy_fields"] == [CPEComponent.ATT_UPDATE]
    assert result["inexpressible_fields"] == []
    assert field["source"] == r"a\-b"
    assert field["target"] == "a-b"
    assert field["roundtripped"] == "a-b"
    assert field["status"] == CPE2_3_FS.URI_CHECK_LOSSY
    assert field["roundtrippable"] is False


def test_unquoted_edition_punctuation_normalization_is_semantic_loss():
    fs = "cpe:2.3:a:vendor:product:1.0:*:a!b:*:*:*:*:*"
    result = CPE2_3_FS(fs).uri_conversion_precheck()
    field = _field(result, CPEComponent.ATT_EDITION)

    assert result["roundtrippable"] is False
    assert result["lossy_fields"] == [CPEComponent.ATT_EDITION]
    assert field["source"] == "a!b"
    assert field["target"] == "a%21b"
    assert field["roundtripped"] == r"a\!b"
    assert field["status"] == CPE2_3_FS.URI_CHECK_LOSSY
    assert field["roundtrippable"] is False


def test_literal_hyphen_colliding_with_not_applicable_is_inexpressible():
    fs = r"cpe:2.3:a:vendor:product:1.0:\-:*:*:*:*:*:*"
    result = CPE2_3_FS(fs).uri_conversion_precheck()
    field = _field(result, CPEComponent.ATT_UPDATE)

    assert result["roundtrippable"] is False
    assert result["lossy_fields"] == []
    assert result["inexpressible_fields"] == [CPEComponent.ATT_UPDATE]
    assert field["source"] == r"\-"
    assert field["target"] == "-"
    assert field["roundtripped"] == "-"
    assert field["status"] == CPE2_3_FS.URI_CHECK_INEXPRESSIBLE
    assert field["roundtrippable"] is False
    assert field["reason"] == "literal_hyphen_collides_with_not_applicable"


def test_wildcard_only_value_is_inexpressible_in_uri():
    fs = "cpe:2.3:a:vendor:product:1.0:??:*:*:*:*:*:*"
    result = CPE2_3_FS(fs).uri_conversion_precheck()
    field = _field(result, CPEComponent.ATT_UPDATE)

    assert result["roundtrippable"] is False
    assert result["parseable_uri"] is False
    assert result["lossy_fields"] == []
    assert result["inexpressible_fields"] == [CPEComponent.ATT_UPDATE]
    assert field["source"] == "??"
    assert field["target"] == "%01%01"
    assert field["roundtripped"] is None
    assert field["status"] == CPE2_3_FS.URI_CHECK_INEXPRESSIBLE
    assert field["roundtrippable"] is False
    assert field["reason"] == "wildcard_only_value_is_not_expressible_in_uri"


def test_value_that_breaks_existing_uri_encoder_is_inexpressible():
    fs = r"cpe:2.3:a:vendor:product:1.0:*:a:*:*:*:*:*"
    result = CPE2_3_FS(fs).uri_conversion_precheck()
    field = _field(result, CPEComponent.ATT_EDITION)

    assert result["uri"] is None
    assert result["parseable_uri"] is False
    assert result["conversion_error"] is True
    assert result["inexpressible_fields"] == [CPEComponent.ATT_EDITION]
    assert result["equivalent_fields"] == []
    assert CPEComponent.ATT_VENDOR in result["lossy_fields"]
    assert field["target"] is None
    assert field["roundtripped"] is None
    assert field["status"] == CPE2_3_FS.URI_CHECK_INEXPRESSIBLE


def test_packed_edition_fields_are_checked_individually():
    fs = r"cpe:2.3:a:vendor:product:1.0:*:*:*:\-:*:*:*"
    result = CPE2_3_FS(fs).uri_conversion_precheck()
    field = _field(result, CPEComponent.ATT_SW_EDITION)

    assert result["uri"] == "cpe:/a:vendor:product:1.0::~~-~~~"
    assert result["inexpressible_fields"] == [CPEComponent.ATT_SW_EDITION]
    assert field["target"] == "-"
    assert field["roundtripped"] == "-"
    assert field["status"] == CPE2_3_FS.URI_CHECK_INEXPRESSIBLE


def test_existing_uri_conversion_still_returns_a_uri():
    fs = r"cpe:2.3:a:vendor:product:1.0:\-:*:*:*:*:*:*"
    cpe = CPE2_3_FS(fs)

    assert cpe.as_uri_2_3() == "cpe:/a:vendor:product:1.0:-"


def test_module_level_precheck_uses_the_same_field_result():
    cpe = CPE2_3_FS("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

    assert uri_conversion_precheck(cpe) == cpe.uri_conversion_precheck()
    assert precheck_uri_conversion(cpe) == cpe.precheck_uri_conversion()
