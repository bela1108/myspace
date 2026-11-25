from cpe.cpe2_3_fs import CPE2_3_FS
from cpe.cpe2_3_wfn import CPE2_3_WFN

ATTRIBUTES = (
    "part", "vendor", "product", "version", "update", "edition",
    "language", "sw_edition", "target_sw", "target_hw", "other",
)

ADVISORY_FS = "cpe:2.3:a:nightjarlabs:paperlantern:2.4.1:*:*:*:*:linux:*:*"

HIT_WFN = (
    'wfn:[part="a", vendor="nightjarlabs", product="paperlantern", '
    'version="2\\.4\\.1", update="ga", edition="team", '
    'language="en\\-us", sw_edition="team", target_sw="linux", '
    'target_hw="x86_64", other="audit"]'
)
HIT_FS = (
    "cpe:2.3:a:nightjarlabs:paperlantern:2.4.1:ga:team:en-us:team:"
    "linux:x86_64:audit"
)

MISSING_ENV_WFN = (
    'wfn:[part="a", vendor="nightjarlabs", product="paperlantern", '
    'version="2\\.4\\.1", update="ga", edition="team", '
    'language="en\\-us", sw_edition=ANY, target_hw=ANY, other=ANY]'
)
MISSING_ENV_FS = (
    "cpe:2.3:a:nightjarlabs:paperlantern:2.4.1:ga:team:en-us:*:*:*:*"
)

# Manually confirmed matches against ADVISORY_FS.  The missing-environment
# asset intentionally has no target_sw entry: the reviewer did not collect it.
HIT_MANUAL_MATCHES = {
    "part": "a",
    "vendor": "nightjarlabs",
    "product": "paperlantern",
    "version": "2.4.1",
    "target_sw": "linux",
}
CORE_MANUAL_MATCHES = {
    "part": "a",
    "vendor": "nightjarlabs",
    "product": "paperlantern",
    "version": "2.4.1",
}
OBSERVED_BEFORE_ENV_GAP = {
    "update": "ga",
    "edition": "team",
    "language": "en-us",
}


def fs_fields(cpe_name):
    pieces = cpe_name.as_fs().split(":")
    assert len(pieces) == 13
    return dict(zip(ATTRIBUTES, pieces[2:]))


def test_hit_asset_manual_matches_survive_round_trip():
    advisory = CPE2_3_FS(ADVISORY_FS)
    hit_from_wfn = CPE2_3_WFN(HIT_WFN)
    hit_from_fs = CPE2_3_FS(HIT_FS)

    assert hit_from_wfn.as_fs() == HIT_FS
    assert hit_from_fs.as_wfn() == hit_from_wfn.as_wfn()

    round_tripped = CPE2_3_WFN(CPE2_3_FS(hit_from_wfn.as_fs()).as_wfn())
    fields = fs_fields(round_tripped)
    advisory_fields = fs_fields(advisory)

    for attribute, value in HIT_MANUAL_MATCHES.items():
        assert fields[attribute] == value
        assert advisory_fields[attribute] == value

    for attribute, value in fields.items():
        assert fs_fields(hit_from_fs)[attribute] == value


def test_missing_environment_is_not_proven_by_wildcard_round_trip():
    inventory_record = {"asset_id": "asset-2402", "target_sw": None,
                        "target_sw_status": "not_collected"}
    original = CPE2_3_WFN(MISSING_ENV_WFN)

    assert "target_sw" not in original.as_wfn()

    original_fields = fs_fields(original)
    for attribute, value in CORE_MANUAL_MATCHES.items():
        assert original_fields[attribute] == value
    for attribute, value in OBSERVED_BEFORE_ENV_GAP.items():
        assert original_fields[attribute] == value
    assert original_fields["target_sw"] == "*"

    converted_fs = CPE2_3_FS(original.as_fs())
    assert converted_fs.as_fs() == MISSING_ENV_FS

    round_tripped = CPE2_3_WFN(converted_fs.as_wfn())
    assert "target_sw=ANY" in round_tripped.as_wfn()

    retained_fields = fs_fields(round_tripped)
    for attribute, value in CORE_MANUAL_MATCHES.items():
        assert retained_fields[attribute] == value
    for attribute, value in OBSERVED_BEFORE_ENV_GAP.items():
        assert retained_fields[attribute] == value
    assert retained_fields["target_sw"] == "*"

    # The public accessor normalizes omission and explicit ANY alike, so it
    # cannot establish whether the environment was observed or collected.
    assert original.get_attribute_values("target_sw") == ["ANY"]
    assert round_tripped.get_attribute_values("target_sw") == ["ANY"]
    assert inventory_record["target_sw"] is None
    assert inventory_record["target_sw_status"] == "not_collected"


def test_fs_wildcard_does_not_encode_not_collected_status():
    fs_original = CPE2_3_FS(MISSING_ENV_FS)
    inventory_record = {"target_sw_status": "not_collected"}

    round_tripped = CPE2_3_FS(CPE2_3_WFN(fs_original.as_wfn()).as_fs())
    assert round_tripped.as_fs() == MISSING_ENV_FS
    assert inventory_record["target_sw_status"] == "not_collected"
