import hashlib

import pytest

import pefile

from _synthetic_pe import (
    ENGLISH_UK,
    ENGLISH_US,
    FRENCH_FRANCE,
    NEUTRAL,
    build_pe,
    build_pe_file,
    lcid,
)


RT_LICENSE = pefile.RESOURCE_TYPE["RT_RCDATA"]
RT_HTML = pefile.RESOURCE_TYPE["RT_HTML"]
LICENSE_ID = 101


def leaf_by_lcid(issue, value):
    candidates = [leaf for leaf in issue.matched if leaf.lcid == value]
    assert len(candidates) == 1
    return candidates[0]


@pytest.fixture
def license_pe(tmp_path):
    path = tmp_path / "licenses.dll"
    build_pe_file(
        path,
        {
            RT_LICENSE: {
                LICENSE_ID: {
                    NEUTRAL: b"license-neutral-v1",
                    ENGLISH_US: b"license-en-us-v1",
                    ENGLISH_UK: b"license-en-gb-v1",
                    FRENCH_FRANCE: b"license-fr-fr-v1",
                }
            }
        },
    )
    return path


def test_requested_language_wins_earlier(license_pe):
    pe = pefile.PE(str(license_pe))
    result = pe.verify_resources(
        [lcid(ENGLISH_US), lcid(ENGLISH_UK), lcid(NEUTRAL)]
    )
    issue = result.by_type[RT_LICENSE][0]
    assert leaf_by_lcid(issue, lcid(ENGLISH_US)).content == b"license-en-us-v1"
    assert [leaf.lcid for leaf in issue.matched] == [lcid(ENGLISH_US)]


def test_order_decides_which_language_matches(license_pe):
    pe = pefile.PE(str(license_pe))
    result = pe.verify_resources(
        [lcid(ENGLISH_UK), lcid(ENGLISH_US), lcid(NEUTRAL)]
    )
    issue = result.by_type[RT_LICENSE][0]
    assert leaf_by_lcid(issue, lcid(ENGLISH_UK)).content == b"license-en-gb-v1"
    assert [leaf.lcid for leaf in issue.matched] == [lcid(ENGLISH_UK)]


def test_first_available_in_order_is_selected(license_pe):
    pe = pefile.PE(str(license_pe))
    result = pe.verify_resources(
        [lcid(FRENCH_FRANCE), lcid(ENGLISH_US), lcid(NEUTRAL)]
    )
    issue = result.by_type[RT_LICENSE][0]
    assert [leaf.lcid for leaf in issue.matched] == [lcid(FRENCH_FRANCE)]
    assert leaf_by_lcid(issue, lcid(FRENCH_FRANCE)).content == b"license-fr-fr-v1"


def test_neutral_fallback_is_explicitly_reported(license_pe):
    pe = pefile.PE(str(license_pe))
    german_germany = (0x07, 0x01)
    result = pe.verify_resources(
        [lcid(german_germany), lcid(NEUTRAL)]
    )
    issue = result.by_type[RT_LICENSE][0]
    assert [leaf.lcid for leaf in issue.matched] == [lcid(NEUTRAL)]
    assert leaf_by_lcid(issue, lcid(NEUTRAL)).content == b"license-neutral-v1"


def test_no_matching_language_reports_unmatched(license_pe):
    pe = pefile.PE(str(license_pe))
    japanese_japan = (0x11, 0x01)
    result = pe.verify_resources([lcid(japanese_japan)])
    issue = result.by_type[RT_LICENSE][0]
    assert issue.matched == []
    assert issue.unmatched is True


def test_equally_preferred_duplicates_list_all_candidates(tmp_path):
    path = tmp_path / "duplicates.dll"
    build_pe_file(
        path,
        {
            RT_LICENSE: {
                LICENSE_ID: {
                    ENGLISH_US: [b"candidate-a", b"candidate-b"],
                    NEUTRAL: b"neutral",
                }
            }
        },
    )
    pe = pefile.PE(str(path))
    result = pe.verify_resources([lcid(ENGLISH_US), lcid(NEUTRAL)])
    issue = result.by_type[RT_LICENSE][0]
    assert len(issue.matched) == 2
    assert {leaf.content for leaf in issue.matched} == {b"candidate-a", b"candidate-b"}
    assert len({leaf.content_hash for leaf in issue.matched}) == 2
    assert all(leaf.lcid == lcid(ENGLISH_US) for leaf in issue.matched)


def test_unknown_language_selector_is_not_guessed(license_pe):
    pe = pefile.PE(str(license_pe))
    with pytest.raises(pefile.ResourceSelectorError):
        pe.verify_resources([{"locale": "en-US"}])
    with pytest.raises(pefile.ResourceSelectorError):
        pe.verify_resources(["en-US"])
    with pytest.raises(pefile.ResourceSelectorError):
        pe.verify_resources([(1, 2, 3)])
    with pytest.raises(pefile.ResourceSelectorError):
        pe.verify_resources([0x10000])


def test_resource_type_filtering(tmp_path):
    path = tmp_path / "two_types.dll"
    build_pe_file(
        path,
        {
            RT_LICENSE: {LICENSE_ID: {ENGLISH_US: b"license"}},
            RT_HTML: {202: {ENGLISH_US: b"<html/>"}},
        },
    )
    pe = pefile.PE(str(path))
    result = pe.verify_resources(
        [lcid(ENGLISH_US)], resource_types=RT_HTML
    )
    assert list(result.by_type) == [RT_HTML]
    assert result.by_type[RT_HTML][0].type == RT_HTML
    by_name = pe.verify_resources([lcid(ENGLISH_US)], resource_types="RT_RCDATA")
    assert list(by_name.by_type) == [RT_LICENSE]


def test_none_resource_type_verifies_everything(tmp_path):
    path = tmp_path / "two_types.dll"
    build_pe_file(
        path,
        {
            RT_LICENSE: {LICENSE_ID: {ENGLISH_US: b"license"}},
            RT_HTML: {202: {ENGLISH_US: b"<html/>"}},
        },
    )
    pe = pefile.PE(str(path))
    result = pe.verify_resources([lcid(ENGLISH_US)])
    assert set(result.by_type) == {RT_LICENSE, RT_HTML}


def test_content_identity_and_independent_raw_byte_location(license_pe):
    raw = license_pe.read_bytes()  # Path.read_bytes
    pe = pefile.PE(str(license_pe))
    result = pe.verify_resources(
        [lcid(ENGLISH_US), lcid(NEUTRAL)]
    )
    issue = result.by_type[RT_LICENSE][0]
    leaf = leaf_by_lcid(issue, lcid(ENGLISH_US))
    expected_hash = hashlib.sha256(b"license-en-us-v1").hexdigest()
    assert leaf.content_hash == expected_hash
    assert leaf.raw_bytes_verifiable is True
    independently_located = raw[leaf.file_offset : leaf.file_offset + leaf.size]
    assert independently_located == leaf.content
    assert hashlib.sha256(independently_located).hexdigest() == expected_hash


def test_each_leaf_is_independently_locatable(license_pe):
    raw = license_pe.read_bytes()  # Path.read_bytes
    pe = pefile.PE(str(license_pe))
    result = pe.verify_resources(
        [lcid(ENGLISH_US), lcid(ENGLISH_UK), lcid(FRENCH_FRANCE), lcid(NEUTRAL)]
    )
    issue = result.by_type[RT_LICENSE][0]
    for leaf in issue.matched:
        assert raw[leaf.file_offset : leaf.file_offset + leaf.size] == leaf.content
        assert leaf.raw_bytes_verifiable is True
    assert result.issues == []


def _build_licenses(path, neutral_text):
    build_pe_file(
        path,
        {
            RT_LICENSE: {
                LICENSE_ID: {
                    NEUTRAL: neutral_text,
                    ENGLISH_US: b"license-en-us",
                    ENGLISH_UK: b"license-en-gb",
                }
            }
        },
    )


def _leaf_identity(pe, target_lcid):
    result = pe.verify_resources([lcid(target_lcid), lcid(NEUTRAL)])
    issue = result.by_type[RT_LICENSE][0]
    return issue.matched[0].content_hash


def test_two_layer_fallback_signoff_after_default_change(tmp_path):
    # Two builds share the explicit en-US/en-GB leaves but the neutral
    # fallback, which is the last resort for locales without their own
    # resource, changes between v1 and v2.
    v1_path = tmp_path / "licenses-v1.dll"
    v2_path = tmp_path / "licenses-v2.dll"
    _build_licenses(v1_path, b"license-neutral-v1")
    _build_licenses(v2_path, b"license-neutral-v2")

    v1 = pefile.PE(str(v1_path))
    v2 = pefile.PE(str(v2_path))

    german_germany = (0x07, 0x01)
    japanese_japan = (0x11, 0x01)

    # Locales served by their own explicit leaves keep identical content.
    assert _leaf_identity(v1, ENGLISH_US) == _leaf_identity(v2, ENGLISH_US)
    assert _leaf_identity(v1, ENGLISH_UK) == _leaf_identity(v2, ENGLISH_UK)

    # Locales that resolve through the two fallback layers (no own leaf,
    # then neutral) get different content and must be re-signed-off.
    assert _leaf_identity(v1, german_germany) != _leaf_identity(v2, german_germany)
    assert _leaf_identity(v1, japanese_japan) != _leaf_identity(v2, japanese_japan)

    # The verifier proves the change is the neutral fallback leaf itself.
    neutral_v1 = leaf_by_lcid(
        v1.verify_resources([lcid(NEUTRAL)]).by_type[RT_LICENSE][0], lcid(NEUTRAL)
    )
    neutral_v2 = leaf_by_lcid(
        v2.verify_resources([lcid(NEUTRAL)]).by_type[RT_LICENSE][0], lcid(NEUTRAL)
    )
    assert neutral_v1.content == b"license-neutral-v1"
    assert neutral_v2.content == b"license-neutral-v2"
    assert neutral_v1.content_hash != neutral_v2.content_hash


def test_primary_language_wildcard_matches_all_sublanguages(tmp_path):
    path = tmp_path / "wildcard.dll"
    build_pe_file(
        path,
        {
            RT_LICENSE: {
                LICENSE_ID: {
                    ENGLISH_US: b"us",
                    ENGLISH_UK: b"gb",
                }
            }
        },
    )
    pe = pefile.PE(str(path))
    # A bare primary-language id carries sublanguage 0, so use the LANG name
    # form to request every English sublanguage at equal priority.
    result = pe.verify_resources(["LANG_ENGLISH"], resource_types=RT_LICENSE)
    issue = result.by_type[RT_LICENSE][0]
    assert len(issue.matched) == 2
    assert {leaf.sublang for leaf in issue.matched} == {1, 2}
    assert {leaf.content for leaf in issue.matched} == {b"us", b"gb"}


def test_named_language_selector_unknown_is_rejected(license_pe):
    pe = pefile.PE(str(license_pe))
    with pytest.raises(pefile.ResourceSelectorError):
        pe.verify_resources(["LANG_KLINGON"])


def test_alternate_hash_algorithm(license_pe):
    pe = pefile.PE(str(license_pe))
    result = pe.verify_resources(
        [lcid(ENGLISH_US)],
        resource_types=RT_LICENSE,
        hash_algorithm=hashlib.md5,
    )
    leaf = result.by_type[RT_LICENSE][0].matched[0]
    assert leaf.content_hash_algorithm == "md5"
    assert leaf.content_hash == hashlib.md5(b"license-en-us-v1").hexdigest()


def test_multiple_resource_names_are_reported_separately(tmp_path):
    path = tmp_path / "multi.dll"
    build_pe_file(
        path,
        {
            RT_LICENSE: {
                101: {ENGLISH_US: b"first"},
                202: {ENGLISH_US: b"second"},
            }
        },
    )
    pe = pefile.PE(str(path))
    result = pe.verify_resources([lcid(ENGLISH_US)], resource_types=RT_LICENSE)
    issues = result.by_type[RT_LICENSE]
    assert [issue.name for issue in issues] == [101, 202]
    assert [issue.matched[0].content for issue in issues] == [b"first", b"second"]


def test_absent_resource_type_returns_empty_report(tmp_path):
    path = tmp_path / "one.dll"
    build_pe_file(path, {RT_LICENSE: {101: {ENGLISH_US: b"x"}}})
    pe = pefile.PE(str(path))
    result = pe.verify_resources([lcid(ENGLISH_US)], resource_types=RT_HTML)
    assert result.results == []
    assert result.by_type == {}
    assert result.issues == []


def test_resource_types_accepts_a_single_scalar(license_pe):
    pe = pefile.PE(str(license_pe))
    result = pe.verify_resources([lcid(ENGLISH_US)], resource_types=RT_LICENSE)
    assert list(result.by_type) == [RT_LICENSE]


def test_non_locatable_leaf_is_reported_as_issue():
    image = bytearray(
        build_pe({RT_LICENSE: {LICENSE_ID: {ENGLISH_US: b"license-bytes"}}})
    )
    pe = pefile.PE(data=bytes(image))
    data_entry = (
        pe.DIRECTORY_ENTRY_RESOURCE.entries[0]
        .directory.entries[0]
        .directory.entries[0]
        .data.struct
    )
    original_size = data_entry.Size
    # Claim more bytes than the section actually holds; the independent
    # on-disk location can no longer satisfy the data entry.
    data_entry.Size = original_size + 0x1000
    result = pe.verify_resources([lcid(ENGLISH_US)], resource_types=RT_LICENSE)
    issue = result.by_type[RT_LICENSE][0].issue
    assert issue is not None
    assert result.issues == [issue]
    leaf = issue.leaf
    assert leaf.raw_bytes_verifiable is False
    assert leaf.file_offset is None
    assert leaf.content_hash is None


def test_pe_without_resources_raises_selector_error():
    # A fast_load image never parses the resource directory, so there is no
    # parsed resource tree to verify.
    image = build_pe({RT_LICENSE: {101: {ENGLISH_US: b"x"}}})
    pe = pefile.PE(data=image, fast_load=True)
    assert not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")
    with pytest.raises(pefile.ResourceSelectorError):
        pe.verify_resources([lcid(ENGLISH_US)])
