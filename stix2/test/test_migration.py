import copy
import random
import uuid

import stix2


def _observation(objects, name="obs"):
    return {
        "type": "observed-data",
        "id": "observed-data--{}".format(uuid.uuid5(uuid.NAMESPACE_URL, name)),
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "first_observed": "2020-01-01T00:00:00.000Z",
        "last_observed": "2020-01-01T00:00:00.000Z",
        "number_observed": 1,
        "objects": objects,
    }


def _file(name):
    return {"type": "file", "name": name}


def _dir(path, refs):
    return {"type": "directory", "path": path, "contains_refs": refs}


def test_local_zero_does_not_collide_across_observations():
    first = _observation(
        {"0": _file("first"), "1": _dir("/first", ["0"])}, "first",
    )
    second = _observation(
        {"0": _file("second"), "1": _dir("/second", ["0"])}, "second",
    )

    result = stix2.convert_observed_data([first, second])

    first_file = result.id_map[first["id"]]["0"]
    second_file = result.id_map[second["id"]]["0"]
    assert first_file != second_file

    by_id = result.object_map
    first_dir = by_id[result.id_map[first["id"]]["1"]]
    second_dir = by_id[result.id_map[second["id"]]["1"]]
    assert first_dir.contains_refs == [first_file]
    assert second_dir.contains_refs == [second_file]


def test_duplicate_content_gets_one_id_and_one_object():
    first = _observation(
        {"0": _file("same"), "1": _dir("/first", ["0"])}, "first",
    )
    second = _observation(
        {"0": _file("same"), "1": _dir("/second", ["0"])}, "second",
    )

    result = stix2.convert_observed_data([first, second])

    first_file = result.id_map[first["id"]]["0"]
    second_file = result.id_map[second["id"]]["0"]
    assert first_file == second_file
    assert len(
        [obj for obj in result.objects if obj["id"] == first_file]
    ) == 1


def test_unknown_custom_ref_is_preserved_and_reported():
    observation = _observation(
        {"0": {"type": "x-widget", "x_name": "widget", "x_foo_ref": "9"}},
        "custom-ref",
    )

    result = stix2.convert_observed_data(observation)

    converted = result.objects[0]
    assert converted["x_foo_ref"] == "9"

    diagnostic = result.unresolved[0]
    assert diagnostic.observed_data_id == observation["id"]
    assert diagnostic.local_id == "0"
    assert diagnostic.path == "x_foo_ref"
    assert diagnostic.value == "9"
    assert diagnostic.custom
    assert diagnostic.preserved
    assert diagnostic["observation_id"] == observation["id"]


def test_unknown_standard_ref_is_dropped_and_reported():
    observation = _observation(
        {"0": _dir("/missing", ["9"])}, "missing-ref",
    )

    result = stix2.convert_observed_data(observation)

    converted = result.objects[0]
    assert "contains_refs" not in converted
    assert result.unresolved[0].path == "contains_refs[0]"
    assert not result.unresolved[0].custom
    assert not result.unresolved[0].preserved


def test_forward_reference_and_shuffled_input_are_stable():
    objects = {
        "0": {
            "type": "file",
            "name": "nested",
            "parent_directory_ref": "1",
        },
        "1": {
            "type": "directory",
            "path": "/parent",
        },
    }
    observations = [
        _observation(objects, "first"),
        _observation(
            {
                "0": _dir("/first", ["1"]),
                "1": _file("first"),
            },
            "second",
        ),
    ]

    baseline = stix2.convert_observed_data(copy.deepcopy(observations))

    for seed in range(10):
        shuffled = copy.deepcopy(observations)
        random.Random(seed).shuffle(shuffled)
        for observation in shuffled:
            items = list(observation["objects"].items())
            random.Random(seed).shuffle(items)
            observation["objects"] = dict(items)

        result = stix2.convert_observed_data(shuffled)
        assert result.id_map.to_dict() == baseline.id_map.to_dict()

        for object_id, obj in result.object_map.items():
            assert baseline.object_map[object_id] == obj


def test_observed_data_is_rewritten_to_object_refs():
    observation = _observation(
        {"0": _file("first"), "1": _dir("/first", ["0"])}, "refs",
    )

    result = stix2.convert_observed_data(observation)

    observed_data = result.observed_data[0]
    assert "objects" not in observed_data
    assert observed_data.spec_version == "2.1"
    assert observed_data.object_refs == [
        result.id_map[observation["id"]]["0"],
        result.id_map[observation["id"]]["1"],
    ]


def test_conversion_result_unpacks_and_exposes_mapping():
    observation = _observation({"0": _file("first")}, "unpack")
    objects, id_map = stix2.convert_observed_data(observation)

    assert objects[0]["id"] == id_map[observation["id"]]["0"]
    assert id_map["0"] == objects[0]["id"]
    assert id_map[(observation["id"], "0")] == objects[0]["id"]


def test_existing_21_observed_data_is_left_untouched():
    observation = stix2.v21.ObservedData(
        id="observed-data--{}".format(uuid.uuid4()),
        first_observed="2020-01-01T00:00:00.000Z",
        last_observed="2020-01-01T00:00:00.000Z",
        number_observed=1,
        object_refs=["file--{}".format(uuid.uuid4())],
    )

    result = stix2.convert_observed_data(observation)

    assert result.objects == []
    assert result.passthrough[0]["id"] == observation.id


def test_untranslatable_object_points_to_source_observation():
    observation = _observation({"0": "not-an-object"}, "bad-object")

    result = stix2.convert_observed_data(observation)

    assert result.objects == []
    assert result.observed_data[0]["object_refs"] == []
    diagnostic = result.unresolved[0]
    assert diagnostic.kind == "untranslatable-object"
    assert diagnostic.source_observation["id"] == observation["id"]
    assert diagnostic.to_dict()["local_id"] == "0"


def test_known_custom_ref_is_rewritten_but_unknown_is_kept():
    observation = _observation(
        {
            "0": {
                "type": "x-widget",
                "x_parent_ref": "1",
                "x_missing_ref": "9",
            },
            "1": {"type": "x-widget", "x_name": "parent"},
        },
        "custom-known-ref",
    )

    result = stix2.convert_observed_data(observation)
    root = result.object_map[result.id_map[observation["id"]]["0"]]

    assert root["x_parent_ref"] == result.id_map[observation["id"]]["1"]
    assert root["x_missing_ref"] == "9"
    assert len(result.unresolved) == 1
    assert result.unresolved[0].path == "x_missing_ref"
