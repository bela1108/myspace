import base64
import json
import os
import unittest

from LnkParse3.excerpt import build_excerpt


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")


def sample_bytes(name):
    with open(os.path.join(SAMPLE_DIR, name), "rb") as handle:
        return base64.b64decode(handle.read())


class TestReadOnlyExcerpt(unittest.TestCase):
    def test_external_release_contains_only_display_text(self):
        excerpt = build_excerpt(sample_bytes("console_properties_block"), case_number="CASE-7")
        self.assertEqual(excerpt.external["case_number"], "CASE-7")
        self.assertEqual(
            excerpt.external["description"],
            "Performs object-based (command-line) functions",
        )
        self.assertNotIn("machine_identifier", excerpt.external)
        self.assertNotIn("leeholm16", json.dumps(excerpt.external))
        self.assertIn("machine_identifier", excerpt.fields)
        self.assertEqual(excerpt.fields["machine_identifier"]["category"], "device")

    def test_identical_text_is_disclosed_by_field_identity(self):
        data = bytearray(sample_bytes("console_properties_block"))
        baseline = build_excerpt(bytes(data), case_number="CASE-8")
        description = baseline.fields["description"]
        machine = baseline.fields["machine_identifier"]
        shared = "leeholm16"
        data[description["offset"] : description["offset"] + len(shared) * 2] = shared.encode(
            "utf-16le"
        )
        data[
            description["offset"] + len(shared) * 2 : description["offset"] + len(shared) * 2 + 2
        ] = b"\x00\x00"
        data[machine["offset"] : machine["offset"] + len(shared)] = shared.encode("cp1252")
        data[machine["offset"] + len(shared) : machine["offset"] + 16] = b"\x00" * (
            16 - len(shared)
        )

        excerpt = build_excerpt(bytes(data), case_number="CASE-8", display_label="Exhibit A")
        self.assertEqual(excerpt.fields["description"]["value"], shared)
        self.assertEqual(excerpt.fields["machine_identifier"]["value"], shared)
        self.assertEqual(excerpt.external["description"], shared)
        self.assertNotIn("machine_identifier", excerpt.external)
        self.assertEqual(
            sum(1 for value in excerpt.external.values() if value == shared),
            1,
        )

    def test_uncertain_decoding_is_never_released(self):
        excerpt = build_excerpt(
            sample_bytes("decoding_error4"),
            case_number="CASE-9",
            approved_fields=["common_path_suffix"],
        )
        self.assertNotIn("common_path_suffix", excerpt.external)
        withheld = [item for item in excerpt.withheld if item["field"] == "common_path_suffix"]
        self.assertEqual(withheld[0]["reason"], "uncertain_decoding")
        self.assertEqual(withheld[0]["decoding"], "replacement")

    def test_reported_spans_re_read_original_bytes(self):
        data = sample_bytes("network_info")
        excerpt = build_excerpt(data, case_number="CASE-10")
        self.assertTrue(excerpt.verify())
        self.assertTrue(all(item["matches"] for item in excerpt.verify()))
        net_name = excerpt.fields["net_name"]
        raw = data[net_name["offset"] : net_name["offset"] + net_name["length"]]
        self.assertEqual(raw.decode(net_name["encoding"]), net_name["value"])

    def test_target_text_requires_explicit_release_switch(self):
        excerpt = build_excerpt(
            sample_bytes("microsoft_example"),
            case_number="CASE-11",
            approved_fields=["relative_path"],
        )
        self.assertIn("relative_path", excerpt.fields)
        self.assertEqual(excerpt.fields["relative_path"]["disclosure"], True)
        self.assertEqual(excerpt.external["relative_path"], ".\\a.txt")

    def test_display_only_switch_blocks_approved_target_text(self):
        excerpt = build_excerpt(
            sample_bytes("microsoft_example"),
            case_number="CASE-11B",
            approved_fields=["relative_path"],
            external_only_display=True,
        )
        self.assertIn("relative_path", excerpt.fields)
        self.assertNotIn("relative_path", excerpt.external)

    def test_allow_non_display_fields_opt_in(self):
        excerpt = build_excerpt(
            sample_bytes("microsoft_example"),
            case_number="CASE-12",
            approved_fields=["relative_path"],
            allow_non_display_fields=True,
        )
        self.assertEqual(excerpt.external["relative_path"], ".\\a.txt")


if __name__ == "__main__":
    unittest.main()
