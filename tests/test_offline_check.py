import struct
import unittest
import uuid as uuidlib

import LnkParse3
from LnkParse3.extra.darwin import decode_darwin_descriptor
from LnkParse3.offline_check import verify_lnk_with_msi


BASE85 = "!$%&'()*+,-.0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{}~"
LNK_CLSID = "00021401-0000-0000-C000-000000000046"
PRODUCT = "11223344-5566-7788-99AA-BBCCDDEEFF00"
MACHINE_COMPONENT = "AAAAAAAA-1111-2222-3333-444444444444"
ALICE_COMPONENT = "BBBBBBBB-2222-3333-4444-555555555555"


def pack_quad(hex_quad):
    number = int(hex_quad, 16)
    chars = []
    for _ in range(5):
        number, remainder = divmod(number, 85)
        chars.append(BASE85[remainder])
    return "".join(chars)


def pack_guid(guid):
    value = guid.replace("-", "").upper()
    first_group = value[0:8]
    second_guid_group = value[8:12]
    third_guid_group = value[12:16]
    fourth_guid_group = value[16:20]
    fifth_guid_group = value[20:32]
    quads = (
        first_group
        + third_guid_group
        + second_guid_group
        + fifth_guid_group[2:4]
        + fifth_guid_group[0:2]
        + fourth_guid_group[2:4]
        + fourth_guid_group[0:2]
        + fifth_guid_group[10:12]
        + fifth_guid_group[8:10]
        + fifth_guid_group[6:8]
        + fifth_guid_group[4:6]
    )
    return "".join(pack_quad(quads[index:index + 8]) for index in range(0, 32, 8))


PRODUCT_PACKED = pack_guid(PRODUCT)
MACHINE_PACKED = pack_guid(MACHINE_COMPONENT)
ALICE_PACKED = pack_guid(ALICE_COMPONENT)


def darwin_block(ansi_descriptor, unicode_descriptor=None):
    if unicode_descriptor is None:
        unicode_descriptor = ansi_descriptor

    ansi_field = ansi_descriptor.encode("ascii") + b"\x00"
    ansi_field = ansi_field.ljust(260, b"\x00")[:260]

    unicode_field = unicode_descriptor.encode("utf-16le") + b"\x00\x00"
    unicode_field = unicode_field.ljust(520, b"\x00")[:520]

    return struct.pack("<II", 788, 0xA0000006) + ansi_field + unicode_field


def lnk_with_darwin(ansi_descriptor, unicode_descriptor=None):
    header = struct.pack("<I", 76)
    header += uuidlib.UUID(LNK_CLSID).bytes_le
    header += struct.pack("<II", 0x00001000, 0)
    header += b"\x00" * 24
    header += struct.pack("<IiiHHII", 0, 0, 1, 0, 0, 0, 0)
    return header + darwin_block(ansi_descriptor, unicode_descriptor)


def excerpt_fixture():
    return {
        "line_file": "MSI-registration.txt",
        "computers": [
            {
                "name": "WORKSTATION-01",
                "line": 2,
                "users": [
                    {
                        "name": "MACHINE",
                        "sid": "S-1-5-18",
                        "scope": "machine",
                        "line": 4,
                        "products": [
                            {
                                "product_code": PRODUCT,
                                "line": 6,
                                "features": [
                                    {
                                        "name": "CoreFeature",
                                        "line": 8,
                                        "state": "Installed",
                                        "components": [
                                            {
                                                "component_code": MACHINE_COMPONENT,
                                                "line": 10,
                                                "installed_path": r"C:\Program Files\Vendor\core.dll",
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "alice",
                        "sid": "S-1-5-21-111-1001",
                        "scope": "user",
                        "line": 14,
                        "products": [
                            {
                                "product_code": PRODUCT,
                                "line": 16,
                                "features": [
                                    {
                                        "name": "AliceFeature",
                                        "line": 18,
                                        "state": "Installed",
                                        "components": [
                                            {
                                                "component_code": ALICE_COMPONENT,
                                                "line": 20,
                                                "installed_path": r"C:\Users\alice\AppData\Local\Vendor\app.exe",
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "bob",
                        "sid": "S-1-5-21-111-1002",
                        "scope": "user",
                        "line": 24,
                        "products": [
                            {
                                "product_code": PRODUCT,
                                "line": 26,
                                "features": [
                                    {
                                        "name": "AdvertisedFeature",
                                        "line": 28,
                                        "state": "Advertised",
                                        "advertised": True,
                                        "components": [],
                                    }
                                ],
                            }
                        ],
                    },
                ],
            }
        ],
    }


class DarwinDescriptorTests(unittest.TestCase):
    def test_pack_test_helper_round_trips_through_existing_decoder(self):
        self.assertEqual(len(PRODUCT_PACKED), 20)
        decoded = decode_darwin_descriptor(PRODUCT_PACKED + "<")
        self.assertEqual(decoded["product_code_id"], PRODUCT)

    def test_four_descriptor_forms(self):
        forms = [
            (PRODUCT_PACKED + "CoreFeature>" + MACHINE_PACKED, 1, "CoreFeature", MACHINE_COMPONENT),
            (PRODUCT_PACKED + ">" + MACHINE_PACKED, 2, None, MACHINE_COMPONENT),
            (PRODUCT_PACKED + "AdvertisedFeature<", 3, "AdvertisedFeature", None),
            (PRODUCT_PACKED + "<", 4, None, None),
        ]

        for raw, number, feature, component in forms:
            with self.subTest(form=number):
                decoded = decode_darwin_descriptor(raw)
                self.assertIsNone(decoded["decode_error"])
                self.assertEqual(decoded["form_number"], number)
                self.assertEqual(decoded["product_code_id"], PRODUCT)
                self.assertEqual(decoded["feature_name"], feature)
                self.assertEqual(decoded["component_id"], component)
                self.assertEqual(decoded["has_feature"], feature is not None)
                self.assertEqual(decoded["has_component"], component is not None)

    def test_ansi_and_unicode_are_decoded_separately_by_lnkparse(self):
        raw = lnk_with_darwin(
            PRODUCT_PACKED + "CoreFeature>" + MACHINE_PACKED,
            PRODUCT_PACKED + ">" + ALICE_PACKED,
        )
        parsed = LnkParse3.lnk_file(indata=raw)
        darwin = parsed.extras.data[0]

        self.assertEqual(darwin.ansi_descriptor()["component_id"], MACHINE_COMPONENT)
        self.assertEqual(darwin.unicode_descriptor()["component_id"], ALICE_COMPONENT)


class OfflineCheckTests(unittest.TestCase):
    def test_conflicting_encodings_and_scopes_point_to_blocks_and_lines(self):
        raw = lnk_with_darwin(
            PRODUCT_PACKED + "CoreFeature>" + MACHINE_PACKED,
            PRODUCT_PACKED + ">" + ALICE_PACKED,
        )
        result = verify_lnk_with_msi(raw, excerpt_fixture(), user="alice")

        self.assertEqual(result["status"], "conflicting_darwin_claims")
        block = result["blocks"][0]
        self.assertTrue(block["conflicts"]["component_id"])
        self.assertEqual(block["offset"], 76)
        self.assertEqual(block["encodings"]["ansi"]["source"]["field_offset"], 84)
        self.assertEqual(block["encodings"]["unicode"]["source"]["field_offset"], 344)

        ansi = next(item for item in result["findings"] if item["encoding"] == "ansi")
        unicode_claim = next(item for item in result["findings"] if item["encoding"] == "unicode")
        self.assertEqual(ansi["component_id"], MACHINE_COMPONENT)
        self.assertEqual(unicode_claim["component_id"], ALICE_COMPONENT)
        self.assertEqual(
            ansi["registration_locators"], ["MSI-registration.txt:10"]
        )
        self.assertEqual(
            unicode_claim["registration_locators"], ["MSI-registration.txt:20"]
        )
        self.assertIn("offset=0x0000004c", ansi["block_locator"])
        self.assertIn("DarwinDataAnsi", ansi["block_locator"])
        self.assertIn("DarwinDataUnicode", unicode_claim["block_locator"])

    def test_alice_finds_installed_component_path(self):
        raw = lnk_with_darwin(
            PRODUCT_PACKED + "AliceFeature>" + ALICE_PACKED
        )
        result = verify_lnk_with_msi(raw, excerpt_fixture(), sid="S-1-5-21-111-1001")

        self.assertEqual(result["status"], "installed_component")
        self.assertTrue(result["installed"])
        self.assertEqual(
            result["installed_paths"],
            [r"C:\Users\alice\AppData\Local\Vendor\app.exe"],
        )
        self.assertEqual(result["findings"][0]["registration_locators"], ["MSI-registration.txt:20"])

    def test_bob_advertised_feature_has_no_installed_path(self):
        raw = lnk_with_darwin(PRODUCT_PACKED + "AdvertisedFeature<")
        result = verify_lnk_with_msi(raw, excerpt_fixture(), user="bob")

        self.assertEqual(result["status"], "advertised_feature_only")
        self.assertFalse(result["installed"])
        self.assertEqual(result["installed_paths"], [])
        finding = result["findings"][0]
        self.assertEqual(finding["classification"], "advertised_feature_only")
        self.assertEqual(finding["registration_locators"], ["MSI-registration.txt:28"])


if __name__ == "__main__":
    unittest.main()
