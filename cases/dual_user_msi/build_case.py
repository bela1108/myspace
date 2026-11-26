#!/usr/bin/env python3
"""Build the same-computer/two-user MSI offline-check case dossier."""

from __future__ import annotations

import json
import struct
import sys
import uuid as uuidlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from LnkParse3.offline_check import verify_lnk_with_msi  # noqa: E402
from LnkParse3.utils import parse_packed_uuid  # noqa: E402


CASE_DIR = Path(__file__).resolve().parent
LNK_DIR = CASE_DIR / "lnk"
FORMS_DIR = LNK_DIR / "darwin_forms"

BASE85 = "!$%&'()*+,-.0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{}~"
LNK_CLSID = "00021401-0000-0000-C000-000000000046"
COMPUTER = "WORKSTATION-01"
PRODUCT = "11223344-5566-7788-99AA-BBCCDDEEFF00"
MACHINE_COMPONENT = "AAAAAAAA-1111-2222-3333-444444444444"
ALICE_COMPONENT = "BBBBBBBB-2222-3333-4444-555555555555"
MACHINE_SID = "S-1-5-18"
ALICE_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
BOB_SID = "S-1-5-21-1111111111-2222222222-3333333333-1002"


def pack_quad(hex_quad: str) -> str:
    number = int(hex_quad, 16)
    chars = []
    for _ in range(5):
        number, remainder = divmod(number, 85)
        chars.append(BASE85[remainder])
    return "".join(chars)


def pack_guid(guid: str) -> str:
    value = guid.replace("-", "").upper()
    first = value[0:8]
    second = value[8:12]
    third = value[12:16]
    fourth = value[16:20]
    fifth = value[20:32]
    quads = (
        first
        + third
        + second
        + fifth[2:4]
        + fifth[0:2]
        + fourth[2:4]
        + fourth[0:2]
        + fifth[10:12]
        + fifth[8:10]
        + fifth[6:8]
        + fifth[4:6]
    )
    packed = "".join(pack_quad(quads[index : index + 8]) for index in range(0, 32, 8))
    if parse_packed_uuid(packed) != guid:
        raise AssertionError(f"packed GUID round trip failed: {guid} -> {packed}")
    return packed


PRODUCT_PACKED = pack_guid(PRODUCT)
MACHINE_PACKED = pack_guid(MACHINE_COMPONENT)
ALICE_PACKED = pack_guid(ALICE_COMPONENT)


def darwin_block(ansi_descriptor: str, unicode_descriptor: str | None = None) -> bytes:
    unicode_descriptor = ansi_descriptor if unicode_descriptor is None else unicode_descriptor
    ansi_field = (ansi_descriptor.encode("ascii") + b"\x00").ljust(260, b"\x00")[:260]
    unicode_field = (unicode_descriptor.encode("utf-16le") + b"\x00\x00").ljust(520, b"\x00")[:520]
    return struct.pack("<II", 788, 0xA0000006) + ansi_field + unicode_field


def minimal_lnk(ansi_descriptor: str, unicode_descriptor: str | None = None) -> bytes:
    header = struct.pack("<I", 76)
    header += uuidlib.UUID(LNK_CLSID).bytes_le
    header += struct.pack("<II", 0x00001000, 0)
    header += b"\x00" * 24
    header += struct.pack("<IiiHHII", 0, 0, 1, 0, 0, 0, 0)
    return header + darwin_block(ansi_descriptor, unicode_descriptor)


class RawLines:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def add(self, text: str = "") -> int:
        self.lines.append(text)
        return len(self.lines)

    def write(self) -> None:
        (CASE_DIR / "MSI-registration.txt").write_text("\n".join(self.lines) + "\n", encoding="utf-8")


def build_excerpt() -> dict:
    raw = RawLines()
    raw.add("MSI registration excerpt - fictional same-computer/two-user case")
    computer_line = raw.add(f"computer={COMPUTER}")
    raw.add("")

    machine_user_line = raw.add(
        f"principal=MACHINE sid={MACHINE_SID} scope=machine hive=UserData/{MACHINE_SID}"
    )
    machine_product_line = raw.add(
        f"product={{{PRODUCT}}} compressed={PRODUCT_PACKED} assignment=installed"
    )
    machine_feature_line = raw.add("feature=CoreFeature state=Installed")
    machine_component_line = raw.add(
        "component={%s} compressed=%s installed_path=C:\\Program Files\\Contoso\\Widget\\core.dll "
        "key=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\%s\\Components\\%s"
        % (MACHINE_COMPONENT, MACHINE_PACKED, MACHINE_SID, MACHINE_PACKED)
    )
    raw.add("")

    alice_user_line = raw.add(f"principal=alice sid={ALICE_SID} scope=user hive=HKU/{ALICE_SID}")
    alice_product_line = raw.add(
        f"product={{{PRODUCT}}} compressed={PRODUCT_PACKED} assignment=installed context=per-user"
    )
    alice_feature_line = raw.add("feature=AliceFeature state=Installed")
    alice_component_line = raw.add(
        "component={%s} compressed=%s "
        "installed_path=C:\\Users\\alice\\AppData\\Local\\Contoso\\Widget\\app.exe "
        "key=HKU\\%s\\Software\\Microsoft\\Installer\\Components\\%s"
        % (ALICE_COMPONENT, ALICE_PACKED, ALICE_SID, ALICE_PACKED)
    )
    raw.add("")

    bob_user_line = raw.add(f"principal=bob sid={BOB_SID} scope=user hive=HKU/{BOB_SID}")
    bob_product_line = raw.add(
        f"product={{{PRODUCT}}} compressed={PRODUCT_PACKED} assignment=advertised context=per-user"
    )
    bob_feature_line = raw.add("feature=BobAdvertisedFeature state=Advertised components=0 key_path=<none>")
    raw.add("notice=Bob has no Components key path and no installed_path for this product")
    raw.write()

    return {
        "schema": "lnkparse.msi_registration_excerpt/v1",
        "line_file": "MSI-registration.txt",
        "case": "dual_user_advertised_feature",
        "computers": [
            {
                "name": COMPUTER,
                "line": computer_line,
                "users": [
                    {
                        "name": "MACHINE",
                        "sid": MACHINE_SID,
                        "scope": "machine",
                        "line": machine_user_line,
                        "products": [
                            {
                                "product_code": PRODUCT,
                                "compressed_product_code": PRODUCT_PACKED,
                                "advertised": False,
                                "line": machine_product_line,
                                "features": [
                                    {
                                        "name": "CoreFeature",
                                        "state": "Installed",
                                        "line": machine_feature_line,
                                        "components": [
                                            {
                                                "component_code": MACHINE_COMPONENT,
                                                "compressed_component_code": MACHINE_PACKED,
                                                "line": machine_component_line,
                                                "installed": True,
                                                "installed_path": r"C:\Program Files\Contoso\Widget\core.dll",
                                                "registry_key": (
                                                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                                                    f"Installer\\UserData\\{MACHINE_SID}\\Components\\{MACHINE_PACKED}"
                                                ),
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "alice",
                        "sid": ALICE_SID,
                        "scope": "user",
                        "line": alice_user_line,
                        "products": [
                            {
                                "product_code": PRODUCT,
                                "compressed_product_code": PRODUCT_PACKED,
                                "advertised": False,
                                "line": alice_product_line,
                                "features": [
                                    {
                                        "name": "AliceFeature",
                                        "state": "Installed",
                                        "line": alice_feature_line,
                                        "components": [
                                            {
                                                "component_code": ALICE_COMPONENT,
                                                "compressed_component_code": ALICE_PACKED,
                                                "line": alice_component_line,
                                                "installed": True,
                                                "installed_path": r"C:\Users\alice\AppData\Local\Contoso\Widget\app.exe",
                                                "registry_key": (
                                                    f"HKU\\{ALICE_SID}\\Software\\Microsoft\\Installer\\"
                                                    f"Components\\{ALICE_PACKED}"
                                                ),
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "bob",
                        "sid": BOB_SID,
                        "scope": "user",
                        "line": bob_user_line,
                        "products": [
                            {
                                "product_code": PRODUCT,
                                "compressed_product_code": PRODUCT_PACKED,
                                "advertised": True,
                                "line": bob_product_line,
                                "features": [
                                    {
                                        "name": "BobAdvertisedFeature",
                                        "state": "Advertised",
                                        "advertised": True,
                                        "line": bob_feature_line,
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


def write_lnk(path: Path, ansi: str, unicode: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(minimal_lnk(ansi, unicode))


def build_lnks() -> dict[str, Path]:
    paths = {
        "alice": LNK_DIR / "alice-installed.lnk",
        "bob": LNK_DIR / "bob-advertised-feature.lnk",
        "conflict": LNK_DIR / "conflicting-encodings-user-vs-machine.lnk",
        "form1": FORMS_DIR / "form1-feature-component.lnk",
        "form2": FORMS_DIR / "form2-component-only.lnk",
        "form3": FORMS_DIR / "form3-feature-advertised.lnk",
        "form4": FORMS_DIR / "form4-product-advertised.lnk",
    }

    write_lnk(paths["alice"], PRODUCT_PACKED + "AliceFeature>" + ALICE_PACKED)
    write_lnk(paths["bob"], PRODUCT_PACKED + "BobAdvertisedFeature<")
    write_lnk(
        paths["conflict"],
        PRODUCT_PACKED + "CoreFeature>" + MACHINE_PACKED,
        PRODUCT_PACKED + ">" + ALICE_PACKED,
    )
    write_lnk(paths["form1"], PRODUCT_PACKED + "CoreFeature>" + MACHINE_PACKED)
    write_lnk(paths["form2"], PRODUCT_PACKED + ">" + MACHINE_PACKED)
    write_lnk(paths["form3"], PRODUCT_PACKED + "BobAdvertisedFeature<")
    write_lnk(paths["form4"], PRODUCT_PACKED + "<")
    return paths


def build_report(excerpt: dict, paths: dict[str, Path]) -> dict:
    checks = []
    scenarios = [
        ("alice_installed_component", paths["alice"], {"sid": ALICE_SID}),
        ("bob_advertised_feature_only", paths["bob"], {"sid": BOB_SID}),
        (
            "conflicting_ansi_unicode_user_machine",
            paths["conflict"],
            {"user": "alice", "computer": COMPUTER},
        ),
        ("form1_feature_component", paths["form1"], {"computer": COMPUTER}),
        ("form2_component_only", paths["form2"], {"computer": COMPUTER}),
        ("form3_feature_advertised", paths["form3"], {"sid": BOB_SID}),
        ("form4_product_advertised", paths["form4"], {"sid": BOB_SID}),
    ]
    for name, path, kwargs in scenarios:
        result = verify_lnk_with_msi(path, excerpt, **kwargs)
        checks.append(
            {
                "name": name,
                "lnk": str(path.relative_to(CASE_DIR)),
                "selector": kwargs,
                "status": result["status"],
                "installed": result["installed"],
                "installed_paths": result["installed_paths"],
                "findings": [
                    {
                        "encoding": item["encoding"],
                        "form_number": item["form_number"],
                        "component_id": item["component_id"],
                        "classification": item["classification"],
                        "installed_paths": item["installed_paths"],
                        "block_locator": item["block_locator"],
                        "registration_locators": item["registration_locators"],
                    }
                    for item in result["findings"]
                ],
                "conflicts": result["blocks"][0]["conflicts"] if result["blocks"] else None,
            }
        )
    report = {"schema": "lnkparse.msi_case_report/v1", "computer": COMPUTER, "checks": checks}
    (CASE_DIR / "verification-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    FORMS_DIR.mkdir(parents=True, exist_ok=True)
    excerpt = build_excerpt()
    (CASE_DIR / "msi_registration_excerpt.json").write_text(
        json.dumps(excerpt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    paths = build_lnks()
    report = build_report(excerpt, paths)
    for check in report["checks"]:
        print(f"{check['name']}: {check['status']} installed={check['installed']}")


if __name__ == "__main__":
    main()
