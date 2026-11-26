import copy
from dataclasses import asdict, is_dataclass, replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from regipy.cross_hive import (
    DIFFERENT_DEVICE,
    PATH_SIMILAR_ONLY,
    SUBJECT_MATCH,
    CollectionChain,
    HiveView,
    correlate_hives,
)
from regipy.exceptions import RegistryKeyNotFoundException
from regipy.plugins.ntuser.network_drives import NetworkDrivesPlugin
from regipy.plugins.software.profilelist import ProfileListPlugin

FIXED_DATETIME = datetime(2026, 11, 27, 1, 2, 3, tzinfo=timezone.utc)
WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
FIXED_FILETIME = int((FIXED_DATETIME - WINDOWS_EPOCH).total_seconds() * 10_000_000)
OLD_SID = "S-1-5-21-1111111111-2222222222-3333333333-1108"
SIMILAR_SID = "S-1-5-21-1111111111-2222222222-3333333333-1109"
NEW_DEVICE_SID = "S-1-5-21-4444444444-5555555555-6666666666-1108"


class SyntheticKey:
    def __init__(self, name, values=None, subkeys=None):
        self.name = name
        self.values = values or {}
        self.subkeys = subkeys or []
        self.header = SimpleNamespace(last_modified=FIXED_FILETIME)

    def get_value(self, value_name, as_json=False):
        return self.values.get(value_name)

    def iter_subkeys(self):
        return iter(self.subkeys)


class SyntheticHive:
    """A RegistryHive-shaped in-memory view sufficient for real plugins."""

    partial_hive_path = None

    def __init__(self, hive_type, root):
        self.hive_type = hive_type
        self.root = root

    def get_key(self, key_path):
        current = self.root
        parts = [part for part in key_path.replace("/", "\\").split("\\") if part]
        for part in parts:
            match = next((child for child in current.subkeys if child.name.lower() == part.lower()), None)
            if match is None:
                raise RegistryKeyNotFoundException(key_path)
            current = match
        return current


@pytest.fixture()
def synthetic_plugin_views():
    z_drive = SyntheticKey("Z", {"RemotePath": r"\\FILE01\OpsDrop"})
    network = SyntheticKey("Network", subkeys=[z_drive])
    ntuser_root = SyntheticKey("CMI-CreateHive-synthetic", subkeys=[network])
    ntuser_hive = SyntheticHive("ntuser", ntuser_root)

    current_version = SyntheticKey(
        "CurrentVersion",
        subkeys=[
            SyntheticKey(
                "ProfileList",
                subkeys=[
                    SyntheticKey(OLD_SID, {"ProfileImagePath": r"C:\Users\caseuser"}),
                    SyntheticKey(SIMILAR_SID, {"ProfileImagePath": r"C:\Users\caseuser.bak"}),
                ],
            )
        ],
    )
    windows_nt = SyntheticKey("Windows NT", subkeys=[current_version])
    microsoft = SyntheticKey("Microsoft", subkeys=[windows_nt])
    software_root = SyntheticKey("CMI-CreateHive-software", subkeys=[microsoft])
    software_hive = SyntheticHive("software", software_root)

    drives_plugin = NetworkDrivesPlugin(ntuser_hive, as_json=True)
    drives_plugin.run()
    profiles_plugin = ProfileListPlugin(software_hive, as_json=True)
    profiles_plugin.run()

    views = [
        HiveView.from_plugin_outputs(
            "ntuser-old",
            hive_type="ntuser",
            network_drives=drives_plugin,
        ),
        HiveView.from_plugin_outputs(
            "software-old",
            hive_type="software",
            profiles=profiles_plugin,
        ),
        HiveView.from_plugin_outputs(
            "software-new-device",
            hive_type="software",
            profiles=[
                {"sid": NEW_DEVICE_SID, "path": r"C:\Users\caseuser"},
            ],
        ),
    ]
    chain = CollectionChain()
    chain.confirm(
        "ntuser-old",
        "M-0421",
        source_path=r"C:\Users\caseuser\NTUSER.DAT",
        confirmed_by="caller-chain-fixture",
    )
    chain.confirm("software-old", "M-0421", confirmed_by="caller-chain-fixture")
    chain.confirm("software-new-device", "M-0731", confirmed_by="caller-chain-fixture")
    chain.confirm("shot-local", "M-0421", confirmed_by="caller-chain-fixture")
    chain.confirm("shot-new-device", "M-0731", confirmed_by="caller-chain-fixture")

    return SimpleNamespace(views=views, chain=chain)


def test_real_plugins_run_against_synthetic_hive_views(synthetic_plugin_views):
    report = correlate_hives(synthetic_plugin_views.views, collection_chain=synthetic_plugin_views.chain)

    subject = report.by_category(SUBJECT_MATCH)[0]
    assert subject.sid == OLD_SID
    assert subject.machine_id == "M-0421"
    assert subject.drive_letter == "Z"
    assert subject.network_path == r"\\FILE01\OpsDrop"


def test_report_separates_subject_path_only_and_different_device(synthetic_plugin_views):
    screenshots = [
        {"claim_id": "shot-local", "path": r"Z:\Cases\2026\capture.png"},
        {"claim_id": "shot-new-device", "path": r"Z:\Cases\2026\capture.png"},
    ]
    report = correlate_hives(
        synthetic_plugin_views.views,
        collection_chain=synthetic_plugin_views.chain,
        screenshots=screenshots,
    )

    subject_findings = report.subject_matches
    path_findings = report.path_similar_only
    device_findings = report.different_devices

    assert any(finding.sid == OLD_SID and finding.subject_id == f"M-0421/{OLD_SID}" for finding in subject_findings)
    assert any(
        finding.category == PATH_SIMILAR_ONLY
        and finding.candidate_sid == SIMILAR_SID
        and finding.candidate_path == r"C:\Users\caseuser.bak"
        for finding in path_findings
    )
    new_device_claim = next(claim for claim in report.claims if claim.claim_id == "shot-new-device")
    assert new_device_claim.category == DIFFERENT_DEVICE
    assert new_device_claim.endorsed is False
    assert any(finding.category == DIFFERENT_DEVICE and finding.machine_id == "M-0731" for finding in device_findings)
    assert any(
        finding.category == DIFFERENT_DEVICE
        and finding.candidate_sid == NEW_DEVICE_SID
        and finding.candidate_machine_id == "M-0731"
        for finding in device_findings
    )


def test_changing_one_machine_id_revokes_path_endorsement(synthetic_plugin_views):
    screenshots = [{"claim_id": "shot-local", "path": r"Z:\Cases\2026\capture.png"}]
    baseline = correlate_hives(
        copy.deepcopy(synthetic_plugin_views.views),
        collection_chain=copy.deepcopy(synthetic_plugin_views.chain),
        screenshots=copy.deepcopy(screenshots),
    )
    baseline_claim = baseline.claims[0]
    assert baseline_claim.endorsed is True
    assert baseline_claim.subject_id == f"M-0421/{OLD_SID}"

    mutated_chain = copy.deepcopy(synthetic_plugin_views.chain)
    old_link = mutated_chain.links["software-old"]
    mutated_chain.links["software-old"] = replace(old_link, machine_id="M-0999")

    differences = _flat_differences(
        asdict(synthetic_plugin_views.chain),
        asdict(mutated_chain),
    )
    assert differences == {"links.software-old.machine_id": ("M-0421", "M-0999")}

    mutated = correlate_hives(
        copy.deepcopy(synthetic_plugin_views.views),
        collection_chain=mutated_chain,
        screenshots=copy.deepcopy(screenshots),
    )
    mutated_claim = mutated.claims[0]

    assert mutated_claim.endorsed is False
    assert mutated_claim.subject_id is None
    assert mutated_claim.category == DIFFERENT_DEVICE
    assert any(
        finding.category == DIFFERENT_DEVICE
        and finding.machine_id == "M-0421"
        and finding.candidate_machine_id == "M-0999"
        and finding.candidate_sid == OLD_SID
        for finding in mutated.findings
    )
    assert any(finding.relation == "path_prefix" for finding in mutated.findings)


def test_changing_claim_machine_alone_revokes_endorsement(synthetic_plugin_views):
    chain = copy.deepcopy(synthetic_plugin_views.chain)
    screenshots = [{"claim_id": "shot-local", "path": r"Z:\Cases\2026\capture.png"}]
    assert (
        correlate_hives(
            synthetic_plugin_views.views,
            collection_chain=chain,
            screenshots=screenshots,
        )
        .claims[0]
        .endorsed
    )

    chain.links["shot-local"] = replace(chain.links["shot-local"], machine_id="M-0731")
    mutated = correlate_hives(
        synthetic_plugin_views.views,
        collection_chain=chain,
        screenshots=screenshots,
    )

    assert mutated.claims[0].endorsed is False
    assert mutated.claims[0].category == DIFFERENT_DEVICE


def test_same_user_name_without_chain_is_not_subject_match():
    views = [
        {
            "hive_id": "ntuser",
            "source_path": r"C:\Users\same\NTUSER.DAT",
            "network_drives": [{"drive_letter": "Z", "network_path": r"\\srv\share"}],
        },
        {
            "hive_id": "software",
            "profiles": [{"sid": "S-1-5-21-1-2-3-1001", "path": r"C:\Users\same"}],
        },
    ]

    report = correlate_hives(views)

    assert report.subject_matches == []
    assert any(finding.category == PATH_SIMILAR_ONLY for finding in report.findings)


def _flat_differences(left, right, prefix=""):
    if is_dataclass(left):
        left = asdict(left)
    if is_dataclass(right):
        right = asdict(right)
    if isinstance(left, dict) and isinstance(right, dict):
        differences = {}
        for key in left.keys() | right.keys():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            differences.update(_flat_differences(left.get(key), right.get(key), child_prefix))
        return differences
    return {} if left == right else {prefix: (left, right)}
