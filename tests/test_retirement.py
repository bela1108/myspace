import itertools

import cbor2

from pycose.retirement import DomainIndex, retirement_dry_run
from pycose.messages.encmessage import EncMessage


FOUR_DOMAINS = ("aurora", "borealis", "cirrus", "drift")

TABLE = [
    {"key_id": "k-a", "key_version": 1, "escrow_domain": "aurora"},
    {"key_id": "k-b", "key_version": 1, "escrow_domain": "borealis", "hardware_id": "hw-bc"},
    {"key_id": "k-c", "key_version": 1, "escrow_domain": "cirrus", "hardware_id": "hw-bc"},
    {"key_id": "k-d", "key_version": 1, "escrow_domain": "drift"},
    {"key_id": "k-a2", "key_version": 2, "escrow_domain": "aurora"},
    {"key_id": "k-u", "key_version": 9, "escrow_domain": "aurora"},
    ("k-v", 7, "versioned"),
]


ARCHIVES = [
    {
        "archive_id": "arc-north",
        "recipients": [
            {"alg": "A128KW", "kid": "k-a"},
            {"alg": "A128KW", "kid": "k-b"},
        ],
    },
    {
        "archive_id": "arc-south",
        "recipients": [
            {"alg": "A128KW", "kid": "k-c"},
            {"alg": "A128KW", "kid": "k-d"},
        ],
    },
    {
        "archive_id": "arc-deep",
        "recipients": [
            {
                "alg": "A128KW",
                "recipients": [
                    {"alg": "A128KW", "kid": "k-a2"},
                    {"alg": "A128KW", "kid": "k-d"},
                ],
            }
        ],
    },
]


def _oracle_survivors(retired_combo):
    index = DomainIndex(TABLE)
    retired, _ = index.canonical_retirement_set(list(retired_combo))

    def node_alive(node):
        own = False
        for kid in (node.get("kid"), node.get("key_id")):
            if kid is None:
                continue
            resolution = index.resolve_key(kid, node.get("key_version"))
            if resolution.domains and any(domain not in retired for domain in resolution.domains):
                own = True
        children = node.get("recipients") or node.get("children") or []
        if children:
            return own or any(node_alive(child) for child in children)
        return own

    survivors = []
    for archive in ARCHIVES:
        if any(node_alive(recipient) for recipient in archive["recipients"]):
            survivors.append(archive["archive_id"])
    return sorted(survivors)


def test_shared_hardware_aliases_are_one_failure_domain():
    report = retirement_dry_run(ARCHIVES, TABLE, ["aurora", "cirrus"])

    assert report.domain_aliases["borealis"] == "borealis"
    assert report.domain_aliases["cirrus"] == "borealis"
    assert report.failure_domains["borealis"] == ["borealis", "cirrus"]
    assert report.retired_domains == ["aurora", "borealis"]
    assert report.archives_with_recovery_paths == ["arc-south", "arc-deep"]


def test_all_sixteen_domain_combinations_match_path_oracle():
    for size in range(5):
        for combo in itertools.combinations(FOUR_DOMAINS, size):
            report = retirement_dry_run(ARCHIVES, TABLE, list(combo))
            assert sorted(report.archives_with_recovery_paths) == _oracle_survivors(combo)

            brute_force_min = None
            for candidate_size in range(5):
                for candidate in itertools.combinations(FOUR_DOMAINS, candidate_size):
                    candidate_report = retirement_dry_run(ARCHIVES, TABLE, list(candidate))
                    if not candidate_report.archives_with_recovery_paths:
                        brute_force_min = candidate_size
                        break
                if brute_force_min is not None:
                    break

            if not report.archives_with_recovery_paths:
                assert len(set(report.retired_domains)) <= len(combo)

    minimum_report = retirement_dry_run(ARCHIVES, TABLE, [])
    assert minimum_report.minimum_domain_set == ["aurora", "borealis", "drift"]
    assert not retirement_dry_run(
        ARCHIVES, TABLE, minimum_report.minimum_domain_set
    ).archives_with_recovery_paths


def test_nested_path_explains_dependency_and_siblings_are_alternatives():
    report = retirement_dry_run(ARCHIVES, TABLE, [])
    deep = next(a for a in report.archives if a.archive_id == "arc-deep")

    assert len(deep.paths) == 2
    assert [len(path.nodes) for path in deep.paths] == [2, 2]
    assert {path.domains[0] for path in deep.paths} == {"aurora", "drift"}

    retired = retirement_dry_run(ARCHIVES, TABLE, ["drift"])
    deep_retired = next(a for a in retired.archives if a.archive_id == "arc-deep")
    assert deep_retired.has_registered_recovery_path is True
    assert len(deep_retired.active_paths) == 1
    assert deep_retired.active_paths[0].domains == ["aurora"]


def test_unknown_algorithm_is_retained_but_not_called_known_path():
    archives = ARCHIVES + [
        {
            "archive_id": "arc-unknown",
            "recipients": [{"alg": -999_999, "kid": "k-u"}],
        }
    ]
    report = retirement_dry_run(archives, TABLE, [])
    unknown = [item for item in report.unknown_algorithms if item.archive_id == "arc-unknown"]

    assert unknown
    assert unknown[0].algorithm == -999_999
    assert "arc-unknown" not in report.archives_with_recovery_paths


def test_key_id_and_version_mapping_is_used():
    report = retirement_dry_run(
        [{"archive_id": "arc-version", "kid": "k-v", "key_version": 7}],
        TABLE,
        [],
    )
    archive = report.archives[0]
    assert archive.paths[0].domains == ["versioned"]


def test_read_raw_cose_headers_without_payload_or_keys():
    child = [b"", {1: -3, 4: b"k-a"}, b"wrapped-key"]
    parent = [b"", {1: -3}, b"encrypted-cek", [child]]
    cose_message = [b"", {1: 1}, b"never-decrypted-payload", [parent]]
    encoded = cbor2.dumps(cbor2.CBORTag(96, cose_message))

    report = retirement_dry_run([("arc-raw", encoded)], TABLE, ["aurora"])
    assert report.archives_with_recovery_paths == []
    archive = report.archives[0]
    assert archive.retired_paths[0].domains == ["aurora"]
    assert [node.location for node in archive.retired_paths[0].nodes] == ["0.0", "0.0.0"]


def test_pycose_message_object_tree_is_header_only_input():
    from pycose.algorithms import A128GCM, A128KW
    from pycose.headers import Algorithm, KID
    from pycose.messages.encmessage import EncMessage
    from pycose.messages.recipient import KeyWrap

    child = KeyWrap(
        uhdr={Algorithm: A128KW, KID: b"k-a"},
        payload=b"wrapped-key",
    )
    parent = KeyWrap(
        uhdr={Algorithm: A128KW},
        payload=b"encrypted-cek",
        recipients=[child],
    )
    message = EncMessage(
        phdr={Algorithm: A128GCM},
        payload=b"never-decrypted-payload",
        recipients=[parent],
    )

    report = retirement_dry_run([("arc-object", message)], TABLE, [])
    archive = report.archives[0]
    assert archive.active_paths[0].domains == ["aurora"]
    assert len(archive.active_paths[0].nodes) == 2
