import json
from pathlib import Path

from regipy.review import ReviewError, load_rule_sets, review_hive

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "review"


def _smb_rule_sets():
    return [
        EXAMPLE_DIR / "smb_signing_legacy.json",
        EXAMPLE_DIR / "smb_signing_domain_server.json",
    ]


def _condition(result, condition_id):
    for interpretation in result["interpretations"]:
        for condition in interpretation["conditions"]:
            if condition["id"] == condition_id:
                return condition
    raise AssertionError(f"Condition {condition_id!r} was not evaluated")


def test_review_diverging_smb_signing_interpretations_stay_pending(system_hive):
    report = review_hive(
        system_hive,
        _smb_rule_sets(),
        prior_claims={"smb_signing": "enabled"},
    )

    result = report["results"]["smb_signing"]
    assert result["status"] == "pending"
    assert result["verdict"] is None
    assert result["reason"] == "interpretations_disagree"
    assert result["candidates"] == ["disabled", "enabled"]
    assert report["pending"] == ["smb_signing"]
    assert report["confirmed"] == []

    # The historical one-line finding is explicitly disputed, and the
    # alternative interpretation is the one that refutes it.
    assert result["prior_claim"]["status"] == "disputed"
    assert [item["rule_set"] for item in result["prior_claim"]["supporting_interpretations"]] == ["legacy_endpoint"]
    assert [item["rule_set"] for item in result["prior_claim"]["refuting_interpretations"]] == ["domain_server"]
    assert result["prior_claim"]["refuting_interpretations"][0]["conclusion"] == "disabled"

    # Exactly the two contested assumptions are reported.
    divergence = result["divergence"]
    assert divergence["assumption_count"] == 2
    assert [item["dimension"] for item in divergence["assumptions"]] == ["scope", "sufficiency"]
    for assumption in divergence["assumptions"]:
        assert assumption["values"]["legacy_endpoint"] != assumption["values"]["domain_server"]
        assert assumption["conditions"]["legacy_endpoint"]
        assert assumption["conditions"]["domain_server"]


def test_review_keeps_plugin_and_raw_entry_provenance(system_hive):
    report = review_hive(system_hive, _smb_rule_sets())
    result = report["results"]["smb_signing"]

    legacy_flag = _condition(result, "legacy.workstation.signature_flag")
    assert legacy_flag["matched"] is True
    assert legacy_flag["actual"] == 1
    assert legacy_flag["path"] == r"\ControlSet001\Services\LanmanWorkstation\Parameters"

    legacy_plugin_evidence = [item for item in legacy_flag["evidence"] if item["kind"] == "plugin_entry"]
    assert len(legacy_plugin_evidence) == 1
    evidence = legacy_plugin_evidence[0]
    assert evidence["plugin"] == "services"
    assert "LanmanWorkstation" in evidence["entry_path"]
    assert "Parameters" in evidence["entry_path"]
    assert evidence["entry_indices"] == [155, 2]
    assert evidence["raw_entry_range"]["plugin"] == "services"
    assert evidence["raw_entry_range"]["start"] == 2
    assert evidence["raw_entry_range"]["end"] == 3
    assert evidence["raw_entry"]["path"].endswith(r"\LanmanWorkstation\Parameters")
    assert evidence["raw_entry"]["value"]["name"] == "EnableSecuritySignature"
    assert evidence["raw_entry"]["value"]["value"] == 1

    domain_condition = _condition(result, "domain.is_domain_joined")
    assert domain_condition["matched"] is True
    assert domain_condition["actual"] == "shieldbase.local"
    domain_evidence = [item for item in domain_condition["evidence"] if item["kind"] == "plugin_entry"]
    assert len(domain_evidence) == 1
    assert domain_evidence[0]["plugin"] == "host_domain_name"
    assert domain_evidence[0]["raw_entry_range"]["start"] == 0
    assert domain_evidence[0]["raw_entry_range"]["end"] == 1
    assert domain_evidence[0]["raw_entry"]["domain"] == "shieldbase.local"

    server_flag = _condition(result, "domain.server_enable_signature")
    assert server_flag["matched"] is True
    assert server_flag["actual"] == 0
    assert server_flag["path"] == r"\ControlSet001\Services\LanmanServer\Parameters"
    server_evidence = [item for item in server_flag["evidence"] if item["kind"] == "plugin_entry"]
    assert len(server_evidence) == 1
    assert server_evidence[0]["plugin"] == "services"
    assert "LanmanServer" in server_evidence[0]["entry_path"]
    assert server_evidence[0]["entry_indices"] == [154, 4]


def test_review_missing_dependency_stays_pending(system_hive):
    rule_set = {
        "name": "missing_dependency",
        "description": "A rule whose dependency key is absent from the collection.",
        "plugins": ["services"],
        "assumptions": {"dependency": "The dependent key must be present."},
        "rules": [
            {
                "id": "missing.enabled",
                "subject": "some_configuration",
                "conclusion": "enabled",
                "conditions": [
                    {
                        "id": "missing.dependency",
                        "path": r"\CurrentControlSet\Control\NoSuchConfigurationKey",
                        "value": "Enabled",
                        "op": "eq",
                        "expected": 1,
                        "assumption": "dependency",
                    }
                ],
            }
        ],
    }

    report = review_hive(
        system_hive,
        rule_set,
        prior_claims={"some_configuration": "enabled"},
    )
    result = report["results"]["some_configuration"]

    assert result["status"] == "pending"
    assert result["verdict"] is None
    assert result["candidates"] == []
    assert result["reason"] == "insufficient_evidence"
    assert result["prior_claim"]["status"] == "unverified"

    condition = _condition(result, "missing.dependency")
    assert condition["unknown"] is True
    assert condition["matched"] is False
    assert condition["found"] is False
    assert condition["reason"] == "missing_key"


def test_review_agreement_is_confirmed(system_hive):
    rule_set = {
        "name": "domain_identity",
        "description": "Both sets agree that this is a domain-joined host.",
        "plugins": ["host_domain_name"],
        "assumptions": {"domain": "A non-empty Tcpip Domain value means domain joined."},
        "rules": [
            {
                "id": "domain.joined",
                "subject": "domain_joined",
                "conclusion": "yes",
                "conditions": [
                    {
                        "id": "domain.value",
                        "path": r"\CurrentControlSet\Services\Tcpip\Parameters",
                        "value": "Domain",
                        "op": "non_empty",
                        "assumption": "domain",
                        "evidence": {
                            "plugin": "host_domain_name",
                            "entry_index": "current",
                            "field": "domain",
                        },
                    }
                ],
            }
        ],
    }

    duplicate = json.loads(json.dumps(rule_set))
    duplicate["name"] = "domain_identity_challenger"
    report = review_hive(system_hive, [rule_set, duplicate])
    result = report["results"]["domain_joined"]

    assert result["status"] == "confirmed"
    assert result["verdict"] == "yes"
    assert result["candidates"] == ["yes"]
    assert result["divergence"] is None
    assert report["confirmed"] == ["domain_joined"]


def test_review_accepts_precollected_plugin_results(system_hive, tmp_path):
    from regipy.plugins.system.host_domain_name import HostDomainNamePlugin
    from regipy.plugins.system.services import ServicesPlugin
    from regipy.registry import RegistryHive

    hive = RegistryHive(system_hive)
    plugin_results = {}
    for plugin_class in (ServicesPlugin, HostDomainNamePlugin):
        plugin = plugin_class(hive, as_json=True)
        plugin.run()
        plugin_results[plugin.NAME] = plugin.entries

    collected_path = tmp_path / "plugin_results.json"
    collected_path.write_text(json.dumps(plugin_results), encoding="utf-8")
    reloaded = json.loads(collected_path.read_text(encoding="utf-8"))

    report = review_hive(
        hive,
        _smb_rule_sets(),
        plugin_results=reloaded,
        run_plugins=False,
    )
    result = report["results"]["smb_signing"]
    assert result["status"] == "pending"
    assert report["plugins"]["errors"] == {}
    assert "services" in report["plugins"]["available"]

    legacy_flag = _condition(result, "legacy.workstation.signature_flag")
    plugin_evidence = [item for item in legacy_flag["evidence"] if item["kind"] == "plugin_entry"]
    assert plugin_evidence[0]["plugin"] == "services"
    assert plugin_evidence[0]["entry_indices"] == [155, 2]


def test_review_flags_plugin_hive_mismatch(system_hive):
    from regipy.plugins.system.host_domain_name import HostDomainNamePlugin
    from regipy.plugins.system.services import ServicesPlugin
    from regipy.registry import RegistryHive

    hive = RegistryHive(system_hive)
    plugin_results = {}
    for plugin_class in (ServicesPlugin, HostDomainNamePlugin):
        plugin = plugin_class(hive, as_json=True)
        plugin.run()
        plugin_results[plugin.NAME] = plugin.entries

    # Simulate stale/corrupted pre-collected plugin output: the hive says the
    # workstation flag is 1, but the plugin entry claims 0.
    for service in plugin_results["services"][r"\ControlSet001\Services"]["services"]:
        if service["name"] != "LanmanWorkstation":
            continue
        for parameter in service["parameters"]:
            if not parameter["path"].endswith(r"\LanmanWorkstation\Parameters"):
                continue
            for value in parameter["values"]:
                if value["name"] == "EnableSecuritySignature":
                    value["value"] = 0

    report = review_hive(
        hive,
        _smb_rule_sets(),
        plugin_results=plugin_results,
        run_plugins=False,
        prior_claims={"smb_signing": "enabled"},
    )
    result = report["results"]["smb_signing"]
    assert result["status"] == "pending"
    assert result["candidates"] == ["disabled"]

    legacy_flag = _condition(result, "legacy.workstation.signature_flag")
    assert legacy_flag["matched"] is False
    assert legacy_flag["unknown"] is True
    assert legacy_flag["reason"] == "plugin_hive_mismatch"
    assert legacy_flag["consistency"]["plugin_value_mismatches"][0]["plugin"] == "services"


def test_rule_set_validation_rejects_bad_operator():
    try:
        load_rule_sets(
            {
                "name": "bad",
                "rules": [
                    {
                        "id": "bad.rule",
                        "subject": "x",
                        "conclusion": "enabled",
                        "conditions": [{"path": r"\Foo", "value": "Bar", "op": "nonsense", "expected": 1}],
                    }
                ],
            }
        )
    except ReviewError as ex:
        assert "unsupported operator" in str(ex)
    else:
        raise AssertionError("Expected ReviewError for an unsupported operator")
