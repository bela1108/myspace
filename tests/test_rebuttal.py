import os

import pytest

import Evtx.rebuttal as rebuttal

LIVEID_CHANNEL = "Microsoft-Windows-LiveId/Operational"
DNS_CHANNEL = "Microsoft-Windows-DNSServer/Analytical"
GUID_520 = "520e6584-8fb6-5000-18fd-9567eb5ac94a"
GUID_176 = "176d51c9-d4d9-5cfa-eb57-6218ab6dc6df"
DNS_GUID = "561068e3-3468-5a3c-4464-ef4758bb742f"


@pytest.fixture
def issue39(data_path):
    return rebuttal.scan_log(os.path.join(data_path, "issue_39.evtx"))


@pytest.fixture
def malformed(data_path):
    return rebuttal.scan_log(os.path.join(data_path, "dns_log_malformed.evtx"))


@pytest.fixture
def issue38(data_path):
    return rebuttal.scan_log(os.path.join(data_path, "issue_38.evtx"))


def _event(name, event_id, channel=LIVEID_CHANNEL, provider=None):
    return rebuttal.EventSpec(name=name, channel=channel, event_id=event_id, provider=provider)


def test_scan_collects_unrenderable_records(malformed):
    assert len(malformed) == 5
    assert sum(1 for witness in malformed if witness.renderable) == 1
    broken = [witness for witness in malformed if not witness.renderable]
    assert {witness.error for witness in broken} == {"UnicodeDecodeError"}
    # the binary record header still yields time and template evidence
    assert all(witness.timestamp is not None for witness in broken)
    assert all(witness.template_guid == DNS_GUID for witness in broken)


def test_identity_supported(issue39):
    spec = _event("generated_record", 2024)
    verdict, witness, note = rebuttal.evaluate_identity(spec, issue39, None)
    assert verdict == rebuttal.SUPPORTED
    assert witness.event_id == 2024


def test_identity_absent_is_unconfirmable_not_rebutted(issue39):
    spec = _event("ghost", 9999)
    verdict, witness, note = rebuttal.evaluate_identity(spec, issue39, None)
    assert verdict == rebuttal.UNCONFIRMABLE
    assert witness is None


def test_ordering_rebuts_post_generation_claim(issue39):
    claim = rebuttal.CaseClaim(
        title="t",
        events={
            "withdrawal_request": _event("withdrawal_request", 6113),
            "generated_record": _event("generated_record", 2024),
        },
        orderings=[
            rebuttal.OrderingRequirement(first="withdrawal_request", relation="before", second="generated_record")
        ],
    )
    verdict, witness, note = rebuttal.evaluate_ordering(claim.orderings[0], claim, issue39, None)
    assert verdict == rebuttal.REBUTTED
    # the shortest credible material is the single earliest contradicting record
    assert witness.record_num == 1
    assert "predates" in note


def test_ordering_supported_when_sequence_holds(issue39):
    claim = rebuttal.CaseClaim(
        title="t",
        events={
            "generated_record": _event("generated_record", 2024),
            "later_service_event": _event("later_service_event", 6117),
        },
        orderings=[
            rebuttal.OrderingRequirement(first="generated_record", relation="before", second="later_service_event")
        ],
    )
    verdict, witness, note = rebuttal.evaluate_ordering(claim.orderings[0], claim, issue39, None)
    assert verdict == rebuttal.SUPPORTED


def test_field_interpretation_rebutted(issue39):
    spec = _event("generated_record", 2024)
    requirement = rebuttal.FieldRequirement(
        event="generated_record", field="Status", op="equals", value="0x00000001"
    )
    verdict, witness, note = rebuttal.evaluate_field(requirement, spec, issue39, None)
    assert verdict == rebuttal.REBUTTED
    assert witness.fields["Status"] == "0x00000000"


def test_field_interpretation_supported(issue39):
    spec = _event("generated_record", 2024)
    requirement = rebuttal.FieldRequirement(
        event="generated_record", field="Status", op="equals", value="0x00000000"
    )
    verdict, _, _ = rebuttal.evaluate_field(requirement, spec, issue39, None)
    assert verdict == rebuttal.SUPPORTED


def test_template_proof_excludes_non_authoritative_version(issue39):
    spec = _event("generated_record", 2024)
    proof = rebuttal.TemplateProof.from_dict(
        {"event_template_guids": {"generated_record": [GUID_176]}}
    )
    verdict, witness, note = rebuttal.evaluate_identity(spec, issue39, proof)
    # a non-authoritative template version is unconfirmable, never a rebuttal
    assert verdict == rebuttal.SUPPORTED
    assert witness.template_guid == GUID_176
    assert witness.record_num == 8


def test_template_proof_makes_identity_unconfirmable_when_only_bad_version(issue39):
    # restrict the proof to a GUID never used by EID 6113 in this material
    spec = _event("withdrawal_request", 6113)
    proof = rebuttal.TemplateProof.from_dict(
        {"event_template_guids": {"withdrawal_request": ["00000000-0000-0000-0000-000000000000"]}}
    )
    verdict, witness, note = rebuttal.evaluate_identity(spec, issue39, proof)
    assert verdict == rebuttal.UNCONFIRMABLE
    assert witness is not None
    assert "not an authoritative version" in note


def test_unrenderable_attributed_record_is_unconfirmable(malformed):
    spec = rebuttal.EventSpec(name="dns_query", channel=DNS_CHANNEL, event_id=260)
    broken = [witness for witness in malformed if not witness.renderable]
    proof = rebuttal.TemplateProof.from_dict({"event_template_guids": {"dns_query": [DNS_GUID]}})
    verdict, witness, note = rebuttal.evaluate_identity(spec, broken, proof)
    assert verdict == rebuttal.UNCONFIRMABLE
    assert witness is not None
    assert "cannot be rendered" in note


def test_unrenderable_unattributed_record_does_not_block_absence(malformed):
    spec = rebuttal.EventSpec(name="ghost", channel=DNS_CHANNEL, event_id=9999)
    broken = [witness for witness in malformed if not witness.renderable]
    verdict, witness, note = rebuttal.evaluate_identity(spec, broken, None)
    assert verdict == rebuttal.UNCONFIRMABLE
    assert witness is None


def test_claim_validation_rejects_unknown_reference():
    with pytest.raises(rebuttal.RebuttalError):
        rebuttal.CaseClaim.from_dict(
            {
                "events": {"a": {"event_id": 1}},
                "orderings": [{"first": "a", "relation": "before", "second": "missing"}],
            }
        )


def test_end_to_end_report_aggregates_verdicts(issue39):
    claim = rebuttal.CaseClaim.from_dict(
        {
            "title": "case",
            "events": {
                "withdrawal_request": {"channel": LIVEID_CHANNEL, "event_id": 6113},
                "generated_record": {"channel": LIVEID_CHANNEL, "event_id": 2024},
                "missing": {"channel": LIVEID_CHANNEL, "event_id": 9999},
            },
            "orderings": [
                {"first": "withdrawal_request", "relation": "before", "second": "generated_record"}
            ],
        }
    )
    report = rebuttal.evaluate_claim(claim, issue39, None)
    assert report["overall"] == rebuttal.REBUTTED
    kinds = {(f["kind"], f["name"]): f["verdict"] for f in report["findings"]}
    assert kinds[("identity", "missing")] == rebuttal.UNCONFIRMABLE
    assert kinds[("ordering", "withdrawal_request before generated_record")] == rebuttal.REBUTTED
    text = rebuttal.render_text_report(report)
    assert "Overall verdict: REBUTTED" in text


def test_revised_template_proof_only_changes_covered_findings(issue39):
    events = {
        "withdrawal_request": {"channel": LIVEID_CHANNEL, "event_id": 6113},
        "generated_record": {"channel": LIVEID_CHANNEL, "event_id": 2024},
        "later_service_event": {"channel": LIVEID_CHANNEL, "event_id": 6117},
        "missing": {"channel": LIVEID_CHANNEL, "event_id": 9999},
    }
    orderings = [
        {"first": "withdrawal_request", "relation": "before", "second": "generated_record"}
    ]
    fields = [
        {"event": "generated_record", "field": "Status", "op": "equals", "value": "0x00000001"}
    ]
    claim = rebuttal.CaseClaim.from_dict(
        {"title": "case", "events": events, "orderings": orderings, "fields": fields}
    )
    original = rebuttal.TemplateProof.from_dict(
        {
            "event_template_guids": {
                "withdrawal_request": [GUID_520, GUID_176],
                "generated_record": [GUID_520, GUID_176],
                "later_service_event": [GUID_176],
            }
        }
    )
    revised = rebuttal.TemplateProof.from_dict(
        {
            "event_template_guids": {
                "withdrawal_request": [GUID_176],
                "generated_record": [GUID_176],
                "later_service_event": [GUID_176],
            }
        }
    )
    before = rebuttal.evaluate_claim(claim, issue39, original)
    after = rebuttal.evaluate_claim(claim, issue39, revised)

    def index(report):
        return {(f["kind"], f["name"]): f for f in report["findings"]}

    before_index = index(before)
    after_index = index(after)

    # the uncovered identity keeps exactly the same conclusion and material
    untouched = ("identity", "missing")
    assert before_index[untouched]["verdict"] == after_index[untouched]["verdict"]
    assert before_index[untouched]["evidence"] == after_index[untouched]["evidence"]

    # covered findings switch their shortest material to the authoritative version
    ordering_key = ("ordering", "withdrawal_request before generated_record")
    assert after_index[ordering_key]["evidence"]["record"] == 8
    assert before_index[ordering_key]["evidence"]["record"] == 1
    # both reports still rebut the ordering and field claim
    assert before_index[ordering_key]["verdict"] == rebuttal.REBUTTED
    assert after_index[ordering_key]["verdict"] == rebuttal.REBUTTED

