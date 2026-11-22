import hashlib
import socket

import dpkt
from dpkt.capture_audit import (
    BIDIRECTIONAL,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
    audit_case,
    audit_files,
    case_from_dict,
    render_markdown,
)


CLIENT = "10.10.0.10"
SERVER = "10.10.0.20"
CLIENT_PORT = 40000
SERVER_PORT = 9100


def _ip(text):
    return socket.inet_aton(text)


def _frame(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    tcp = dpkt.tcp.TCP(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        data=payload,
    )
    ip = dpkt.ip.IP(
        src=_ip(src_ip),
        dst=_ip(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp,
    )
    eth = dpkt.ethernet.Ethernet(
        src=b"\x02\x00\x00\x00\x00\x02",
        dst=b"\x02\x00\x00\x00\x00\x01",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _write_pcap(path, packets):
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for timestamp, frame in packets:
            writer.writepkt(frame, ts=timestamp)


def _syn(t, sport=CLIENT_PORT, dport=SERVER_PORT, seq=1000):
    return (t, _frame(CLIENT, SERVER, sport, dport, seq, 0, dpkt.tcp.TH_SYN))


def _synack(t, sport=SERVER_PORT, dport=CLIENT_PORT, seq=5000, ack=1001):
    return (t, _frame(SERVER, CLIENT, sport, dport, seq, ack, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK))


def _ack(t, sport=CLIENT_PORT, dport=SERVER_PORT, seq=1001, ack=5001):
    return (t, _frame(CLIENT, SERVER, sport, dport, seq, ack, dpkt.tcp.TH_ACK))


def _data(t, src, dst, sport, dport, seq, ack, payload=b"diag"):
    return (t, _frame(src, dst, sport, dport, seq, ack, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload))


def _audit(tmp_path, captures, anchors=None, wiring=None, claims=None, opinions=None, disputes=None):
    return audit_files(
        captures,
        anchors=anchors or [],
        wiring=wiring or [],
        claims=claims or [],
        opinions=opinions or [],
        disputes=disputes or [],
        base_dir=tmp_path,
        service="diag",
    )


def test_cross_capture_handshake_confirms_both_capture_directions(tmp_path):
    cap_a = tmp_path / "a.pcap"
    cap_b = tmp_path / "b.pcap"
    _write_pcap(cap_a, [_syn(1000.0), _ack(1000.2)])
    _write_pcap(cap_b, [_synack(1000.1)])

    report = _audit(
        tmp_path,
        [
            {"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"},
            {"id": "cap_b", "path": "b.pcap", "declared_direction": "server_to_client"},
        ],
        anchors=[
            {"id": "A1", "time": 990, "capture": "cap_a", "source_role": "client"},
            {"id": "A2", "time": 990, "capture": "cap_b", "source_role": "server"},
        ],
        claims=[
            {"id": "C1", "capture": "cap_a", "from": 995, "to": 1010, "direction": "client_to_server"},
            {"id": "C2", "capture": "cap_b", "from": 995, "to": 1010, "direction": "server_to_client"},
        ],
    )

    assert report["summary"]["confirmed_sessions"] == 1
    assert report["summary"]["confirmed_claims"] == 2
    assert report["conflicts"] == []
    session = report["sessions"][0]
    assert session["handshake"]["state"] == "full"
    assert session["handshake"]["cross_capture"] is True
    assert {segment["capture"] for segment in session["handshake"]["segments"]} == {"cap_a", "cap_b"}
    assert {claim["verdict"] for claim in report["claims"]} == {"confirmed"}
    assert all(claim["trusted_anchor_ids"] for claim in report["claims"])
    assert session["direction"]["value"] == BIDIRECTIONAL
    # The handshake, not the display-only port data, is the evidence.
    assert any(row["kind"] == "tcp_handshake" for row in session["direction"]["evidence"])
    assert not any("port" in row["kind"] for row in session["direction"]["evidence"])


def test_rewire_reversal_is_confirmed_and_traceable_to_anchor(tmp_path):
    cap_a = tmp_path / "a.pcap"
    cap_b = tmp_path / "b.pcap"
    # After the cable swap cap_a observes server->client and cap_b observes
    # client->server.  The sequence/ack numbers still connect the two legs.
    _write_pcap(cap_a, [_synack(2000.1, seq=9000, ack=7001)])
    _write_pcap(cap_b, [_syn(2000.0, seq=7000), _ack(2000.2, seq=7001, ack=9001)])

    report = _audit(
        tmp_path,
        [
            {"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"},
            {"id": "cap_b", "path": "b.pcap", "declared_direction": "server_to_client"},
        ],
        anchors=[
            {"id": "A1", "time": 1900, "capture": "cap_a", "source_role": "client", "basis": "bench verified"},
            {"id": "A2", "time": 1900, "capture": "cap_b", "source_role": "server", "basis": "bench verified"},
        ],
        wiring=[
            {
                "id": "W1",
                "time": 1950,
                "captures": ["cap_a", "cap_b"],
                "direction": "reversed",
                "note": "mirror leads swapped",
            }
        ],
        claims=[
            {"id": "C1", "capture": "cap_a", "from": 1950, "to": 2100, "direction": "client_to_server"},
            {"id": "C2", "capture": "cap_b", "from": 1950, "to": 2100, "direction": "server_to_client"},
        ],
    )

    assert report["conflicts"] == []
    assert report["summary"]["reversed_claims"] == 2
    for claim in report["claims"]:
        assert claim["verdict"] == "reversed"
        assert claim["reversal_confirmed"] is True
        assert "A1" in claim["trusted_anchor_ids"] or "A2" in claim["trusted_anchor_ids"]
        assert any(event["id"].startswith("W1") for event in claim["anchor_trace"])
    trace_ids = {
        event["id"]
        for claim in report["claims"]
        for event in claim["anchor_trace"]
    }
    assert {"A1", "A2", "W1@cap_a", "W1@cap_b"} <= trace_ids
    markdown = render_markdown(report)
    assert "Reversal Traceability" in markdown
    assert "trusted anchor" in markdown
    assert "W1" in markdown


def test_half_handshake_with_investigator_disagreement_stays_undetermined(tmp_path):
    cap_a = tmp_path / "a.pcap"
    _write_pcap(cap_a, [_syn(3000.0, seq=12000)])

    selector = {
        "capture": "cap_a",
        "src": CLIENT,
        "sport": CLIENT_PORT,
        "dst": SERVER,
        "dport": SERVER_PORT,
    }
    report = _audit(
        tmp_path,
        [{"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"}],
        claims=[
            {"id": "C1", "capture": "cap_a", "from": 2990, "to": 3010, "direction": "client_to_server"},
        ],
        opinions=[
            {"investigator": "Li", "sample": selector, "direction": "client_to_server", "note": "SYN sender is the client"},
            {"investigator": "Wang", "sample": selector, "direction": "server_to_client", "note": "mirror polarity is unknown"},
        ],
    )

    session = report["sessions"][0]
    assert session["handshake"]["state"] == "syn_only"
    assert session["direction"]["status"] == "undetermined"
    assert session["direction"]["value"] == "unknown"
    assert set(session["direction"]["candidate_directions"]) == {CLIENT_TO_SERVER, SERVER_TO_CLIENT}
    assert report["candidates"][0]["session"] == session["id"]
    assert report["summary"]["disputes"] == 1
    dispute = report["disputes"][0]
    assert dispute["status"] == "undetermined"
    assert {row["investigator"] for row in dispute["opinions"]} == {"Li", "Wang"}
    assert dispute["packet_refs"] == ["cap_a#0"]
    assert "reciprocal" in dispute["why_pending"]
    markdown = render_markdown(report)
    assert "Why still pending" in markdown
    assert "Li" in markdown and "Wang" in markdown


def test_ports_are_display_only_even_when_they_look_backwards(tmp_path):
    cap_a = tmp_path / "a.pcap"
    cap_b = tmp_path / "b.pcap"
    # Client uses port 80, server uses 40000: a port heuristic would be wrong.
    _write_pcap(cap_a, [
        _syn(4000.0, sport=80, dport=40000, seq=3000),
        _ack(4000.2, sport=80, dport=40000, seq=3001, ack=8001),
    ])
    _write_pcap(cap_b, [
        _synack(4000.1, sport=40000, dport=80, seq=8000, ack=3001),
    ])
    report = _audit(
        tmp_path,
        [
            {"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"},
            {"id": "cap_b", "path": "b.pcap", "declared_direction": "server_to_client"},
        ],
        claims=[{"id": "C1", "capture": "cap_a", "from": 3990, "to": 4010, "direction": "client_to_server"}],
    )
    session = report["sessions"][0]
    assert session["direction"]["status"] == "confirmed"
    assert session["direction"]["value"] == BIDIRECTIONAL
    assert session["display_only"]["ports"] == {"80": 3, "40000": 3}
    assert report["claims"][0]["verdict"] == "confirmed"
    assert all(row["kind"] != "port" for row in session["direction"]["evidence"])


def test_mutually_exclusive_anchors_report_conflict_sources(tmp_path):
    cap_a = tmp_path / "a.pcap"
    _write_pcap(cap_a, [_data(4000.0, CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 1, 1)])
    report = _audit(
        tmp_path,
        [{"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"}],
        anchors=[
            {"id": "A1", "time": 3900, "capture": "cap_a", "source_role": "client", "basis": "capture station log"},
            {"id": "A2", "time": 4100, "capture": "cap_a", "source_role": "server", "basis": "second reviewer"},
        ],
        claims=[{"id": "C1", "capture": "cap_a", "from": 3950, "to": 4050, "direction": "client_to_server"}],
    )
    assert report["summary"]["conflicts"] >= 1
    conflict = next(item for item in report["conflicts"] if item["kind"] == "trusted_anchor_disagreement")
    assert {source["id"] for source in conflict["sources"]} == {"A1", "A2"}
    assert "mutually exclusive" in conflict["detail"]
    assert report["claims"][0]["verdict"] == "conflict"
    assert report["sessions"][0]["direction"]["status"] == "conflict"


def test_two_of_three_handshake_is_strong_when_final_ack_missing(tmp_path):
    cap_a = tmp_path / "a.pcap"
    cap_b = tmp_path / "b.pcap"
    _write_pcap(cap_a, [_syn(5000.0, seq=9000)])
    _write_pcap(cap_b, [_synack(5000.1, seq=12000, ack=9001)])
    report = _audit(
        tmp_path,
        [
            {"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"},
            {"id": "cap_b", "path": "b.pcap", "declared_direction": "server_to_client"},
        ],
        claims=[{"id": "C1", "capture": "cap_a", "from": 4990, "to": 5010, "direction": "client_to_server"}],
    )
    session = report["sessions"][0]
    assert session["handshake"]["state"] == "two_way"
    assert session["handshake"]["strong"] is True
    assert session["direction"]["status"] == "confirmed"
    assert any("Final ACK was not captured" in note for note in session["handshake"]["notes"])


def test_capture_files_are_not_modified(tmp_path):
    cap_a = tmp_path / "a.pcap"
    _write_pcap(cap_a, [_syn(6000.0), _synack(6000.1), _ack(6000.2)])
    before = hashlib.sha256(cap_a.read_bytes()).hexdigest()
    report = _audit(
        tmp_path,
        [{"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"}],
    )
    after = hashlib.sha256(cap_a.read_bytes()).hexdigest()
    assert before == after
    assert report["read_only"] is True
    assert report["captures"][0]["sha256"] == before


def test_case_relative_paths_and_sample_scoped_claim(tmp_path):
    cap_a = tmp_path / "a.pcap"
    _write_pcap(cap_a, [_synack(7000.0, seq=5000, ack=1001)])
    raw = {
        "captures": {"cap_a": {"path": "a.pcap", "declared_direction": "server_to_client"}},
        "claims": [
            {
                "id": "C1",
                "capture": "cap_a",
                "direction": "server_to_client",
                "sample": {"capture": "cap_a", "src": SERVER},
            }
        ],
    }
    case = case_from_dict(raw, base_dir=tmp_path)
    report = audit_case(case)
    session = report["sessions"][0]
    assert session["handshake"]["state"] == "synack_only"
    assert session["direction"]["status"] == "candidate"
    assert report["claims"][0]["verdict"] == "candidate"


def test_relative_direction_is_resolved_from_capture_declaration(tmp_path):
    cap_a = tmp_path / "a.pcap"
    _write_pcap(cap_a, [_syn(8000.0, seq=1000), _synack(8000.1, seq=5000, ack=1001), _ack(8000.2)])
    report = _audit(
        tmp_path,
        [{"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"}],
        wiring=[{"id": "W1", "time": 7900, "capture": "cap_a", "direction": "reversed"}],
        claims=[{"id": "C1", "capture": "cap_a", "from": 7990, "to": 8010, "direction": "reversed"}],
    )
    # The capture sees both directions, so a single-direction claim is too narrow
    # even though the relative direction resolved to server_to_client.
    assert report["claims"][0]["claimed_direction"] == SERVER_TO_CLIENT
    assert report["claims"][0]["verdict"] == "conflict"
    assert report["sessions"][0]["handshake"]["cross_capture"] is False


def test_cross_capture_handshake_survives_recorder_clock_offset(tmp_path):
    cap_a = tmp_path / "a.pcap"
    cap_b = tmp_path / "b.pcap"
    _write_pcap(cap_a, [_syn(1000.0, seq=4100)])
    _write_pcap(cap_b, [_synack(1000000.1, seq=8100, ack=4101)])
    report = _audit(
        tmp_path,
        [
            {"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"},
            {"id": "cap_b", "path": "b.pcap", "declared_direction": "server_to_client"},
        ],
        claims=[{"id": "C1", "capture": "cap_a", "from": 990, "to": 1010, "direction": "client_to_server"}],
    )
    session = report["sessions"][0]
    assert session["handshake"]["state"] == "two_way"
    assert session["handshake"]["cross_capture"] is True
    assert report["claims"][0]["verdict"] == "confirmed"


def test_handshake_contradicting_anchor_keeps_conflict_source(tmp_path):
    cap_a = tmp_path / "a.pcap"
    cap_b = tmp_path / "b.pcap"
    _write_pcap(cap_a, [_syn(5000.0, seq=7000), _ack(5000.2, seq=7001, ack=9001)])
    _write_pcap(cap_b, [_synack(5000.1, seq=9000, ack=7001)])
    report = _audit(
        tmp_path,
        [
            {"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"},
            {"id": "cap_b", "path": "b.pcap", "declared_direction": "server_to_client"},
        ],
        anchors=[
            {"id": "A1", "time": 4900, "capture": "cap_a", "source_role": "server", "basis": "bad anchor"},
        ],
        claims=[{"id": "C1", "capture": "cap_a", "from": 4990, "to": 5010, "direction": "client_to_server"}],
    )
    assert report["claims"][0]["verdict"] == "confirmed"
    conflict = next(item for item in report["conflicts"] if item["kind"] == "handshake_vs_trusted_epoch")
    assert conflict["sources"][0]["kind"] == "tcp_handshake"
    assert any(source.get("kind") == "anchor_or_wiring_trace" for source in conflict["sources"])
    assert conflict["id"] in report["claims"][0]["conflict_ids"]


def test_anchor_plus_wiring_change_supports_reversal_without_handshake(tmp_path):
    cap_a = tmp_path / "a.pcap"
    _write_pcap(cap_a, [
        _data(1200.0, SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 5001, 1001),
    ])
    report = _audit(
        tmp_path,
        [{"id": "cap_a", "path": "a.pcap", "declared_direction": "client_to_server"}],
        anchors=[{"id": "A1", "time": 1000, "capture": "cap_a", "source_role": "client"}],
        wiring=[{"id": "W1", "time": 1100, "capture": "cap_a", "direction": "reversed"}],
        claims=[{"id": "C1", "capture": "cap_a", "from": 1150, "to": 1250, "direction": "client_to_server"}],
    )
    session = report["sessions"][0]
    assert session["direction"]["status"] == "supported"
    assert session["direction"]["value"] == SERVER_TO_CLIENT
    claim = report["claims"][0]
    assert claim["verdict"] == "reversed"
    assert claim["evidence_grade"] == "supported"
    assert claim["trusted_anchor_ids"] == ["A1"]
    assert any(row["kind"] == "anchor_plus_wiring_record" for row in claim["evidence"])
    assert any(event["id"].startswith("W1") for event in claim["anchor_trace"])


def test_id_keyed_json_records_are_accepted(tmp_path):
    cap_a = tmp_path / "a.pcap"
    _write_pcap(cap_a, [_syn(9000.0), _synack(9000.1), _ack(9000.2)])
    raw = {
        "captures": {"cap_a": "a.pcap"},
        "anchors": {"A1": {"time": 8900, "capture": "cap_a", "source_role": "client"}},
        "claims": {"C1": {"capture": "cap_a", "from": 8990, "to": 9010, "direction": "bidirectional"}},
    }
    report = audit_case(case_from_dict(raw, base_dir=tmp_path))
    assert report["anchors"][0]["id"] == "A1"
    assert report["claims"][0]["id"] == "C1"
    assert report["claims"][0]["verdict"] == "confirmed"


def test_pcapng_raw_and_sll_inputs_are_supported(tmp_path):
    frames = [_syn(10000.0), _synack(10000.1), _ack(10000.2)]

    pcapng_path = tmp_path / "a.pcapng"
    with open(pcapng_path, "wb") as handle:
        writer = dpkt.pcapng.Writer(handle)
        for timestamp, frame in frames:
            writer.writepkt(frame, ts=timestamp)

    raw_path = tmp_path / "a.raw"
    with open(raw_path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle, linktype=dpkt.pcap.DLT_RAW)
        for timestamp, frame in frames:
            writer.writepkt(bytes(dpkt.ethernet.Ethernet(frame).data), ts=timestamp)

    sll_path = tmp_path / "a.sll"
    with open(sll_path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle, linktype=dpkt.pcap.DLT_LINUX_SLL)
        for timestamp, frame in frames:
            network = dpkt.ethernet.Ethernet(frame).data
            sll = dpkt.sll.SLL(
                type=0, hrd=1, hlen=6, hdr=b"\x00" * 8,
                ethtype=dpkt.ethernet.ETH_TYPE_IP, data=network,
            )
            writer.writepkt(sll, ts=timestamp)

    for name in ("a.pcapng", "a.raw", "a.sll"):
        report = _audit(
            tmp_path,
            [{"id": "cap_a", "path": name, "declared_direction": "client_to_server"}],
        )
        assert report["captures"][0]["packet_count"] == 3
        assert report["sessions"][0]["handshake"]["state"] == "full"
        assert report["sessions"][0]["direction"]["status"] == "confirmed"


def test_ipv6_tcp_handshake_is_audited(tmp_path):
    client6 = "2001:db8::10"
    server6 = "2001:db8::20"

    def frame(src, dst, sport, dport, seq, ack, flags):
        tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
        ip6 = dpkt.ip6.IP6(
            src=socket.inet_pton(socket.AF_INET6, src),
            dst=socket.inet_pton(socket.AF_INET6, dst),
            nxt=dpkt.ip.IP_PROTO_TCP,
            data=tcp,
        )
        return bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP6, data=ip6))

    cap = tmp_path / "v6.pcap"
    _write_pcap(cap, [
        (11000.0, frame(client6, server6, 40000, 9100, 1000, 0, dpkt.tcp.TH_SYN)),
        (11000.1, frame(server6, client6, 9100, 40000, 5000, 1001, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)),
        (11000.2, frame(client6, server6, 40000, 9100, 1001, 5001, dpkt.tcp.TH_ACK)),
    ])
    report = _audit(
        tmp_path,
        [{"id": "cap_a", "path": "v6.pcap", "declared_direction": "client_to_server"}],
    )
    session = report["sessions"][0]
    assert session["handshake"]["state"] == "full"
    assert session["direction"]["status"] == "confirmed"
    assert session["flow"].count("2001:db8::") == 2
