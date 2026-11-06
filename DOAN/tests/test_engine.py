import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Controller"))

from dos_engine import (ALLOW, BlockFlow, BlockPort, Config, DetectionEngine, DROP, FlowKey,
                        FlowSample, Note, PROTO_ICMP, PROTO_TCP, PROTO_UDP, StartSample, StopSample)

H1_MAC, H2_MAC, H4_MAC = "ba:21:cf:91:39:ff", "76:0f:39:5a:3c:04", "de:27:b4:5b:65:e6"
H1, H2, H4 = "10.0.0.1", "10.0.0.2", "10.0.0.4"


def key(proto=PROTO_TCP, src_mac=H1_MAC, src=H1, dst_mac=H4_MAC, dst=H4, port=2, dpid=1):
    return FlowKey(dpid, port, src_mac, dst_mac, src, dst, proto)


def types(actions):
    return [type(action) for action in actions]


def feed_rate(engine, flow, pps, size, start=100.0, seconds=3):
    actions, packets = [], 0
    for second in range(seconds + 1):
        packets = int(pps * second)
        actions += engine.on_flow_stats(start + second, [FlowSample(flow, packets, packets * size, second + 1.0)])
    return actions


def test_syn_flood_from_test_a_is_blocked():
    # Toc do do duoc o Test A: 839 pps, frame 54 byte.
    engine = DetectionEngine()
    assert StartSample in types(feed_rate(engine, key(), 839, 54, seconds=1))
    actions = []
    for index in range(20):
        actions += engine.on_sample(102.0 + index / 1000, key(), True)
    assert types(actions)[:2] == [StopSample, BlockFlow]
    block = actions[1]
    assert (block.reason, block.dpid, block.port, block.dst_ip, block.proto) == ("syn_flood", 1, 2, H4, PROTO_TCP)


def test_victim_rst_reply_is_not_blocked():
    # Test A cho thay h4 tra RST cung toc do va kich thuoc nhu h1.
    engine = DetectionEngine()
    reply = key(src_mac=H4_MAC, src=H4, dst_mac=H1_MAC, dst=H1, port=2, dpid=2)
    assert StartSample in types(feed_rate(engine, reply, 839, 54, seconds=1))
    actions = []
    for index in range(20):
        actions += engine.on_sample(102.0, reply, False)
    assert BlockFlow not in types(actions)
    assert any(isinstance(a, Note) and a.event == "cleared" for a in actions)


def test_iperf_flow_is_sampled_once_then_left_alone():
    # Test A: iperf h2->h4 co 191 goi/giay trong counter, moi goi khoang 62 KB do TSO.
    engine = DetectionEngine()
    flow = key(src_mac=H2_MAC, src=H2, port=3)
    feed_rate(engine, flow, 191, 62000, seconds=1)
    actions = []
    for _ in range(20):
        actions += engine.on_sample(102.0, flow, False)
    assert BlockFlow not in types(actions)
    assert not engine.flow_blocks
    later = feed_rate(engine, flow, 191, 62000, start=110.0, seconds=2)
    assert StartSample not in types(later)


def test_sample_timeout_without_packets_clears():
    engine = DetectionEngine()
    feed_rate(engine, key(), 839, 54, seconds=1)
    assert engine.tick(101.0) == []
    actions = engine.tick(110.0)
    assert StopSample in types(actions) and BlockFlow not in types(actions)
    assert not engine.samples


def test_icmp_flood_blocks_request_side_only():
    engine = DetectionEngine()
    request = key(proto=PROTO_ICMP)
    feed_rate(engine, request, 835, 42, seconds=1)
    actions = []
    for _ in range(20):
        actions += engine.on_sample(102.0, request, True)
    assert actions[1].reason == "icmp_flood"


def test_low_rate_ping_is_ignored():
    engine = DetectionEngine()
    assert feed_rate(engine, key(proto=PROTO_ICMP), 1, 98) == []


def test_udp_flood_needs_two_windows():
    engine = DetectionEngine()
    flow = key(proto=PROTO_UDP)
    assert engine.on_flow_stats(100.0, [FlowSample(flow, 1000, 42000, 2.0)]) == []
    actions = engine.on_flow_stats(101.0, [FlowSample(flow, 1835, 77070, 3.0)])
    assert types(actions) == [BlockFlow] and actions[0].reason == "udp_flood"


def test_legit_iperf_udp_10mbps_is_not_blocked():
    engine = DetectionEngine()
    assert feed_rate(engine, key(proto=PROTO_UDP, port=3), 850, 1512, seconds=5) == []


def test_very_high_bandwidth_udp_is_blocked():
    engine = DetectionEngine()
    actions = feed_rate(engine, key(proto=PROTO_UDP), 8000, 1400, seconds=3)
    assert BlockFlow in types(actions)


def test_short_udp_burst_does_not_block():
    engine = DetectionEngine()
    flow = key(proto=PROTO_UDP)
    engine.on_flow_stats(100.0, [FlowSample(flow, 0, 0, 1.0)])
    engine.on_flow_stats(101.0, [FlowSample(flow, 900, 37800, 2.0)])
    assert engine.on_flow_stats(102.0, [FlowSample(flow, 900, 37800, 3.0)]) == []
    assert engine.on_flow_stats(103.0, [FlowSample(flow, 1800, 75600, 4.0)]) == []


def test_flow_block_timeout_doubles_on_repeat_and_resets_later():
    engine = DetectionEngine()
    assert engine._block_flow(100.0, key(), "syn_flood", "").timeout == 30
    assert engine._block_flow(140.0, key(), "syn_flood", "").timeout == 60
    assert engine._block_flow(210.0, key(), "syn_flood", "").timeout == 120
    assert engine._block_flow(1000.0, key(), "syn_flood", "").timeout == 30


def test_block_timeout_has_ceiling():
    engine = DetectionEngine(Config(offence_forget=10 ** 9))
    timeouts = [engine._block_flow(float(i), key(), "x", "").timeout for i in range(8)]
    assert max(timeouts) == 480


def test_blocked_source_is_never_forwarded_from_stale_packet_in():
    engine = DetectionEngine()
    engine._block_flow(100.0, key(), "syn_flood", "")
    assert engine.on_packet_in(100.1, 1, 2, H1_MAC, H1, PROTO_TCP, H4)[0] == DROP
    # h1 van di toi dich khac, va h2 van di toi h4.
    assert engine.on_packet_in(100.1, 1, 2, H1_MAC, H1, PROTO_TCP, H2)[0] == ALLOW
    assert engine.on_packet_in(100.1, 1, 3, H2_MAC, H2, PROTO_TCP, H4)[0] == ALLOW


def test_block_expires():
    engine = DetectionEngine()
    engine._block_flow(100.0, key(), "syn_flood", "")
    assert any(isinstance(a, Note) and a.event == "released" for a in engine.tick(131.0))
    assert engine.on_packet_in(131.0, 1, 2, H1_MAC, H1, PROTO_TCP, H4)[0] == ALLOW


def test_spoofing_victim_ip_blocks_attacker_port_not_victim():
    engine = DetectionEngine()
    assert engine.on_packet_in(100.0, 1, 3, H2_MAC, H2)[0] == ALLOW
    assert engine.on_packet_in(100.0, 1, 2, H1_MAC, H1)[0] == ALLOW
    last = None
    for _ in range(21):
        last = engine.on_packet_in(101.0, 1, 2, H1_MAC, H2, PROTO_TCP, H4)
    assert last[0] == DROP and types(last[1]) == [BlockPort]
    assert last[1][0].port == 2 and last[1][0].reason == "spoofing"
    assert engine.on_packet_in(101.5, 1, 3, H2_MAC, H2, PROTO_TCP, H4)[0] == ALLOW


def test_random_source_flood_blocks_port():
    engine = DetectionEngine()
    engine.on_packet_in(100.0, 1, 2, H1_MAC, H1)
    blocks = []
    for index in range(30):
        ip = "172.16.%d.%d" % (index // 200, index % 200 + 1)
        verdict, actions = engine.on_packet_in(101.0, 1, 2, H1_MAC, ip, PROTO_TCP, H4)
        assert verdict == DROP
        blocks += actions
    assert types(blocks) == [BlockPort]


def test_random_mac_flood_blocks_port():
    engine = DetectionEngine()
    engine.on_packet_in(100.0, 1, 2, H1_MAC, H1)
    blocks = []
    for index in range(30):
        mac = "02:00:00:00:00:%02x" % index
        blocks += engine.on_packet_in(101.0, 1, 2, mac, H1, PROTO_TCP, H4)[1]
    assert types(blocks) == [BlockPort]


def test_binding_released_after_port_block_expires():
    engine = DetectionEngine()
    engine.on_packet_in(100.0, 1, 2, H1_MAC, "172.16.0.1")
    assert engine.on_packet_in(100.1, 1, 2, H1_MAC, H1)[0] == DROP
    engine._block_port(100.2, (1, 2), "spoofing", "")
    engine.tick(140.0)
    assert engine.on_packet_in(140.1, 1, 2, H1_MAC, H1)[0] == ALLOW


def test_packet_in_flood_blocks_port_with_valid_source():
    engine = DetectionEngine()
    blocks = []
    for _ in range(101):
        blocks += engine.on_packet_in(100.0, 1, 2, H1_MAC, H1)[1]
    assert types(blocks) == [BlockPort] and blocks[0].reason == "packet_in_flood"


def test_flow_setup_burst_from_test_b_is_not_a_violation():
    # Test B: 26 packet_in tren 2 switch, tuc khoang 13 goi tai cong bien.
    engine = DetectionEngine()
    results = [engine.on_packet_in(100.0, 1, 2, H1_MAC, H1, PROTO_TCP, H4) for _ in range(13)]
    assert all(verdict == ALLOW and not actions for verdict, actions in results)


def test_counter_reset_does_not_produce_negative_rate():
    engine = DetectionEngine()
    engine.on_flow_stats(100.0, [FlowSample(key(), 5000, 270000, 10.0)])
    assert engine.on_flow_stats(101.0, [FlowSample(key(), 5, 270, 1.0)]) == []


def test_victim_reply_burst_during_flow_setup_does_not_block_port():
    # Flood lam h4 gui hang tram goi RST truoc khi rule chieu ve kip cai.
    engine = DetectionEngine()
    flow = (H4_MAC, H1_MAC, 0x0800, PROTO_TCP, H4, H1)
    actions = []
    assert engine.on_packet_in(100.0, 2, 2, H4_MAC, H4, PROTO_TCP, H1, flow)[0] == ALLOW
    assert engine.note_flow_installed(100.0, 2, 2, flow) is True
    for index in range(500):
        now = 100.0 + index / 1000
        verdict, new = engine.on_packet_in(now, 2, 2, H4_MAC, H4, PROTO_TCP, H1, flow)
        assert verdict == ALLOW
        actions += new
        assert engine.note_flow_installed(now, 2, 2, flow) is False
    assert actions == [] and not engine.port_blocks


def test_packet_in_that_never_gets_a_rule_still_blocks_port():
    engine = DetectionEngine()
    flow = (H1_MAC, "ff:ff:ff:ff:ff:ff", 0x0806, None, H1, None)
    blocks = []
    for _ in range(101):
        blocks += engine.on_packet_in(100.0, 1, 2, H1_MAC, H1, None, None, flow)[1]
    assert types(blocks) == [BlockPort]


def test_packet_in_persisting_after_setup_grace_is_counted_again():
    engine = DetectionEngine()
    flow = (H1_MAC, H4_MAC, 0x0800, PROTO_TCP, H1, H4)
    engine.note_flow_installed(100.0, 1, 2, flow)
    blocks = []
    for _ in range(101):
        blocks += engine.on_packet_in(103.0, 1, 2, H1_MAC, H1, PROTO_TCP, H4, flow)[1]
    assert types(blocks) == [BlockPort]
