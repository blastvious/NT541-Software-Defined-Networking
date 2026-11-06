"""Chay Ryu app voi parser OpenFlow that va switch gia lap. Can bien RYU_SRC tro toi ma nguon Ryu.
Tren may ao da cai Ryu thi khong can dat RYU_SRC."""
import os
import sys
import types
import tempfile

import pytest

for extra in filter(None, [os.environ.get("RYU_SRC"), os.environ.get("NETADDR_SRC")]):
    sys.path.insert(0, extra)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Controller"))

# Thay hub va cfg bang ban toi gian de khong can eventlet, oslo.config khi test.
hub = types.ModuleType("ryu.lib.hub")
hub.spawn = lambda *args, **kwargs: None
hub.sleep = lambda *args, **kwargs: None
hub.Event = object
sys.modules["ryu.lib.hub"] = hub


class _Conf(dict):
    def __getattr__(self, name):
        return _Conf()

    def __getitem__(self, name):
        return _Conf()

    def __call__(self, *args, **kwargs):
        return None


class _Cfg(types.ModuleType):
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


cfg = _Cfg("ryu.cfg")
cfg.CONF = _Conf()
sys.modules["ryu.cfg"] = cfg

# app_manager keo theo wsgi, routes, webob; test chi can lop co so RyuApp.


class _RyuApp:
    def __init__(self, *args, **kwargs):
        import logging
        self.logger = logging.getLogger("test")


app_manager = types.ModuleType("ryu.base.app_manager")
app_manager.RyuApp = _RyuApp
sys.modules["ryu.base.app_manager"] = app_manager

ryu_ok = True
try:
    import ryu.lib
    ryu.lib.hub = hub
    ryu.cfg = cfg
    from ryu.lib.packet import arp, ethernet, icmp, ipv4, packet, tcp
    from ryu.ofproto import ofproto_v1_3 as ofp, ofproto_v1_3_parser as parser
    import dos_guard
except ImportError as error:  # pragma: no cover
    ryu_ok = False
    import_error = error
    print("Khong nap duoc Ryu:", error)

if not ryu_ok:
    pytest.skip("can Ryu de chay test nay", allow_module_level=True)

H1_MAC, H4_MAC = "00:00:00:00:00:01", "00:00:00:00:00:04"
H1, H4 = "10.0.0.1", "10.0.0.4"


class FakeDatapath:
    ofproto = ofp
    ofproto_parser = parser

    def __init__(self, dpid):
        self.id = dpid
        self.sent = []
        self.xid = 0

    def set_xid(self, msg):
        self.xid += 1
        msg.set_xid(self.xid)

    def send_msg(self, msg):
        # Serialize that de phat hien match, action hoac truong sai.
        msg.set_xid(1)
        msg.serialize()
        self.sent.append(msg)


class Event:
    def __init__(self, msg):
        self.msg = msg


def frame(src_mac, dst_mac, src_ip, dst_ip, l4):
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=0x0800))
    proto = 6 if isinstance(l4, tcp.tcp) else 1
    pkt.add_protocol(ipv4.ipv4(src=src_ip, dst=dst_ip, proto=proto))
    pkt.add_protocol(l4)
    pkt.serialize()
    return bytes(pkt.data)


def arp_frame(src_mac, dst_mac, src_ip, dst_ip, opcode):
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=0x0806))
    pkt.add_protocol(arp.arp(opcode=opcode, src_mac=src_mac, src_ip=src_ip,
                             dst_mac="00:00:00:00:00:00", dst_ip=dst_ip))
    pkt.serialize()
    return bytes(pkt.data)


def packet_in(datapath, in_port, data, reason=ofp.OFPR_NO_MATCH):
    msg = parser.OFPPacketIn(datapath, buffer_id=ofp.OFP_NO_BUFFER, total_len=len(data),
                             reason=reason, table_id=0, cookie=0,
                             match=parser.OFPMatch(in_port=in_port), data=data)
    return Event(msg)


def syn():
    return tcp.tcp(src_port=1234, dst_port=80, seq=1, bits=0x02)


def rst_ack():
    return tcp.tcp(src_port=80, dst_port=1234, seq=1, ack=2, bits=0x14)


@pytest.fixture
def app(monkeypatch):
    path = tempfile.mktemp(suffix=".csv")
    monkeypatch.setenv("DOS_EVENT_LOG", path)
    monkeypatch.setenv("DOS_MITIGATE", "1")
    monkeypatch.setattr(dos_guard.hub, "spawn", lambda *a, **k: None)
    guard = dos_guard.DoSGuard()
    return guard


def connect(app, dpid):
    datapath = FakeDatapath(dpid)
    app.datapaths[dpid] = datapath
    return datapath


def stats_reply(datapath, entries):
    body = []
    for match, packets, octets, seconds in entries:
        body.append(parser.OFPFlowStats(table_id=0, duration_sec=seconds, duration_nsec=0,
                                        priority=1, idle_timeout=30, hard_timeout=0, flags=0,
                                        cookie=0, packet_count=packets, byte_count=octets,
                                        match=match, instructions=[]))
    msg = parser.OFPFlowStatsReply(datapath)
    msg.body = body
    return Event(msg)


def learn_hosts(app, s1):
    app.packet_in_handler(packet_in(s1, 2, arp_frame(H1_MAC, "ff:ff:ff:ff:ff:ff", H1, H4, 1)))
    app.packet_in_handler(packet_in(s1, 1, arp_frame(H4_MAC, H1_MAC, H4, H1, 2)))


def flow_mods(datapath, priority=None):
    mods = [m for m in datapath.sent if isinstance(m, parser.OFPFlowMod)]
    return [m for m in mods if priority is None or m.priority == priority]


def test_table_miss_is_installed_with_real_parser(app):
    datapath = FakeDatapath(1)
    app.switch_features_handler(Event(type("M", (), {"datapath": datapath})()))
    mod = flow_mods(datapath)[0]
    assert mod.priority == 0 and app.datapaths[1] is datapath


def test_forward_rule_is_per_ip_and_protocol_with_timeout(app):
    s1 = connect(app, 1)
    learn_hosts(app, s1)
    app.packet_in_handler(packet_in(s1, 2, frame(H1_MAC, H4_MAC, H1, H4, syn())))
    ip_rules = [m for m in flow_mods(s1, 1) if "ip_proto" in m.match]
    assert len(ip_rules) == 1
    match = ip_rules[0].match
    assert match["ipv4_src"] == H1 and match["ipv4_dst"] == H4 and match["ip_proto"] == 6
    assert ip_rules[0].idle_timeout == 30


def run_attack_to_block(app, s1):
    learn_hosts(app, s1)
    app.packet_in_handler(packet_in(s1, 2, frame(H1_MAC, H4_MAC, H1, H4, syn())))
    match = [m for m in flow_mods(s1, 1) if "ip_proto" in m.match][0].match
    app.flow_stats_reply_handler(stats_reply(s1, [(match, 839, 45306, 1)]))
    sample = flow_mods(s1, 50)[0]
    assert sample.hard_timeout == 2 and sample.match["ipv4_src"] == H1
    for _ in range(20):
        app.packet_in_handler(packet_in(s1, 2, frame(H1_MAC, H4_MAC, H1, H4, syn()), ofp.OFPR_ACTION))


def test_syn_flood_end_to_end_installs_edge_block(app):
    s1 = connect(app, 1)
    run_attack_to_block(app, s1)
    block = flow_mods(s1, 100)[0]
    assert block.match["in_port"] == 2 and block.match["ipv4_dst"] == H4 and block.match["ip_proto"] == 6
    assert "ipv4_src" not in block.match
    assert block.instructions == [] and block.hard_timeout == 30
    deletes = [m for m in flow_mods(s1, 50) if m.command == ofp.OFPFC_DELETE_STRICT]
    assert len(deletes) == 1
    with open(app.event_path) as handle:
        text = handle.read()
    assert "blocked" in text and "syn_flood" in text


def test_sampled_packets_are_not_sent_out_twice(app):
    s1 = connect(app, 1)
    learn_hosts(app, s1)
    app.packet_in_handler(packet_in(s1, 2, frame(H1_MAC, H4_MAC, H1, H4, syn())))
    before = len(s1.sent)
    app.packet_in_handler(packet_in(s1, 2, frame(H1_MAC, H4_MAC, H1, H4, syn()), ofp.OFPR_ACTION))
    assert len(s1.sent) == before


def test_victim_reply_flow_on_edge_is_not_blocked(app):
    s2 = connect(app, 2)
    app.packet_in_handler(packet_in(s2, 1, arp_frame(H1_MAC, "ff:ff:ff:ff:ff:ff", H1, H4, 1)))
    app.packet_in_handler(packet_in(s2, 2, arp_frame(H4_MAC, H1_MAC, H4, H1, 2)))
    app.packet_in_handler(packet_in(s2, 2, frame(H4_MAC, H1_MAC, H4, H1, rst_ack())))
    match = [m for m in flow_mods(s2, 1) if "ip_proto" in m.match][0].match
    app.flow_stats_reply_handler(stats_reply(s2, [(match, 839, 45306, 1)]))
    for _ in range(20):
        app.packet_in_handler(packet_in(s2, 2, frame(H4_MAC, H1_MAC, H4, H1, rst_ack()), ofp.OFPR_ACTION))
    assert flow_mods(s2, 100) == []


def test_transit_stats_are_ignored(app):
    s1 = connect(app, 1)
    match = parser.OFPMatch(in_port=1, eth_src=H4_MAC, eth_dst=H1_MAC, eth_type=0x0800,
                            ip_proto=6, ipv4_src=H4, ipv4_dst=H1)
    app.flow_stats_reply_handler(stats_reply(s1, [(match, 839, 45306, 1)]))
    assert app.engine.samples == {}


def test_spoofed_flood_blocks_edge_port(app):
    s1 = connect(app, 1)
    learn_hosts(app, s1)
    sent_before = len(s1.sent)
    for index in range(22):
        spoof = "172.16.0.%d" % (index + 1)
        app.packet_in_handler(packet_in(s1, 2, frame(H1_MAC, H4_MAC, spoof, H4, syn())))
    block = flow_mods(s1, 110)
    assert len(block) == 1 and block[0].match["in_port"] == 2
    assert not [m for m in s1.sent[sent_before:] if isinstance(m, parser.OFPPacketOut)]


def test_detect_only_mode_logs_without_blocking(app):
    app.mitigate = False
    s1 = connect(app, 1)
    run_attack_to_block(app, s1)
    assert flow_mods(s1, 100) == []
    with open(app.event_path) as handle:
        text = handle.read()
    assert "detected" in text and "blocked" not in text


def test_flood_reply_burst_keeps_victim_port_open_and_installs_one_rule(app):
    s2 = connect(app, 2)
    app.packet_in_handler(packet_in(s2, 1, arp_frame(H1_MAC, "ff:ff:ff:ff:ff:ff", H1, H4, 1)))
    app.packet_in_handler(packet_in(s2, 2, arp_frame(H4_MAC, H1_MAC, H4, H1, 2)))
    for _ in range(300):
        app.packet_in_handler(packet_in(s2, 2, frame(H4_MAC, H1_MAC, H4, H1, rst_ack())))
    assert flow_mods(s2, 110) == [] and flow_mods(s2, 100) == []
    assert len([m for m in flow_mods(s2, 1) if "ip_proto" in m.match]) == 1
    outs = [m for m in s2.sent if isinstance(m, parser.OFPPacketOut)]
    assert len(outs) == 302


def test_syn_flood_setup_burst_still_ends_in_syn_block(app):
    s1 = connect(app, 1)
    learn_hosts(app, s1)
    for _ in range(300):
        app.packet_in_handler(packet_in(s1, 2, frame(H1_MAC, H4_MAC, H1, H4, syn())))
    assert flow_mods(s1, 110) == []
    match = [m for m in flow_mods(s1, 1) if "ip_proto" in m.match][0].match
    app.flow_stats_reply_handler(stats_reply(s1, [(match, 5000, 270000, 1)]))
    for _ in range(20):
        app.packet_in_handler(packet_in(s1, 2, frame(H1_MAC, H4_MAC, H1, H4, syn()), ofp.OFPR_ACTION))
    assert len(flow_mods(s1, 100)) == 1
