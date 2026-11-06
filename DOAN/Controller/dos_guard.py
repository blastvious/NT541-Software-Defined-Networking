"""Ryu app DoS Guard. Chay: ryu-manager dos_guard.py

Bien moi truong:
  DOS_MITIGATE=0        chi phat hien, khong chan (de do muc anh huong cua tan cong)
  DOS_EVENT_LOG=<path>  file CSV su kien, mac dinh ./dos_events.csv
"""
import csv
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import arp, ether_types, ethernet, icmp, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3

from dos_engine import (BlockFlow, BlockPort, DetectionEngine, DROP, FlowKey,
                        FlowSample, Note, PROTO_ICMP, PROTO_TCP, StartSample, StopSample)

# Cong noi giua cac switch theo 23521717_custom_topology.py. Cac cong con lai la cong bien.
TRANSIT_PORTS = {1: {1}, 2: {1}}

PRIORITY_MISS = 0
PRIORITY_FORWARD = 1
PRIORITY_SAMPLE = 50
PRIORITY_BLOCK_FLOW = 100
PRIORITY_BLOCK_PORT = 110
FORWARD_IDLE_TIMEOUT = 30
SAMPLE_BYTES = 128
TCP_SYN = 0x02
TCP_ACK = 0x10


class DoSGuard(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DoSGuard, self).__init__(*args, **kwargs)
        self.engine = DetectionEngine()
        self.mitigate = os.environ.get("DOS_MITIGATE", "1") != "0"
        self.datapaths = {}
        self.mac_to_port = {}
        self.event_path = os.environ.get("DOS_EVENT_LOG", "dos_events.csv")
        with open(self.event_path, "w", newline="") as handle:
            csv.writer(handle).writerow(["time", "event", "reason", "dpid", "port", "timeout", "detail"])
        self.logger.info("DoS Guard: mitigate=%s, events=%s", self.mitigate, self.event_path)
        self.monitor_thread = hub.spawn(self._monitor)

    # ---------- Ket noi switch ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, PRIORITY_MISS, parser.OFPMatch(), actions)

    def _add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = []
        if actions:
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=instructions,
            idle_timeout=idle, hard_timeout=hard))

    def _is_edge(self, dpid, port):
        return port not in TRANSIT_PORTS.get(dpid, ())

    # ---------- Xu ly packet_in ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        in_port = msg.match["in_port"]
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # Goi mau da duoc rule lay mau chuyen tiep, controller chi doc de phan loai.
        if msg.reason == datapath.ofproto.OFPR_ACTION:
            self._handle_sample(datapath.id, in_port, eth, ip_pkt, pkt)
            return

        if self._is_edge(datapath.id, in_port):
            source_ip, dst_ip, proto = self._addresses(pkt, ip_pkt)
            verdict, actions = self.engine.on_packet_in(
                time.time(), datapath.id, in_port, eth.src, source_ip, proto, dst_ip,
                self._flow_id(eth, ip_pkt))
            self._apply(actions)
            if verdict == DROP and self.mitigate:
                return

        self._forward(msg, datapath, in_port, eth, ip_pkt)

    @staticmethod
    def _flow_id(eth, ip_pkt):
        if ip_pkt is None:
            return (eth.src, eth.dst, eth.ethertype)
        return (eth.src, eth.dst, eth.ethertype, ip_pkt.proto, ip_pkt.src, ip_pkt.dst)

    @staticmethod
    def _addresses(pkt, ip_pkt):
        if ip_pkt is not None:
            return ip_pkt.src, ip_pkt.dst, ip_pkt.proto
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            return arp_pkt.src_ip, None, None
        return None, None, None

    def _handle_sample(self, dpid, in_port, eth, ip_pkt, pkt):
        if ip_pkt is None:
            return
        key = FlowKey(dpid, in_port, eth.src, eth.dst, ip_pkt.src, ip_pkt.dst, ip_pkt.proto)
        self._apply(self.engine.on_sample(time.time(), key, self._is_attack_packet(ip_pkt, pkt)))

    @staticmethod
    def _is_attack_packet(ip_pkt, pkt):
        if ip_pkt.proto == PROTO_TCP:
            header = pkt.get_protocol(tcp.tcp)
            return header is not None and bool(header.bits & TCP_SYN) and not header.bits & TCP_ACK
        if ip_pkt.proto == PROTO_ICMP:
            header = pkt.get_protocol(icmp.icmp)
            return header is not None and header.type == icmp.ICMP_ECHO_REQUEST
        return False

    def _forward(self, msg, datapath, in_port, eth, ip_pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        table = self.mac_to_port.setdefault(datapath.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            # Trong luc flood, nhieu goi cua cung flow toi truoc khi rule co hieu luc.
            if self.engine.note_flow_installed(time.time(), datapath.id, in_port, self._flow_id(eth, ip_pkt)):
                match = self._forward_match(parser, in_port, eth, ip_pkt)
                self._add_flow(datapath, PRIORITY_FORWARD, match, actions, idle=FORWARD_IDLE_TIMEOUT)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))

    @staticmethod
    def _forward_match(parser, in_port, eth, ip_pkt):
        if ip_pkt is None:
            return parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst,
                                   eth_type=eth.ethertype)
        return parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst,
                               eth_type=ether_types.ETH_TYPE_IP, ip_proto=ip_pkt.proto,
                               ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)

    # ---------- Thong ke dinh ky ----------
    def _monitor(self):
        while True:
            hub.sleep(self.engine.cfg.stats_interval)
            self._apply(self.engine.tick(time.time()))
            for datapath in list(self.datapaths.values()):
                datapath.send_msg(datapath.ofproto_parser.OFPFlowStatsRequest(datapath))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        stats = []
        for entry in ev.msg.body:
            match = entry.match
            if entry.priority != PRIORITY_FORWARD or "ip_proto" not in match:
                continue
            if not self._is_edge(dpid, match["in_port"]):
                continue
            key = FlowKey(dpid, match["in_port"], match["eth_src"], match["eth_dst"],
                          match["ipv4_src"], match["ipv4_dst"], match["ip_proto"])
            duration = entry.duration_sec + entry.duration_nsec / 1e9
            stats.append(FlowSample(key, entry.packet_count, entry.byte_count, duration))
        self._apply(self.engine.on_flow_stats(time.time(), stats))

    # ---------- Thuc thi quyet dinh cua engine ----------
    def _apply(self, actions):
        for action in actions:
            if isinstance(action, StartSample):
                self._start_sample(action)
            elif isinstance(action, StopSample):
                self._stop_sample(action)
            elif isinstance(action, BlockFlow):
                self._block_flow(action)
            elif isinstance(action, BlockPort):
                self._block_port(action)
            elif isinstance(action, Note):
                self._record(action.event, "", "", "", "", action.detail)

    @staticmethod
    def _sample_match(parser, key):
        return parser.OFPMatch(in_port=key.in_port, eth_src=key.src_mac, eth_dst=key.dst_mac,
                               eth_type=ether_types.ETH_TYPE_IP, ip_proto=key.proto,
                               ipv4_src=key.src_ip, ipv4_dst=key.dst_ip)

    def _start_sample(self, action):
        key = action.key
        datapath = self.datapaths.get(key.dpid)
        out_port = self.mac_to_port.get(key.dpid, {}).get(key.dst_mac)
        if datapath is None or out_port is None:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, SAMPLE_BYTES)]
        self._add_flow(datapath, PRIORITY_SAMPLE, self._sample_match(parser, key), actions,
                       hard=action.timeout)

    def _stop_sample(self, action):
        key = action.key
        datapath = self.datapaths.get(key.dpid)
        if datapath is None:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_DELETE_STRICT, priority=PRIORITY_SAMPLE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            match=self._sample_match(parser, key)))

    def _block_flow(self, action):
        self._record("detected", action.reason, action.dpid, action.port, action.timeout, action.detail)
        datapath = self.datapaths.get(action.dpid)
        if not self.mitigate or datapath is None:
            return
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=action.port, eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=action.proto, ipv4_dst=action.dst_ip)
        self._add_flow(datapath, PRIORITY_BLOCK_FLOW, match, [], hard=action.timeout)
        self._record("blocked", action.reason, action.dpid, action.port, action.timeout, action.detail)

    def _block_port(self, action):
        self._record("detected", action.reason, action.dpid, action.port, action.timeout, action.detail)
        datapath = self.datapaths.get(action.dpid)
        if not self.mitigate or datapath is None:
            return
        match = datapath.ofproto_parser.OFPMatch(in_port=action.port)
        self._add_flow(datapath, PRIORITY_BLOCK_PORT, match, [], hard=action.timeout)
        self._record("blocked", action.reason, action.dpid, action.port, action.timeout, action.detail)

    def _record(self, event, reason, dpid, port, timeout, detail):
        now = time.time()
        with open(self.event_path, "a", newline="") as handle:
            csv.writer(handle).writerow(["%.3f" % now, event, reason, dpid, port, timeout, detail])
        self.logger.warning("[%s] %s %s", event.upper(), reason, detail)
