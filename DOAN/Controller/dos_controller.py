from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.lib import hub
from datetime import datetime

class DoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DoSDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        
        # Cấu hình phát hiện DoS
        self.dt = 5  # Khoảng thời gian Delta t (giây)
        self.packet_in_count = {}  # Đếm số lượng packet_in theo IP nguồn
        self.PACKET_IN_THRESHOLD = 50  # Ngưỡng báo động (Gói/Delta_t)
        self.blocked_ips = set()   # Lưu các IP đã bị chặn
        
        # Thread chạy ngầm
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        
        # Rule mặc định (Table-miss)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # --- 1. THUẬT TOÁN PHÁT HIỆN DoS ---
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            if src_ip not in self.blocked_ips:
                self.packet_in_count[src_ip] = self.packet_in_count.get(src_ip, 0) + 1
                
                if self.packet_in_count[src_ip] > self.PACKET_IN_THRESHOLD:
                    self.logger.warning(f"\n[PHAT HIEN TAN CONG] Ke tan cong: {src_ip} | Nan nhan: {dst_ip}")
                    self.logger.warning(f"Dang tha rule chan moi luu luong tu {src_ip} tai Switch {datapath.id}...\n")
                    self.block_ip(datapath, src_ip)
                    self.blocked_ips.add(src_ip)
                    return

        # --- 2. HỌC ĐỊA CHỈ MAC VÀ ĐỊNH TUYẾN ---
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def block_ip(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
        actions = []
        self.add_flow(datapath, priority=100, match=match, actions=actions)

    # --- 3. ĐỊNH KỲ THU THẬP THỐNG KÊ ---
    def _monitor(self):
        while True:
            hub.sleep(self.dt)
            self.logger.info(f"--- [BAO CAO MOI {self.dt}s] Thoi gian: {datetime.now().strftime('%H:%M:%S')} ---")
            
            for ip, count in list(self.packet_in_count.items()):
                pps = count / self.dt
                self.logger.info(f"   IP {ip} tao ra {count} packet_in ({pps:.2f} packets/s)")
            
            self.packet_in_count.clear()
            
            for dp in self.datapaths.values():
                self._request_stats(dp)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        pass