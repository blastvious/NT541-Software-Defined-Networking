"""Logic phat hien va ngan chan DoS, khong phu thuoc Ryu de co the unit test.

Luong xu ly:
  1. Flow stats tai cong bien -> tim flow co toc do bat thuong (nghi ngo).
  2. TCP/ICMP: lay mau goi that de xac nhan (SYN, ICMP echo request).
     UDP: khong co co de phan biet, xac nhan bang toc do trong nhieu chu ky.
  3. Source guard va gioi han packet_in theo cong -> xu ly gia mao dia chi.
  4. Chan tai cong vao bang rule co thoi han; tai pham thi tang gap doi.
"""
from collections import namedtuple
from dataclasses import dataclass, field

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

ALLOW = "allow"
DROP = "drop"

FlowKey = namedtuple("FlowKey", "dpid in_port src_mac dst_mac src_ip dst_ip proto")
FlowSample = namedtuple("FlowSample", "key packets bytes duration")

BlockFlow = namedtuple("BlockFlow", "dpid port dst_ip proto timeout reason detail")
BlockPort = namedtuple("BlockPort", "dpid port timeout reason detail")
StartSample = namedtuple("StartSample", "key timeout")
StopSample = namedtuple("StopSample", "key")
Note = namedtuple("Note", "event detail")


@dataclass
class Config:
    stats_interval: float = 1.0

    # Nguong nghi ngo cua buoc 1 (goi/giay). Vuot nguong chua bi chan.
    tcp_suspect_pps: float = 100.0
    icmp_suspect_pps: float = 100.0

    # Xac nhan bang mau goi o buoc 2.
    sample_size: int = 20
    sample_min: int = 5
    sample_timeout: int = 2
    confirm_ratio: float = 0.8
    clear_cooldown: float = 30.0

    # UDP: nhieu goi nho, hoac bang thong rat lon, lien tiep nhieu chu ky.
    udp_pps: float = 500.0
    udp_small_bytes: float = 200.0
    udp_bps: float = 60e6
    udp_windows: int = 2

    # Bao ve controller, tinh tren tung cong bien trong moi giay.
    packet_in_limit: int = 100
    # Goi cua cung flow toi controller ngay sau khi vua cai rule khong bi tinh la qua tai.
    flow_setup_grace: float = 2.0
    violation_limit: int = 20

    # Thoi gian chan: 30, 60, 120... toi da 480 giay.
    block_base: int = 30
    block_max: int = 480
    offence_forget: float = 600.0

    binding_ttl: float = 300.0
    min_rate_interval: float = 0.2
    flow_state_ttl: float = 60.0


@dataclass
class _Binding:
    mac: str
    ip: str
    seen: float


@dataclass
class _Sample:
    started: float
    total: int = 0
    matched: int = 0
    pps: float = 0.0


@dataclass
class _Counter:
    second: int = -1
    packet_in: int = 0
    violation: int = 0


@dataclass
class _FlowState:
    packets: int
    bytes: int
    seen: float
    udp_streak: int = 0


@dataclass
class _Offence:
    count: int = 0
    last: float = 0.0


class DetectionEngine:
    def __init__(self, config=None):
        self.cfg = config or Config()
        self.flows = {}
        self.samples = {}
        self.cooldown = {}
        self.bindings = {}
        self.mac_owner = {}
        self.ip_owner = {}
        self.counters = {}
        self.offences = {}
        self.flow_blocks = {}
        self.port_blocks = {}
        self.recent_rules = {}

    # ---------- Buoc 1: thong ke flow ----------
    def on_flow_stats(self, now, stats):
        actions = []
        for stat in stats:
            actions.extend(self._check_flow(now, stat))
        return actions

    def _check_flow(self, now, stat):
        key = stat.key
        if self._flow_blocked(key.dpid, key.in_port, key.dst_ip, key.proto):
            self.flows.pop(key, None)
            return []
        state = self.flows.get(key)
        if state is None or stat.packets < state.packets or stat.bytes < state.bytes:
            # Flow moi, hoac flow vua duoc cai lai sau khi het han.
            interval = stat.duration
            packets, octets = stat.packets, stat.bytes
            streak = 0
        else:
            interval = now - state.seen
            packets = stat.packets - state.packets
            octets = stat.bytes - state.bytes
            streak = state.udp_streak
        if interval < self.cfg.min_rate_interval:
            return []
        self.flows[key] = _FlowState(stat.packets, stat.bytes, now, streak)
        pps = packets / interval
        bps = octets * 8 / interval

        if key.proto == PROTO_UDP:
            return self._check_udp(now, key, pps, bps, octets, packets)
        if key.proto == PROTO_TCP and pps >= self.cfg.tcp_suspect_pps:
            return self._start_sample(now, key, pps)
        if key.proto == PROTO_ICMP and pps >= self.cfg.icmp_suspect_pps:
            return self._start_sample(now, key, pps)
        return []

    def _check_udp(self, now, key, pps, bps, octets, packets):
        state = self.flows[key]
        average = octets / packets if packets else 0.0
        small_flood = pps >= self.cfg.udp_pps and average < self.cfg.udp_small_bytes
        if not (small_flood or bps >= self.cfg.udp_bps):
            state.udp_streak = 0
            return []
        state.udp_streak += 1
        if state.udp_streak < self.cfg.udp_windows:
            return []
        detail = "pps=%.0f mbps=%.2f avg_bytes=%.0f" % (pps, bps / 1e6, average)
        return [self._block_flow(now, key, "udp_flood", detail)]

    # ---------- Buoc 2: xac nhan bang mau goi ----------
    def _start_sample(self, now, key, pps):
        if key in self.samples or self.cooldown.get(key, 0.0) > now:
            return []
        self.samples[key] = _Sample(started=now, pps=pps)
        detail = "%s pps=%.0f" % (_flow_text(key), pps)
        return [Note("suspect", detail), StartSample(key, self.cfg.sample_timeout)]

    def on_sample(self, now, key, is_attack_packet):
        """is_attack_packet: goi SYN khong ACK, hoac ICMP echo request."""
        sample = self.samples.get(key)
        if sample is None:
            return []
        sample.total += 1
        sample.matched += 1 if is_attack_packet else 0
        if sample.total < self.cfg.sample_size:
            return []
        return [StopSample(key)] + self._finish_sample(now, key)

    def _finish_sample(self, now, key):
        sample = self.samples.pop(key)
        ratio = sample.matched / sample.total if sample.total else 0.0
        detail = "pps=%.0f matched=%d/%d" % (sample.pps, sample.matched, sample.total)
        if sample.total >= self.cfg.sample_min and ratio >= self.cfg.confirm_ratio:
            reason = "syn_flood" if key.proto == PROTO_TCP else "icmp_flood"
            return [self._block_flow(now, key, reason, detail)]
        self.cooldown[key] = now + self.cfg.clear_cooldown
        return [Note("cleared", "%s %s" % (_flow_text(key), detail))]

    # ---------- Buoc 3: source guard va gioi han packet_in ----------
    def note_flow_installed(self, now, dpid, port, flow_id):
        """Tra ve True neu can cai rule, False neu rule cua flow nay vua duoc cai."""
        installed = self.recent_rules.get((dpid, port, flow_id))
        if installed is not None and now - installed < self.cfg.flow_setup_grace:
            return False
        self.recent_rules[(dpid, port, flow_id)] = now
        return True

    def _in_setup_burst(self, now, where, flow_id):
        installed = self.recent_rules.get((where[0], where[1], flow_id))
        return installed is not None and now - installed < self.cfg.flow_setup_grace

    def on_packet_in(self, now, dpid, port, mac, ip, proto=None, dst_ip=None, flow_id=None):
        """Goi cho cac goi table-miss tai cong bien."""
        where = (dpid, port)
        if where in self.port_blocks:
            return DROP, []
        if dst_ip is not None and (dpid, port, dst_ip, proto) in self.flow_blocks:
            return DROP, []

        counter = self._counter(now, where)
        if not self._in_setup_burst(now, where, flow_id):
            counter.packet_in += 1
        if counter.packet_in > self.cfg.packet_in_limit:
            detail = "packet_in>%d/s" % self.cfg.packet_in_limit
            return DROP, [self._block_port(now, where, "packet_in_flood", detail)]

        if self._source_valid(now, where, mac, ip):
            return ALLOW, []
        counter.violation += 1
        if counter.violation > self.cfg.violation_limit:
            detail = "violations>%d/s mac=%s ip=%s" % (self.cfg.violation_limit, mac, ip)
            return DROP, [self._block_port(now, where, "spoofing", detail)]
        return DROP, []

    def _counter(self, now, where):
        second = int(now)
        counter = self.counters.get(where)
        if counter is None or counter.second != second:
            counter = _Counter(second=second)
            self.counters[where] = counter
        return counter

    def _source_valid(self, now, where, mac, ip):
        ip = None if ip == "0.0.0.0" else ip
        if self.mac_owner.get(mac, where) != where:
            return False
        if ip is not None and self.ip_owner.get(ip, where) != where:
            return False
        binding = self.bindings.get(where)
        if binding is None:
            self.bindings[where] = _Binding(mac, ip, now)
            self.mac_owner[mac] = where
            if ip is not None:
                self.ip_owner[ip] = where
            return True
        if binding.mac != mac:
            return False
        if ip is not None and binding.ip is not None and binding.ip != ip:
            return False
        if ip is not None and binding.ip is None:
            binding.ip = ip
            self.ip_owner[ip] = where
        binding.seen = now
        return True

    # ---------- Buoc 4: chan co thoi han ----------
    def _block_timeout(self, now, where):
        offence = self.offences.setdefault(where, _Offence())
        if offence.count and now - offence.last > self.cfg.offence_forget:
            offence.count = 0
        timeout = min(self.cfg.block_base * (2 ** offence.count), self.cfg.block_max)
        offence.count += 1
        offence.last = now
        return timeout

    def _block_flow(self, now, key, reason, detail):
        where = (key.dpid, key.in_port)
        timeout = self._block_timeout(now, where)
        self.flow_blocks[(key.dpid, key.in_port, key.dst_ip, key.proto)] = now + timeout
        self.samples.pop(key, None)
        self.flows.pop(key, None)
        text = "%s %s" % (_flow_text(key), detail)
        return BlockFlow(key.dpid, key.in_port, key.dst_ip, key.proto, timeout, reason, text)

    def _block_port(self, now, where, reason, detail):
        timeout = self._block_timeout(now, where)
        self.port_blocks[where] = now + timeout
        return BlockPort(where[0], where[1], timeout, reason, detail)

    def _flow_blocked(self, dpid, port, dst_ip, proto):
        return (dpid, port) in self.port_blocks or (dpid, port, dst_ip, proto) in self.flow_blocks

    # ---------- Tac vu dinh ky ----------
    def tick(self, now):
        actions = []
        for key, sample in list(self.samples.items()):
            if now - sample.started >= self.cfg.sample_timeout:
                actions.append(StopSample(key))
                actions.extend(self._finish_sample(now, key))
        for block_key, expires in list(self.flow_blocks.items()):
            if expires <= now:
                del self.flow_blocks[block_key]
                actions.append(Note("released", "flow %s" % (block_key,)))
        for where, expires in list(self.port_blocks.items()):
            if expires <= now:
                del self.port_blocks[where]
                self._forget_binding(where)
                actions.append(Note("released", "port %s" % (where,)))
        for where, binding in list(self.bindings.items()):
            if now - binding.seen > self.cfg.binding_ttl:
                self._forget_binding(where)
        for key, state in list(self.flows.items()):
            if now - state.seen > self.cfg.flow_state_ttl:
                del self.flows[key]
        for rule, installed in list(self.recent_rules.items()):
            if now - installed >= self.cfg.flow_setup_grace:
                del self.recent_rules[rule]
        for key, expires in list(self.cooldown.items()):
            if expires <= now:
                del self.cooldown[key]
        return actions

    def _forget_binding(self, where):
        binding = self.bindings.pop(where, None)
        if binding is None:
            return
        self.mac_owner.pop(binding.mac, None)
        if binding.ip is not None:
            self.ip_owner.pop(binding.ip, None)


def _flow_text(key):
    return "s%s:%s %s->%s proto=%s" % (key.dpid, key.in_port, key.src_ip, key.dst_ip, key.proto)
