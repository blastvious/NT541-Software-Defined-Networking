#!/usr/bin/env python3
"""Do tu dong anh huong cua tan cong va hieu qua ngan chan.

Vi du:
  sudo python3 run_experiment.py --controller guard --attack syn --rate flood
  sudo python3 run_experiment.py --all

Moi lan chay: iperf h2->h4 lien tuc 35 giay, tan cong tu giay 5 den giay 30.
"""
import argparse
import csv
import importlib.util
import os
import re
import socket
import subprocess
import time
from functools import partial

HERE = os.path.dirname(os.path.abspath(__file__))
DOAN = os.path.dirname(HERE)
CONTROLLER_DIR = os.path.join(DOAN, "Controller")
TOPOLOGY_FILE = os.path.join(DOAN, "Topology", "23521717_custom_topology.py")
RESULTS_DIR = os.path.join(HERE, "results")

VICTIM = "10.0.0.4"
PRE_SECONDS = 5
ATTACK_SECONDS = 25
POST_SECONDS = 5
TOTAL_SECONDS = PRE_SECONDS + ATTACK_SECONDS + POST_SECONDS

ATTACK_FLAGS = {
    "syn": "-S -p 80",
    "udp": "--udp -p 80",
    "icmp": "--icmp",
    "rand": "-S -p 80 --rand-source",
}
CONTROLLERS = {
    "old": ("dos_controller.py", {}),
    "detect": ("dos_guard.py", {"DOS_MITIGATE": "0"}),
    "guard": ("dos_guard.py", {"DOS_MITIGATE": "1"}),
}
FIELDS = ["run", "controller", "attack", "rate", "pingall_loss_pct", "baseline_mbps", "before_mbps",
          "attack_mbps", "attack_last5s_mbps", "after_mbps", "h3_ping_loss_pct", "h1_to_h3_loss_pct",
          "detect_s", "block_s", "block_events", "reasons"]

INTERVAL_RE = re.compile(r"(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)\s+sec\s+.*?([\d.]+)\s+Mbits/sec")
LOSS_RE = re.compile(r"([\d.]+)% packet loss")


def parse_iperf_intervals(text):
    """Tra ve danh sach (giay bat dau, Mbps), bo dong tong ket."""
    rows = []
    for match in INTERVAL_RE.finditer(text):
        start, end, mbps = float(match.group(1)), float(match.group(2)), float(match.group(3))
        if end - start <= 1.5:
            rows.append((start, mbps))
    return rows


def parse_iperf_summary(text):
    rows = [float(match.group(3)) for match in INTERVAL_RE.finditer(text)]
    return rows[-1] if rows else None


def parse_ping_loss(text):
    match = LOSS_RE.search(text)
    return float(match.group(1)) if match else None


def mean_between(rows, start, end):
    values = [mbps for second, mbps in rows if start <= second < end]
    return round(sum(values) / len(values), 2) if values else None


def read_events(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle))


def summarize_events(events, attack_start):
    def first(name):
        times = [float(row["time"]) for row in events if row["event"] == name]
        return round(min(times) - attack_start, 3) if times else None

    blocks = [row for row in events if row["event"] == "blocked"]
    reasons = sorted({row["reason"] for row in events if row["event"] in ("detected", "blocked")})
    return first("detected"), first("blocked"), len(blocks), "|".join(reasons)


def attack_command(attack, rate):
    if attack == "benign":
        return "timeout %d iperf -u -c %s -b 10M -t %d" % (ATTACK_SECONDS, VICTIM, ATTACK_SECONDS)
    speed = "--flood" if rate == "flood" else "-i u%d" % (1000000 // int(rate))
    return "timeout %d hping3 -q %s %s %s" % (ATTACK_SECONDS, ATTACK_FLAGS[attack], speed, VICTIM)


def run_shell(command):
    subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def give_to_user(path):
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        os.chown(path, int(uid), int(gid))


def ryu_script(controller, label):
    app, env = CONTROLLERS[controller]
    env = dict(env, DOS_EVENT_LOG=os.path.join(RESULTS_DIR, label + "_events.csv"))
    assignments = " ".join("%s=%s" % item for item in env.items())
    log = os.path.join(RESULTS_DIR, label + "_ryu.txt")
    return "cd '%s' && exec env %s ryu-manager %s > '%s' 2>&1" % (CONTROLLER_DIR, assignments, app, log), log


def start_ryu(controller, label):
    script, log = ryu_script(controller, label)
    user = os.environ.get("SUDO_USER")
    command = ["sudo", "-u", user, "-i", "bash", "-c", script] if user else ["bash", "-c", script]
    process = subprocess.Popen(command, start_new_session=True)
    deadline = time.time() + 20
    while time.time() < deadline:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(("127.0.0.1", 6653)) == 0:
                return process
        time.sleep(0.5)
    raise RuntimeError("Ryu khong mo cong 6653, xem %s" % log)


def build_network():
    from mininet.link import TCLink
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch, RemoteController

    spec = importlib.util.spec_from_file_location("project_topology", TOPOLOGY_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    net = Mininet(topo=module.DoS_Topo(), switch=partial(OVSKernelSwitch, protocols="OpenFlow13"),
                  link=TCLink, controller=None, build=False)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    net.build()
    net.start()
    if not net.waitConnected(timeout=15):
        raise RuntimeError("Switch chua ket noi duoc voi controller")
    return net


def measure(net, controller, attack, rate, run, label):
    h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")
    iperf_file = os.path.join(RESULTS_DIR, label + "_iperf.txt")
    ping_file = os.path.join(RESULTS_DIR, label + "_ping.txt")

    pingall_loss = net.pingAll()
    h4.cmd("iperf -s -f m > /dev/null 2>&1 &")
    h4.cmd("iperf -s -u -f m > /dev/null 2>&1 &")
    time.sleep(1)
    baseline = parse_iperf_summary(h2.cmd("iperf -c %s -t 5 -f m" % VICTIM))

    h3.cmd("ping -i 0.2 -w %d %s > '%s' 2>&1 &" % (TOTAL_SECONDS, VICTIM, ping_file))
    h2.cmd("iperf -c %s -t %d -i 1 -f m > '%s' 2>&1 &" % (VICTIM, TOTAL_SECONDS, iperf_file))
    time.sleep(PRE_SECONDS)
    attack_start = time.time()
    h1.cmd(attack_command(attack, rate) + " > /dev/null 2>&1 &")
    time.sleep(ATTACK_SECONDS - 5)
    h1_to_h3 = parse_ping_loss(h1.cmd("ping -c 3 -W 1 10.0.0.3"))
    time.sleep(POST_SECONDS + POST_SECONDS + 3)

    with open(iperf_file) as handle:
        rows = parse_iperf_intervals(handle.read())
    with open(ping_file) as handle:
        ping_loss = parse_ping_loss(handle.read())
    detect_s, block_s, block_count, reasons = summarize_events(
        read_events(os.path.join(RESULTS_DIR, label + "_events.csv")), attack_start)
    return {
        "run": run, "controller": controller, "attack": attack, "rate": rate,
        "pingall_loss_pct": pingall_loss, "baseline_mbps": baseline,
        "before_mbps": mean_between(rows, 0, PRE_SECONDS),
        "attack_mbps": mean_between(rows, PRE_SECONDS, PRE_SECONDS + ATTACK_SECONDS),
        "attack_last5s_mbps": mean_between(rows, PRE_SECONDS + ATTACK_SECONDS - 5, PRE_SECONDS + ATTACK_SECONDS),
        "after_mbps": mean_between(rows, PRE_SECONDS + ATTACK_SECONDS, TOTAL_SECONDS),
        "h3_ping_loss_pct": ping_loss, "h1_to_h3_loss_pct": h1_to_h3,
        "detect_s": detect_s, "block_s": block_s, "block_events": block_count, "reasons": reasons,
    }


def run_once(controller, attack, rate, run):
    label = "%s_%s_%s_run%d" % (controller, attack, rate, run)
    run_shell("mn -c")
    process = start_ryu(controller, label)
    net = None
    try:
        net = build_network()
        result = measure(net, controller, attack, rate, run, label)
    finally:
        if net is not None:
            net.stop()
        process.terminate()
        run_shell("pkill -f ryu-manager")
        run_shell("mn -c")
    return result


def save(result):
    path = os.path.join(RESULTS_DIR, "results.csv")
    is_new = not os.path.exists(path)
    with open(path, "a", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        if is_new:
            writer.writeheader()
        writer.writerow(result)
    for name in os.listdir(RESULTS_DIR):
        give_to_user(os.path.join(RESULTS_DIR, name))
    print(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", choices=CONTROLLERS, default="guard")
    parser.add_argument("--attack", choices=list(ATTACK_FLAGS) + ["benign"], default="syn")
    parser.add_argument("--rate", default="flood", help="so goi/giay, hoac flood")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--all", action="store_true", help="chay toan bo ma tran kich ban")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("can chay bang sudo")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    give_to_user(RESULTS_DIR)

    if args.all:
        plan = [("guard", "benign", "10M")]
        for attack in ATTACK_FLAGS:
            for controller in ("old", "detect", "guard"):
                plan.append((controller, attack, args.rate))
    else:
        plan = [(args.controller, args.attack, args.rate)]
    for controller, attack, rate in plan:
        for run in range(1, args.repeat + 1):
            save(run_once(controller, attack, rate, run))


if __name__ == "__main__":
    main()
