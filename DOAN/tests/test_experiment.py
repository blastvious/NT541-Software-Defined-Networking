import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Experiments"))

import run_experiment as rx

IPERF = """------------------------------------------------------------
Client connecting to 10.0.0.4, TCP port 5001
[  1] local 10.0.0.2 port 44602 connected with 10.0.0.4 port 5001
[ ID] Interval       Transfer     Bandwidth
[  1] 0.0000-1.0000 sec  11.2 MBytes  94.2 Mbits/sec
[  1] 1.0000-2.0000 sec  11.0 MBytes  92.0 Mbits/sec
[  1] 2.0000-3.0000 sec  1.00 MBytes  8.4 Mbits/sec
[  1] 0.0000-3.0136 sec  23.2 MBytes  64.5 Mbits/sec
"""


def test_iperf_intervals_skip_summary():
    assert rx.parse_iperf_intervals(IPERF) == [(0.0, 94.2), (1.0, 92.0), (2.0, 8.4)]
    assert rx.parse_iperf_summary(IPERF) == 64.5
    assert rx.mean_between(rx.parse_iperf_intervals(IPERF), 0, 2) == 93.1
    assert rx.mean_between([], 0, 2) is None


def test_ping_loss():
    assert rx.parse_ping_loss("3 packets transmitted, 0 received, 100% packet loss, time 2030ms") == 100.0
    assert rx.parse_ping_loss("no output") is None


def test_attack_commands():
    assert rx.attack_command("syn", "1000") == "timeout 25 hping3 -q -S -p 80 -i u1000 10.0.0.4"
    assert rx.attack_command("rand", "flood") == "timeout 25 hping3 -q -S -p 80 --rand-source --flood 10.0.0.4"
    assert "iperf -u" in rx.attack_command("benign", "10M")


def test_summarize_events():
    events = [
        {"time": "101.5", "event": "suspect", "reason": ""},
        {"time": "102.0", "event": "detected", "reason": "syn_flood"},
        {"time": "102.0", "event": "blocked", "reason": "syn_flood"},
    ]
    assert rx.summarize_events(events, 100.0) == (2.0, 2.0, 1, "syn_flood")
    assert rx.summarize_events([], 100.0) == (None, None, 0, "")


def test_ryu_script_runs_in_a_shell(tmp_path, monkeypatch):
    import stat
    import subprocess

    fake = tmp_path / "ryu-manager"
    fake.write_text('#!/bin/sh\necho "$PWD|$DOS_MITIGATE|$DOS_EVENT_LOG|$1"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(rx, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(rx, "CONTROLLER_DIR", str(tmp_path))
    script, log = rx.ryu_script("detect", "label")
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"])
    subprocess.run(["bash", "-c", script], check=True, env=env)
    with open(log) as handle:
        assert handle.read().strip() == "%s|0|%s|dos_guard.py" % (tmp_path, tmp_path / "label_events.csv")
