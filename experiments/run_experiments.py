#!/usr/bin/env python3
"""
run_experiments.py - baseline (static) vs dynamic SDN firewall.

What is measured
  h2 is a legitimate user. While h3 floods the log server, we measure what h2 gets:
    * throughput  : iperf TCP h2 -> h1 (Mbit/s)
    * latency     : ping h2 -> h1 (avg / max RTT, packet loss)
  and what the attacker achieves (flood Mbit/s accepted, messages blocked) and how much
  the switch dropped (flow-statistics counters of the drop rules).

Conditions
  idle     no flood (reference: what h2 gets on a quiet network)
  static   baseline: flood runs, log server only MONITORS (--no-block): the network never reacts
  dynamic  flood runs, log server enforces: controller installs / removes a BLOCK rule

Flood intensities (1400-byte messages, persistent attacker that reconnects after a block)
  low     1 connection  at 20 msg/s     (light, but violates the rate policy)
  medium  1 connection  unthrottled
  high    4 connections unthrottled     (saturates the 10 Mbit/s server link)

Usage (Ryu must already be running in another tab):
    cd ~/dynamic-firewall
    sudo python3 experiments/run_experiments.py              # about 10 minutes
    sudo python3 experiments/run_experiments.py --quick      # about 2 minutes
    python3 experiments/analyze.py                           # tables + charts

Do NOT run `sudo mn -c` while Ryu is running (it kills Ryu).
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API = "http://127.0.0.1:8080"
H1_API = "http://10.0.0.254:8080"

INTENSITY = {
    "low":    {"connections": 1, "rate": 20},
    "medium": {"connections": 1, "rate": 0},
    "high":   {"connections": 4, "rate": 0},
}
FIELDS = ["condition", "intensity", "run", "duration_s", "iperf_mbps", "ping_avg_ms",
          "ping_max_ms", "ping_loss_pct", "flood_sent", "flood_acked", "flood_blocked_replies",
          "flood_accepted_mbps", "first_blocked_s", "alerts", "blocks_installed",
          "switch_dropped_packets", "switch_dropped_bytes"]


# ----------------------------------------------------------------- parsing helpers
def parse_ping(text):
    """Parse the summary of `ping -q`. Missing values are None."""
    out = {"avg": None, "max": None, "loss": None}
    m = re.search(r"([\d.]+)% packet loss", text)
    if m:
        out["loss"] = float(m.group(1))
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", text)
    if m:
        out["avg"], out["max"] = float(m.group(2)), float(m.group(3))
    return out


def parse_iperf_csv(text):
    """Parse `iperf -y C` output. Returns Mbit/s or None."""
    for line in reversed([l.strip() for l in text.splitlines() if l.strip()]):
        parts = line.split(",")
        if len(parts) >= 9:
            try:
                return int(parts[-1]) / 1e6
            except ValueError:
                continue
    m = re.findall(r"([\d.]+)\s*([KMG]?)bits/sec", text)          # fallback: human format
    if m:
        value, unit = m[-1]
        return float(value) * {"": 1e-6, "K": 1e-3, "M": 1.0, "G": 1e3}[unit]
    return None


def parse_summary(text):
    """Find the `SUMMARY {...}` line printed by app/client.py --summary-json."""
    for line in text.splitlines():
        if line.startswith("SUMMARY "):
            return json.loads(line[len("SUMMARY "):])
    return {}


def count_in_file(path, needle):
    try:
        with open(path) as f:
            return sum(1 for line in f if needle in line)
    except OSError:
        return 0


# ------------------------------------------------------------------ controller REST
def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.loads(r.read().decode())


def reset_controller():
    """Remove every rule so each trial starts from the same state."""
    for rule in api("GET", "/firewall/rules")["rules"]:
        api("POST", "/firewall/rule/remove", {"id": rule["id"]})


def dropped_totals():
    d = api("GET", "/firewall/stats")["dropped"]
    return d["packets"], d["bytes"]


# --------------------------------------------------------------------- one trial
def wait_for_port(host, ip, port, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        out = host.cmd('timeout 1 bash -c "echo > /dev/tcp/%s/%d" && echo UP' % (ip, port))
        if "UP" in out:
            return True
        time.sleep(0.3)
    return False


def run_trial(net, condition, intensity, run, args, rawdir):
    from subprocess import PIPE, DEVNULL, STDOUT
    h1, h2, h3 = net.get("h1"), net.get("h2"), net.get("h3")
    tag = "%s_%s_%d" % (condition, intensity, run)
    server_log = os.path.join(rawdir, tag + ".server.log")
    flood_out = os.path.join(rawdir, tag + ".flood.txt")
    for p in (server_log, flood_out):
        if os.path.exists(p):
            os.remove(p)

    reset_controller()
    before_pk, before_by = dropped_totals()

    srv_cmd = ["python3", os.path.join(ROOT, "app", "log_server.py"),
               "--controller", "10.0.0.254:8080", "--no-trusted", "--quiet-events",
               "--log-file", server_log]
    if condition == "static":
        srv_cmd.append("--no-block")
    server = h1.popen(srv_cmd, stdout=DEVNULL, stderr=DEVNULL)
    if not wait_for_port(h2, "10.0.0.1", 9000):
        server.terminate()
        raise RuntimeError("log server did not start on h1 (see %s)" % server_log)

    D = args.duration
    ping = h2.popen(["ping", "-c", str(int(D * 5)), "-i", "0.2", "-q", "10.0.0.1"],
                    stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    flood = None
    if condition != "idle":
        cfg = INTENSITY[intensity]
        flood = h3.popen(["python3", os.path.join(ROOT, "app", "client.py"),
                          "--server", "10.0.0.1", "--mode", "flood", "--size", "1400",
                          "--rate", str(cfg["rate"]), "--connections", str(cfg["connections"]),
                          "--duration", str(D), "--persist", "--quiet", "--summary-json",
                          "--connect-timeout", "2", "--recv-timeout", "2"],
                         stdout=open(flood_out, "w"), stderr=STDOUT)
    iperf_text = h2.cmd("iperf -c 10.0.0.1 -p 5001 -t %d -y C" % D)

    if flood is not None:
        flood.wait(timeout=D + 20)
    ping_text, _ = ping.communicate(timeout=D + 20)
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
    reset_controller()                      # also folds the last drop-rule counters in
    after_pk, after_by = dropped_totals()

    pg = parse_ping(ping_text)
    summary = {}
    if flood is not None:
        with open(flood_out) as f:
            summary = parse_summary(f.read())
    row = {
        "condition": condition, "intensity": intensity if condition != "idle" else "none",
        "run": run, "duration_s": D,
        "iperf_mbps": parse_iperf_csv(iperf_text),
        "ping_avg_ms": pg["avg"], "ping_max_ms": pg["max"], "ping_loss_pct": pg["loss"],
        "flood_sent": summary.get("sent"), "flood_acked": summary.get("acked"),
        "flood_blocked_replies": summary.get("blocked_replies"),
        "flood_accepted_mbps": (round(summary["bytes_acked"] * 8 / D / 1e6, 3)
                                if summary else None),
        "first_blocked_s": summary.get("first_blocked_s"),
        "alerts": count_in_file(server_log, "ALERT"),
        "blocks_installed": count_in_file(server_log, "BLOCKED by SDN controller"),
        "switch_dropped_packets": after_pk - before_pk,
        "switch_dropped_bytes": after_by - before_by,
    }
    return row


# -------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--duration", type=int, default=20, help="seconds per trial")
    ap.add_argument("--runs", type=int, default=3, help="repetitions of every condition")
    ap.add_argument("--bw", type=float, default=10.0, help="server link bandwidth (Mbit/s)")
    ap.add_argument("--queue", type=int, default=50, help="link queue size (packets)")
    ap.add_argument("--intensities", default="low,medium,high")
    ap.add_argument("--out", default=os.path.join(ROOT, "results"))
    ap.add_argument("--quick", action="store_true", help="10 s trials, 1 run")
    args = ap.parse_args()
    if args.quick:
        args.duration, args.runs = 10, 1
    intensities = [i for i in args.intensities.split(",") if i]
    for i in intensities:
        if i not in INTENSITY:
            sys.exit("unknown intensity %r (use low, medium, high)" % i)

    if os.geteuid() != 0:
        sys.exit("Run with sudo (Mininet needs root).")
    try:
        api("GET", "/firewall/status")
    except Exception as exc:
        sys.exit("Cannot reach the Ryu controller REST API at %s (%s).\n"
                 "Start it first in another tab:  ryu-manager controller/firewall_controller.py" % (API, exc))

    sys.path.insert(0, ROOT)
    from mininet.log import setLogLevel
    from topology.firewall_topo import build_net
    setLogLevel("warning")

    rawdir = os.path.join(args.out, "raw")
    os.makedirs(rawdir, exist_ok=True)
    csv_path = os.path.join(args.out, "results.csv")
    new_file = not os.path.exists(csv_path)

    trials = []
    for run in range(1, args.runs + 1):
        trials.append(("idle", "none", run))
        for intensity in intensities:
            for condition in ("static", "dynamic"):
                trials.append((condition, intensity, run))
    est = len(trials) * (args.duration + 6)
    print("%d trials x %ds  (about %d min). Results -> %s" % (len(trials), args.duration,
                                                              est // 60 + 1, csv_path))

    net = build_net(bw=args.bw, max_queue_size=args.queue)
    iperf_srv = None
    try:
        h1, h2 = net.get("h1"), net.get("h2")
        if "blocked_ips" not in h1.cmd("curl -s -m 3 %s/firewall/status" % H1_API):
            sys.exit("h1 cannot reach the controller REST API at %s" % H1_API)
        if not api("GET", "/firewall/stats")["switches"]:
            sys.exit("The switch is not connected to Ryu.")
        iperf_srv = h1.popen(["iperf", "-s", "-p", "5001"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        time.sleep(1)
        with open(csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            if new_file:
                writer.writeheader()
            for n, (condition, intensity, run) in enumerate(trials, 1):
                t0 = time.time()
                row = run_trial(net, condition, intensity, run, args, rawdir)
                writer.writerow(row)
                f.flush()
                print("[%2d/%d] %-8s %-7s run%d  iperf=%s Mbit/s  ping avg=%s max=%s ms  "
                      "flood=%s Mbit/s  blocks=%s  (%.0fs)" % (
                          n, len(trials), condition, row["intensity"], run,
                          "%.2f" % row["iperf_mbps"] if row["iperf_mbps"] is not None else "?",
                          row["ping_avg_ms"], row["ping_max_ms"], row["flood_accepted_mbps"],
                          row["blocks_installed"], time.time() - t0))
    finally:
        if iperf_srv is not None:
            iperf_srv.terminate()
        try:
            reset_controller()
        except Exception:
            pass
        net.stop()
    print("Done. Now run:  python3 experiments/analyze.py")


if __name__ == "__main__":
    main()
