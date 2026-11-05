#!/usr/bin/env python3
"""
analyze.py - summarize results/results.csv (written by run_experiments.py).

Writes results/summary.md (a table you can paste into the report) and, when matplotlib
is installed (pip3 install matplotlib), three charts:
    results/h2_throughput.png   results/h2_latency.png   results/attack_traffic.png

    python3 experiments/analyze.py [--csv results/results.csv] [--out results]
"""
import argparse
import csv
import os
import statistics
import sys
from collections import defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ORDER = ["low", "medium", "high"]
METRICS = ["iperf_mbps", "ping_avg_ms", "ping_max_ms", "ping_loss_pct", "flood_accepted_mbps",
           "flood_acked", "blocks_installed", "switch_dropped_packets", "first_blocked_s"]


def num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load(path):
    rows = defaultdict(list)
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows[(r["condition"], r["intensity"])].append({k: num(r[k]) for k in METRICS})
    return rows


def stat(rows, key, metric):
    vals = [r[metric] for r in rows.get(key, []) if r[metric] is not None]
    if not vals:
        return None, None, 0
    return statistics.mean(vals), (statistics.stdev(vals) if len(vals) > 1 else 0.0), len(vals)


def fmt(rows, key, metric, digits=2):
    mean, sd, n = stat(rows, key, metric)
    if mean is None:
        return "-"
    return ("%.*f +/- %.*f" % (digits, mean, digits, sd)) if n > 1 else "%.*f" % (digits, mean)


def build_markdown(rows):
    intens = [i for i in ORDER if ("static", i) in rows or ("dynamic", i) in rows]
    idle = ("idle", "none")
    out = ["# Results: static baseline vs dynamic SDN firewall", "",
           "Mean +/- standard deviation over the repeated runs. h2 is the legitimate user; "
           "h3 floods the log server. The server link is the shared bottleneck.", ""]
    n_runs = max((stat(rows, k, "iperf_mbps")[2] for k in rows), default=0)
    out.append("Runs per condition: %d. Idle reference (no flood): iperf %s Mbit/s, "
               "ping avg %s ms." % (n_runs, fmt(rows, idle, "iperf_mbps"),
                                    fmt(rows, idle, "ping_avg_ms")))
    out.append("")
    sections = [
        ("h2 throughput (iperf, Mbit/s) - higher is better", "iperf_mbps", 2),
        ("h2 average ping RTT (ms) - lower is better", "ping_avg_ms", 2),
        ("h2 maximum ping RTT (ms) - lower is better", "ping_max_ms", 2),
        ("Attacker traffic accepted by the server (Mbit/s) - lower is better",
         "flood_accepted_mbps", 2),
    ]
    for title, metric, digits in sections:
        out += ["## " + title, "", "| Flood intensity | Static (no response) | Dynamic (SDN block) |",
                "|---|---|---|"]
        for i in intens:
            out.append("| %s | %s | %s |" % (i, fmt(rows, ("static", i), metric, digits),
                                            fmt(rows, ("dynamic", i), metric, digits)))
        out.append("")
    out += ["## What the dynamic firewall did", "",
            "| Flood intensity | Blocks installed | Packets dropped by the switch | "
            "Time to first BLOCKED reply (s) | h2 throughput retained vs idle |",
            "|---|---|---|---|---|"]
    idle_tp = stat(rows, idle, "iperf_mbps")[0]
    for i in intens:
        dyn_tp = stat(rows, ("dynamic", i), "iperf_mbps")[0]
        stat_tp = stat(rows, ("static", i), "iperf_mbps")[0]
        retained = "-"
        if idle_tp and dyn_tp is not None and stat_tp is not None:
            retained = "%.0f%% (static: %.0f%%)" % (100 * dyn_tp / idle_tp, 100 * stat_tp / idle_tp)
        out.append("| %s | %s | %s | %s | %s |" % (
            i, fmt(rows, ("dynamic", i), "blocks_installed", 1),
            fmt(rows, ("dynamic", i), "switch_dropped_packets", 0),
            fmt(rows, ("dynamic", i), "first_blocked_s", 2), retained))
    out.append("")
    return "\n".join(out)


def charts(rows, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed - skipping charts (pip3 install matplotlib)")
        return []
    intens = [i for i in ORDER if ("static", i) in rows or ("dynamic", i) in rows]
    idle = ("idle", "none")
    files = []

    def bars(metric, ylabel, title, fname, show_idle=True, extra_max=None):
        fig, ax = plt.subplots(figsize=(6.5, 4))
        x = range(len(intens))
        w = 0.36
        for off, cond, color in ((-w / 2, "static", "#c0504d"), (w / 2, "dynamic", "#4f81bd")):
            means = [stat(rows, (cond, i), metric)[0] or 0 for i in intens]
            sds = [stat(rows, (cond, i), metric)[1] or 0 for i in intens]
            ax.bar([p + off for p in x], means, w, yerr=sds, capsize=3, color=color,
                   label="static (no response)" if cond == "static" else "dynamic (SDN block)")
        if show_idle and stat(rows, idle, metric)[0] is not None:
            ax.axhline(stat(rows, idle, metric)[0], color="gray", linestyle="--",
                       label="idle (no flood)")
        ax.set_xticks(list(x))
        ax.set_xticklabels(intens)
        ax.set_xlabel("flood intensity")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.legend(fontsize=8)
        fig.tight_layout()
        path = os.path.join(outdir, fname)
        fig.savefig(path, dpi=150)
        plt.close(fig)
        files.append(path)

    bars("iperf_mbps", "Mbit/s", "h2 throughput under attack", "h2_throughput.png")
    bars("ping_avg_ms", "ms", "h2 average ping RTT under attack", "h2_latency.png")
    bars("flood_accepted_mbps", "Mbit/s", "Attacker traffic accepted by the server",
         "attack_traffic.png", show_idle=False)
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(ROOT, "results", "results.csv"))
    ap.add_argument("--out", default=os.path.join(ROOT, "results"))
    a = ap.parse_args()
    if not os.path.exists(a.csv):
        sys.exit("No results file at %s - run experiments/run_experiments.py first." % a.csv)
    rows = load(a.csv)
    md = build_markdown(rows)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "summary.md"), "w") as f:
        f.write(md + "\n")
    print(md)
    for p in charts(rows, a.out):
        print("wrote", p)
    print("wrote", os.path.join(a.out, "summary.md"))


if __name__ == "__main__":
    main()
