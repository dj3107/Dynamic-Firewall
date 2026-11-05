# Dynamic Firewall with Security Event Logger
**SDN + TCP socket programming mini project (UE25CS243A, Project #1)** - Mininet, Ryu, Python sockets.

A TCP application whose traffic is classified by a central **log server**. The log server tells a
**Ryu SDN controller** to install **allow**, **deny** or **block** rules in the switch while the network
is running, and removes them again automatically.

```
                     REST (:8080)  POST /firewall/block | rule | rule/remove      GET /firewall/stats
        +--------------------------------------------------------------------------------+
        |                                                                                v
 h1 10.0.0.1  log server (policy engine, ports 9000 + 9001)                      Ryu controller
        ^   \                                                                    (rule engine,
        |    \  nat0 10.0.0.254 (VM root namespace: lets hosts reach the REST API)  flow-stats poller)
        |     \                                                                       |
 h2 10.0.0.2 --+-- s1 (Open vSwitch, OpenFlow 1.3) <--------- OpenFlow :6653 ---------+
 h3 10.0.0.3 --+     drop / allow rules installed at run time
 (good client)  (flooder / unauthorised client)
```

## Quick start: the whole demo with one command
```bash
sudo python3 demo.py            # guided: a banner and "press Enter" before each scenario
```
`demo.py` cleans up old Mininet state, starts Ryu, the live dashboard, the network and the log
server **in the right order**, then runs scenarios A-E below. After each step it prints the evidence
(the important security-log lines and the switch's rules) and counts down the recovery timers. At the
end it opens the normal Mininet CLI; Ctrl+C at any point cleans everything up.

Open the **live dashboard** at `http://<vm-ip>:8000`, or from the Mac:
`ssh -L 8000:localhost:8000 <user>@<vm>` and then `http://localhost:8000`. It shows the topology
(hosts turn red when blocked, green when trusted, denied flows are marked), the rules in the switch
with live counters, per-host traffic measured by the switch, the security events, and which scenario
is running.

| Option | |
|---|---|
| `--only A,B` | run some scenarios only |
| `--auto` | no pauses (rehearsal) |
| `--userspace` | OVS userspace datapath, for machines without the openvswitch kernel module |
| `--no-dashboard`, `--dashboard-port N` | dashboard off / other port |
| `--ryu PATH` | where `ryu-manager` is, if it is not found automatically |

The dashboard also works on its own next to a manual demo: `python3 dashboard/server.py`.
The manual, step-by-step way is described under *Running the demo* below.

## What it does

| Rule | OpenFlow | Triggered by | Recovery |
|---|---|---|---|
| **BLOCK** (priority 100) | drop everything from one source IP | a source sends more than 8 messages in 5 s to a rate-limited service (port 9000), or the switch measures it above a bandwidth threshold (optional) | removed after 15 s of silence |
| **DENY** (priority 200) | drop one flow: src IP, dst IP, TCP/UDP, port | a source that is not on the allow-list connects to a protected service (port 9001, "admin") | removed after 30 s |
| **ALLOW** (priority 300) | skip the drop rules, continue to normal forwarding (`goto_table:1`) | source is in `trusted_sources` (h2 by default): exempt from rate limiting, overrides block/deny | permanent while the server runs |

Traffic is **classified by source, destination and port** (`config/policy.json`). The switch runs a
two-table pipeline: **table 0 (policy)** holds these rules, higher priority wins (allow beats deny beats
block), and anything no rule drops continues to **table 1 (forwarding)**, where the controller's learned
MAC flows live.

The controller also **polls flow statistics every second**: per-source throughput and the packets /
bytes each drop rule has discarded (used as evidence in the evaluation).

## Project layout
```
demo.py                            one-command guided demo (scenarios A-E, evidence, countdowns)
dashboard/server.py, index.html    live web dashboard (port 8000; standard library only)
controller/firewall_controller.py  Ryu app: two-table pipeline, L2 learning, rule engine, stats poller, REST API
app/log_server.py                  threaded TCP server + policy engine (classify, block, deny, recover)
app/client.py                      TCP client: normal / flood, rate, size, connections, duration
config/policy.json                 ports, services, trusted hosts, rate limits
topology/firewall_topo.py          Mininet topology (h1, h2, h3, s1, NAT node); --bw for shaping
experiments/run_experiments.py     static-vs-dynamic experiment harness
experiments/analyze.py             tables (summary.md) and charts from results.csv
tests/                             unit tests + localhost end-to-end test (no Mininet needed)
scripts/install_deps.sh            installs Mininet, OVS, Ryu (Ubuntu 22.04)
scripts/run_tests.sh               runs all tests
docs/VIVA_NOTES.md                 design explanation and likely viva questions
```

## Setup (Ubuntu 22.04 VM, tested layout: VirtualBox on Apple Silicon, SSH from the Mac)
```bash
unzip dynamic-firewall.zip && cd dynamic-firewall
./scripts/install_deps.sh
source ~/.bashrc
./scripts/run_tests.sh          # optional sanity check, takes about 40 s
```
`install_deps.sh` uses Ryu from GitHub with eventlet 0.33.3, because plain `pip install ryu` crashes on
Python 3.10. It also disables the `openvswitch-testcontroller` service, which otherwise holds port 6653.

## Running the demo (three SSH tabs, all in `~/dynamic-firewall`)

**Order matters: `sudo mn -c` kills Ryu, so clean up first and start Ryu second.**

| Tab | Command |
|---|---|
| 2 | `sudo mn -c` then wait |
| 1 | `ryu-manager controller/firewall_controller.py` &nbsp;(wait for `wsgi starting up on http://0.0.0.0:8080`) |
| 2 | `sudo python3 topology/firewall_topo.py` |
| 3 | `tail -F logs/security_events.log` |

At the `mininet>` prompt (tab 2):
```
pingall                                          # 0% dropped (12/12)
h1 curl http://10.0.0.254:8080/firewall/status   # {"blocked_ips": [], "rules": 0}
h1 python3 app/log_server.py --controller 10.0.0.254:8080 > logs/server_stdout.txt 2>&1 &
```
Check the rules the switch holds at any time (tab 4, or a spare tab):
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -E "actions=drop|priority=300"
curl -s http://127.0.0.1:8080/firewall/rules | python3 -m json.tool
curl -s http://127.0.0.1:8080/firewall/stats  | python3 -m json.tool
```

### Scenario A - flood is blocked, then recovers (BLOCK)
```
h2 python3 app/client.py --server 10.0.0.1 --mode normal --count 6     # all ACK
h3 python3 app/client.py --server 10.0.0.1 --mode flood  --count 40    # ACK x8, BLOCKED, then timeout
```
Expect `priority=100,ip,nw_src=10.0.0.3 actions=drop` for about 15 s, then it disappears.
`h3 ping -c 3 10.0.0.1` fails while blocked and works again afterwards.

### Scenario B - one flow denied, everything else still works (DENY)
```
h2 python3 app/client.py --server 10.0.0.1 --port 9001 --count 3 --delay 0.5   # ACK (h2 is allowed)
h3 python3 app/client.py --server 10.0.0.1 --port 9001 --count 3               # DENIED
h3 python3 app/client.py --server 10.0.0.1 --port 9000 --count 3 --delay 0.5   # still ACK
```
Expect `priority=200,tcp,nw_src=10.0.0.3,nw_dst=10.0.0.1,tp_dst=9001 actions=drop` for 30 s. Only
h3 -> port 9001 is dropped; h3 can still use port 9000.

### Scenario C - trusted host is exempt (ALLOW)
The log server installs `table=0, priority=300,ip,nw_src=10.0.0.2 actions=goto_table:1` on start-up.
```
h2 python3 app/client.py --server 10.0.0.1 --mode flood --count 40     # every reply is ACK
```

### Scenario D - controller failure and recovery (robustness)
Stop Ryu in tab 1 (Ctrl+C) and run the h3 flood. Nothing can be blocked, so every reply stays `ACK`; the
log server logs **one** warning, keeps serving (no stalls, no log spam) and retries every 5 s.
Restart Ryu in tab 1: the switch reconnects (up to about 10 s) and the log server's reconcile loop
(every 2 s) re-installs the trusted ALLOW rule and any active BLOCK / DENY rule that the restarted
controller lost. Check with `pingall` and the `dump-flows` command.

### Scenario E - detection from switch statistics (optional)
Restart the log server with message-rate detection effectively off, so only the switch's own
measurements can trigger a block:
```
h1 pkill -f "[l]og_server.py"
h1 python3 app/log_server.py --controller 10.0.0.254:8080 --threshold 100000 --bw-threshold-mbps 3 > logs/server_stdout.txt 2>&1 &
h3 python3 app/client.py --server 10.0.0.1 --mode flood --rate 0 --size 1400 --connections 2 --duration 10 --persist --quiet
```
The log shows `ALERT: 10.0.0.3 measured X Mbps by the switch` followed by the block: detection driven
by flow statistics, not by counting messages. The server's own address and the controller's are never
blocked this way (the log line `Bandwidth detection on ... (never: 10.0.0.1, 10.0.0.254)` lists them):
the server's replies to a flood are measured too, and blocking the server would cut it off from the
REST API so the rule could never be removed. Scenario E also works straight after scenario D: when the
switch reconnects, the controller clears the forwarding flows the previous controller learned, so it
relearns which MAC belongs to which IP and per-source statistics keep working.

## Experiments: static baseline vs dynamic firewall
```bash
# Ryu running in tab 1; no Mininet session open
cd ~/dynamic-firewall
sudo python3 experiments/run_experiments.py --quick     # about 3 minutes, smoke test
sudo python3 experiments/run_experiments.py             # 3 runs, 20 s trials, about 10 minutes
python3 experiments/analyze.py                          # results/summary.md + 3 charts
```
Conditions: **idle** (no flood), **static** (baseline: flood runs, the log server only monitors),
**dynamic** (the SDN block is active). Intensities: **low** (1 connection, 20 msg/s), **medium**
(1 connection, unthrottled), **high** (4 connections, unthrottled; saturates the 10 Mbit/s server link).
Measured for the legitimate host h2: iperf throughput, ping latency / loss; and for the attacker:
traffic accepted, time to first block, packets dropped by the switch.

Results go to `results/results.csv` (one row per trial), `results/summary.md` and `results/*.png`.
**Status: harness written, parsers and analysis tested on sample data, but not yet run on Mininet;
paste your own `summary.md` into the report.** Do not run `sudo mn -c` while Ryu is running.

## Configuration (`config/policy.json`)
```json
{ "listen_ports": [9000, 9001],
  "rate": {"window_seconds": 5, "threshold": 8, "recovery_seconds": 15},
  "trusted_sources": ["10.0.0.2"],
  "services": {
    "9000": {"name": "logging", "policy": "rate_limit"},
    "9001": {"name": "admin", "policy": "allowlist", "allowed_sources": ["10.0.0.2"], "deny_seconds": 30}}}
```
Log-server options: `--no-block` (monitor-only baseline), `--no-trusted`, `--threshold/--window/--recovery`,
`--bw-threshold-mbps`, `--quiet-events`, `--log-file`, `--policy`.

## REST API (Ryu, port 8080)
| Method and path | Body | Purpose |
|---|---|---|
| GET `/firewall/status` | | blocked IPs, rule count |
| POST `/firewall/block` / `/firewall/unblock` | `{"ip": "10.0.0.3"}` | block rule on / off |
| POST `/firewall/rule` | `{"action": "allow\|deny\|block", "src", "dst", "proto", "dport"}` | add a rule (duplicates ignored) |
| POST `/firewall/rule/remove` | `{"id": 3}` or the same body used to add | remove one rule (strict match) |
| GET `/firewall/rules` | | all rules with packet / byte counters |
| GET `/firewall/stats` | | per-source rates, dropped totals, connected switches |

## Tests (no Mininet needed)
| File | Covers |
|---|---|
| `tests/test_controller_logic.py` | rule engine, priorities, strict removal, validation; builds and **serialises real OpenFlow messages** against a fake switch; flow-stats maths |
| `tests/test_policy_server.py` | classification, rate threshold, deny, monitor-only, controller-down, bandwidth detection |
| `tests/test_experiment_parsing.py` | ping / iperf / client-summary parsers |
| `tests/local_test.py` | real Ryu + log server + clients on localhost: block, recovery, deny, allow, monitor-only, circuit breaker, load options |

**Not covered by the unit tests:** the real Open vSwitch behaviour (the drop rules actually discarding
packets, the NAT node, bandwidth shaping). `sudo python3 demo.py --auto` runs scenarios A-E on the real
network without pauses, so it doubles as an end-to-end check.

## Troubleshooting
- **`pingall` shows `X`**: Ryu is not running or the switch has not reconnected; check tab 1 for `Switch 1 connected`.
- **`Please shut down the controller which is running on port 6653`**: `sudo pkill -x ovs-testcontrol`.
- **h1 cannot reach the REST API**: Mininet hosts are separate namespaces; they use the NAT node at
  `10.0.0.254`. Test: `h1 curl http://10.0.0.254:8080/firewall/status`.
- **Ryu crashes on start with `is_timeout` or `ALREADY_HANDLED`**: use `scripts/install_deps.sh` (see Setup).
- **`dump-flows` shows nothing for a rule**: OVS prints `nw_src=` / `tp_dst=`, not `ipv4_src`; use
  `grep -E "actions=drop|priority=300"`. Rules are short-lived (15 s / 30 s).
- **Always** run `sudo mn -c` after a crash, **before** starting Ryu.
- **`Error connecting to ovs-db`**: Open vSwitch is not running: `sudo systemctl start openvswitch-switch`
  (`demo.py` tries this itself).
- **`modprobe: FATAL: Module openvswitch not found`** (containers, WSL, some cloud VMs): use the userspace
  datapath, `sudo python3 topology/firewall_topo.py --userspace` or `sudo python3 demo.py --userspace`.
- **Dashboard says "controller DOWN"**: Ryu is not running or not on port 8080; the switch keeps the rules
  it already has meanwhile.

## Publishing to GitHub (required by the rubric)
```bash
cd ~/dynamic-firewall
git init && git add . && git commit -m "Dynamic firewall: Mininet + Ryu + TCP sockets"
git branch -M main
git remote add origin https://github.com/<your-username>/dynamic-firewall.git
git push -u origin main
```
Commit `results/results.csv`, `results/summary.md` and the charts after you run the experiments
(`results/raw/` is git-ignored). Add your Ubuntu / Mininet / Ryu versions to this README.

## Limitations and future work
- IPv4 / TCP-UDP matching only; one switch (the rule engine installs on every connected switch, but the topology has one).
- Application-level detection is per source IP; a spoofed source address would defeat it (flow statistics help but are not a full answer).
- A blocked host loses *all* connectivity; finer-grained responses use DENY rules.
- Statistics-based detection is a simple threshold on one-second samples; windowed or adaptive thresholds would reduce false positives.
- Controller failure leaves existing rules in place (fail-static); it does not add protection while down.
