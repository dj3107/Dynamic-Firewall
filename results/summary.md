# Results: static baseline vs dynamic SDN firewall

Mean +/- standard deviation over the repeated runs. h2 is the legitimate user; h3 floods the log server. The server link is the shared bottleneck.

Runs per condition: 3. Idle reference (no flood): iperf 9.57 +/- 0.01 Mbit/s, ping avg 135.32 +/- 0.26 ms.

## h2 throughput (iperf, Mbit/s) - higher is better

| Flood intensity | Static (no response) | Dynamic (SDN block) |
|---|---|---|
| low | 9.49 +/- 0.01 | 9.56 +/- 0.01 |
| medium | 9.49 +/- 0.01 | 9.56 +/- 0.01 |
| high | 9.21 +/- 0.01 | 9.54 +/- 0.01 |

## h2 average ping RTT (ms) - lower is better

| Flood intensity | Static (no response) | Dynamic (SDN block) |
|---|---|---|
| low | 134.65 +/- 0.52 | 134.74 +/- 1.00 |
| medium | 135.65 +/- 0.65 | 134.97 +/- 0.68 |
| high | 138.40 +/- 0.43 | 135.40 +/- 0.60 |

## h2 maximum ping RTT (ms) - lower is better

| Flood intensity | Static (no response) | Dynamic (SDN block) |
|---|---|---|
| low | 164.64 +/- 0.12 | 163.55 +/- 0.34 |
| medium | 164.76 +/- 0.18 | 163.91 +/- 0.46 |
| high | 167.94 +/- 0.81 | 163.85 +/- 0.19 |

## Attacker traffic accepted by the server (Mbit/s) - lower is better

| Flood intensity | Static (no response) | Dynamic (SDN block) |
|---|---|---|
| low | 0.09 +/- 0.00 | 0.01 +/- 0.00 |
| medium | 0.09 +/- 0.00 | 0.01 +/- 0.00 |
| high | 0.40 +/- 0.00 | 0.01 +/- 0.00 |

## What the dynamic firewall did

| Flood intensity | Blocks installed | Packets dropped by the switch | Time to first BLOCKED reply (s) | h2 throughput retained vs idle |
|---|---|---|---|---|
| low | 1.7 +/- 0.6 | 32 +/- 4 | 1.66 +/- 0.08 | 100% (static: 99%) |
| medium | 2.0 +/- 0.0 | 34 +/- 1 | 1.70 +/- 0.04 | 100% (static: 99%) |
| high | 2.0 +/- 0.0 | 157 +/- 13 | 0.54 +/- 0.03 | 100% (static: 96%) |
