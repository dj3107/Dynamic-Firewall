# Viva notes - Dynamic Firewall with Security Event Logger

## 60-second explanation
A TCP logging service runs on h1. Every client connection is classified by source IP, destination and
port against a policy file. If a client floods the rate-limited port, the log server calls the Ryu
controller's REST API and the controller installs an OpenFlow **block** rule (drop everything from that
IP) on the switch. If a client touches a protected port it is not allowed to use, only that one flow
(src, dst, TCP, port) is **denied**. Trusted hosts get an **allow** rule that overrides the drop rules.
Rules are removed automatically after a quiet period, so the network recovers without an operator.
The point of SDN here is that the application layer controls the network layer at run time.

## How the pieces talk
1. Client -> log server over TCP (ports 9000 logging, 9001 admin). Threaded server, one thread per client.
2. Log server -> controller over REST (`/firewall/block`, `/firewall/rule`, `/firewall/rule/remove`).
3. Controller -> switch over OpenFlow 1.3 (`OFPFlowMod`, strict delete, flow-stats request).
4. Controller -> log server: `GET /firewall/stats` returns per-source throughput measured by the switch.
5. h1 reaches the controller through a NAT node in the VM's root namespace (`10.0.0.254`), because
   Mininet hosts are isolated network namespaces.

## Design decisions (and why)
- **Two-table pipeline.** Table 0 = policy (allow / deny / block), table 1 = learned L2 forwarding. An
  allow rule means "continue to table 1", so a trusted host is exempt from drop rules but still forwarded by
  the learning switch. (My first version used the `NORMAL` action; that makes OVS run its own MAC
  learning, which never sees reply traffic, so it would flood. Found while reviewing, fixed.)
- **Priorities 300 / 200 / 100 / 1.** More specific intent beats less specific: allow > deny > block > forwarding.
- **Strict delete.** Removing a block rule must not remove a deny rule for the same host (non-strict delete would).
- **Block vs deny.** Block is a heavy response to a misbehaving *host*; deny is a precise response to an
  unauthorised *flow*. Different granularity, different recovery times.
- **Recovery by silence.** A blocked host cannot reach the server, so its last-seen time stops advancing;
  after 15 s the block is removed. No timers in the switch, the log server owns the policy.
- **Circuit breaker + reconcile.** If the controller is down the log server logs one warning, keeps serving, and retries every 5 s
  (instead of stalling on every message). Every 2 s it also compares the controller's rule list with the rules it believes
  are installed and re-installs anything missing, so a controller restart (which loses its rule table) heals itself.
- **Monitor-only baseline (`--no-block`).** Same detection and logging, but the network never reacts. This gives a
  fair static baseline: the only difference between the two conditions is the SDN response.
- **Persistent attacker in the experiments.** The flood client reconnects after being blocked, as a real attacker would,
  so the comparison is not flattered by a client that gives up.

## Rubric map
| Rubric item | Where |
|---|---|
| Problem understanding & architecture | README diagram, this file |
| TCP socket implementation | `app/log_server.py` (threads, multiple ports, timeouts, replies), `app/client.py` |
| Mininet + SDN | `topology/firewall_topo.py`, `controller/firewall_controller.py` (2-table pipeline, rule engine) |
| Socket-SDN integration | log server -> REST -> flow rules; controller flow stats -> log server (bandwidth detection) |
| Complete functionality | classification by src/dst/port; allow, deny, block; auto recovery; multiple clients |
| Dynamic SDN functionality | rules installed and removed at run time; stats polling |
| Challenging scenario | flood (block + recovery), unauthorised access (deny), controller failure |
| Performance evaluation | `experiments/` static vs dynamic, 3 intensities, idle reference |
| Documentation | README, tests, this file |

## Likely questions
- **Why not just iptables on h1?** iptables protects one machine after the traffic has crossed the network.
  The SDN rule drops it at the switch, before it reaches h1, protects every host behind the switch, and
  can be driven by any application through one controller.
- **Why does the 9th message trigger the block?** Threshold is 8 messages per 5-second sliding window; the 9th exceeds it.
- **What happens to the TCP connection of a blocked host?** Its packets are dropped; TCP retransmits with
  growing delays, the client times out. A stray retransmission can get through after the rule is removed
  (visible as one extra log line).
- **Can a trusted host abuse its allow rule?** Yes, by design: allow is an operator decision. It is configured in
  `policy.json`, not by traffic.
- **What if the attacker spoofs its source IP?** Source-IP rules would block the wrong host. Mitigations: anti-spoofing
  (ingress filtering, port-MAC-IP binding at the switch). Out of scope; listed as a limitation.
- **False positives?** A legitimate burst above 8 messages / 5 s is blocked for ~15 s. Tune threshold and window
  in `policy.json`; the experiments show the trade-off.
- **What if the controller dies?** Installed flows stay in the switch (OpenFlow fail-secure), but no new rules are installed and
  unknown destinations cannot be learned. The log server keeps serving and retries; when the controller returns, the
  reconcile loop re-installs the rules the restarted controller lost.
- **How does it scale?** One flow-mod per rule; the rule table is a dict; the controller polls stats once a second for
  all flows (one request per switch). With many switches, stats polling and the REST call rate are the limits.
- **Why REST between the log server and the controller?** It decouples the application from OpenFlow: the application
  only says *what* (block this IP), the controller decides *how* (which switches, which tables, which priority).
- **Why is detection partly in the application and not the switch?** The application knows what a "message" is;
  the switch only sees packets. Both views are used: messages for policy, switch statistics for bandwidth detection.

## Problems I hit and how they were solved (good to mention)
- Ryu 4.34 + eventlet 0.30.2 crashes on Python 3.10 -> Ryu from GitHub + eventlet 0.33.3 + dnspython 2.2.1.
- `openvswitch-testcontroller` service held port 6653 -> disabled the service (Mininet only needs the binary).
- Mininet hosts could not reach the controller's REST API -> NAT node in the root namespace.
- `sudo mn -c` kills Ryu -> start order: clean up first, start Ryu second.
- `ovs-ofctl dump-flows` prints `nw_src=` and `tp_dst=`, not OpenFlow field names -> grep for `actions=drop`.
- Bandwidth detection blocked the **server itself** (its replies to a flood also exceed the threshold);
  then h1 could not reach the REST API to remove any rule and the network stayed locked -> the server's
  own address and the controller's are never blocked by bandwidth detection.
- After a controller restart, bandwidth detection silently did nothing: the switch kept forwarding with
  the old controller's learned flows, so the new controller never saw packets and never relearned
  MAC -> IP (per-source stats were empty) -> on switch connect, clear table 1 (forwarding) only; table 0
  (the firewall rules) stays, so the switch remains protected.

## Fill in after running the experiments
- Time from first flood message to BLOCKED reply: ____ s (from `first_blocked_s` / logs)
- Block rule install time (ALERT -> BLOCKED log lines): ____ ms
- Recovery time (last message -> UNBLOCKED): ____ s
- h2 throughput during the high flood: static ____ vs dynamic ____ Mbit/s (idle ____)
- h2 average RTT during the high flood: static ____ vs dynamic ____ ms (idle ____)
- Packets dropped by the switch (dynamic, high): ____
