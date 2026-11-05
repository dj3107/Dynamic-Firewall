"""
log_server.py - Centralized Security Event Logging Server (TCP) and policy engine.

Every TCP connection is CLASSIFIED by source IP, destination IP and destination port
against config/policy.json, and the SDN controller is told to install the matching rule:

  trusted source            -> ALLOW rule  (priority 300, exempt from rate limiting)
  port with an allow-list   -> a source not on the list gets a DENY rule for that one
                               flow (src, dst, tcp, port); its other traffic still works
  port with rate limiting   -> a source sending too many messages gets a BLOCK rule
                               (all traffic from that IP is dropped by the switch)

Recovery: block rules are removed after the host has been quiet for `recovery_seconds`;
deny rules are removed after the service's `deny_seconds`.

Modes
  default            enforce: call the controller (REST) to install / remove rules
  --no-block         monitor-only baseline: detect and log, but never touch the network
  --bw-threshold-mbps N   also block any source the SWITCH reports above N Mbps
                          (flow statistics from the controller, not application messages)

Run from the project root:
    python3 app/log_server.py --controller 10.0.0.254:8080
"""
import argparse
import json
import os
import socket
import threading
import time
import urllib.request
from collections import deque, defaultdict
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_POLICY_FILE = os.path.join(ROOT, "config", "policy.json")
DEFAULT_LOG_FILE = os.path.join(ROOT, "logs", "security_events.log")

DEFAULT_POLICY = {
    "listen_ports": [9000],
    "rate": {"window_seconds": 5, "threshold": 8, "recovery_seconds": 15},
    "trusted_sources": [],
    "services": {"9000": {"name": "logging", "policy": "rate_limit"}},
}


class Logger:
    """Timestamped console + file logger. EVENT lines can be silenced for load tests."""

    def __init__(self, path, quiet_events=False):
        self.path = path
        self.quiet_events = quiet_events
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def info(self, text):
        line = "[%s] %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], text)
        with self.lock:
            print(line, flush=True)
            try:
                with open(self.path, "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    def event(self, text):
        if not self.quiet_events:
            self.info(text)


class ControllerClient:
    """REST client for the Ryu controller with a circuit breaker.

    If the controller is unreachable the client backs off for `backoff` seconds instead
    of retrying (and stalling) on every message; the server keeps serving meanwhile.
    """

    def __init__(self, addr, log, enabled=True, backoff=5.0, timeout=2.0):
        self.addr, self.log, self.enabled = addr, log, enabled
        self.backoff, self.timeout = backoff, timeout
        self._retry_at = 0.0
        self._down = False

    def ready(self):
        return self.enabled and time.time() >= self._retry_at

    def _call(self, method, path, payload=None):
        if not self.ready():
            return None
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request("http://%s%s" % (self.addr, path), data=data,
                                     headers={"Content-Type": "application/json"},
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode())
        except Exception as exc:
            self._retry_at = time.time() + self.backoff
            if not self._down:
                self._down = True
                self.log.info("WARNING: controller %s unreachable (%s); continuing without "
                              "SDN enforcement, retrying in %.0fs" % (self.addr, exc, self.backoff))
            return None
        if self._down:
            self._down = False
            self.log.info("controller %s reachable again" % self.addr)
        return result

    def post(self, path, payload):
        return self._call("POST", path, payload)

    def get(self, path):
        return self._call("GET", path)


class PolicyServer:
    def __init__(self, policy, ctl, log, monitor_only=False, use_trusted=True,
                 bw_threshold_mbps=0.0):
        self.policy, self.ctl, self.log = policy, ctl, log
        self.monitor_only = monitor_only
        self.bw_threshold = bw_threshold_mbps * 1e6
        rate = policy["rate"]
        self.window = rate["window_seconds"]
        self.threshold = rate["threshold"]
        self.recovery = rate["recovery_seconds"]
        self.trusted = set(policy.get("trusted_sources", [])) if use_trusted else set()
        self.lock = threading.Lock()
        self.recent = defaultdict(deque)     # ip -> message timestamps
        self.blocked = {}                    # ip -> {"since", "reason", "virtual"}
        self.denied = {}                     # (src, dst, port) -> {"since", "until", "virtual"}
        self.last_seen = {}                  # ip -> time of last message
        # Addresses bandwidth detection must never block: this server's own addresses (its
        # replies to a flood are measured too) and the controller's. Blocking either would
        # cut the server off from the REST API, so it could never remove the rule again.
        self.protected = set()
        self._last_reconcile = 0.0
        self.stop = threading.Event()

    # ---------------------------------------------------------- classification
    def service(self, port):
        return self.policy["services"].get(str(port),
                                           {"name": "port-%d" % port, "policy": "rate_limit"})

    def classify(self, src, service):
        if src in self.trusted:
            return "trusted"
        if service.get("policy") == "allowlist":
            return "allowed" if src in service.get("allowed_sources", []) else "violation"
        return "monitored"

    # ---------------------------------------------------------------- actions
    def _block(self, ip, reason):
        """Called with self.lock held. Block `ip` (or just flag it in monitor-only mode)."""
        if not self.monitor_only and not self.ctl.ready():
            return                                    # controller down: retry later, no spam
        self.log.info("ALERT: %s %s -> %s" % (
            ip, reason, "monitor-only, no SDN action" if self.monitor_only
            else "requesting SDN block"))
        if self.monitor_only:
            self.blocked[ip] = {"since": time.time(), "reason": reason, "virtual": True}
            return
        res = self.ctl.post("/firewall/block", {"ip": ip})
        if res is not None:
            self.blocked[ip] = {"since": time.time(), "reason": reason, "virtual": False}
            self.log.info("ACTION: %s BLOCKED by SDN controller, response=%s" % (ip, res))

    def _deny(self, src, dst, port, service):
        """Called with self.lock held. Install a DENY rule for one flow."""
        key = (src, dst, port)
        if key in self.denied:
            return
        secs = service.get("deny_seconds", 30)
        self.log.info("ALERT: POLICY VIOLATION %s -> %s:%d (%s is allow-listed)" % (
            src, dst, port, service["name"]))
        if self.monitor_only:
            self.denied[key] = {"since": time.time(), "until": time.time() + secs,
                                "virtual": True}
            return
        res = self.ctl.post("/firewall/rule", {"action": "deny", "src": src, "dst": dst,
                                               "proto": "tcp", "dport": port})
        if res is not None:
            self.denied[key] = {"since": time.time(), "until": time.time() + secs,
                                "virtual": False}
            self.log.info("ACTION: DENY %s -> %s:%d/tcp installed for %ds, response=%s" % (
                src, dst, port, secs, res))

    def _rate_check(self, ip):
        now = time.time()
        dq = self.recent[ip]
        dq.append(now)
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) > self.threshold and ip not in self.blocked:
            self._block(ip, "sent %d msgs in %ds (threshold %d)" % (len(dq), self.window,
                                                                   self.threshold))

    # --------------------------------------------------------- connection loop
    def handle(self, conn, addr, port):
        src, sport = addr
        dst = conn.getsockname()[0]
        self.protected.add(dst)              # an address of this server: never block it
        service = self.service(port)
        cls = self.classify(src, service)
        self.log.event("CONNECT %s:%d -> %s:%d service=%s class=%s" %
                       (src, sport, dst, port, service["name"], cls))
        try:
            with conn:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                conn.settimeout(30)
                if cls == "violation":
                    with self.lock:
                        self._deny(src, dst, port, service)
                    try:
                        conn.sendall(b"DENIED")
                    except OSError:
                        pass
                    return
                while True:
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    with self.lock:
                        self.last_seen[src] = time.time()
                        if service.get("policy") == "rate_limit" and cls != "trusted":
                            if src not in self.blocked:
                                self._rate_check(src)
                        state = self.blocked.get(src)
                        enforced = state is not None and not state["virtual"]
                    if not self.log.quiet_events:
                        msg = data.decode(errors="replace").strip()[:60]
                        self.log.event("EVENT %s:%d -> %s:%d %r (blocked=%s)" %
                                       (src, sport, dst, port, msg, enforced))
                    try:
                        conn.sendall(b"BLOCKED" if enforced else b"ACK")
                    except OSError:
                        break
        finally:
            self.log.event("DISCONNECT %s:%d" % (src, sport))

    def listen(self, port, host="0.0.0.0"):
        """Bind a listening socket. Raises OSError (e.g. port already in use)."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((host, port))
        except OSError:
            srv.close()
            raise
        srv.listen(128)
        srv.settimeout(1.0)
        self.log.info("Listening on %s:%d (service=%s, policy=%s)" % (
            host, port, self.service(port)["name"], self.service(port).get("policy")))
        return srv

    def serve(self, srv, port):
        while not self.stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.handle, args=(conn, addr, port),
                             daemon=True).start()
        srv.close()

    # -------------------------------------------------------- background tasks
    def reconcile(self):
        """Called with self.lock held. Make sure the controller really holds every rule
        this server believes is installed (trusted ALLOW rules, active BLOCKs and DENYs).

        This repairs the network after a controller restart, which loses its rule table.
        """
        if self.monitor_only or not self.ctl.ready():
            return
        res = self.ctl.get("/firewall/rules")
        if res is None:
            return
        present = {(r["action"], r["src"], r["dst"], r["proto"], r["dport"])
                   for r in res.get("rules", [])}
        wanted = [("allow", ip, None, None, None, "ALLOW rule for trusted source %s" % ip)
                  for ip in sorted(self.trusted)]
        wanted += [("block", ip, None, None, None, "BLOCK rule for %s" % ip)
                   for ip, info in self.blocked.items() if not info["virtual"]]
        wanted += [("deny", s, d, "tcp", p, "DENY rule %s -> %s:%d" % (s, d, p))
                   for (s, d, p), info in self.denied.items() if not info["virtual"]]
        for action, src, dst, proto, dport, label in wanted:
            if (action, src, dst, proto, dport) in present:
                continue
            body = {"action": action, "src": src}
            if dst:
                body["dst"] = dst
            if proto:
                body["proto"] = proto
                body["dport"] = dport
            res = self.ctl.post("/firewall/rule", body)
            if res is not None:
                self.log.info("ACTION: %s installed on the controller, response=%s"
                              % (label, res))

    def sweeper(self):
        """Every second: expire blocks and denies; every 2 s: reconcile with the controller."""
        while not self.stop.wait(1.0):
            now = time.time()
            with self.lock:
                if now - self._last_reconcile >= 2.0:
                    self._last_reconcile = now
                    self.reconcile()
                for ip, info in list(self.blocked.items()):
                    quiet = now - max(self.last_seen.get(ip, 0), info["since"])
                    if quiet < self.recovery:
                        continue
                    if info["virtual"]:
                        res = {"monitor_only": True}
                    else:
                        res = self.ctl.post("/firewall/unblock", {"ip": ip})
                    if res is not None:
                        self.log.info("ACTION: %s UNBLOCKED after %.1fs quiet, response=%s" %
                                      (ip, quiet, res))
                        del self.blocked[ip]
                        self.recent.pop(ip, None)
                for key, info in list(self.denied.items()):
                    if now < info["until"]:
                        continue
                    src, dst, port = key
                    res = {"monitor_only": True} if info["virtual"] else self.ctl.post(
                        "/firewall/rule/remove", {"action": "deny", "src": src, "dst": dst,
                                                  "proto": "tcp", "dport": port})
                    if res is not None:
                        self.log.info("ACTION: DENY %s -> %s:%d expired and removed, "
                                      "response=%s" % (src, dst, port, res))
                        del self.denied[key]

    def check_bandwidth(self, stats):
        """Block any source the switch reports above the bandwidth threshold."""
        for ip, d in stats.get("sources", {}).items():
            if ip in self.protected:
                continue
            if d.get("bps", 0) >= self.bw_threshold and ip not in self.trusted:
                with self.lock:
                    if ip not in self.blocked:
                        self.last_seen.setdefault(ip, time.time())
                        self._block(ip, "measured %.1f Mbps by the switch (threshold "
                                    "%.1f Mbps)" % (d["bps"] / 1e6, self.bw_threshold / 1e6))

    def bandwidth_monitor(self):
        """Optional: poll the controller's flow statistics once a second."""
        while not self.stop.wait(1.0):
            stats = self.ctl.get("/firewall/stats")
            if stats:
                self.check_bandwidth(stats)


def protected_addresses(controller):
    """The controller's IP and this host's IP on the path to it (e.g. 10.0.0.254, 10.0.0.1)."""
    host = controller.rsplit(":", 1)[0]
    found = set()
    try:
        found.add(socket.gethostbyname(host))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, 9))             # UDP connect sends nothing; it only picks a route
            found.add(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass
    return found


def load_policy(path):
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    if path and os.path.exists(path):
        with open(path) as f:
            user = json.load(f)
        for key, value in user.items():
            if isinstance(value, dict) and isinstance(policy.get(key), dict) and key != "services":
                policy[key].update(value)
            else:
                policy[key] = value
    return policy


def main():
    ap = argparse.ArgumentParser(description="Security Event Logging Server / policy engine")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--ports", help="comma-separated ports (default: policy listen_ports)")
    ap.add_argument("--controller", default="127.0.0.1:8080", help="Ryu REST API host:port")
    ap.add_argument("--policy", default=DEFAULT_POLICY_FILE)
    ap.add_argument("--threshold", type=int, help="override rate threshold (msgs per window)")
    ap.add_argument("--window", type=int, help="override rate window (seconds)")
    ap.add_argument("--recovery", type=int, help="override recovery time (seconds)")
    ap.add_argument("--no-block", action="store_true",
                    help="monitor-only baseline: detect and log, never change the network")
    ap.add_argument("--no-trusted", action="store_true",
                    help="ignore trusted_sources (no allow rules, no exemption)")
    ap.add_argument("--bw-threshold-mbps", type=float, default=0.0,
                    help="also block sources the switch measures above this rate (0 = off)")
    ap.add_argument("--quiet-events", action="store_true",
                    help="do not log every message (use for heavy load tests)")
    ap.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    a = ap.parse_args()

    policy = load_policy(a.policy)
    if a.threshold is not None:
        policy["rate"]["threshold"] = a.threshold
    if a.window is not None:
        policy["rate"]["window_seconds"] = a.window
    if a.recovery is not None:
        policy["rate"]["recovery_seconds"] = a.recovery
    ports = [int(p) for p in a.ports.split(",")] if a.ports else policy["listen_ports"]

    log = Logger(a.log_file, quiet_events=a.quiet_events)
    ctl = ControllerClient(a.controller, log, enabled=not a.no_block)
    server = PolicyServer(policy, ctl, log, monitor_only=a.no_block,
                          use_trusted=not a.no_trusted, bw_threshold_mbps=a.bw_threshold_mbps)
    r = policy["rate"]
    log.info("Log server starting: controller=%s mode=%s" % (
        a.controller, "MONITOR-ONLY" if a.no_block else "ENFORCE"))
    log.info("Policy: >%d msgs/%ds => block; unblock after %ds quiet; trusted=%s" % (
        r["threshold"], r["window_seconds"], r["recovery_seconds"], sorted(server.trusted)))

    threading.Thread(target=server.sweeper, daemon=True).start()
    if a.bw_threshold_mbps > 0 and not a.no_block:
        server.protected |= protected_addresses(a.controller)
        threading.Thread(target=server.bandwidth_monitor, daemon=True).start()
        log.info("Bandwidth detection on: block sources above %.1f Mbps (never: %s)" % (
            a.bw_threshold_mbps, ", ".join(sorted(server.protected)) or "-"))
    sockets = []
    for p in ports:                      # bind in the main thread so a failure is loud
        try:
            sockets.append((server.listen(p, a.host), p))
        except OSError as exc:
            log.info("ERROR: cannot listen on port %d: %s (is another log server running?)"
                     % (p, exc))
            raise SystemExit(1)
    for srv, p in sockets:
        threading.Thread(target=server.serve, args=(srv, p), daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop.set()
        log.info("Shutting down")


if __name__ == "__main__":
    main()
