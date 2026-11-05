"""
End-to-end test on localhost (no Mininet / Open vSwitch needed).

Starts the real Ryu controller, the log server and the clients, and checks the REST
API and every policy path. All traffic comes from 127.0.0.1, so the policy used here
is a test policy; the switch itself is not involved (see tests/test_controller_logic.py
for the OpenFlow side).

    python3 tests/local_test.py        (ryu-manager must be on PATH)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API = "http://127.0.0.1:8080"
TMP = tempfile.mkdtemp(prefix="fwtest_")

POLICY = {
    "listen_ports": [19000, 19001],
    "rate": {"window_seconds": 5, "threshold": 8, "recovery_seconds": 3},
    "trusted_sources": [],
    "services": {
        "19000": {"name": "logging", "policy": "rate_limit"},
        "19001": {"name": "admin", "policy": "allowlist",
                  "allowed_sources": ["10.0.0.2"], "deny_seconds": 3},
    },
}


def http(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def wait_port(port, timeout=8):
    import socket
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(0.3)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            s.close()
            return True
        s.close()
        time.sleep(0.2)
    return False


def client(*args, timeout=40):
    out = subprocess.run([sys.executable, os.path.join(ROOT, "app", "client.py"),
                          "--server", "127.0.0.1"] + list(args),
                         capture_output=True, text=True, timeout=timeout).stdout
    return out


def replies(out):
    return [l.split("reply='")[1].rstrip("'") for l in out.splitlines() if "reply=" in l]


class EndToEnd(unittest.TestCase):
    procs = []

    @classmethod
    def setUpClass(cls):
        cls.policy_file = os.path.join(TMP, "policy.json")
        with open(cls.policy_file, "w") as f:
            json.dump(POLICY, f)
        cls.ryu = subprocess.Popen(["ryu-manager", os.path.join(ROOT, "controller",
                                    "firewall_controller.py")], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        end = time.time() + 15
        while time.time() < end:
            try:
                http("GET", "/firewall/status")
                break
            except Exception:
                time.sleep(0.3)
        else:
            raise RuntimeError("Ryu did not start")

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs + [cls.ryu]:
            p.terminate()
        shutil.rmtree(TMP, ignore_errors=True)

    def setUp(self):
        for p in self.procs:             # one log server at a time: ports are reused
            p.terminate()
            p.wait(timeout=5)
        self.procs.clear()

    def start_server(self, name, ports, *extra, controller="127.0.0.1:8080", policy=None):
        logf = os.path.join(TMP, name + ".log")
        pf = self.policy_file
        if policy is not None:
            pf = os.path.join(TMP, name + "_policy.json")
            with open(pf, "w") as f:
                json.dump(policy, f)
        p = subprocess.Popen([sys.executable, os.path.join(ROOT, "app", "log_server.py"),
                              "--policy", pf, "--ports", ports,
                              "--controller", controller, "--log-file", logf] + list(extra),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        self.assertTrue(wait_port(int(ports.split(",")[0])), "log server did not start")
        return p, logf

    def read(self, logf):
        with open(logf) as f:
            return f.read()

    def reset_rules(self):
        for r in http("GET", "/firewall/rules")[1]["rules"]:
            http("POST", "/firewall/rule/remove", {"id": r["id"]})

    # -------------------------------------------------------------- REST API
    def test_01_rest_validation(self):
        self.assertEqual(http("GET", "/firewall/status")[1]["blocked_ips"], [])
        self.assertEqual(http("POST", "/firewall/block", {"ip": "not-an-ip"})[0], 400)
        self.assertEqual(http("POST", "/firewall/rule", {"action": "deny", "src": "1.2.3.4",
                              "dport": 80})[0], 400)
        code, body = http("POST", "/firewall/rule", {"action": "allow", "src": "10.9.9.9"})
        self.assertEqual((code, body["changed"]), (200, True))
        self.assertFalse(http("POST", "/firewall/rule", {"action": "allow",
                                                           "src": "10.9.9.9"})[1]["changed"])
        self.assertTrue(http("POST", "/firewall/rule/remove", {"action": "allow",
                                                                 "src": "10.9.9.9"})[1]["removed"])
        self.assertIn("sources", http("GET", "/firewall/stats")[1])
        self.reset_rules()

    # ----------------------------------------------- rate limit block + recovery
    def test_02_flood_blocked_then_recovered(self):
        _, logf = self.start_server("enforce", "19000,19001")
        normal = replies(client("--port", "19000", "--mode", "normal", "--count", "4",
                                "--delay", "0.2"))
        self.assertEqual(normal, ["ACK"] * 4)
        self.assertEqual(http("GET", "/firewall/status")[1]["blocked_ips"], [])
        time.sleep(5.2)          # same source IP: let the 5 s rate window clear first
        flood = replies(client("--port", "19000", "--mode", "flood", "--count", "14",
                               "--delay", "0.05"))
        self.assertEqual(flood[:8], ["ACK"] * 8)
        self.assertEqual(flood[8], "BLOCKED")                       # 9th message
        self.assertEqual(http("GET", "/firewall/status")[1]["blocked_ips"], ["127.0.0.1"])
        rules = http("GET", "/firewall/rules")[1]["rules"]
        self.assertEqual([(r["action"], r["src"], r["priority"]) for r in rules],
                         [("block", "127.0.0.1", 100)])
        time.sleep(5)                                              # recovery_seconds = 3
        self.assertEqual(http("GET", "/firewall/status")[1]["blocked_ips"], [])
        text = self.read(logf)
        self.assertIn("ALERT", text)
        self.assertIn("BLOCKED by SDN controller", text)
        self.assertIn("UNBLOCKED after", text)

    # ------------------------------------------- deny on an allow-listed port
    def test_03_allowlist_port_denies_one_flow_only(self):
        self.reset_rules()
        _, logf = self.start_server("deny", "19000,19001")
        out = replies(client("--port", "19001", "--count", "2", "--delay", "0.1"))
        self.assertEqual(out, ["DENIED"])
        rule = http("GET", "/firewall/rules")[1]["rules"][0]
        self.assertEqual((rule["action"], rule["src"], rule["dst"], rule["proto"],
                          rule["dport"], rule["priority"]),
                         ("deny", "127.0.0.1", "127.0.0.1", "tcp", 19001, 200))
        # fine-grained: the same source can still use the logging service
        self.assertEqual(replies(client("--port", "19000", "--count", "2", "--delay", "0.1")),
                         ["ACK", "ACK"])
        self.assertEqual(http("GET", "/firewall/status")[1]["blocked_ips"], [])
        time.sleep(5.5)                                            # deny_seconds = 3
        self.assertEqual(http("GET", "/firewall/rules")[1]["rules"], [])
        self.assertIn("DENY 127.0.0.1 -> 127.0.0.1:19001 expired", self.read(logf))

    # --------------------------------------------- trusted source (allow rule)
    def test_04_trusted_source_gets_allow_rule_and_is_exempt(self):
        self.reset_rules()
        pol = dict(POLICY, trusted_sources=["127.0.0.1"], listen_ports=[19100],
                   services={"19100": {"name": "logging", "policy": "rate_limit"}})
        p, logf = self.start_server("trusted", "19100", policy=pol)
        time.sleep(3.5)                       # reconcile runs every 2 s
        rules = http("GET", "/firewall/rules")[1]["rules"]
        self.assertEqual([(r["action"], r["src"], r["priority"]) for r in rules],
                         [("allow", "127.0.0.1", 300)])
        flood = replies(client("--port", "19100", "--mode", "flood", "--count", "20",
                               "--delay", "0.02"))
        self.assertEqual(flood, ["ACK"] * 20)                      # trusted: never blocked
        self.assertEqual(http("GET", "/firewall/status")[1]["blocked_ips"], [])
        self.reset_rules()

    # -------------------------------------------------- monitor-only baseline
    def test_05_monitor_only_never_touches_the_network(self):
        self.reset_rules()
        _, logf = self.start_server("monitor", "19200", "--no-block")
        flood = replies(client("--port", "19200", "--mode", "flood", "--count", "20",
                               "--delay", "0.02"))
        self.assertEqual(flood, ["ACK"] * 20)                      # nothing is blocked
        self.assertEqual(http("GET", "/firewall/rules")[1]["rules"], [])
        text = self.read(logf)
        self.assertIn("monitor-only, no SDN action", text)
        self.assertEqual(text.count("ALERT"), 1)                   # flagged once, not per msg

    # ----------------------------------------------- controller down: breaker
    def test_06_controller_down_does_not_stall_or_spam(self):
        self.reset_rules()
        _, logf = self.start_server("down", "19300", controller="127.0.0.1:18999")
        t0 = time.time()
        flood = replies(client("--port", "19300", "--mode", "flood", "--count", "40",
                               "--delay", "0.02"))
        self.assertLess(time.time() - t0, 6)                       # no per-message timeouts
        self.assertEqual(flood, ["ACK"] * 40)                      # keeps serving
        text = self.read(logf)
        self.assertEqual(text.count("unreachable"), 1)             # logged once, not 30x

    # ------------------------------------- controller restart: rules come back
    def test_06c_rules_restored_after_controller_restart(self):
        self.reset_rules()
        pol = dict(POLICY, trusted_sources=["10.9.9.9"], listen_ports=[19600],
                   rate={"window_seconds": 5, "threshold": 8, "recovery_seconds": 60},
                   services={"19600": {"name": "logging", "policy": "rate_limit"}})
        self.start_server("restore", "19600", policy=pol)
        client("--port", "19600", "--mode", "flood", "--count", "12", "--delay", "0.03")
        time.sleep(2.5)
        have = lambda: {(r["action"], r["src"]) for r in http("GET", "/firewall/rules")[1]["rules"]}
        self.assertEqual(have(), {("allow", "10.9.9.9"), ("block", "127.0.0.1")})
        type(self).ryu.terminate()                       # controller dies, rule table lost
        type(self).ryu.wait(timeout=5)
        type(self).ryu = subprocess.Popen(["ryu-manager", os.path.join(ROOT, "controller",
                                           "firewall_controller.py")],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 12
        while time.time() < end:
            try:
                if have() == {("allow", "10.9.9.9"), ("block", "127.0.0.1")}:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        self.assertEqual(have(), {("allow", "10.9.9.9"), ("block", "127.0.0.1")})

    # --------------------------------------------------- port already in use
    def test_06b_second_server_on_same_port_fails_loudly(self):
        self.reset_rules()
        self.start_server("first", "19500")
        logf = os.path.join(TMP, "second.log")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "app", "log_server.py"),
                            "--ports", "19500", "--log-file", logf], capture_output=True,
                           text=True, timeout=10)
        self.assertEqual(p.returncode, 1)
        self.assertIn("cannot listen on port 19500", p.stdout)

    # ----------------------------------------------------- client load options
    def test_07_client_duration_persist_summary(self):
        self.reset_rules()
        self.start_server("load", "19400", "--quiet-events", "--threshold", "100000")
        out = client("--port", "19400", "--mode", "flood", "--rate", "0", "--size", "1400",
                     "--connections", "2", "--duration", "2", "--persist", "--quiet",
                     "--summary-json")
        summary = json.loads(out.strip().split("SUMMARY ")[1])
        self.assertGreater(summary["acked"], 100)
        self.assertEqual(summary["connects"], 2)
        self.assertGreater(summary["bytes_acked"], summary["acked"] * 1300)


if __name__ == "__main__":
    unittest.main(verbosity=2)
