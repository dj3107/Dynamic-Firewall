"""Unit tests for the log server's policy logic (fake controller, no sockets / Ryu)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import log_server as ls


class FakeCtl:
    def __init__(self):
        self.calls = []
        self.up = True
        self.rules = []          # what the "controller" currently holds

    def ready(self):
        return self.up

    def post(self, path, payload):
        if not self.up:
            return None
        self.calls.append((path, payload))
        return {"ok": True}

    def get(self, path):
        if path == "/firewall/rules":
            return {"rules": self.rules}
        return {}


def make(monitor=False, trusted=("10.0.0.2",), bw=0.0):
    policy = ls.load_policy(os.path.join(os.path.dirname(__file__), "..", "config",
                                         "policy.json"))
    log = ls.Logger(os.path.join(tempfile.mkdtemp(), "t.log"), quiet_events=True)
    ctl = FakeCtl()
    srv = ls.PolicyServer(policy, ctl, log, monitor_only=monitor, bw_threshold_mbps=bw)
    srv.trusted = set(trusted)
    return srv, ctl


class Policy(unittest.TestCase):
    def test_default_policy_file_loads(self):
        srv, _ = make()
        self.assertEqual(srv.threshold, 8)
        self.assertEqual(srv.service(9001)["policy"], "allowlist")
        self.assertEqual(srv.service(9000)["policy"], "rate_limit")
        self.assertEqual(srv.service(1234)["policy"], "rate_limit")      # unknown port

    def test_classification_by_source_and_port(self):
        srv, _ = make()
        admin, logging_ = srv.service(9001), srv.service(9000)
        self.assertEqual(srv.classify("10.0.0.2", admin), "trusted")
        self.assertEqual(srv.classify("10.0.0.3", admin), "violation")
        self.assertEqual(srv.classify("10.0.0.3", logging_), "monitored")

    def test_rate_threshold_blocks_on_ninth_message(self):
        srv, ctl = make()
        for _ in range(8):
            srv._rate_check("10.0.0.3")
        self.assertEqual(ctl.calls, [])
        srv._rate_check("10.0.0.3")
        self.assertEqual(ctl.calls, [("/firewall/block", {"ip": "10.0.0.3"})])
        self.assertIn("10.0.0.3", srv.blocked)
        srv._rate_check("10.0.0.3")                                       # no duplicate call
        self.assertEqual(len(ctl.calls), 1)

    def test_violation_installs_one_deny_rule_once(self):
        srv, ctl = make()
        svc = srv.service(9001)
        srv._deny("10.0.0.3", "10.0.0.1", 9001, svc)
        srv._deny("10.0.0.3", "10.0.0.1", 9001, svc)
        self.assertEqual(ctl.calls, [("/firewall/rule", {
            "action": "deny", "src": "10.0.0.3", "dst": "10.0.0.1", "proto": "tcp",
            "dport": 9001})])

    def test_controller_down_installs_nothing_and_retries_later(self):
        srv, ctl = make()
        ctl.up = False
        for _ in range(20):
            srv._rate_check("10.0.0.3")
        self.assertEqual(srv.blocked, {})
        ctl.up = True
        srv._rate_check("10.0.0.3")                                       # next message blocks
        self.assertIn("10.0.0.3", srv.blocked)

    def test_monitor_only_flags_but_never_calls_controller(self):
        srv, ctl = make(monitor=True)
        for _ in range(30):
            srv._rate_check("10.0.0.3")
        self.assertEqual(ctl.calls, [])
        self.assertTrue(srv.blocked["10.0.0.3"]["virtual"])

    def test_reconcile_installs_trusted_allow_rule(self):
        srv, ctl = make()
        srv.reconcile()
        self.assertEqual(ctl.calls, [("/firewall/rule", {"action": "allow", "src": "10.0.0.2"})])

    def test_reconcile_skips_rules_the_controller_already_has(self):
        srv, ctl = make()
        ctl.rules = [{"action": "allow", "src": "10.0.0.2", "dst": None, "proto": None,
                      "dport": None}]
        srv.reconcile()
        self.assertEqual(ctl.calls, [])

    def test_reconcile_restores_everything_after_controller_restart(self):
        srv, ctl = make()
        for _ in range(9):
            srv._rate_check("10.0.0.3")                       # active block
        srv._deny("10.0.0.4", "10.0.0.1", 9001, srv.service(9001))   # active deny
        ctl.calls.clear()
        ctl.rules = []                                        # controller restarted: empty
        srv.reconcile()
        posted = {(p, tuple(sorted(b.items()))) for p, b in ctl.calls}
        self.assertEqual(len(ctl.calls), 3)
        self.assertIn(("/firewall/rule", (("action", "block"), ("src", "10.0.0.3"))), posted)
        self.assertIn(("/firewall/rule", (("action", "allow"), ("src", "10.0.0.2"))), posted)
        self.assertIn(("/firewall/rule", (("action", "deny"), ("dport", 9001),
                       ("dst", "10.0.0.1"), ("proto", "tcp"), ("src", "10.0.0.4"))), posted)

    def test_reconcile_does_nothing_in_monitor_only_mode(self):
        srv, ctl = make(monitor=True)
        srv.reconcile()
        self.assertEqual(ctl.calls, [])

    def test_bandwidth_detection(self):
        srv, ctl = make(bw=2.0)
        srv.check_bandwidth({"sources": {
            "10.0.0.3": {"bps": 5e6},      # above 2 Mbps  -> block
            "10.0.0.4": {"bps": 1e6},      # below         -> ignore
            "10.0.0.2": {"bps": 9e6}}})    # trusted       -> ignore
        self.assertEqual(ctl.calls, [("/firewall/block", {"ip": "10.0.0.3"})])
        self.assertIn("measured 5.0 Mbps", srv.blocked["10.0.0.3"]["reason"])

    def test_bandwidth_detection_never_blocks_server_or_controller(self):
        # The server's own replies to a flood are measured too. Blocking the server (or the
        # controller) would cut it off from the REST API and the rule could never be removed.
        srv, ctl = make(bw=2.0)
        srv.protected = {"10.0.0.1", "10.0.0.254"}
        srv.check_bandwidth({"sources": {
            "10.0.0.1": {"bps": 9e6},
            "10.0.0.254": {"bps": 9e6},
            "10.0.0.3": {"bps": 9e6}}})
        self.assertEqual(ctl.calls, [("/firewall/block", {"ip": "10.0.0.3"})])

    def test_protected_addresses_include_controller_and_local_route(self):
        found = ls.protected_addresses("127.0.0.1:8080")
        self.assertIn("127.0.0.1", found)


if __name__ == "__main__":
    unittest.main(verbosity=2)
