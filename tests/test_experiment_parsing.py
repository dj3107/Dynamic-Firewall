"""Tests for the experiment output parsers (no Mininet needed)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))
import run_experiments as rx

PING = """PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.

--- 10.0.0.1 ping statistics ---
100 packets transmitted, 97 received, +3 errors, 3% packet loss, time 20301ms
rtt min/avg/max/mdev = 0.052/12.340/48.321/9.034 ms
"""
PING_DEAD = "--- 10.0.0.1 ping statistics ---\n50 packets transmitted, 0 received, 100% packet loss, time 10200ms\n"
IPERF = "20261013120102,10.0.0.2,48390,10.0.0.1,5001,3,0.0-20.0,23592960,9437152\n"
IPERF_HUMAN = "[  3]  0.0-20.0 sec  22.5 MBytes  9.44 Mbits/sec\n"


class Parsing(unittest.TestCase):
    def test_ping(self):
        r = rx.parse_ping(PING)
        self.assertEqual((r["avg"], r["max"], r["loss"]), (12.34, 48.321, 3.0))

    def test_ping_total_loss_has_no_rtt(self):
        r = rx.parse_ping(PING_DEAD)
        self.assertEqual((r["avg"], r["max"], r["loss"]), (None, None, 100.0))

    def test_iperf_csv(self):
        self.assertAlmostEqual(rx.parse_iperf_csv("noise\n" + IPERF), 9.437152)

    def test_iperf_human_fallback(self):
        self.assertAlmostEqual(rx.parse_iperf_csv(IPERF_HUMAN), 9.44)

    def test_iperf_garbage(self):
        self.assertIsNone(rx.parse_iperf_csv("connect failed: Connection refused"))

    def test_client_summary(self):
        s = rx.parse_summary('x\nSUMMARY {"sent": 10, "acked": 8, "bytes_acked": 11200}\n')
        self.assertEqual((s["sent"], s["acked"]), (10, 8))
        self.assertEqual(rx.parse_summary("nothing"), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
