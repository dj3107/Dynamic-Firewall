"""
Unit tests for the controller's rule engine and flow-stats processing.
Runs without Mininet / Open vSwitch: a fake datapath records the OpenFlow messages.

    python3 tests/test_controller_logic.py
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "controller"))

from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
import firewall_controller as fc


class FakeWSGI:
    def register(self, *a, **k):
        pass


class FakeDP:
    def __init__(self, dpid=1):
        self.id = dpid
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
        self.sent = []
        self.xid = 0

    def send_msg(self, msg):
        msg.serialize()              # raises if the match / actions are malformed
        self.sent.append(msg)

    def set_xid(self, msg):
        self.xid += 1
        msg.set_xid(self.xid)
        return self.xid


def fake_stat(priority, packets, nbytes, **match):
    m = ofproto_v1_3_parser.OFPMatch(**match)
    return types.SimpleNamespace(priority=priority, packet_count=packets,
                                 byte_count=nbytes, match=m)


class ControllerLogic(unittest.TestCase):
    def setUp(self):
        self.app = fc.DynamicFirewall(wsgi=FakeWSGI())
        self.dp = FakeDP()
        self.app.datapaths[1] = self.dp

    def flow_mods(self):
        return [m for m in self.dp.sent if isinstance(m, ofproto_v1_3_parser.OFPFlowMod)]

    def test_block_installs_priority_100_drop(self):
        rule, created = self.app.block_ip("10.0.0.3")
        self.assertTrue(created)
        fm = self.flow_mods()[-1]
        self.assertEqual(fm.priority, 100)
        self.assertEqual(fm.match["ipv4_src"], "10.0.0.3")
        self.assertEqual(fm.instructions[0].actions, [])          # drop
        self.assertEqual(self.app.blocked_ips, {"10.0.0.3"})

    def test_duplicate_rule_not_reinstalled(self):
        self.app.block_ip("10.0.0.3")
        n = len(self.dp.sent)
        _, created = self.app.block_ip("10.0.0.3")
        self.assertFalse(created)
        self.assertEqual(len(self.dp.sent), n)

    def test_deny_matches_src_dst_proto_port(self):
        rule, _ = self.app.add_rule({"action": "deny", "src": "10.0.0.3",
                                     "dst": "10.0.0.1", "proto": "tcp", "dport": 9001})
        fm = self.flow_mods()[-1]
        self.assertEqual(fm.priority, 200)
        self.assertEqual(fm.match["ipv4_src"], "10.0.0.3")
        self.assertEqual(fm.match["ipv4_dst"], "10.0.0.1")
        self.assertEqual(fm.match["ip_proto"], 6)
        self.assertEqual(fm.match["tcp_dst"], 9001)
        self.assertEqual(fm.instructions[0].actions, [])

    def test_udp_deny_uses_udp_dst(self):
        self.app.add_rule({"action": "deny", "src": "10.0.0.3", "proto": "udp", "dport": 53})
        fm = self.flow_mods()[-1]
        self.assertEqual(fm.match["udp_dst"], 53)

    def test_allow_is_priority_300_goto_forwarding_table(self):
        self.app.add_rule({"action": "allow", "src": "10.0.0.2"})
        fm = self.flow_mods()[-1]
        self.assertEqual((fm.table_id, fm.priority), (0, 300))
        inst = fm.instructions[0]
        self.assertIsInstance(inst, ofproto_v1_3_parser.OFPInstructionGotoTable)
        self.assertEqual(inst.table_id, 1)

    def test_drop_rules_live_in_policy_table(self):
        self.app.block_ip("10.0.0.3")
        self.assertEqual(self.flow_mods()[-1].table_id, 0)

    def test_switch_connect_installs_two_table_pipeline(self):
        ev = types.SimpleNamespace(msg=types.SimpleNamespace(datapath=self.dp))
        self.app.switch_features_handler(ev)
        miss = {(fm.table_id): fm for fm in self.flow_mods() if fm.priority == 0}
        self.assertIsInstance(miss[0].instructions[0],
                              ofproto_v1_3_parser.OFPInstructionGotoTable)
        out = miss[1].instructions[0].actions[0]
        self.assertEqual(out.port, ofproto_v1_3.OFPP_CONTROLLER)

    def test_switch_connect_clears_stale_learned_flows_first(self):
        # After a controller restart the switch still holds the old controller's learned
        # flows; they must go (table 1 only), or no packet-ins arrive and MAC -> IP is
        # never relearned, which silently disables per-source statistics.
        ev = types.SimpleNamespace(msg=types.SimpleNamespace(datapath=self.dp))
        self.app.switch_features_handler(ev)
        fms = self.flow_mods()
        deletes = [fm for fm in fms if fm.command == ofproto_v1_3.OFPFC_DELETE]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0].table_id, 1)
        self.assertIs(fms[0], deletes[0])          # before the new table-miss entries

    def _packet_in(self, src_mac, dst_mac, in_port, src_ip=None):
        from ryu.lib.packet import packet, ethernet, ipv4
        pkt = packet.Packet()
        if src_ip:
            pkt.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=0x0800))
            pkt.add_protocol(ipv4.ipv4(src=src_ip, dst="10.0.0.1", proto=17))
        else:
            pkt.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=0x9999))
        pkt.serialize()
        msg = types.SimpleNamespace(datapath=self.dp, data=bytes(pkt.data),
                                    match={"in_port": in_port},
                                    buffer_id=ofproto_v1_3.OFP_NO_BUFFER)
        return types.SimpleNamespace(msg=msg)

    def test_learning_switch_floods_then_installs_flow_in_table_1(self):
        A, B = "00:00:00:00:00:0a", "00:00:00:00:00:0b"
        self.app.packet_in_handler(self._packet_in(A, B, 1, src_ip="10.0.0.1"))
        self.assertEqual(self.flow_mods(), [])                    # unknown dst: flood only
        outs = [m for m in self.dp.sent if isinstance(m, ofproto_v1_3_parser.OFPPacketOut)]
        self.assertEqual(outs[-1].actions[0].port, ofproto_v1_3.OFPP_FLOOD)
        self.app.packet_in_handler(self._packet_in(B, A, 2, src_ip="10.0.0.2"))
        fm = self.flow_mods()[-1]
        self.assertEqual((fm.table_id, fm.priority), (1, 1))
        self.assertEqual((fm.match["eth_src"], fm.match["eth_dst"], fm.match["in_port"]),
                         (B, A, 2))
        self.assertEqual(fm.instructions[0].actions[0].port, 1)
        self.assertEqual(self.app.mac_to_ip[A], "10.0.0.1")       # IP learned from IPv4
        self.assertEqual(self.app.mac_to_ip[B], "10.0.0.2")

    def test_priorities_order_allow_over_deny_over_block(self):
        self.assertGreater(fc.PRIORITY["allow"], fc.PRIORITY["deny"])
        self.assertGreater(fc.PRIORITY["deny"], fc.PRIORITY["block"])
        self.assertGreater(fc.PRIORITY["block"], fc.LEARNED_FLOW_PRIORITY)

    def test_remove_is_strict_and_only_that_rule(self):
        self.app.block_ip("10.0.0.3")
        self.app.add_rule({"action": "deny", "src": "10.0.0.3", "dst": "10.0.0.1",
                           "proto": "tcp", "dport": 9001})
        self.app.unblock_ip("10.0.0.3")
        fm = self.flow_mods()[-1]
        self.assertEqual(fm.command, ofproto_v1_3.OFPFC_DELETE_STRICT)
        self.assertEqual(fm.priority, 100)
        self.assertEqual(len(self.app.rules), 1)                  # the deny rule survives
        self.assertEqual(list(self.app.rules.values())[0]["action"], "deny")

    def test_remove_by_spec_and_by_id(self):
        r, _ = self.app.add_rule({"action": "deny", "src": "10.0.0.3", "dst": "10.0.0.1",
                                  "proto": "tcp", "dport": 9001})
        self.assertIsNotNone(self.app.remove_rule(spec={"action": "deny", "src": "10.0.0.3",
                             "dst": "10.0.0.1", "proto": "tcp", "dport": 9001}))
        r2, _ = self.app.add_rule({"action": "allow", "src": "10.0.0.2"})
        self.assertIsNotNone(self.app.remove_rule(rule_id=r2["id"]))
        self.assertIsNone(self.app.remove_rule(rule_id=999))

    def test_validation(self):
        bad = [{"action": "nope", "src": "10.0.0.3"},
               {"action": "block", "src": "999.1.1.1"},
               {"action": "deny", "src": "10.0.0.3", "dport": 80},          # dport needs proto
               {"action": "deny", "src": "10.0.0.3", "proto": "icmp"},
               {"action": "deny", "proto": "tcp", "dport": 70000},
               {"action": "block", "src": "10.0.0.3", "dport": 80, "proto": "tcp"},
               {"action": "deny"}]
        for spec in bad:
            with self.assertRaises(fc.RuleError, msg=str(spec)):
                self.app.add_rule(spec)

    def test_rules_reapplied_when_switch_reconnects(self):
        self.app.block_ip("10.0.0.3")
        self.app.add_rule({"action": "allow", "src": "10.0.0.2"})
        dp2 = FakeDP()
        for rule in self.app.rules.values():          # what switch_features_handler does
            self.app._install(dp2, rule)
        self.assertEqual(len(dp2.sent), 2)

    def test_flow_stats_rule_counters_and_dropped_totals(self):
        rule, _ = self.app.block_ip("10.0.0.3")
        body = [fake_stat(100, 250, 350000, eth_type=0x0800, ipv4_src="10.0.0.3")]
        self.app.process_flow_stats(1, body, 100.0)
        self.assertEqual(rule["packets"], 250)
        self.assertEqual(rule["bytes"], 350000)
        self.app.unblock_ip("10.0.0.3")
        self.assertEqual(self.app.dropped_totals, {"packets": 250, "bytes": 350000})

    def test_flow_stats_deny_rule_matched_by_five_tuple(self):
        rule, _ = self.app.add_rule({"action": "deny", "src": "10.0.0.3", "dst": "10.0.0.1",
                                     "proto": "tcp", "dport": 9001})
        body = [fake_stat(200, 7, 420, eth_type=0x0800, ipv4_src="10.0.0.3",
                          ipv4_dst="10.0.0.1", ip_proto=6, tcp_dst=9001)]
        self.app.process_flow_stats(1, body, 5.0)
        self.assertEqual(rule["packets"], 7)

    def test_source_rate_from_learned_flows(self):
        self.app.mac_to_ip["00:00:00:00:00:03"] = "10.0.0.3"
        mk = lambda nbytes, pk: [fake_stat(1, pk, nbytes, in_port=3,
                                 eth_dst="00:00:00:00:00:01", eth_src="00:00:00:00:00:03")]
        self.app.process_flow_stats(1, mk(1000, 10), 10.0)
        self.app.process_flow_stats(1, mk(126000, 110), 12.0)      # +125000 B in 2 s
        rate = self.app.source_rates["10.0.0.3"]
        self.assertAlmostEqual(rate["bps"], 500000.0, places=0)    # 125000*8/2
        self.assertAlmostEqual(rate["pps"], 50.0, places=1)

    def test_counter_reset_does_not_give_negative_rate(self):
        self.app.mac_to_ip["00:00:00:00:00:03"] = "10.0.0.3"
        mk = lambda nbytes: [fake_stat(1, 1, nbytes, in_port=3, eth_dst="00:00:00:00:00:01",
                                       eth_src="00:00:00:00:00:03")]
        self.app.process_flow_stats(1, mk(5000), 1.0)
        self.app.process_flow_stats(1, mk(100), 2.0)               # flow was replaced
        self.assertEqual(self.app.source_rates["10.0.0.3"]["bps"], 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
