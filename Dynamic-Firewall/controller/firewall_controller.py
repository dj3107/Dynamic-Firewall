"""
firewall_controller.py
-----------------------
Ryu SDN controller for the Dynamic Firewall with Security Event Logger project.

What it does
  1. L2 learning switch for normal traffic (OpenFlow 1.3), two-table pipeline:
        table 0  policy     allow / deny / block rules; anything else -> table 1
        table 1  forwarding learned MAC flows; unknown destination -> controller
  2. A rule engine that installs three kinds of OpenFlow rules at run time:
        allow  priority 300  skip the drop rules, continue to normal forwarding
        deny   priority 200  drop              (one flow: src / dst / protocol / port)
        block  priority 100  drop              (everything coming from one source IP)
     Higher priority wins, so an allow rule overrides a deny or block rule.
  3. Polls flow statistics once a second: per-source throughput, and the packets
     and bytes dropped by each drop rule.
  4. REST API (port 8080) used by app/log_server.py.

Run:  ryu-manager controller/firewall_controller.py

REST API
  GET  /firewall/status          blocked IPs and rule count
  POST /firewall/block           {"ip": "10.0.0.3"}               (block rule)
  POST /firewall/unblock         {"ip": "10.0.0.3"}
  POST /firewall/rule            {"action": "allow|deny|block", "src": ip, "dst": ip,
                                  "proto": "tcp|udp", "dport": 9001}
  POST /firewall/rule/remove     {"id": 3}  or the same body used to add the rule
  GET  /firewall/rules           every rule with its packet / byte counters
  GET  /firewall/stats           per-source rates, dropped totals, connected switches
"""
import ipaddress
import json
import logging
import threading
import time
from collections import defaultdict

from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (MAIN_DISPATCHER, CONFIG_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route

INSTANCE_NAME = "firewall_api_app"
LOG = logging.getLogger("firewall_controller")

PRIORITY = {"block": 100, "deny": 200, "allow": 300}
PROTO_NUM = {"tcp": 6, "udp": 17}
STATS_INTERVAL = 1.0            # seconds between flow-statistics polls
LEARNED_FLOW_PRIORITY = 1
POLICY_TABLE = 0
FORWARD_TABLE = 1


class RuleError(ValueError):
    """Raised for an invalid rule request (returned to the client as HTTP 400)."""


class DynamicFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}            # dpid -> {mac: port}
        self.mac_to_ip = {}              # mac -> ip, learned from ARP / IPv4 packets
        self.datapaths = {}              # dpid -> datapath
        self.rules = {}                  # rule id -> rule dict
        self._next_rule_id = 1
        self._lock = threading.RLock()
        self.source_rates = {}           # ip -> {"bps", "pps", "bytes", "packets"}
        self._prev_samples = {}          # (dpid, mac) -> (time, bytes, packets)
        self.dropped_totals = {"packets": 0, "bytes": 0}
        kwargs["wsgi"].register(FirewallController, {INSTANCE_NAME: self})
        self._stats_thread = hub.spawn(self._stats_loop)

    # ------------------------------------------------------------------
    # Switch connection handling
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        self.mac_to_port[dp.id] = {}      # forget stale learning after a reconnect
        # ...and drop the switch's learned forwarding flows too. After a controller restart
        # they would otherwise keep forwarding without packet-ins, so this controller would
        # never relearn MAC -> IP, and per-source statistics (bandwidth detection) would be
        # empty. Table 0 (the firewall rules) is left alone: the switch stays protected.
        dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=FORWARD_TABLE,
                                      command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY,
                                      out_group=ofp.OFPG_ANY, match=parser.OFPMatch()))
        # table 0 (policy): traffic no rule matches continues to the forwarding table
        self.add_flow(dp, 0, parser.OFPMatch(), [], table_id=POLICY_TABLE, goto=FORWARD_TABLE)
        # table 1 (forwarding): unknown destinations go to the controller for learning
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, parser.OFPMatch(), actions, table_id=FORWARD_TABLE)
        with self._lock:
            for rule in self.rules.values():              # re-apply rules on reconnect
                self._install(dp, rule)
        LOG.info("Switch %s connected", dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == DEAD_DISPATCHER and dp is not None:
            if self.datapaths.get(dp.id) is dp:
                del self.datapaths[dp.id]
                LOG.info("Switch %s disconnected", dp.id)

    # ------------------------------------------------------------------
    # Flow-table helpers
    # ------------------------------------------------------------------
    def add_flow(self, dp, priority, match, actions, buffer_id=None, table_id=0, goto=None):
        """Install a flow. `goto` makes it a 'continue in table N' flow instead of actions."""
        ofp, parser = dp.ofproto, dp.ofproto_parser
        if goto is not None:
            inst = [parser.OFPInstructionGotoTable(goto)]
        else:
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kw = dict(datapath=dp, table_id=table_id, priority=priority, match=match,
                  instructions=inst)
        if buffer_id:
            kw["buffer_id"] = buffer_id
        dp.send_msg(parser.OFPFlowMod(**kw))

    @staticmethod
    def _rule_match(parser, rule):
        """Build the OpenFlow match for a rule (IPv4 only)."""
        fields = {"eth_type": 0x0800}
        if rule["src"]:
            fields["ipv4_src"] = rule["src"]
        if rule["dst"]:
            fields["ipv4_dst"] = rule["dst"]
        if rule["proto"]:
            fields["ip_proto"] = PROTO_NUM[rule["proto"]]
            if rule["dport"]:
                fields["tcp_dst" if rule["proto"] == "tcp" else "udp_dst"] = rule["dport"]
        return parser.OFPMatch(**fields)

    def _install(self, dp, rule):
        parser = dp.ofproto_parser
        match = self._rule_match(parser, rule)
        if rule["action"] == "allow":
            # exempt from the drop rules below it: carry on to the forwarding table
            self.add_flow(dp, rule["priority"], match, [], table_id=POLICY_TABLE,
                          goto=FORWARD_TABLE)
        else:
            self.add_flow(dp, rule["priority"], match, [], table_id=POLICY_TABLE)  # drop

    def _uninstall(self, dp, rule):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = self._rule_match(parser, rule)
        # STRICT so only this exact rule is removed, not more specific ones
        dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=POLICY_TABLE,
                                      command=ofp.OFPFC_DELETE_STRICT,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      priority=rule["priority"], match=match))

    # ------------------------------------------------------------------
    # Packet-in: learning switch + IP/MAC learning
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        if ip_pkt is not None:
            self.mac_to_ip[eth.src] = ip_pkt.src
        elif arp_pkt is not None:
            self.mac_to_ip[eth.src] = arp_pkt.src_ip

        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self.add_flow(dp, LEARNED_FLOW_PRIORITY, match, actions, msg.buffer_id,
                              table_id=FORWARD_TABLE)
                return
            self.add_flow(dp, LEARNED_FLOW_PRIORITY, match, actions, table_id=FORWARD_TABLE)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    # ------------------------------------------------------------------
    # Rule engine
    # ------------------------------------------------------------------
    @staticmethod
    def _clean_ip(value, name):
        if value in (None, "", "any"):
            return None
        try:
            return str(ipaddress.IPv4Address(value))
        except ValueError:
            raise RuleError("invalid %s address: %r" % (name, value))

    def _normalise(self, spec):
        action = str(spec.get("action", "")).lower()
        if action not in PRIORITY:
            raise RuleError("action must be one of allow, deny, block")
        src = self._clean_ip(spec.get("src"), "src")
        dst = self._clean_ip(spec.get("dst"), "dst")
        proto = spec.get("proto")
        proto = str(proto).lower() if proto not in (None, "", "any") else None
        if proto is not None and proto not in PROTO_NUM:
            raise RuleError("proto must be tcp or udp")
        dport = spec.get("dport")
        if dport in (None, "", 0):
            dport = None
        else:
            try:
                dport = int(dport)
            except (TypeError, ValueError):
                raise RuleError("dport must be an integer")
            if not 1 <= dport <= 65535:
                raise RuleError("dport out of range")
            if proto is None:
                raise RuleError("dport requires proto (tcp or udp)")
        if action == "block" and (src is None or dst or proto or dport):
            raise RuleError("a block rule needs src only (use deny for finer rules)")
        if src is None and dst is None and dport is None:
            raise RuleError("rule needs at least one of src, dst, dport")
        return {"action": action, "src": src, "dst": dst, "proto": proto, "dport": dport}

    @staticmethod
    def _key(r):
        return (r["action"], r["src"], r["dst"], r["proto"], r["dport"])

    def add_rule(self, spec):
        """Add a rule. Returns (rule, created). Identical rules are not duplicated."""
        norm = self._normalise(spec)
        with self._lock:
            for rule in self.rules.values():
                if self._key(rule) == self._key(norm):
                    return rule, False
            rule = dict(norm, id=self._next_rule_id, priority=PRIORITY[norm["action"]],
                        created=time.time(), packets=0, bytes=0, _per_dp={})
            self._next_rule_id += 1
            self.rules[rule["id"]] = rule
            for dp in list(self.datapaths.values()):
                self._install(dp, rule)
        LOG.warning("RULE ADD   #%d %s", rule["id"], self._describe(rule))
        return rule, True

    def remove_rule(self, rule_id=None, spec=None):
        """Remove a rule by id, or by the spec used to add it. Returns the rule or None."""
        with self._lock:
            if rule_id is None:
                norm = self._normalise(spec)
                for rid, rule in self.rules.items():
                    if self._key(rule) == self._key(norm):
                        rule_id = rid
                        break
            rule = self.rules.pop(rule_id, None) if rule_id is not None else None
            if rule is None:
                return None
            if rule["action"] in ("deny", "block"):      # keep a running total of drops
                self.dropped_totals["packets"] += rule["packets"]
                self.dropped_totals["bytes"] += rule["bytes"]
            for dp in list(self.datapaths.values()):
                self._uninstall(dp, rule)
        LOG.warning("RULE DEL   #%d %s (dropped %d pkts)", rule["id"],
                    self._describe(rule), rule["packets"])
        return rule

    @staticmethod
    def _describe(rule):
        parts = [rule["action"].upper(), "src=%s" % (rule["src"] or "*"),
                 "dst=%s" % (rule["dst"] or "*")]
        if rule["proto"]:
            parts.append("%s/%s" % (rule["proto"], rule["dport"] or "*"))
        return " ".join(parts)

    @staticmethod
    def public_rule(rule):
        return {k: v for k, v in rule.items() if not k.startswith("_")}

    # --- compatibility helpers used by the block / unblock endpoints ---
    @property
    def blocked_ips(self):
        with self._lock:
            return {r["src"] for r in self.rules.values() if r["action"] == "block"}

    def block_ip(self, ip):
        rule, created = self.add_rule({"action": "block", "src": ip})
        LOG.warning("BLOCKED %s on %d switch(es)", ip, len(self.datapaths))
        return rule, created

    def unblock_ip(self, ip):
        rule = self.remove_rule(spec={"action": "block", "src": ip})
        if rule:
            LOG.warning("UNBLOCKED %s on %d switch(es)", ip, len(self.datapaths))
        return rule

    # ------------------------------------------------------------------
    # Flow-statistics polling
    # ------------------------------------------------------------------
    def _stats_loop(self):
        while True:
            hub.sleep(STATS_INTERVAL)
            for dp in list(self.datapaths.values()):
                try:
                    parser, ofp = dp.ofproto_parser, dp.ofproto
                    dp.send_msg(parser.OFPFlowStatsRequest(
                        dp, flags=0, table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY,
                        out_group=ofp.OFPG_ANY, cookie=0, cookie_mask=0,
                        match=parser.OFPMatch()))
                except Exception as exc:                  # a switch may vanish mid-poll
                    LOG.debug("stats request failed: %s", exc)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        self.process_flow_stats(ev.msg.datapath.id, ev.msg.body, time.time())

    def process_flow_stats(self, dpid, body, now):
        """Update per-source rates and per-rule counters from a flow-stats reply."""
        src_bytes = defaultdict(int)
        src_packets = defaultdict(int)
        with self._lock:
            by_key = {self._key(r): r for r in self.rules.values()}
            for stat in body:
                match = stat.match
                if stat.priority == LEARNED_FLOW_PRIORITY:
                    mac = match.get("eth_src")
                    if mac:
                        src_bytes[mac] += stat.byte_count
                        src_packets[mac] += stat.packet_count
                    continue
                proto_num = match.get("ip_proto")
                proto = {6: "tcp", 17: "udp"}.get(proto_num)
                dport = match.get("tcp_dst") or match.get("udp_dst")
                for action, prio in PRIORITY.items():
                    if prio == stat.priority:
                        key = (action, match.get("ipv4_src"), match.get("ipv4_dst"),
                               proto, dport)
                        rule = by_key.get(key)
                        if rule is not None:
                            rule["_per_dp"][dpid] = (stat.packet_count, stat.byte_count)
                            rule["packets"] = sum(v[0] for v in rule["_per_dp"].values())
                            rule["bytes"] = sum(v[1] for v in rule["_per_dp"].values())
            for mac, total in src_bytes.items():
                ip = self.mac_to_ip.get(mac)
                if ip is None:
                    continue
                prev = self._prev_samples.get((dpid, mac))
                pkts = src_packets[mac]
                self._prev_samples[(dpid, mac)] = (now, total, pkts)
                bps = pps = 0.0
                if prev and now > prev[0]:
                    dt = now - prev[0]
                    bps = max(0, total - prev[1]) * 8.0 / dt
                    pps = max(0, pkts - prev[2]) / dt
                self.source_rates[ip] = {"bps": round(bps, 1), "pps": round(pps, 1),
                                         "bytes": total, "packets": pkts}


class FirewallController(ControllerBase):
    """REST endpoints used by log_server.py and the experiment scripts."""

    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.app = data[INSTANCE_NAME]

    # --- helpers -------------------------------------------------------
    @staticmethod
    def _json(payload, status=200):
        return Response(content_type="application/json", charset="utf-8",
                        body=json.dumps(payload).encode("utf-8"), status=status)

    def _body(self, req):
        try:
            data = json.loads(req.body)
            if not isinstance(data, dict):
                raise ValueError("JSON object expected")
            return data, None
        except Exception as exc:
            return None, self._json({"error": str(exc)}, 400)

    # --- endpoints -----------------------------------------------------
    @route("firewall", "/firewall/status", methods=["GET"])
    def status(self, req, **kw):
        return self._json({"blocked_ips": sorted(self.app.blocked_ips),
                           "rules": len(self.app.rules)})

    @route("firewall", "/firewall/block", methods=["POST"])
    def block(self, req, **kw):
        data, err = self._body(req)
        if err:
            return err
        try:
            rule, created = self.app.block_ip(data.get("ip"))
        except RuleError as exc:
            return self._json({"error": str(exc)}, 400)
        return self._json({"ip": rule["src"], "blocked": True, "changed": created,
                           "rule_id": rule["id"]})

    @route("firewall", "/firewall/unblock", methods=["POST"])
    def unblock(self, req, **kw):
        data, err = self._body(req)
        if err:
            return err
        try:
            rule = self.app.unblock_ip(data.get("ip"))
        except RuleError as exc:
            return self._json({"error": str(exc)}, 400)
        return self._json({"ip": data.get("ip"), "blocked": False,
                           "changed": rule is not None})

    @route("firewall", "/firewall/rule", methods=["POST"])
    def add_rule(self, req, **kw):
        data, err = self._body(req)
        if err:
            return err
        try:
            rule, created = self.app.add_rule(data)
        except RuleError as exc:
            return self._json({"error": str(exc)}, 400)
        return self._json({"rule": self.app.public_rule(rule), "changed": created})

    @route("firewall", "/firewall/rule/remove", methods=["POST"])
    def remove_rule(self, req, **kw):
        data, err = self._body(req)
        if err:
            return err
        try:
            if "id" in data:
                rule = self.app.remove_rule(rule_id=int(data["id"]))
            else:
                rule = self.app.remove_rule(spec=data)
        except (RuleError, ValueError) as exc:
            return self._json({"error": str(exc)}, 400)
        return self._json({"removed": rule is not None,
                           "rule": self.app.public_rule(rule) if rule else None})

    @route("firewall", "/firewall/rules", methods=["GET"])
    def rules(self, req, **kw):
        with self.app._lock:
            rules = [self.app.public_rule(r) for r in self.app.rules.values()]
        return self._json({"rules": sorted(rules, key=lambda r: r["id"])})

    @route("firewall", "/firewall/stats", methods=["GET"])
    def stats(self, req, **kw):
        with self.app._lock:
            drop_pk = self.app.dropped_totals["packets"]
            drop_by = self.app.dropped_totals["bytes"]
            for r in self.app.rules.values():          # include rules still installed
                if r["action"] in ("deny", "block"):
                    drop_pk += r["packets"]
                    drop_by += r["bytes"]
            return self._json({"sources": dict(self.app.source_rates),
                               "dropped": {"packets": drop_pk, "bytes": drop_by},
                               "rules": len(self.app.rules),
                               "switches": sorted(self.app.datapaths)})
