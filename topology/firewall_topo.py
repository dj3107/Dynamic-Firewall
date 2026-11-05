"""
firewall_topo.py - Mininet topology for the Dynamic Firewall project.

    h1 10.0.0.1 (log server) --+
    h2 10.0.0.2 (good client) -+-- s1 ---- Ryu controller (127.0.0.1:6653)
    h3 10.0.0.3 (flooder) -----+
    nat0 10.0.0.254 (VM root namespace: lets hosts reach Ryu's REST API on :8080)

Interactive demo (from the project root):
    sudo python3 topology/firewall_topo.py
Bandwidth-limited network (what the experiments use; h1's link is the bottleneck):
    sudo python3 topology/firewall_topo.py --bw 10
"""
import argparse

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def build_net(bw=None, delay=None, max_queue_size=None,
              controller_ip="127.0.0.1", controller_port=6653, userspace=False):
    """Create and start the network. Returns the Mininet object (no CLI).

    bw   : Mbit/s on h1's link (the server side). h2 and h3 get 10x that, so the
           server link is the shared bottleneck. None = unlimited, no traffic shaping.
    userspace : run Open vSwitch's userspace datapath, for machines without the
           openvswitch kernel module (containers, WSL, some cloud VMs).
    """
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink,
                  autoSetMacs=True)
    c0 = net.addController("c0", controller=RemoteController,
                           ip=controller_ip, port=controller_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13",
                       **({"datapath": "user"} if userspace else {}))
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")

    def link_opts(mbps):
        opts = {}
        if mbps is not None:
            opts["bw"] = mbps
        if delay is not None:
            opts["delay"] = delay
        if max_queue_size is not None and mbps is not None:
            opts["max_queue_size"] = max_queue_size
        return opts

    net.addLink(h1, s1, **link_opts(bw))
    net.addLink(h2, s1, **link_opts(bw * 10 if bw else None))
    net.addLink(h3, s1, **link_opts(bw * 10 if bw else None))
    # NAT node sits in the root namespace, so hosts can reach the REST API at 10.0.0.254:8080
    net.addNAT(name="nat0", connect=s1, ip="10.0.0.254/24")

    net.build()
    if userspace:
        # userspace datapath + veth: TCP checksum offload leaves bad checksums (ping works,
        # TCP does not), so compute checksums in software on every host interface
        for h in net.hosts:
            for intf in h.intfList():
                if intf.name != "lo":
                    h.cmd("ethtool -K %s tx off >/dev/null 2>&1" % intf.name)
    c0.start()
    s1.start([c0])
    try:
        net.waitConnected(timeout=15)
    except AttributeError:          # very old Mininet without waitConnected
        pass
    return net


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bw", type=float, help="bottleneck bandwidth in Mbit/s (default: none)")
    ap.add_argument("--delay", help="link delay, e.g. 1ms")
    ap.add_argument("--userspace", action="store_true",
                    help="OVS userspace datapath (no openvswitch kernel module needed)")
    args = ap.parse_args()
    setLogLevel("info")
    net = build_net(bw=args.bw, delay=args.delay,
                    max_queue_size=50 if args.bw else None, userspace=args.userspace)
    info("*** Up. On h1: python3 app/log_server.py --controller 10.0.0.254:8080\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
