#!/bin/bash
# Installs Mininet, Open vSwitch and a Ryu that works on Ubuntu 22.04 (Python 3.10).
#
# Why not just "pip install ryu"?  Ryu 4.34 needs eventlet 0.30.2, which crashes on
# Python 3.10 ("cannot set 'is_timeout' attribute of immutable type"), and newer eventlet
# needs the GitHub version of Ryu. So: Ryu from GitHub + eventlet 0.33.3 + dnspython 2.2.1.
set -e
sudo apt update
sudo apt install -y mininet openvswitch-switch openvswitch-testcontroller \
                    python3-pip git curl net-tools iperf unzip
sudo systemctl enable --now openvswitch-switch

# The testcontroller package starts a background service on port 6653, which is the port
# Ryu and Mininet need. Mininet only needs the binary, not the service.
sudo systemctl disable --now openvswitch-testcontroller 2>/dev/null || true
sudo systemctl mask openvswitch-testcontroller 2>/dev/null || true
sudo pkill -x ovs-testcontrol 2>/dev/null || true      # process names are cut at 15 chars

pip3 install "setuptools==58.2.0" wheel packaging
pip3 install "eventlet==0.33.3" "dnspython==2.2.1" webob routes oslo.config msgpack \
             netaddr ovs tinyrpc
pip3 install --no-deps "git+https://github.com/faucetsdn/ryu.git"
pip3 install matplotlib || echo "matplotlib failed to install (only needed for charts)"

grep -q '.local/bin' ~/.bashrc || echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
export PATH=$PATH:$HOME/.local/bin
ryu-manager --version
echo "Done. Open a new shell (or run: source ~/.bashrc) so ryu-manager is on PATH."
