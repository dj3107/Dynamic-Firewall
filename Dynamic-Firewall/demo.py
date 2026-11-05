#!/usr/bin/env python3
"""
demo.py - the whole demo with one command.

    sudo python3 demo.py                 # guided: press Enter before each scenario
    sudo python3 demo.py --auto          # no pauses (rehearsal)
    sudo python3 demo.py --only A,B      # just some scenarios
    sudo python3 demo.py --userspace     # machine without the openvswitch kernel module

It does the start-up in the right order (clean up Mininet first, then Ryu, then the
network, then the log server), opens the live dashboard on port 8000, runs scenarios A-E
with a banner before each one, shows the evidence after each step (security-log lines and
the switch's rules) and waits out the recovery timers with a countdown. At the end it can
drop into the normal Mininet CLI. Ctrl+C at any time cleans everything up.

Scenarios: A flood -> BLOCK -> recovery   B unauthorised port -> DENY   C trusted host -> ALLOW
           D controller crash -> heal       E detection from switch statistics
"""
import argparse
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
LOGS = os.path.join(ROOT, "logs")
SEC_LOG = os.path.join(LOGS, "security_events.log")
DEMO_STATE = os.path.join(LOGS, "demo_state.json")
SERVER_CMD = "python3 app/log_server.py --controller 10.0.0.254:8080"
FLOWS_CMD = 'ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -E "actions=drop|priority=300"'

# ---------------------------------------------------------------- terminal output
USE_COLOR = sys.stdout.isatty()


def c(code, s):
    return "\033[%sm%s\033[0m" % (code, s) if USE_COLOR else s


BOLD, DIM, RED, GREEN, YELLOW, BLUE, CYAN, MAG = "1", "2", "31", "32", "33", "34", "36", "35"


def colour_line(line):
    if "ALERT" in line:
        return c(YELLOW, line)
    if "WARNING" in line:
        return c(YELLOW, line)
    if any(k in line for k in ("UNBLOCKED", "reachable again", "expired", "ALLOW rule", "0% dropped",
                               " 0% packet loss", "priority=300", "reply='ACK'", "64 bytes from")):
        return c(GREEN, line)
    if any(k in line for k in ("BLOCKED", "DENIED", "DENY", "actions=drop", "100% packet loss",
                               "timed out", "connection error", "could not connect")):
        return c(RED, line)
    return line


def say(text="", code=None):
    print(c(code, text) if code else text, flush=True)


def banner(step, title, lines):
    w = 78
    say()
    say(c(MAG, "━" * w))
    say(c(BOLD, "  %s  %s" % (step, title)))
    for l in lines:
        say("     " + l)
    say(c(MAG, "━" * w))


def short(line):
    """Log line without the date and the long response={...} dictionary."""
    line = re.sub(r", response=\{.*\}$", "", line)
    return re.sub(r"^\[\d{4}-\d\d-\d\d ", "[", line)


def give_back(*dirs):
    """Files demo.py creates as root (logs, results) go back to the user who ran sudo, so
    they can be overwritten later without sudo (e.g. ryu-manager > logs/ryu.log)."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid:
        return
    for d in dirs:
        for base, _, files in os.walk(d):
            for name in [base] + [os.path.join(base, f) for f in files]:
                try:
                    os.chown(name, int(uid), int(gid))
                except OSError:
                    pass


# ---------------------------------------------------------------- the demo
class Demo:
    def __init__(self, args):
        self.a = args
        self.ryu = None
        self.dash = None
        self.net = None
        self.log_pos = 0

    # ------------------------------------------------------------ helpers
    def pause(self, what="continue"):
        if self.a.auto:
            time.sleep(self.a.gap)
            return
        try:
            input(c(DIM, "  ⏎  press Enter to %s " % what))
        except EOFError:
            pass

    def state(self, step, title, hint):
        try:
            with open(DEMO_STATE, "w") as f:
                json.dump({"step": step, "title": title, "hint": hint, "t": time.time()}, f)
        except OSError:
            pass

    def run(self, host, cmd, show=True, tally=False):
        """Run a command on a Mininet host, printing its output live."""
        say(c(CYAN, "  mininet> %s %s" % (host, cmd)))
        h = self.net.get(host)
        p = h.popen("cd %s && %s" % (ROOT, cmd), shell=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, universal_newlines=True)
        out, counts = [], {}
        for line in p.stdout:
            line = line.rstrip("\n")
            out.append(line)
            m = re.search(r"reply='(\w+)'", line)
            if m:
                counts[m.group(1)] = counts.get(m.group(1), 0) + 1
            if show and not (tally and m and len(out) > 4 and m.group(1) == "ACK"):
                say("    " + colour_line(line))
        p.wait()
        if tally and counts:
            say("    " + c(BOLD, "→ replies: " + ", ".join("%s × %d" % kv for kv in counts.items())))
        return "\n".join(out)

    def new_log(self, keep=r"ALERT|ACTION|WARNING|reachable|UNBLOCK|expired|Bandwidth detection"):
        """Print the important security-log lines written since the last call."""
        try:
            with open(SEC_LOG) as f:
                f.seek(self.log_pos)
                data = f.read()
                self.log_pos = f.tell()
        except OSError:
            return ""
        lines = [l for l in data.splitlines() if re.search(keep, l)]
        if lines:
            say(c(DIM, "  security log (tab 3):"))
            for l in lines:
                say("    " + colour_line(short(l)))
        return data

    def flows(self, note="switch rules (table 0):"):
        out = subprocess.run(FLOWS_CMD, shell=True, capture_output=True, text=True).stdout
        say(c(DIM, "  " + note))
        rules = [re.sub(r"cookie=\S+ duration=(\S+), table=0, ", r"age=\1 ", l.strip())
                 for l in out.splitlines()]
        for l in rules or ["(no firewall rules)"]:
            say("    " + colour_line(l))
        return out

    def wait_log(self, pattern, timeout, label):
        """Countdown until `pattern` appears in the security log."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                with open(SEC_LOG) as f:
                    f.seek(self.log_pos)
                    if re.search(pattern, f.read()):
                        if USE_COLOR:
                            sys.stdout.write("\r\033[K")
                        return True
            except OSError:
                pass
            if USE_COLOR:
                sys.stdout.write("\r  ⏳ %s … %2.0f s " % (label, time.time() - start))
                sys.stdout.flush()
            time.sleep(0.5)
        say()
        say(c(YELLOW, "  (gave up waiting for: %s)" % label))
        return False

    # ------------------------------------------------------------ start-up / shutdown
    def find_ryu(self):
        if self.a.ryu:
            return self.a.ryu
        cand = [shutil.which("ryu-manager")]
        user = os.environ.get("SUDO_USER")
        if user:
            cand.append(os.path.join(pwd.getpwnam(user).pw_dir, ".local", "bin", "ryu-manager"))
        cand.append(os.path.expanduser("~/.local/bin/ryu-manager"))
        for p in cand:
            if p and os.path.exists(p):
                return p
        sys.exit("ryu-manager not found. Run scripts/install_deps.sh, or pass --ryu /path/to/ryu-manager")

    def port_busy(self, port):
        with socket.socket() as s:
            return s.connect_ex(("127.0.0.1", port)) == 0

    def start_ryu(self):
        ryu = self.find_ryu()
        cmd = [ryu, "controller/firewall_controller.py"]
        user = os.environ.get("SUDO_USER")
        # Ryu is normally pip-installed for the user (~/.local), so run it as that user
        if user and os.geteuid() == 0 and ryu.startswith(pwd.getpwnam(user).pw_dir):
            cmd = ["sudo", "-u", user, "-H"] + cmd
        self.ryu_log = open(os.path.join(LOGS, "ryu.log"), "w")
        self.ryu = subprocess.Popen(cmd, cwd=ROOT, stdout=self.ryu_log, stderr=subprocess.STDOUT,
                                    start_new_session=True)
        for _ in range(60):
            if "wsgi starting up" in open(os.path.join(LOGS, "ryu.log")).read():
                return True
            if self.ryu.poll() is not None:
                break
            time.sleep(0.5)
        sys.exit("Ryu did not start, see logs/ryu.log:\n" + open(os.path.join(LOGS, "ryu.log")).read()[-1500:])

    def stop_ryu(self):
        if self.ryu and self.ryu.poll() is None:
            os.killpg(self.ryu.pid, 15)
            try:
                self.ryu.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(self.ryu.pid, 9)
        self.ryu = None

    def start_server(self, extra=""):
        self.net.get("h1").cmd("%s %s > logs/server_stdout.txt 2>&1 &" % (SERVER_CMD, extra))

    def stop_server(self):
        self.net.get("h1").cmd('pkill -f "[l]og_server.py"')
        time.sleep(0.5)

    def setup(self):
        if os.geteuid() != 0:
            sys.exit("Mininet needs root: sudo python3 demo.py")
        os.makedirs(LOGS, exist_ok=True)
        banner("●", "Starting up", ["clean up old Mininet state  →  Ryu  →  dashboard  →  network  →  log server"])
        if subprocess.run(["ovs-vsctl", "--timeout=3", "show"], capture_output=True).returncode != 0:
            say("  Open vSwitch is not running; starting it …")
            for cmd in (["service", "openvswitch-switch", "start"],
                        ["/usr/share/openvswitch/scripts/ovs-ctl", "start"]):
                subprocess.run(cmd, capture_output=True)
                if subprocess.run(["ovs-vsctl", "--timeout=3", "show"], capture_output=True).returncode == 0:
                    break
            else:
                sys.exit("Open vSwitch is not running: sudo systemctl start openvswitch-switch")
        say("  sudo mn -c                          (always first: it would kill a running Ryu)")
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for port, what in ((6653, "OpenFlow"), (8080, "REST")):
            if self.port_busy(port):
                sys.exit("Port %d (%s) is already in use: stop the other ryu-manager / "
                         "ovs-testcontroller first (sudo pkill -x ovs-testcontrol)." % (port, what))
        say("  ryu-manager controller/firewall_controller.py   → logs/ryu.log")
        self.start_ryu()
        say("    " + c(GREEN, "controller up (OpenFlow :6653, REST :8080)"))
        if not self.a.no_dashboard:
            if self.port_busy(self.a.dashboard_port):
                say(c(YELLOW, "    port %d busy: dashboard not started" % self.a.dashboard_port))
            else:
                self.dash = subprocess.Popen([sys.executable, "dashboard/server.py", "--port",
                                              str(self.a.dashboard_port)], cwd=ROOT,
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                say("    " + c(GREEN, "dashboard: http://<vm-ip>:%d" % self.a.dashboard_port) +
                    c(DIM, "   (from the Mac: ssh -L %d:localhost:%d <user>@<vm>, then http://localhost:%d)"
                      % ((self.a.dashboard_port,) * 3)))
        self.state("●", "Starting up", "Controller, network and log server are starting.")
        from mininet.log import setLogLevel
        from topology.firewall_topo import build_net
        setLogLevel("warning")
        say("  building the network: h1 h2 h3 + s1 + nat0 …")
        self.net = build_net(userspace=self.a.userspace)
        for h in self.net.hosts:
            h.cmd("cd " + ROOT)               # relative paths (app/, logs/) work on every host
        loss = self.net.pingAll(timeout=1)
        say("    pingall: " + colour_line("%d%% dropped" % loss))
        if loss:
            say(c(YELLOW, "    some pings failed; the switch may still be connecting. Continuing."))
        for f in (SEC_LOG, DEMO_STATE):
            if os.path.exists(f):
                os.remove(f)
        self.log_pos = 0
        say("  h1: " + SERVER_CMD + " &")
        self.start_server()
        self.wait_log(r"ALLOW rule", 20, "log server starting")
        self.new_log(r"Listening|ALLOW rule|Policy")
        self.flows()

    def teardown(self):
        say()
        say(c(DIM, "  cleaning up …"))
        try:
            if self.net:
                self.stop_server()
                self.net.stop()
        except Exception:
            pass
        if self.dash and self.dash.poll() is None:
            self.dash.terminate()
        self.stop_ryu()
        try:
            os.remove(DEMO_STATE)
        except OSError:
            pass
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        give_back(LOGS)
        say(c(DIM, "  done."))

    # ------------------------------------------------------------ scenarios
    def scenario_A(self):
        t = "Flood → BLOCK → automatic recovery"
        banner("A", t, ["h3 floods the rate-limited logging port 9000 (10 messages/s).",
                        "Limit: 8 messages per 5 s.  Watch: h3 turns red on the dashboard,",
                        "a priority-100 drop rule appears in the switch, and it removes itself",
                        "after 15 s of silence."])
        self.state("A", t, "h3 floods port 9000. The 9th message in 5 s triggers a BLOCK rule in the switch; "
                           "it is removed after 15 s of silence.")
        self.pause("start scenario A")
        self.new_log()
        say(c(DIM, "  first, a normal client:"))
        self.run("h2", "python3 app/client.py --server 10.0.0.1 --count 3 --delay 0.4")
        say(c(DIM, "  now the flood:"))
        self.run("h3", "python3 app/client.py --server 10.0.0.1 --mode flood --count 40")
        self.new_log()
        self.flows()
        self.run("h3", "ping -c 2 -W 1 10.0.0.1")
        say(c(DIM, "  h3 is cut off at the switch. Waiting for the automatic recovery (15 s of silence):"))
        self.wait_log(r"UNBLOCKED", 40, "waiting for UNBLOCKED")
        self.new_log()
        self.flows()
        self.run("h3", "ping -c 2 10.0.0.1")

    def scenario_B(self):
        t = "Unauthorised access → DENY one flow"
        banner("B", t, ["Port 9001 (admin) is allow-listed for h2 only.",
                        "Watch: h3 → :9001 gets DENIED and a priority-200 rule drops just that flow;",
                        "h3 can still use port 9000, h2 can still use port 9001."])
        self.state("B", t, "Port 9001 is for h2 only. h3 is denied on that one flow; everything else still works.")
        self.pause("start scenario B")
        self.new_log()
        self.run("h2", "python3 app/client.py --server 10.0.0.1 --port 9001 --count 2 --delay 0.4")
        self.run("h3", "python3 app/client.py --server 10.0.0.1 --port 9001 --count 2")
        time.sleep(0.5)
        self.new_log()
        self.flows()
        self.run("h3", "python3 app/client.py --server 10.0.0.1 --port 9000 --count 2 --delay 0.4")
        say(c(DIM, "  (the DENY rule expires by itself after 30 s; you can watch it go on the dashboard)"))

    def scenario_C(self):
        t = "Trusted host → ALLOW (exempt)"
        banner("C", t, ["h2 sends the very same 40-message flood.",
                        "Watch: every reply is ACK; the priority-300 ALLOW rule's counter climbs."])
        self.state("C", t, "h2 is trusted: its priority-300 ALLOW rule skips the drop rules and rate limiting.")
        self.pause("start scenario C")
        self.new_log()
        self.run("h2", "python3 app/client.py --server 10.0.0.1 --mode flood --count 40", tally=True)
        self.flows()

    def scenario_D(self):
        t = "Controller crash → the network heals itself"
        banner("D", t, ["The demo stops Ryu, floods from h3, then restarts Ryu.",
                        "Watch: the log server keeps serving (one WARNING, no stall), and when Ryu",
                        "comes back the reconcile loop re-installs the rules it lost."])
        self.state("D", t, "Ryu is stopped: nothing can be blocked, but the server keeps serving. "
                           "When Ryu returns, the log server re-installs its rules.")
        self.pause("stop the controller")
        self.new_log()
        say(c(CYAN, "  tab 1: Ctrl+C   (Ryu stopped)"))
        self.stop_ryu()
        time.sleep(1)
        self.run("h3", "python3 app/client.py --server 10.0.0.1 --mode flood --count 20", tally=True)
        self.new_log()
        self.pause("restart the controller")
        say(c(CYAN, "  tab 1: ryu-manager controller/firewall_controller.py"))
        self.start_ryu()
        self.wait_log(r"installed on the controller", 30, "waiting for the reconcile loop")
        time.sleep(1)
        self.new_log()
        self.flows()
        loss = self.net.pingAll(timeout=1)
        say("    pingall: " + colour_line("%d%% dropped" % loss))

    def scenario_E(self):
        t = "Detection from switch statistics"
        banner("E", t, ["The log server restarts with message counting off and a 3 Mbit/s limit.",
                        "h3 sends bulk traffic; the switch's own byte counters (polled every second)",
                        "trigger the block. h1 and the controller are never blocked."])
        self.state("E", t, "Only the switch's measurements can trigger a block now: watch h3's line on the "
                           "traffic chart cross 3 Mbit/s.")
        self.pause("start scenario E")
        self.stop_server()
        self.new_log()
        say(c(CYAN, "  mininet> h1 %s --threshold 100000 --bw-threshold-mbps 3 --quiet-events &" % SERVER_CMD))
        self.start_server("--threshold 100000 --bw-threshold-mbps 3 --quiet-events")
        self.wait_log(r"Bandwidth detection on", 15, "log server restarting")
        time.sleep(2)
        self.run("h3", "python3 app/client.py --server 10.0.0.1 --mode flood --rate 0 --size 1400 "
                       "--connections 2 --duration 8 --persist --quiet")
        self.new_log()
        self.flows()
        self.run("h2", "ping -c 2 10.0.0.1")
        say(c(DIM, "  the server is still reachable. Waiting for h3's automatic recovery …"))
        self.wait_log(r"UNBLOCKED", 40, "waiting for UNBLOCKED")
        self.new_log()
        self.stop_server()
        self.start_server()                          # back to the normal policy
        self.wait_log(r"Listening on 0.0.0.0:9001", 15, "log server restarting")

    # ------------------------------------------------------------ main
    def main(self):
        steps = [s.strip().upper() for s in self.a.only.split(",")] if self.a.only else list("ABCDE")
        try:
            self.setup()
            for s in steps:
                getattr(self, "scenario_" + s)()
            self.state("✓", "Demo complete", "Detect → decide → enforce → recover. Questions?")
            cli = not self.a.auto and not self.a.no_cli
            banner("✓", "Demo complete", ["Application detects · controller decides · switch enforces · rules expire."] +
                   (["Dashboard stays live; type Mininet commands below (exit to finish)."] if cli else []))
            if cli:
                from mininet.cli import CLI
                from mininet.log import setLogLevel
                setLogLevel("info")       # the demo ran quietly; the CLI must print command output
                CLI(self.net)
        except KeyboardInterrupt:
            say()
            say(c(YELLOW, "  interrupted"))
        finally:
            self.teardown()


def main():
    ap = argparse.ArgumentParser(description="Run the dynamic firewall demo with one command")
    ap.add_argument("--auto", action="store_true", help="no pauses (rehearsal / recording)")
    ap.add_argument("--gap", type=float, default=2.0, help="seconds between steps with --auto")
    ap.add_argument("--only", help="comma-separated scenarios, e.g. A,B,C (default: A-E)")
    ap.add_argument("--userspace", action="store_true",
                    help="OVS userspace datapath (no openvswitch kernel module needed)")
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--dashboard-port", type=int, default=8000)
    ap.add_argument("--no-cli", action="store_true", help="do not open the Mininet CLI at the end")
    ap.add_argument("--ryu", help="path to ryu-manager (default: found automatically)")
    Demo(ap.parse_args()).main()


if __name__ == "__main__":
    main()
