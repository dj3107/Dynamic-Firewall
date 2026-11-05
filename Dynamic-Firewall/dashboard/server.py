"""
server.py - live web dashboard for the dynamic firewall (standard library only).

Runs on the VM next to Ryu (not inside Mininet). It serves one page and one JSON endpoint
that combines everything the audience should see:

  * the controller's rules and flow statistics   (Ryu REST API, /firewall/rules, /stats)
  * new lines of logs/security_events.log         (the log server writes it; Mininet hosts
                                                   share the VM's filesystem)
  * the current demo step                         (logs/demo_state.json, written by demo.py)

    python3 dashboard/server.py                   # then open http://<vm>:8000
    ssh -L 8000:localhost:8000 user@vm            # from the Mac, then http://localhost:8000
"""
import argparse
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MAX_LINES = 300          # never send more than this many log lines in one response


class State:
    def __init__(self, controller, log_path, demo_path):
        self.controller, self.log_path, self.demo_path = controller, log_path, demo_path
        self.lock = threading.Lock()
        self.cache = {}           # controller data, refreshed at most every 0.5 s
        self.cache_t = 0.0

    def _get(self, path):
        with urllib.request.urlopen("http://%s%s" % (self.controller, path), timeout=0.8) as r:
            return json.loads(r.read().decode())

    def controller_view(self):
        with self.lock:
            if time.time() - self.cache_t < 0.5:
                return self.cache
            try:
                view = {"up": True, "rules": self._get("/firewall/rules").get("rules", []),
                        "stats": self._get("/firewall/stats")}
            except Exception as exc:                       # controller down or restarting
                view = {"up": False, "error": str(exc), "rules": [], "stats": {}}
            self.cache, self.cache_t = view, time.time()
            return view

    def log_lines(self, since):
        """New log lines after byte offset `since` (-1 = just the last few lines)."""
        try:
            size = os.path.getsize(self.log_path)
        except OSError:
            return [], 0, False
        reset = since > size                               # log was rotated / recreated
        start = max(0, size - 6000) if (since < 0 or reset) else since
        with open(self.log_path, "rb") as f:
            f.seek(start)
            data = f.read(size - start).decode(errors="replace")
        if start and (since < 0 or reset):
            data = data.split("\n", 1)[-1]                 # drop the partial first line
        lines = [l for l in data.split("\n") if l.strip()]
        return lines[-MAX_LINES:], size, reset

    def demo(self):
        try:
            with open(self.demo_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):                         # keep the terminal quiet
            pass

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif url.path == "/api/state":
                since = int(parse_qs(url.query).get("since", ["-1"])[0])
                lines, offset, reset = state.log_lines(since)
                body = dict(state.controller_view(), events=lines, offset=offset, reset=reset,
                            demo=state.demo(), time=time.time())
                self._send(200, json.dumps(body).encode(), "application/json")
            elif url.path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            else:
                self._send(404, b"not found", "text/plain")
    return Handler


def main():
    ap = argparse.ArgumentParser(description="Live dashboard for the dynamic firewall")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--controller", default="127.0.0.1:8080", help="Ryu REST API host:port")
    ap.add_argument("--log", default=os.path.join(ROOT, "logs", "security_events.log"))
    ap.add_argument("--demo-state", default=os.path.join(ROOT, "logs", "demo_state.json"))
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.bind, a.port), make_handler(State(a.controller, a.log, a.demo_state)))
    print("Dashboard on http://%s:%d  (controller %s)" % (
        "localhost" if a.bind == "0.0.0.0" else a.bind, a.port, a.controller), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
