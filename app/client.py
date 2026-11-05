"""
client.py - TCP client that generates traffic for the Security Event Logging Server.

Demo use (prints every message):
  python3 app/client.py --server 10.0.0.1 --mode normal --count 6
  python3 app/client.py --server 10.0.0.1 --mode flood  --count 40
  python3 app/client.py --server 10.0.0.1 --port 9001 --count 3      # admin service

Load-test use (used by the experiments):
  python3 app/client.py --server 10.0.0.1 --mode flood --rate 0 --size 1400 \
          --connections 4 --duration 20 --persist --quiet --summary-json

  --mode normal : one message every 2 s            --mode flood : one message every 0.1 s
  --rate R      : messages per second per connection (0 = as fast as possible)
  --persist     : after a drop / block, reconnect and keep going (a persistent attacker)
"""
import argparse
import json
import socket
import threading
import time


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.d = dict(connects=0, connect_fails=0, sent=0, acked=0, blocked_replies=0,
                      denied_replies=0, errors=0, bytes_acked=0, first_blocked_s=None,
                      first_error_s=None)
        self.t0 = time.time()

    def add(self, **kw):
        with self.lock:
            for k, v in kw.items():
                self.d[k] += v

    def mark(self, key):
        with self.lock:
            if self.d[key] is None:
                self.d[key] = round(time.time() - self.t0, 3)


def make_payload(mode, n, size):
    text = "hello #%d (mode=%s)" % (n, mode)
    if size and len(text) < size:
        text += " " + "x" * (size - len(text) - 1)
    return text.encode()


def worker(args, stats, deadline, delay):
    n = 0
    while True:
        if deadline and time.time() >= deadline:
            return
        try:
            s = socket.create_connection((args.server, args.port), timeout=args.connect_timeout)
        except OSError as exc:
            stats.add(connect_fails=1)
            stats.mark("first_error_s")
            if not args.persist:
                if not args.quiet:
                    print("[client] could not connect to %s:%d -> %s" % (args.server, args.port, exc))
                return
            time.sleep(0.2)
            continue
        stats.add(connects=1)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(args.recv_timeout)
        sent_here = 0
        reconnect = False
        try:
            with s:
                while True:
                    if deadline and time.time() >= deadline:
                        return
                    if not deadline and sent_here >= args.count:
                        return
                    n += 1
                    sent_here += 1
                    payload = make_payload(args.mode, n, args.size)
                    t0 = time.time()
                    s.sendall(payload)
                    stats.add(sent=1)
                    reply = s.recv(1024)
                    if not reply:
                        raise ConnectionError("server closed the connection")
                    word = reply.decode(errors="replace")
                    if word == "ACK":
                        stats.add(acked=1, bytes_acked=len(payload))
                    elif word == "BLOCKED":
                        stats.add(blocked_replies=1)
                        stats.mark("first_blocked_s")
                    elif word == "DENIED":
                        stats.add(denied_replies=1)
                    if not args.quiet:
                        print("[client] sent=%r reply=%r" % (payload.decode()[:40], word),
                              flush=True)
                    if word == "DENIED":
                        reconnect = True
                        break
                    if delay:
                        time.sleep(max(0.0, delay - (time.time() - t0)))
        except OSError as exc:
            stats.add(errors=1)
            stats.mark("first_error_s")
            if not args.persist and not deadline:
                if not args.quiet:
                    print("[client] connection error after %d messages: %s (traffic is "
                          "probably being dropped by the SDN firewall)" % (sent_here, exc))
                return
        if reconnect and not args.persist:
            return


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", required=True)
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--mode", choices=["normal", "flood"], default="normal")
    p.add_argument("--count", type=int, default=5, help="messages per connection")
    p.add_argument("--delay", type=float, help="seconds between messages")
    p.add_argument("--rate", type=float, help="messages/s per connection (0 = unlimited)")
    p.add_argument("--size", type=int, default=0, help="pad each message to this many bytes")
    p.add_argument("--connections", type=int, default=1)
    p.add_argument("--duration", type=float, help="run for this many seconds (ignores --count)")
    p.add_argument("--persist", action="store_true", help="reconnect after errors / blocks")
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--recv-timeout", type=float, default=5.0)
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--summary-json", action="store_true",
                   help="print one 'SUMMARY {...}' line at the end")
    args = p.parse_args()

    if args.delay is not None:
        delay = args.delay
    elif args.rate is not None:
        delay = 1.0 / args.rate if args.rate > 0 else 0.0
    else:
        delay = 0.1 if args.mode == "flood" else 2.0

    stats = Stats()
    deadline = time.time() + args.duration if args.duration else None
    threads = [threading.Thread(target=worker, args=(args, stats, deadline, delay), daemon=True)
               for _ in range(args.connections)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if args.summary_json:
        out = dict(stats.d, duration_s=round(time.time() - stats.t0, 3))
        print("SUMMARY " + json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
