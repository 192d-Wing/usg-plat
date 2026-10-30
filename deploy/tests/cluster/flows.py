#!/usr/bin/env python3
"""Traffic generator and meter for the cluster/HA tests (plan §8.2).

server:  TCP echo + UDP echo on <bind>:<port> (run in netns `inet` on the edge)
client:  from netns `cli`, through the translators to the server's NAT64 address
  - <flows> long-lived TCP flows, each sending one 8-byte probe every 100 ms
    and expecting the echo; per-flow max gap and survival are recorded
  - a UDP stream with sequence numbers at <udp-pps>, echoed by the server
  - <cps> new short TCP connections per second (success / failure)
  Source addresses rotate over <sources> subscriber /64s (2001:db8:100:<n>::10),
  so subscribers spread over both nodes by the edge ECMP hash.
syslog:  UDP syslog sink appending each message's JSON payload to a file
  (the SIEM copy of the audit stream used by attrib-check.sh)

Writes one JSON summary (client) to --out. Test tool only; stdlib only.
"""
import argparse
import errno
import json
import os
import selectors
import socket
import struct
import time

PROBE_MS = 100


def server(args):
    sel = selectors.DefaultSelector()
    lt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lt.bind((args.bind, args.port))
    lt.listen(4096)
    lt.setblocking(False)
    sel.register(lt, selectors.EVENT_READ, "accept")
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.bind((args.bind, args.port))
    us.setblocking(False)
    sel.register(us, selectors.EVENT_READ, "udp")
    while True:
        for key, _ in sel.select(1.0):
            if key.data == "accept":
                try:
                    c, _ = lt.accept()
                except OSError:
                    continue
                c.setblocking(False)
                sel.register(c, selectors.EVENT_READ, "tcp")
            elif key.data == "udp":
                try:
                    d, peer = us.recvfrom(2048)
                    us.sendto(d, peer)
                except OSError:
                    pass
            else:
                c = key.fileobj
                try:
                    d = c.recv(4096)
                except OSError:
                    d = b""
                if not d:
                    sel.unregister(c)
                    c.close()
                    continue
                try:
                    c.send(d)
                except OSError:
                    pass


def src(i, n):
    return "2001:db8:100:%x::10" % (i % n + 1)


def client(args):
    now = time.monotonic
    sel = selectors.DefaultSelector()
    flows = {}
    # Connect every flow in parallel with one 5 s deadline (a serial 5 s
    # timeout per flow made a blackholed run last up to flows * 5 s).
    pending = {}
    csel = selectors.DefaultSelector()
    for i in range(args.flows):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind((src(i, args.sources), 0))
        s.setblocking(False)
        if s.connect_ex((args.target, args.port)) not in (0, errno.EINPROGRESS):
            s.close()
            continue
        pending[s] = True
        csel.register(s, selectors.EVENT_WRITE)
    deadline = now() + 5
    while pending and now() < deadline:
        for key, _ in csel.select(max(0.0, deadline - now())):
            s = key.fileobj
            csel.unregister(s)
            del pending[s]
            if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
                s.close()
                continue
            flows[s] = {"last": now(), "gap": 0.0, "alive": True}
            sel.register(s, selectors.EVENT_READ, "tcp")
    for s in pending:
        s.close()
    csel.close()
    us = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    us.bind((src(0, args.sources), 0))
    us.connect((args.target, args.port))
    us.setblocking(False)
    sel.register(us, selectors.EVENT_READ, "udp")

    start = now()
    # The connect phase can last up to its 5 s deadline: measure gaps from
    # here, not from each flow's own connect time.
    for f in flows.values():
        f["last"] = start
    end = start + args.duration
    next_probe = start
    next_udp = start
    next_new = start
    seq = 0
    udp_last = now()
    udp_gap = 0.0
    udp_recv = 0
    new_ok = new_fail = 0
    newc = {}
    new_idx = 0
    while now() < end:
        t = now()
        if t >= next_probe:
            for s, f in flows.items():
                if f["alive"]:
                    try:
                        s.send(b"probe\x00\x00\x00")
                    except BlockingIOError:
                        pass
                    except OSError:
                        f["alive"] = False
            next_probe = t + PROBE_MS / 1000
        if args.udp_pps and t >= next_udp:
            try:
                us.send(struct.pack("!Q", seq))
            except OSError:
                pass
            seq += 1
            next_udp = t + 1 / args.udp_pps
        if args.cps and t >= next_new:
            # Non-blocking: a failing new connection must not stall the
            # probe/echo loop (a blocking 0.3-1 s connect per iteration
            # inflated the measured flow gaps).
            n = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            n.setblocking(False)
            try:
                n.bind((src(new_idx, args.sources), 0))
                if n.connect_ex((args.target, args.port)) in (0, errno.EINPROGRESS):
                    newc[n] = t + 1.0
                    sel.register(n, selectors.EVENT_WRITE, "new")
                else:
                    n.close()
                    new_fail += 1
            except OSError:
                n.close()
                new_fail += 1
            new_idx += 1
            next_new = t + 1 / args.cps
        for n, dl in list(newc.items()):
            if t >= dl:
                sel.unregister(n)
                n.close()
                del newc[n]
                new_fail += 1
        for key, _ in sel.select(0.01):
            s = key.fileobj
            if key.data == "new":
                sel.unregister(s)
                newc.pop(s, None)
                if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                    new_ok += 1
                else:
                    new_fail += 1
                s.close()
                continue
            if key.data == "udp":
                try:
                    while us.recv(64):
                        t2 = now()
                        udp_gap = max(udp_gap, t2 - udp_last)
                        udp_last = t2
                        udp_recv += 1
                except OSError:
                    pass
                continue
            f = flows[s]
            try:
                d = s.recv(4096)
            except BlockingIOError:
                continue
            except OSError:
                d = b""
            if not d:
                f["alive"] = False
                sel.unregister(s)
                continue
            t2 = now()
            f["gap"] = max(f["gap"], t2 - f["last"])
            f["last"] = t2
    t = now()
    for f in flows.values():
        if f["alive"]:
            f["gap"] = max(f["gap"], t - f["last"])
            # A flow that has not seen an echo for 10 s is counted as dead.
            if t - f["last"] > 10:
                f["alive"] = False
    out = {
        "tcp_flows": len(flows),
        "tcp_requested": args.flows,
        "tcp_survived": sum(1 for f in flows.values() if f["alive"]),
        "tcp_max_gap_ms": int(max((f["gap"] for f in flows.values() if f["alive"]), default=0) * 1000),
        "udp_sent": seq,
        "udp_recv": udp_recv,
        "udp_max_gap_ms": int(udp_gap * 1000),
        "new_ok": new_ok,
        "new_fail": new_fail,
    }
    with open(args.out + ".tmp", "w") as fh:
        json.dump(out, fh)
    os.replace(args.out + ".tmp", args.out)


def syslog(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((args.bind, args.port))
    with open(args.out, "a", buffering=1) as fh:
        while True:
            d = s.recv(65535).decode("utf-8", "replace")
            i = d.find("{")
            if i >= 0:
                fh.write(d[i:].rstrip("\n") + "\n")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["server", "client", "syslog"])
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5201)
    p.add_argument("--target", default="64:ff9b:1::cb00:710a")
    p.add_argument("--duration", type=float, default=60)
    p.add_argument("--flows", type=int, default=200)
    p.add_argument("--udp-pps", type=float, default=200)
    p.add_argument("--cps", type=float, default=20)
    p.add_argument("--sources", type=int, default=8)
    p.add_argument("--out", default="/run/plat-flows.json")
    a = p.parse_args()
    {"server": server, "client": client, "syslog": syslog}[a.mode](a)


if __name__ == "__main__":
    main()
