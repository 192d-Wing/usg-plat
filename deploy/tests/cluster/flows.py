#!/usr/bin/env python3
"""Traffic generator and meter for the cluster/HA tests (plan §8.2).

server:  TCP echo + UDP echo on <bind>:<port> (run in netns `inet` on the edge)
client:  from netns `cli`, through the translators to the server's NAT64 address
  - <flows> long-lived TCP flows, each sending one 8-byte probe every 100 ms
    and expecting the echo; per-flow max gap and survival are recorded
  - a UDP stream with sequence numbers at <udp-pps>, echoed by the server
  - <cps> new short TCP connections per second (success / failure)
  - <push-flows> server-speaks-first TCP flows (POAM-028 session hints): the
    client never sends after the handshake; the server (port + 1) pushes one
    8-byte probe every 100 ms, so after a takeover the new owner sees the
    IPv4 side first (only a restored session passes ADF/APDF)
  - <idle-flows> idle-then-push TCP flows: silent in both directions for
    <idle-secs> after the handshake (across the takeover), then the server
    (port + 2) pushes as above
  - <udp-push-flows> server-speaks-first UDP flows (QUIC-like, POAM-028 UDP
    hints with session_hints = "tcp_udp"): each client socket sends one
    datagram every 100 ms for <udp-warm-secs> (so the flow is bidirectional
    and older than udp_hint_after_secs), then only listens; the server
    (UDP port + 1) pushes one datagram every 100 ms to every peer it heard
  - <dns-qps> one-shot UDP exchanges per second (DNS-like churn): each from
    a new socket (new source port) to the UDP echo port; these must never
    be hinted
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


def listener(sel, args, port, kind):
    lt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lt.bind((args.bind, port))
    lt.listen(4096)
    lt.setblocking(False)
    sel.register(lt, selectors.EVENT_READ, kind)


def server(args):
    sel = selectors.DefaultSelector()
    listener(sel, args, args.port, "accept")
    # Pushed flows: socket -> monotonic time of the next probe.
    pushed = {}
    listener(sel, args, args.port + 1, ("push", 0.0))
    listener(sel, args, args.port + 2, ("push", float(args.idle_secs)))
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.bind((args.bind, args.port))
    us.setblocking(False)
    sel.register(us, selectors.EVENT_READ, "udp")
    # UDP push: peer -> monotonic time of the next datagram.
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.bind((args.bind, args.port + 1))
    up.setblocking(False)
    sel.register(up, selectors.EVENT_READ, "udp_push")
    upeers = {}
    while True:
        t = time.monotonic()
        for peer, due in list(upeers.items()):
            if t >= due:
                try:
                    up.sendto(b"upush\x00\x00\x00", peer)
                except OSError:
                    pass
                upeers[peer] = t + PROBE_MS / 1000
        for c, due in list(pushed.items()):
            if t < due:
                continue
            try:
                c.send(b"push\x00\x00\x00\x00")
                pushed[c] = t + PROBE_MS / 1000
            except BlockingIOError:
                pushed[c] = t + PROBE_MS / 1000
            except OSError:
                del pushed[c]
                sel.unregister(c)
                c.close()
        for key, _ in sel.select(PROBE_MS / 2000):
            if isinstance(key.data, tuple):
                try:
                    c, _ = key.fileobj.accept()
                except OSError:
                    continue
                c.setblocking(False)
                pushed[c] = time.monotonic() + key.data[1]
                sel.register(c, selectors.EVENT_READ, "pushed")
            elif key.data == "pushed":
                c = key.fileobj
                try:
                    d = c.recv(4096)
                except OSError:
                    d = b""
                if not d:
                    pushed.pop(c, None)
                    sel.unregister(c)
                    c.close()
            elif key.data == "accept":
                try:
                    c, _ = key.fileobj.accept()
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
            elif key.data == "udp_push":
                try:
                    _, peer = up.recvfrom(2048)
                    upeers.setdefault(peer, time.monotonic())
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
    kinds = [("echo", args.port)] * args.flows
    kinds += [("push", args.port + 1)] * args.push_flows
    kinds += [("idle", args.port + 2)] * args.idle_flows
    for i, (kind, port) in enumerate(kinds):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind((src(i, args.sources), 0))
        s.setblocking(False)
        if s.connect_ex((args.target, port)) not in (0, errno.EINPROGRESS):
            s.close()
            continue
        pending[s] = kind
        csel.register(s, selectors.EVENT_WRITE)
    deadline = now() + 5
    while pending and now() < deadline:
        for key, _ in csel.select(max(0.0, deadline - now())):
            s = key.fileobj
            csel.unregister(s)
            kind = pending.pop(s)
            if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
                s.close()
                continue
            flows[s] = {"last": now(), "gap": 0.0, "alive": True, "kind": kind, "seen": False}
            sel.register(s, selectors.EVENT_READ, "tcp")
    for s in pending:
        s.close()
    csel.close()
    us = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    us.bind((src(0, args.sources), 0))
    us.connect((args.target, args.port))
    us.setblocking(False)
    sel.register(us, selectors.EVENT_READ, "udp")
    # UDP push flows: socket -> stats; the client sends only while warming.
    uflows = {}
    for i in range(args.udp_push_flows):
        u = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        u.bind((src(i, args.sources), 0))
        u.connect((args.target, args.port + 1))
        u.setblocking(False)
        uflows[u] = {"last": 0.0, "gap": 0.0, "seen": False}
        sel.register(u, selectors.EVENT_READ, "udp_push")
    dns = {}
    dns_ok = dns_fail = 0
    dns_idx = 0

    start = now()
    next_dns = start
    next_uwarm = start
    for f in uflows.values():
        f["last"] = start + args.udp_warm_secs
    # The connect phase can last up to its 5 s deadline: measure gaps from
    # here, not from each flow's own connect time.
    for f in flows.values():
        # Idle flows are measured from the end of their silence.
        f["last"] = start + (args.idle_secs if f["kind"] == "idle" else 0)
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
                # Pushed flows never send after the handshake.
                if f["alive"] and f["kind"] == "echo":
                    try:
                        s.send(b"probe\x00\x00\x00")
                    except BlockingIOError:
                        pass
                    except OSError:
                        f["alive"] = False
            next_probe = t + PROBE_MS / 1000
        if uflows and t >= next_uwarm and t < start + args.udp_warm_secs:
            for u in uflows:
                try:
                    u.send(b"uwarm\x00\x00\x00")
                except OSError:
                    pass
            next_uwarm = t + PROBE_MS / 1000
        if args.dns_qps and t >= next_dns:
            q = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                q.bind((src(dns_idx, args.sources), 0))
                q.connect((args.target, args.port))
                q.setblocking(False)
                q.send(b"dnsq")
                dns[q] = t + 1.0
                sel.register(q, selectors.EVENT_READ, "dns")
            except OSError:
                q.close()
                dns_fail += 1
            dns_idx += 1
            next_dns = t + 1 / args.dns_qps
        for q, dl in list(dns.items()):
            if t >= dl:
                sel.unregister(q)
                q.close()
                del dns[q]
                dns_fail += 1
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
            if key.data == "dns":
                sel.unregister(s)
                dns.pop(s, None)
                try:
                    s.recv(64)
                    dns_ok += 1
                except OSError:
                    dns_fail += 1
                s.close()
                continue
            if key.data == "udp_push":
                f = uflows[s]
                try:
                    while s.recv(64):
                        t2 = now()
                        if f["seen"]:
                            f["gap"] = max(f["gap"], t2 - f["last"])
                        f["last"] = t2
                        f["seen"] = True
                except OSError:
                    pass
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
            f["seen"] = True
    t = now()
    for f in flows.values():
        if f["alive"]:
            f["gap"] = max(f["gap"], t - f["last"])
            # A flow that has not seen an echo (or a push) for 10 s, or a
            # pushed flow that never received anything, is counted as dead.
            if t - f["last"] > 10 or (f["kind"] != "echo" and not f["seen"]):
                f["alive"] = False

    for f in uflows.values():
        f["gap"] = max(f["gap"], t - f["last"])
        f["alive"] = f["seen"] and t - f["last"] <= 10

    def of(kind):
        return [f for f in flows.values() if f["kind"] == kind]

    def gap_ms(fs):
        return int(max((f["gap"] for f in fs if f["alive"]), default=0) * 1000)

    echo = of("echo")
    out = {
        "tcp_flows": len(echo),
        "tcp_requested": args.flows,
        "tcp_survived": sum(1 for f in echo if f["alive"]),
        "tcp_max_gap_ms": gap_ms(echo),
        "push_flows": len(of("push")),
        "push_requested": args.push_flows,
        "push_survived": sum(1 for f in of("push") if f["alive"]),
        "push_max_gap_ms": gap_ms(of("push")),
        "idle_flows": len(of("idle")),
        "idle_requested": args.idle_flows,
        "idle_survived": sum(1 for f in of("idle") if f["alive"]),
        "udp_sent": seq,
        "udp_recv": udp_recv,
        "udp_max_gap_ms": int(udp_gap * 1000),
        "new_ok": new_ok,
        "new_fail": new_fail,
        "udp_push_flows": len(uflows),
        "udp_push_survived": sum(1 for f in uflows.values() if f["alive"]),
        "udp_push_max_gap_ms": int(max((f["gap"] for f in uflows.values() if f["alive"]), default=0) * 1000),
        "dns_ok": dns_ok,
        "dns_fail": dns_fail,
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
    p.add_argument("--push-flows", type=int, default=0)
    p.add_argument("--idle-flows", type=int, default=0)
    p.add_argument("--idle-secs", type=float, default=20)
    p.add_argument("--udp-push-flows", type=int, default=0)
    p.add_argument("--udp-warm-secs", type=float, default=3)
    p.add_argument("--dns-qps", type=float, default=0)
    p.add_argument("--out", default="/run/plat-flows.json")
    a = p.parse_args()
    {"server": server, "client": client, "syslog": syslog}[a.mode](a)


if __name__ == "__main__":
    main()
