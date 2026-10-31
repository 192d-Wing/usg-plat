#!/usr/bin/env python3
"""Load-time gates on the plat-xdp-ebpf object (plan §2.5 rule 5, §11 levels 2-3).

Test-only loader: parses the object's legacy `maps` section and relocations,
creates the maps, loads `plat_xdp` with bpf(BPF_PROG_LOAD) and runs it with
bpf(BPF_PROG_TEST_RUN). It is not the production loader (plat-xdp, WU3) and
never attaches or pins anything. Runs as root (CAP_BPF, CAP_NET_ADMIN for
the devmap).

  stats OBJECT [--max-stack B] [--max-insns N]
      Load with verifier statistics (log level 4) and fail when
        - the verifier's "processed N insns" or "stack depth" line is missing
          (fail closed);
        - the deepest bpf-to-bpf call chain, summing the verifier's per-
          subprogram stack depths, exceeds B (default 384; 256 when the
          object combines tail calls with subprograms, plan §2.5 rule 5);
        - processed instructions exceed N (default INSN_BUDGET).
      Prints one "obj-gate: stats ..." line for the logs.

  testrun OBJECT VECTORS
      Level-2 smoke (WU2; the full harness is WU3): for each frame of
      VECTORS (written and checked against plat-xdp-core by
      crates/plat-xdp-ebpf/tests/level2_vectors.rs), re-apply the map state,
      run the program once in non-live mode with ingress_ifindex set, and
      compare the action and output bytes; a pass must leave the frame
      unmodified and count its reason in STATS; a redirect must touch
      SLOT.seen_ns. Run it inside the level-2 namespace (netns.sh):
        nsenter --net=/run/netns/platxdp python3 -I obj-gate.py testrun ...

  --self-test
      The statistics evaluation on canned verifier logs (no kernel; make
      check-xdp).

Exit: 0 ok, 1 a gate or vector failed, 2 usage, unreadable object or
unsupported host.

COMPLIANCE MAPPING:
- NIST 800-53: SA-11 (Developer Testing) - verifier budgets and compiled-
  object vectors; SC-5 (Denial-of-Service Protection) - bounded per-packet
  work (instruction budget, no loops, stack headroom)
"""

import ctypes
import os
import platform
import re
import struct
import sys

SYS_BPF = {"x86_64": 321, "aarch64": 280}

BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_PROG_LOAD = 5
BPF_PROG_TEST_RUN = 10
BPF_PROG_TYPE_XDP = 6
BPF_PSEUDO_MAP_FD = 1
BPF_PSEUDO_CALL = 1
PERCPU_TYPES = {5, 6, 10}  # PERCPU_HASH, PERCPU_ARRAY, LRU_PERCPU_HASH
HELPER_TAIL_CALL = 12
ATTR_SIZE = 144

XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT = range(5)

# plan §2.5 rule 5: stack ≤ 384 B (256 B with tail calls and subprograms).
STACK_BUDGET = 384
STACK_BUDGET_TAILCALL = 256
# Verified ("processed") instructions, limit 1 M. WU2 measured 5553 on
# 6.1.176 and 3241 on 6.8 (336 B stack on both); the budget is about 2x the
# larger, so a change that doubles the verifier's work fails here first.
INSN_BUDGET = 12000

SHT_SYMTAB = 2
SHT_REL = 9
SHF_EXECINSTR = 0x4
STT_SECTION = 3
R_BPF_64_64 = 1
R_BPF_64_32 = 10
OP_LD_IMM64 = 0x18
OP_CALL = 0x85


class Fail(Exception):
    pass


class Usage(Exception):
    pass


# ---------------------------------------------------------------- bpf(2)

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def bpf(cmd, attr):
    nr = SYS_BPF.get(platform.machine())
    if nr is None:
        raise Usage(f"unsupported machine {platform.machine()}")
    ret = _libc.syscall(ctypes.c_long(nr), ctypes.c_long(cmd), ctypes.c_void_p(ctypes.addressof(attr)), ctypes.c_long(ATTR_SIZE))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def possible_cpus():
    with open("/sys/devices/system/cpu/possible") as f:
        n = 0
        for part in f.read().strip().split(","):
            lo, _, hi = part.partition("-")
            n = max(n, int(hi or lo) + 1)
        return n


class Map:
    def __init__(self, name, mtype, key_size, value_size, max_entries, flags):
        self.name, self.type, self.key_size, self.value_size = name, mtype, key_size, value_size
        attr = ctypes.create_string_buffer(ATTR_SIZE)
        struct.pack_into("<IIIIIII", attr, 0, mtype, key_size, value_size, max_entries, flags, 0, 0)
        struct.pack_into("16s", attr, 28, name[:15].encode())
        self.fd = bpf(BPF_MAP_CREATE, attr)

    def _value_len(self):
        if self.type in PERCPU_TYPES:
            return possible_cpus() * ((self.value_size + 7) // 8 * 8)
        return self.value_size

    def update(self, key, value):
        if len(key) != self.key_size:
            raise Fail(f"{self.name}: key is {len(key)} bytes, map has {self.key_size}")
        if self.type in PERCPU_TYPES:
            if len(value) != self.value_size:
                raise Fail(f"{self.name}: value is {len(value)} bytes, map has {self.value_size}")
            slot = (self.value_size + 7) // 8 * 8
            value = (value + bytes(slot - len(value))) * possible_cpus()
        elif len(value) != self.value_size:
            raise Fail(f"{self.name}: value is {len(value)} bytes, map has {self.value_size}")
        k = ctypes.create_string_buffer(key, len(key))
        v = ctypes.create_string_buffer(value, len(value))
        attr = ctypes.create_string_buffer(ATTR_SIZE)
        struct.pack_into("<IIQQQ", attr, 0, self.fd, 0, ctypes.addressof(k), ctypes.addressof(v), 0)
        bpf(BPF_MAP_UPDATE_ELEM, attr)

    def lookup(self, key):
        """The value; per-CPU maps: the list of per-CPU values."""
        k = ctypes.create_string_buffer(key, len(key))
        n = self._value_len()
        v = ctypes.create_string_buffer(n)
        attr = ctypes.create_string_buffer(ATTR_SIZE)
        struct.pack_into("<IIQQ", attr, 0, self.fd, 0, ctypes.addressof(k), ctypes.addressof(v))
        bpf(BPF_MAP_LOOKUP_ELEM, attr)
        if self.type in PERCPU_TYPES:
            slot = (self.value_size + 7) // 8 * 8
            return [v.raw[i : i + self.value_size] for i in range(0, n, slot)]
        return v.raw[:n]


# ---------------------------------------------------------------- object


def parse_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise Usage("not an ELF64 little-endian object")
    (machine,) = struct.unpack_from("<H", data, 0x12)
    if machine != 247:
        raise Usage(f"e_machine {machine}, want EM_BPF")
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    _, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    secs = []
    for i in range(shnum):
        name, typ, flags, _a, off, size, link, info, _al, entsize = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * 64)
        body = b"" if typ == 8 else data[off : off + size]
        secs.append({"name_off": name, "type": typ, "flags": flags, "body": body, "link": link, "info": info, "entsize": entsize})
    strtab = secs[shstrndx]["body"]
    for s in secs:
        e = strtab.find(b"\x00", s["name_off"])
        s["name"] = strtab[s["name_off"] : e].decode()
    syms = []
    for s in secs:
        if s["type"] == SHT_SYMTAB:
            strs = secs[s["link"]]["body"]
            for off in range(0, len(s["body"]) - 23, 24):
                st_name, info, _o, shndx, value, size = struct.unpack_from("<IBBHQQ", s["body"], off)
                e = strs.find(b"\x00", st_name)
                syms.append({"name": strs[st_name:e].decode(), "type": info & 0xF, "shndx": shndx, "value": value, "size": size})
    return secs, syms


def relocs(secs, target):
    out = []
    for s in secs:
        if s["type"] == SHT_REL and s["info"] == target:
            for off in range(0, len(s["body"]) - 15, 16):
                r_off, r_info = struct.unpack_from("<QQ", s["body"], off)
                out.append((r_off, r_info & 0xFFFFFFFF, r_info >> 32))
    return out


class Program:
    """The object's maps (created) and `plat_xdp` with its subprograms linked
    in (bpf-to-bpf calls into .text are appended, as libbpf and Aya do)."""

    def __init__(self, path, prog="plat_xdp"):
        with open(path, "rb") as f:
            data = f.read()
        secs, syms = parse_elf(data)
        self.license = None
        self.maps = {}
        maps_idx = next((i for i, s in enumerate(secs) if s["name"] == "maps"), None)
        for i, s in enumerate(secs):
            if s["name"] == "license":
                self.license = s["body"].split(b"\x00")[0]
        if maps_idx is not None:
            body = secs[maps_idx]["body"]
            for sym in syms:
                if sym["shndx"] == maps_idx and sym["size"] >= 20:
                    mtype, ks, vs, maxe, flags = struct.unpack_from("<IIIII", body, sym["value"])
                    self.maps[sym["name"]] = Map(sym["name"], mtype, ks, vs, maxe, flags)
        entry = next((s for s in syms if s["name"] == prog and s["type"] == 2), None)
        if entry is None:
            raise Usage(f"no program {prog}")
        sec_idx = entry["shndx"]
        code = bytearray(secs[sec_idx]["body"][entry["value"] : entry["value"] + entry["size"]])
        # Subprograms: (section, start byte) -> start insn in the linked code.
        self.subprogs = [0]
        placed = {(sec_idx, entry["value"]): 0}
        self.calls = []  # (caller start insn, callee start insn)
        self.tail_calls = False
        work = [(sec_idx, entry["value"], 0, len(code) // 8)]
        while work:
            si, base, at, n = work.pop()
            rel = {r_off: (rtype, symi) for r_off, rtype, symi in relocs(secs, si)}
            k = 0
            while k < n:
                pos = (at + k) * 8
                op = code[pos]
                src = code[pos + 1] >> 4
                r = rel.get(base + k * 8)
                if r is not None and r[0] == R_BPF_64_64 and op == OP_LD_IMM64:
                    name = syms[r[1]]["name"]
                    if name not in self.maps:
                        raise Usage(f"relocation to non-map symbol {name} (data sections are not supported)")
                    code[pos + 1] = (code[pos + 1] & 0x0F) | (BPF_PSEUDO_MAP_FD << 4)
                    struct.pack_into("<i", code, pos + 4, self.maps[name].fd)
                elif op == OP_CALL and src == BPF_PSEUDO_CALL:
                    (imm,) = struct.unpack_from("<i", code, pos + 4)
                    if r is not None:
                        sym = syms[r[1]]
                        tsec = sym["shndx"]
                        tbyte = sym["value"] + ((imm + 1) * 8 if sym["type"] == STT_SECTION else 0)
                    else:
                        tsec, tbyte = si, base + (k + 1 + imm) * 8
                    key = (tsec, tbyte)
                    if key not in placed:
                        fn = next(
                            (s for s in syms if s["shndx"] == tsec and s["type"] == 2 and s["value"] == tbyte), None
                        )
                        if fn is None or not fn["size"]:
                            raise Usage(f"call to an unknown function at {secs[tsec]['name']}+{tbyte:#x}")
                        start = len(code) // 8
                        code += secs[tsec]["body"][tbyte : tbyte + fn["size"]]
                        placed[key] = start
                        self.subprogs.append(start)
                        work.append((tsec, tbyte, start, fn["size"] // 8))
                    struct.pack_into("<i", code, pos + 4, placed[key] - (at + k) - 1)
                    self.calls.append((at + k, placed[key]))
                elif op == OP_CALL and src == 0 and struct.unpack_from("<i", code, pos + 4)[0] == HELPER_TAIL_CALL:
                    self.tail_calls = True
                k += 2 if op == OP_LD_IMM64 else 1
        self.code = bytes(code)
        self.subprogs.sort()
        self.fd = None
        self.log = ""

    def load(self, log_level=4, log_size=1 << 16):
        insns = ctypes.create_string_buffer(self.code, len(self.code))
        lic = ctypes.create_string_buffer(self.license or b"")
        log = ctypes.create_string_buffer(max(log_size, 1))
        # The kernel rejects a log buffer with log level 0.
        log_ptr = ctypes.addressof(log) if log_level else 0
        attr = ctypes.create_string_buffer(ATTR_SIZE)
        struct.pack_into(
            "<IIQQIIQ", attr, 0, BPF_PROG_TYPE_XDP, len(self.code) // 8, ctypes.addressof(insns), ctypes.addressof(lic),
            log_level, log_size if log_level else 0, log_ptr,
        )
        struct.pack_into("16s", attr, 48, b"plat_xdp")
        try:
            self.fd = bpf(BPF_PROG_LOAD, attr)
        finally:
            self.log = log.value.decode(errors="replace")
        return self.fd

    def test_run(self, frame, ingress_ifindex):
        data_in = ctypes.create_string_buffer(frame, len(frame))
        data_out = ctypes.create_string_buffer(len(frame) + 512)
        # struct xdp_md: data, data_end, data_meta, ingress_ifindex,
        # rx_queue_index, egress_ifindex (data_end must equal the size).
        ctx = ctypes.create_string_buffer(struct.pack("<IIIIII", 0, len(frame), 0, ingress_ifindex, 0, 0), 24)
        attr = ctypes.create_string_buffer(ATTR_SIZE)
        struct.pack_into(
            "<IIIIQQIIIIQQ", attr, 0, self.fd, 0, len(frame), len(data_out), ctypes.addressof(data_in),
            ctypes.addressof(data_out), 1, 0, 24, 0, ctypes.addressof(ctx), 0,
        )
        bpf(BPF_PROG_TEST_RUN, attr)
        retval, _, size_out = struct.unpack_from("<III", attr, 4)
        return retval, data_out.raw[:size_out]


# ---------------------------------------------------------------- stats


def deepest_chain(subprogs, calls, depths):
    """Largest sum of stack depths along a call chain from subprogram 0."""
    index = {start: i for i, start in enumerate(subprogs)}

    def owner(insn):
        return max(i for i, s in enumerate(subprogs) if s <= insn)

    callees = {i: set() for i in range(len(subprogs))}
    for at, target in calls:
        callees[owner(at)].add(index[target])

    def walk(i, seen):
        if i in seen:
            raise Fail("recursive bpf-to-bpf calls")
        return depths[i] + max((walk(c, seen | {i}) for c in callees[i]), default=0)

    return walk(0, frozenset())


def evaluate(log, subprogs, calls, tail_calls, max_stack, max_insns):
    """(summary line, problems) for a verifier statistics log."""
    m_insns = re.search(r"processed (\d+) insns", log)
    m_stack = re.search(r"stack depth ([0-9+]+)", log)
    if not m_insns or not m_stack:
        return None, ["verifier statistics missing (no 'processed N insns' / 'stack depth' line); failing closed"]
    insns = int(m_insns.group(1))
    depths = [int(x) for x in m_stack.group(1).split("+")]
    if len(depths) != len(subprogs):
        return None, [f"verifier reports {len(depths)} stack depths for {len(subprogs)} subprograms"]
    chain = deepest_chain(subprogs, calls, depths)
    rounded = deepest_chain(subprogs, calls, [(max(d, 1) + 31) // 32 * 32 for d in depths])
    budget = max_stack
    if tail_calls and len(subprogs) > 1:
        budget = min(budget, STACK_BUDGET_TAILCALL)
    summary = (
        f"insns_processed={insns} insn_budget={max_insns} stack_depths={m_stack.group(1)} "
        f"deepest_chain={chain} (rounded {rounded}) stack_budget={budget} subprograms={len(subprogs)} "
        f"tail_calls={'yes' if tail_calls else 'no'}"
    )
    problems = []
    if chain > budget:
        problems.append(f"stack: deepest call chain {chain} B > budget {budget} B")
    if insns > max_insns:
        problems.append(f"verifier: {insns} processed insns > budget {max_insns}")
    return summary, problems


def cmd_stats(path, max_stack, max_insns):
    prog = Program(path)
    try:
        prog.load(log_level=4)
    except OSError as e:
        tail = prog.log
        try:
            prog.load(log_level=1 | 4, log_size=1 << 24)
        except OSError:
            tail = prog.log
        lines = tail.strip().splitlines()
        print("\n".join(lines[-40:]), file=sys.stderr)
        raise Fail(f"BPF_PROG_LOAD failed: {e}") from None
    os.close(prog.fd)
    summary, problems = evaluate(prog.log, prog.subprogs, prog.calls, prog.tail_calls, max_stack, max_insns)
    if summary is None:
        print(prog.log, file=sys.stderr)
    else:
        print(f"obj-gate: stats kernel={platform.release()} {summary} xlated_insns={len(prog.code) // 8}")
    if problems:
        raise Fail("; ".join(problems))
    print("obj-gate: stats ok")


def self_test():
    """The statistics evaluation without a kernel (make check-xdp)."""
    one = "verification time 120 usec\nstack depth 336\nprocessed 3185 insns (limit 1000000) max_states_per_insn 4"
    # main (0) calls 10, which calls 20; main also calls 30.
    sub, calls = [0, 10, 20, 30], [(2, 10), (12, 20), (4, 30)]
    multi = "stack depth 8+100+200+250\nprocessed 500 insns (limit 1000000)"
    cases = [
        ("one frame within budget", evaluate(one, [0], [], False, 384, 8000), True),
        ("stack over budget", evaluate(one, [0], [], False, 320, 8000), False),
        ("insns over budget", evaluate(one, [0], [], False, 384, 3000), False),
        ("missing stats line fails closed", evaluate("verification time 9 usec", [0], [], False, 384, 8000), False),
        ("missing stack line fails closed", evaluate("processed 10 insns", [0], [], False, 384, 8000), False),
        ("depth count mismatch fails", evaluate("stack depth 8+9\nprocessed 1 insns", [0], [], False, 384, 8000), False),
        ("deepest chain 8+100+200 = 308", evaluate(multi, sub, calls, False, 308, 8000), True),
        ("deepest chain 308 > 307", evaluate(multi, sub, calls, False, 307, 8000), False),
        ("tail calls with subprograms: 256 B budget", evaluate(multi, sub, calls, True, 384, 8000), False),
        ("tail calls without subprograms keep the budget", evaluate(one, [0], [], True, 384, 8000), True),
    ]
    failed = 0
    for label, (_summary, problems), want_ok in cases:
        ok = (not problems) == want_ok
        failed += not ok
        print(f"obj-gate self-test: {'ok' if ok else 'FAIL'}: {label}")
    return 1 if failed else 0


# ---------------------------------------------------------------- testrun


def ifindex(name):
    i = _libc.if_nametoindex(name.encode())
    if i == 0:
        raise Fail(f"no interface {name} (run inside the level-2 namespace, netns.sh)")
    return i


def parse_vectors(path):
    state, frames, extra = [], [], {}
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].split()
            if not line:
                continue
            kind = line[0]
            if kind in ("map", "percpu", "iface", "egress", "control"):
                state.append(line)
            elif kind == "frame":
                frames.append(line)
            elif kind == "with" and len(line) > 2 and line[2] in ("map", "percpu", "iface", "egress", "control"):
                extra.setdefault(line[1], []).append(line[2:])
            else:
                raise Usage(f"{path}:{n}: unknown line kind {kind}")
    names = {f[1] for f in frames}
    for name in extra:
        if name not in names:
            raise Usage(f"{path}: 'with' line for unknown frame {name}")
    return state, frames, extra


def apply_state(prog, state):
    maps = prog.maps
    for line in state:
        kind = line[0]
        if kind in ("map", "percpu"):
            _, name, key, value = line
            maps[name].update(bytes.fromhex(key), bytes.fromhex(value))
        elif kind == "iface":  # IfaceEnt {ifindex u32, mac[6], role u8, pad}
            _, dev, role, mac = line
            i = ifindex(dev)
            maps["IFACES"].update(struct.pack("<I", i % 64), struct.pack("<I6sBB", i, bytes.fromhex(mac), int(role), 0))
        elif kind == "egress":  # EgressEnt {ifindex u32, allowed u8, role u8, pad[2]}; TX[ifindex]
            _, dev, role = line
            i = ifindex(dev)
            maps["EGRESS"].update(struct.pack("<I", i % 64), struct.pack("<IBBH", i, 1, int(role), 0))
            maps["TX"].update(struct.pack("<I", i), struct.pack("<Ii", i, 0)[: maps["TX"].value_size])
        elif kind == "control":  # Control {enabled, tun_ifindex, deadline_ns u64, tun_mtu, pad}
            _, dev, mtu, *rest = line
            enabled, deadline = (int(rest[0]), int(rest[1])) if rest else (1, 2**64 - 1)
            maps["CONTROL"].update(
                struct.pack("<I", 0), struct.pack("<IIQII", enabled, ifindex(dev), deadline, int(mtu), 0)
            )


def stat_sum(prog, idx):
    return sum(struct.unpack("<Q", v)[0] for v in prog.maps["STATS"].lookup(struct.pack("<I", idx)))


def cmd_testrun(path, vectors):
    prog = Program(path)
    try:
        prog.load(log_level=0, log_size=0)
    except OSError as e:
        raise Fail(f"BPF_PROG_LOAD failed: {e} (run 'stats' for the verifier log)") from None
    state, frames, extra = parse_vectors(vectors)
    if not frames:
        raise Fail(f"{vectors}: no frames")
    failed = 0
    for line in frames:
        # frame NAME INGRESS redirect EGRESS SLOT IN OUT
        # frame NAME INGRESS pass REASON STAT_IDX IN
        name, dev, verdict = line[1], line[2], line[3]
        apply_state(prog, state)
        apply_state(prog, extra.get(name, []))
        frame = bytes.fromhex(line[-2] if verdict == "redirect" else line[-1])
        problems = []
        if verdict == "redirect":
            _, slot, want = line[4], int(line[5]), bytes.fromhex(line[-1])
            before = prog.maps["SLOT"].lookup(struct.pack("<I", slot))[8:16]
            rc, out = prog.test_run(frame, ifindex(dev))
            after = prog.maps["SLOT"].lookup(struct.pack("<I", slot))[8:16]
            if rc != XDP_REDIRECT:
                problems.append(f"action {rc}, want XDP_REDIRECT")
            elif out != want:
                problems.append(f"output differs from plat-xdp-core\n    want {want.hex()}\n    got  {out.hex()}")
            elif after == before:
                problems.append("SLOT.seen_ns not touched")
        elif verdict == "pass":
            reason, idx = line[4], int(line[5])
            before = stat_sum(prog, idx)
            rc, out = prog.test_run(frame, ifindex(dev))
            if rc != XDP_PASS:
                problems.append(f"action {rc}, want XDP_PASS ({reason})")
            elif out != frame:
                problems.append("XDP_PASS frame modified")
            elif stat_sum(prog, idx) != before + 1:
                problems.append(f"STATS[{idx}] ({reason}) not incremented")
        else:
            raise Usage(f"frame {name}: unknown verdict {verdict}")
        status = "FAIL" if problems else "ok"
        print(f"obj-gate: testrun {status}: {name} ({verdict}{' ' + line[4] if verdict == 'pass' else ''})")
        for p in problems:
            print(f"  {p}")
        failed += bool(problems)
    os.close(prog.fd)
    if failed:
        raise Fail(f"{failed} of {len(frames)} frames failed")
    print(f"obj-gate: testrun ok ({len(frames)} frames, kernel {platform.release()})")


def main(argv):
    try:
        if len(argv) == 2 and argv[1] == "--self-test":
            return self_test()
        if len(argv) >= 3 and argv[1] == "stats":
            args = argv[3:]
            max_stack, max_insns = STACK_BUDGET, INSN_BUDGET
            while args:
                if args[0] == "--max-stack" and len(args) > 1:
                    max_stack = int(args[1])
                elif args[0] == "--max-insns" and len(args) > 1:
                    max_insns = int(args[1])
                else:
                    raise Usage(f"unknown argument {args[0]}")
                args = args[2:]
            cmd_stats(argv[2], max_stack, max_insns)
        elif len(argv) == 4 and argv[1] == "testrun":
            cmd_testrun(argv[2], argv[3])
        else:
            raise Usage("usage: obj-gate.py stats OBJECT [--max-stack B] [--max-insns N] | testrun OBJECT VECTORS | --self-test")
    except Fail as e:
        print(f"obj-gate: FAIL: {e}", file=sys.stderr)
        return 1
    except (Usage, OSError, ValueError) as e:
        print(f"obj-gate: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
