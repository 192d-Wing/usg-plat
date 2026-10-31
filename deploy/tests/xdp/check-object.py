#!/usr/bin/env python3
"""Static checks on the plat-xdp-ebpf object (plan §15 xdp-build, §2.5 rule 4).

  - the `license` section is exactly "Dual MIT/GPL\\0" (decision Q2, Option A:
    bpf_fib_lookup is gpl_only, so the object must be GPL-compatible, and it
    must not claim more than the dual licence);
  - every helper call (opcode 0x85, src_reg 0) in an executable section is on
    the allow-list verified in spike Q7; no bpf_printk / bpf_trace_vprintk /
    bpf_snprintf / ringbuf or perf output; no kfunc calls (src_reg 2);
  - no aya-log maps or symbols (AYA_LOGS and friends);
  - prints the object's SHA-256 for the CI record.

Adding a helper means recording its gpl_only flag at the 6.1 and current kernel
tags (plan §2.5 rule 4) and extending ALLOWED_HELPERS in the same change.

Usage: python3 -I check-object.py OBJECT | --self-test
Exit: 0 ok, 1 a check failed, 2 usage or unreadable / not an eBPF ELF.

COMPLIANCE MAPPING:
- NIST 800-53: CM-10 (Software Usage Restrictions) - licence string;
  SA-11 (Developer Testing), SI-7 (Integrity) - helper allow-list, digest
"""

import hashlib
import struct
import sys

LICENSE = b"Dual MIT/GPL\x00"

# include/uapi/linux/bpf.h __BPF_FUNC_MAPPER order (identical in v6.1 and later).
# No bpf_map_update_elem (2) or bpf_map_delete_elem (3): the program creates
# and removes no per-packet map state; it writes only through lookup pointers
# (SLOT.seen_ns, IDENT, STATS). NIST 800-53 SC-5.
ALLOWED_HELPERS = {
    1: "bpf_map_lookup_elem",
    5: "bpf_ktime_get_ns",
    8: "bpf_get_smp_processor_id",
    28: "bpf_csum_diff",
    44: "bpf_xdp_adjust_head",
    51: "bpf_redirect_map",
    65: "bpf_xdp_adjust_tail",
    69: "bpf_fib_lookup",
    160: "bpf_ktime_get_coarse_ns",
}
NAMED_FORBIDDEN = {
    6: "bpf_trace_printk",
    25: "bpf_perf_event_output",
    130: "bpf_ringbuf_output",
    165: "bpf_snprintf",
    177: "bpf_trace_vprintk",
}
FORBIDDEN_NAME_PARTS = ("AYA_LOG",)

EM_BPF = 247
SHF_EXECINSTR = 0x4
SHT_SYMTAB = 2
OP_CALL = 0x85
OP_LD_IMM64 = 0x18
BPF_PSEUDO_KFUNC_CALL = 2


class NotBpf(Exception):
    pass


def sections(data):
    """Yield (name, sh_type, sh_flags, body, sh_link, sh_entsize) per section."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise NotBpf("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise NotBpf("not ELF64 little-endian (bpfel)")
    (machine,) = struct.unpack_from("<H", data, 0x12)
    if machine != EM_BPF:
        raise NotBpf(f"e_machine {machine}, want EM_BPF ({EM_BPF})")
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if shentsize != 64 or shoff + shnum * 64 > len(data) or shstrndx >= shnum:
        raise NotBpf("bad section header table")
    raw = []
    for i in range(shnum):
        name, typ, flags, _addr, off, size, link, _info, _align, entsize = struct.unpack_from(
            "<IIQQQQIIQQ", data, shoff + i * 64
        )
        body = b"" if typ == 8 else data[off : off + size]  # SHT_NOBITS
        if typ != 8 and off + size > len(data):
            raise NotBpf(f"section {i} out of bounds")
        raw.append((name, typ, flags, body, link, entsize))
    strtab = raw[shstrndx][3]
    for name, typ, flags, body, link, entsize in raw:
        end = strtab.find(b"\x00", name)
        yield strtab[name : end if end >= 0 else None].decode(errors="replace"), typ, flags, body, link, entsize, raw


def check(data):
    """Return a list of problems (empty when the object passes)."""
    problems = []
    license_seen = None
    for name, typ, flags, body, link, entsize, raw in sections(data):
        if name == "license":
            license_seen = body
        if any(p in name for p in FORBIDDEN_NAME_PARTS):
            problems.append(f"forbidden section {name}")
        if flags & SHF_EXECINSTR:
            i = 0
            while i + 8 <= len(body):
                op, regs = body[i], body[i + 1]
                (imm,) = struct.unpack_from("<i", body, i + 4)
                if op == OP_CALL:
                    src = regs >> 4
                    if src == BPF_PSEUDO_KFUNC_CALL:
                        problems.append(f"{name}+{i:#x}: kfunc call (not allowed)")
                    elif src == 0 and imm not in ALLOWED_HELPERS:
                        what = NAMED_FORBIDDEN.get(imm, "not on the allow-list")
                        problems.append(f"{name}+{i:#x}: helper {imm} ({what})")
                i += 16 if op == OP_LD_IMM64 else 8
        if typ == SHT_SYMTAB and entsize == 24 and link < len(raw):
            strs = raw[link][3]
            for off in range(0, len(body) - 23, 24):
                (st_name,) = struct.unpack_from("<I", body, off)
                end = strs.find(b"\x00", st_name)
                sym = strs[st_name : end if end >= 0 else None].decode(errors="replace")
                if any(p in sym for p in FORBIDDEN_NAME_PARTS):
                    problems.append(f"forbidden symbol {sym}")
    if license_seen is None:
        problems.append("no license section")
    elif license_seen != LICENSE:
        problems.append(f"license section {license_seen!r}, want {LICENSE!r}")
    return problems


def build_elf(secs, symbols=()):
    """Minimal ELF64 LE EM_BPF relocatable for the self-test."""
    names = [b""] + [n for n, *_ in secs] + [b".symtab", b".strtab", b".shstrtab"]
    shstr = b"\x00"
    name_off = {}
    for n in names[1:]:
        name_off[n] = len(shstr)
        shstr += n + b"\x00"
    symstr = b"\x00"
    symtab = bytes(24)
    for s in symbols:
        symtab += struct.pack("<IBBHQQ", len(symstr), 0, 0, 0, 0, 0)
        symstr += s + b"\x00"
    allsecs = [(n, t, f, b) for n, t, f, b in secs]
    nsec = 1 + len(allsecs) + 3
    body = b""
    offs = []
    base = 64
    for _n, _t, _f, b in allsecs + [(b".symtab", 2, 0, symtab), (b".strtab", 3, 0, symstr), (b".shstrtab", 3, 0, shstr)]:
        offs.append(base + len(body))
        body += b
    shoff = base + len(body)
    hdr = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    hdr += struct.pack("<HHIQQQIHHHHHH", 1, EM_BPF, 1, 0, 0, shoff, 0, 64, 0, 0, 64, nsec, nsec - 1)
    sh = bytes(64)
    entries = allsecs + [(b".symtab", 2, 0, symtab), (b".strtab", 3, 0, symstr), (b".shstrtab", 3, 0, shstr)]
    strtab_index = 1 + len(allsecs) + 1
    for k, (n, t, f, b) in enumerate(entries):
        link = strtab_index if t == 2 else 0
        entsize = 24 if t == 2 else 0
        sh += struct.pack("<IIQQQQIIQQ", name_off[n], t, f, 0, offs[k], len(b), link, 0, 8, entsize)
    return hdr + body + sh


def insn(op, src=0, imm=0):
    return struct.pack("<BBhi", op, src << 4, 0, imm)


def self_test():
    ok_code = insn(OP_CALL, imm=69) + insn(OP_LD_IMM64) + insn(0) + insn(0xB7, imm=2) + insn(0x95)
    good = build_elf([(b"xdp", 1, 0x6, ok_code), (b"license", 1, 0x3, LICENSE)], [b"plat_xdp"])
    cases = [
        ("good object", good, 0),
        ("MIT-only licence", build_elf([(b"xdp", 1, 0x6, ok_code), (b"license", 1, 0x3, b"MIT\x00")]), 1),
        ("no licence", build_elf([(b"xdp", 1, 0x6, ok_code)]), 1),
        ("bpf_trace_printk", build_elf([(b"xdp", 1, 0x6, insn(OP_CALL, imm=6)), (b"license", 1, 0x3, LICENSE)]), 1),
        (
            "bpf_map_update_elem",
            build_elf([(b"xdp", 1, 0x6, insn(OP_CALL, imm=2)), (b"license", 1, 0x3, LICENSE)]),
            1,
        ),
        (
            "bpf_map_delete_elem",
            build_elf([(b"xdp", 1, 0x6, insn(OP_CALL, imm=3)), (b"license", 1, 0x3, LICENSE)]),
            1,
        ),
        ("kfunc", build_elf([(b"xdp", 1, 0x6, insn(OP_CALL, src=2, imm=6)), (b"license", 1, 0x3, LICENSE)]), 1),
        (
            "aya-log symbol",
            build_elf([(b"xdp", 1, 0x6, ok_code), (b"license", 1, 0x3, LICENSE)], [b"AYA_LOGS"]),
            1,
        ),
        (
            "helper id in ld_imm64 upper half is not a call",
            build_elf(
                [(b"xdp", 1, 0x6, insn(OP_LD_IMM64) + insn(OP_CALL, imm=6) + insn(0x95)), (b"license", 1, 0x3, LICENSE)]
            ),
            0,
        ),
        (
            "non-executable data is not scanned",
            build_elf([(b"xdp", 1, 0x6, ok_code), (b".rodata", 1, 0x2, insn(OP_CALL, imm=6)), (b"license", 1, 0x3, LICENSE)]),
            0,
        ),
    ]
    failed = 0
    for label, data, want in cases:
        got = 1 if check(data) else 0
        status = "ok" if got == want else "FAIL"
        failed += got != want
        print(f"check-object self-test: {status}: {label}")
    try:
        check(b"\x7fELF" + bytes(60))
        print("check-object self-test: FAIL: non-BPF ELF accepted")
        failed += 1
    except NotBpf:
        print("check-object self-test: ok: non-BPF ELF rejected")
    return 1 if failed else 0


def main(argv):
    if len(argv) != 2:
        print("usage: check-object.py OBJECT | --self-test", file=sys.stderr)
        return 2
    if argv[1] == "--self-test":
        return self_test()
    try:
        with open(argv[1], "rb") as f:
            data = f.read()
        problems = check(data)
    except (OSError, NotBpf) as e:
        print(f"check-object: {argv[1]}: {e}", file=sys.stderr)
        return 2
    print(f"check-object: sha256 {hashlib.sha256(data).hexdigest()}  {argv[1]}")
    for p in problems:
        print(f"check-object: {p}", file=sys.stderr)
    if problems:
        return 1
    print("check-object: ok (Dual MIT/GPL, helpers on the allow-list, no aya-log)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
