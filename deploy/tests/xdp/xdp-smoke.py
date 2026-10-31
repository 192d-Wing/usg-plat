#!/usr/bin/env python3
"""Kernel smoke test for the XDP matrix (plan §3 WU7 criterion 6).

Runs in the virtme-ng guest as root, before the plat-xdp crates exist: loads
two tiny hand-assembled XDP programs with bpf(BPF_PROG_LOAD) and runs each with
bpf(BPF_PROG_TEST_RUN) in non-live mode, asserting XDP_PASS and an unmodified
frame. This proves that the kernel under test has the BPF syscall, the XDP
program type, the verifier, BPF_PROG_TEST_RUN for XDP and the
bpf_ktime_get_coarse_ns helper that the fast path relies on.

Usage: python3 -I xdp-smoke.py      Exit: 0 ok, 1 failure, 2 unsupported host.
"""

import ctypes
import os
import platform
import struct
import sys

SYS_BPF = {"x86_64": 321, "aarch64": 280}

BPF_PROG_LOAD = 5
BPF_PROG_TEST_RUN = 10
BPF_PROG_TYPE_XDP = 6
XDP_PASS = 2
HELPER_KTIME_GET_COARSE_NS = 160  # include/uapi/linux/bpf.h, v5.11+
ATTR_SIZE = 128  # covers every field used below; the rest stays zero


def insn(op, dst=0, src=0, off=0, imm=0):
    """One eBPF instruction (little-endian)."""
    return struct.pack("<BBhi", op, (src << 4) | dst, off, imm)


MOV64_IMM = 0xB7
CALL = 0x85
EXIT = 0x95

PROGRAMS = {
    "pass": insn(MOV64_IMM, dst=0, imm=XDP_PASS) + insn(EXIT),
    "coarse_clock": insn(CALL, imm=HELPER_KTIME_GET_COARSE_NS)
    + insn(MOV64_IMM, dst=0, imm=XDP_PASS)
    + insn(EXIT),
}


def main():
    nr = SYS_BPF.get(platform.machine())
    if nr is None:
        print(f"xdp-smoke: unsupported machine {platform.machine()}", file=sys.stderr)
        return 2
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def bpf(cmd, attr):
        ret = libc.syscall(
            ctypes.c_long(nr),
            ctypes.c_long(cmd),
            ctypes.c_void_p(ctypes.addressof(attr)),
            ctypes.c_long(ATTR_SIZE),
        )
        if ret < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return ret

    print(f"xdp-smoke: kernel {platform.release()} ({platform.machine()})")
    license_buf = ctypes.create_string_buffer(b"Dual MIT/GPL")
    log_buf = ctypes.create_string_buffer(1 << 16)
    # A 64-byte frame: broadcast destination, locally administered source,
    # ethertype 0x88B5 (IEEE local experimental), zero payload.
    frame = bytes.fromhex("ffffffffffff" "020000000001" "88b5") + bytes(50)

    for name, code in PROGRAMS.items():
        insns = ctypes.create_string_buffer(code, len(code))
        attr = ctypes.create_string_buffer(ATTR_SIZE)
        struct.pack_into(
            "<IIQQIIQ",
            attr,
            0,
            BPF_PROG_TYPE_XDP,
            len(code) // 8,
            ctypes.addressof(insns),
            ctypes.addressof(license_buf),
            1,  # log_level
            len(log_buf),
            ctypes.addressof(log_buf),
        )
        struct.pack_into("16s", attr, 48, f"plat_{name}"[:15].encode())
        try:
            fd = bpf(BPF_PROG_LOAD, attr)
        except OSError as e:
            print(f"xdp-smoke: {name}: BPF_PROG_LOAD failed: {e}", file=sys.stderr)
            print(log_buf.value.decode(errors="replace"), file=sys.stderr)
            return 1
        try:
            data_in = ctypes.create_string_buffer(frame, len(frame))
            data_out = ctypes.create_string_buffer(256)
            attr = ctypes.create_string_buffer(ATTR_SIZE)
            struct.pack_into(
                "<IIIIQQI",
                attr,
                0,
                fd,
                0,  # retval (out)
                len(frame),
                len(data_out),
                ctypes.addressof(data_in),
                ctypes.addressof(data_out),
                1,  # repeat
            )
            bpf(BPF_PROG_TEST_RUN, attr)
            (retval,) = struct.unpack_from("<I", attr, 4)
            (size_out,) = struct.unpack_from("<I", attr, 12)
        except OSError as e:
            print(f"xdp-smoke: {name}: BPF_PROG_TEST_RUN failed: {e}", file=sys.stderr)
            return 1
        finally:
            os.close(fd)
        out = data_out.raw[:size_out]
        if retval != XDP_PASS or out != frame:
            print(
                f"xdp-smoke: {name}: retval={retval} (want {XDP_PASS}), "
                f"unmodified={out == frame}, size_out={size_out}",
                file=sys.stderr,
            )
            return 1
        print(f"xdp-smoke: {name}: load + test_run ok (XDP_PASS, frame unmodified)")
    print("xdp-smoke: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
