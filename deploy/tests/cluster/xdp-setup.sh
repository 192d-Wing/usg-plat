#!/bin/sh
# Adds the XDP fast path (POAM-016 Phase 1) to the two nodes of the cluster
# test bed prepared by setup.sh (LINUX_VERIFICATION L30), from the host.
# Idempotent. Installs on plat-linux and plat-linux-2:
#   /usr/bin/platd (built with --features xdp, `make xdp`)
#   /usr/libexec/plat/plat-xdp-loader
#   /etc/systemd/system/{platd,plat-xdp}.service, run-plat-bpf.mount
#   /usr/lib/tmpfiles.d/plat-xdp.conf
#   /etc/systemd/system/platd.service.d/xdp.conf (the shipped drop-in)
#   /etc/systemd/system/plat-xdp.service.d/plat-test-overlay.conf (boot
#   ordering after the test overlay)
#   /etc/plat/platd.toml with [xdp] on plha0 (PLAT_XDP=1, lib.sh gen_config)
# and restarts platd; on plat-edge it installs the same /usr/bin/platd and
# restarts plat-witness (the witness must compute the same config digest as
# the nodes, so it runs the same release). Back up the VMs first: this
# replaces files that setup.sh installed.
#
# Usage: PLATD_BIN=<platd> PLAT_XDP_LOADER_BIN=<loader> deploy/tests/cluster/xdp-setup.sh
#        (aarch64 Linux binaries from `make xdp`)
set -eu
CASE=xdp-setup
PLAT_XDP=1
# shellcheck source=deploy/tests/cluster/lib.sh
. "$(dirname "$0")/lib.sh"

PLATD_BIN=${PLATD_BIN:-$ROOT/target/aarch64-unknown-linux-gnu/release/platd}
LOADER_BIN=${PLAT_XDP_LOADER_BIN:-$ROOT/target/aarch64-unknown-linux-gnu/release/plat-xdp-loader}
for f in "$PLATD_BIN" "$LOADER_BIN"; do
    [ -x "$f" ] || { echo "xdp-setup: no binary at $f (set PLATD_BIN / PLAT_XDP_LOADER_BIN)" >&2; exit 2; }
done
for v in "$A" "$B" "$E"; do vm_up "$v" || { echo "xdp-setup: VM $v is not running" >&2; exit 2; }; done

for v in "$A" "$B"; do
    vm "$v" "uname -r | awk -F. '{ exit !(\$1 > 6 || (\$1 == 6 && \$2 >= 6)) }'" ||
        { echo "xdp-setup: $v runs a kernel older than 6.6" >&2; exit 2; }
    limactl copy "$PLATD_BIN" "$v:/tmp/platd"
    limactl copy "$LOADER_BIN" "$v:/tmp/plat-xdp-loader"
    for u in platd.service plat-xdp.service run-plat-bpf.mount plat-xdp.tmpfiles.conf platd.service.d.example/xdp.conf; do
        limactl copy "$ROOT/deploy/systemd/$u" "$v:/tmp/$(basename "$u")"
    done
    vm "$v" "set -e
systemctl stop platd 2>/dev/null || true
install -m 0755 /tmp/platd /usr/bin/platd
install -D -m 0755 /tmp/plat-xdp-loader /usr/libexec/plat/plat-xdp-loader
install -m 0644 /tmp/platd.service /tmp/plat-xdp.service /tmp/run-plat-bpf.mount /etc/systemd/system/
install -D -m 0644 /tmp/plat-xdp.tmpfiles.conf /usr/lib/tmpfiles.d/plat-xdp.conf
install -D -m 0644 /tmp/xdp.conf /etc/systemd/system/platd.service.d/xdp.conf
rm -f /tmp/platd /tmp/plat-xdp-loader /tmp/platd.service /tmp/plat-xdp.service /tmp/run-plat-bpf.mount /tmp/plat-xdp.tmpfiles.conf /tmp/xdp.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/plat-xdp.conf
# Test bed only: plha0 comes from plat-overlay.service, which orders itself
# before platd but not before the loader.
install -d /etc/systemd/system/plat-xdp.service.d
printf '[Unit]\\nAfter=plat-overlay.service\\n' >/etc/systemd/system/plat-xdp.service.d/plat-test-overlay.conf
systemctl daemon-reload"
done
limactl copy "$PLATD_BIN" "$E:/tmp/platd"
vm "$E" "install -m 0755 /tmp/platd /usr/bin/platd && rm -f /tmp/platd && systemctl restart plat-witness"
restore_configs
for v in "$A" "$B"; do
    vm "$v" "platd check-config --config /etc/plat/platd.toml >/dev/null" || { echo "xdp-setup: check-config failed on $v" >&2; exit 1; }
    vm "$v" "systemctl restart platd"
done
ensure_cluster
for v in "$A" "$B"; do
    wait_until 30000 metric_eq "$v" plat_xdp_enabled 1 >/dev/null || fail "$v: fast path not enabled"
done
info "XDP test bed ready: A=$(active_slices "$A") B=$(active_slices "$B") active slices, fast path on both"
finish
