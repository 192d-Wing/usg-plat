# Linux Verification Checklist

The deployment target is Linux (multiqueue TUN, systemd, nftables). The
development host is macOS, so the items below have **not been run**. Until
each item passes on a Linux host and the result is recorded here, the
matching controls in [`NIST_800-53_MAPPING.md`](NIST_800-53_MAPPING.md) stay
"Implemented (not tested on Linux)" or "Partial", and must not be presented
as tested ATO evidence.

Sources, in the 2026-10-28 initial-review run directory
(`target/agent-workflow/20261028-145332-initial-review/`):
`fixes-round-1-unit2.md` (U2-D row, PERF-009), `fixes-round-2-unit2.md`
(Linux verification checklist), and the security and NIST re-checks
(`recheck-security.md`, `recheck2-security.md`, `recheck-nist.md`,
`recheck2-nist.md`).

What was checked on macOS instead: `sh -n` and `shellcheck` on
`deploy/systemd/plat-tun-setup.sh`; a `dash` dry run of the script with
stubbed `ip`/`nft`/`sysctl` and the real `platd` (generated ruleset and
routes as expected; a route mismatch, a missing argument and an invalid
config each exit 1 before `sysctl`); `make check-linux` (clippy for
`aarch64-unknown-linux-gnu`); the audit disk-full scenarios on a 2 MiB HFS+
image.

## Summary

| ID | Check | Controls | POA&M | Result |
|----|-------|----------|-------|--------|
| L1 | `systemd-analyze verify` and `systemd-analyze security` on the unit | AC-6, CM-7, SC-39 | — | NOT RUN |
| L2 | No capabilities at run time; all TUN queues attach | AC-6 | POAM-006 | NOT RUN |
| L3 | Setup script refuses a foreign-owned or non-multiqueue TUN, and a host without `nft` | AC-6, CM-6 | — | NOT RUN |
| L4 | `ExecStartPre=+` script works despite the service sandbox | AC-6 | — | NOT RUN |
| L5 | Fresh-host setup: table, routes, forwarding; stale routes replaced | SC-7, CM-7, CM-6 | — | NOT RUN |
| L6 | Forward policy behaviour, including spoofed client sources | SC-7, SC-7(5), AC-4 | POAM-014 | NOT RUN |
| L7 | platd survives the system-call filter, with CPU pinning | SC-39, AC-6 | — | NOT RUN |
| L8 | Device policy and sandbox options leave `/dev/net/tun` usable | SC-39 | — | NOT RUN |
| L9 | `MemoryMax` / `TasksMax` adequate for the production config | SC-5, SC-39, CP-10 | POAM-021 | NOT RUN |
| L10 | Two-node cluster: each node routes only its own slice | SC-7, SC-5(2) | POAM-017 | NOT RUN |
| L11 | No other forward drop policy overrides ours; no conntrack loaded | SC-7, CM-7 | — | NOT RUN |
| L12 | Audit lifecycle on ext4/xfs, including `statvfs` under the sandbox and a power cut mid-rotation | AU-5, AU-5(1), AU-9, AU-11 | POAM-020 | NOT RUN |
| L13 | Log directory permissions and shipper access | AU-9, AC-6 | — | NOT RUN |
| L14 | Start waits for clock synchronisation | AU-8 | — | NOT RUN |
| L15 | nftables reload or flush (expected to fail today) | SC-7, CM-7, SC-24 | POAM-019 | NOT RUN |
| L16 | Crash and restart behaviour | CP-10, SC-24, AU-9 | POAM-009 | NOT RUN |
| L17 | TUN back-pressure is a counted drop, not a stall | SC-5, SI-4 | — | NOT RUN |

## Procedures and pass criteria

### L1 — unit analysis

- Run `systemd-analyze verify /etc/systemd/system/platd.service`: no errors.
- Run `systemd-analyze security platd`: record the exposure score and review
  every item not marked as protected.

### L2 — no capabilities (closes POAM-006 together with L1, L3, L4)

- Start the service with the shipped unit and config.
- `grep Cap /proc/$(pidof platd)/status`: `CapInh`, `CapPrm`, `CapEff`,
  `CapBnd` and `CapAmb` are all 0.
- The log shows `platd running` with the configured worker count, and every
  worker's queue is attached (traffic is received on each queue under load).

### L3 — TUN and tool checks

- With the TUN pre-created and owned by root (or another user): the setup
  script exits 1 and the service does not start.
- With a TUN created without `multi_queue`: the script exits 1.
- With the TUN absent: the script creates it owned by `plat:plat` with
  `IFF_MULTI_QUEUE` (`/sys/class/net/plat0/tun_flags` has 0x100).
- With `nft` not installed: the script exits 1.

### L4 — `ExecStartPre=+` outside the sandbox

- The setup script runs as root without the service sandbox, so `ip` and
  `nft` work even though `RestrictAddressFamilies` excludes AF_NETLINK for
  platd itself. The service starts.

### L5 — fresh-host setup

- On a fresh host: `plat-tun-setup.sh /etc/plat/platd.toml`.
- `nft list table inet plat` shows the `forward` chain with `policy drop`.
- `ip -4 route show dev plat0` lists only this node's pool slice
  (`platd check-config --format env`, `PLAT_OWNED_POOL`), and
  `ip -6 route show dev plat0` lists only the NAT64 prefix.
- `sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding` are both 1.
- A pre-existing `proto boot` whole-pool route on `plat0` is flushed and
  replaced by the node's slice.

### L6 — forward policy behaviour

- From a client: native IPv6 to a destination outside the NAT64 prefix is
  dropped (the drop counter in `nft list chain inet plat forward` increases).
- NAT64 traffic from clients and IPv4 return traffic to the pool pass.
- An ICMPv6 Packet Too Big from an access router (outside the client
  prefixes) reaches the TUN and is translated.
- Record the result of a packet with a client-prefix source arriving on a
  non-access interface (e.g. the upstream side). Expected today: accepted
  and attributed to that subscriber, because the policy has no reverse-path
  check (POAM-014). Confirm that the access edge enforces SAVI/uRPF.

### L7 — system-call filter

- With `SystemCallFilter=@system-service`, `~@privileged @resources` and
  `sched_setaffinity` re-added, and `dataplane.pin_cpus = true`: platd starts
  and is not killed or refused (`EPERM`) on `TUNSETIFF`, `poll`, socket calls
  for syslog and metrics, or affinity.
- `taskset -p <worker tid>` shows each worker pinned.

### L8 — device policy and sandbox

- With `DevicePolicy=closed`, `DeviceAllow=/dev/net/tun rw`, `ProtectClock`,
  `PrivateIPC`, `ProtectProc=invisible`: platd opens `/dev/net/tun` and
  attaches its queues.

### L9 — resource limits

- Under load at the production `nat64.max_sessions` and worker count,
  `systemctl show -p MemoryCurrent,TasksCurrent platd` stays below
  `MemoryMax` and `TasksMax`. Compare `MemoryMax` with the unit's formula
  (`max_sessions × 512 B + queue_capacity × 64 B + 256 MiB`).

### L10 — two-node cluster

- Two nodes with `cluster.node_count = 2`: each routes only its own `/25`
  of the example pool, and `check-config` slices are disjoint.
- Return traffic steered to the wrong node is dropped and counted as
  `wrong_node`.

### L11 — interaction with other rulesets

- No other ruleset (e.g. firewalld) drops in its own forward hook; nftables
  evaluates every base chain, so a drop there overrides our accepts.
- `lsmod | grep nf_conntrack` shows no conntrack loaded by our ruleset (it
  uses no `ct` expressions).

### L12 — audit lifecycle on ext4 / xfs

- On a small loop-mounted `/var/log/plat`: a full volume gives the same
  results as the HFS+ repro (degraded, new bindings refused, no rotation or
  pruning during the outage, recovery after free space returns, files
  verify).
- `min_free_bytes` triggers `audit_storage_threshold` `below_threshold`
  before ENOSPC.
- `statvfs` works under the unit's sandbox (`ProtectSystem=strict`,
  `ReadWritePaths=/var/log/plat`): no `unknown` state record at start-up.
- Power cut mid-rotation (`echo b > /proc/sysrq-trigger`): after reboot the
  start-up resumes from the newest file, sequence numbers are not reused,
  and `platd verify-log` on all files reports no broken link (rename plus
  directory `fsync` hold).

### L13 — log directory permissions

- `/var/log/plat` is mode 0700 (`LogsDirectoryMode=0700`), audit files are
  0640, owned by `plat`.
- The log shipper and `verify-log` operators have read access through an ACL
  (or root), not through the `plat` group.

### L14 — clock synchronisation

- With chrony or systemd-timesyncd enabled, platd starts only after
  `systemd-time-wait-sync.service` reports synchronisation
  (`systemctl list-dependencies platd`, start timestamps).

### L15 — nftables reload or flush (expected to fail today)

- Run `systemctl reload nftables` (or apply a ruleset that starts with
  `flush ruleset`).
- Pass criterion: `table inet plat` is restored, or forwarding is disabled.
- Expected today: the table is gone and forwarding stays enabled (POAM-019).
  Record the result.
- Also add a `proto static` route for the whole pool on `plat0` and re-run
  the setup script: expected today, it is neither removed nor reported.

### L16 — crash and restart

- `kill -9 $(pidof platd)`: systemd restarts the service after 2 s
  (`Restart=on-failure`); the new file continues the chain and sequence
  numbers (`verify-log` reports the crashed file's unverified tail only with
  `--allow-tail`, and no broken link); a `service_start` record follows
  without a `service_stop`; no rotated file is deleted.
- Repeat with the log volume unwritable: start-up exits non-zero and
  restarts do not consume retention.

### L17 — TUN back-pressure

- Saturate a TUN queue so `write` returns `EAGAIN`: the worker drops the
  packet immediately (no sleep) and `plat_tx_queue_full_total` increases,
  separately from `plat_io_errors_total`.
