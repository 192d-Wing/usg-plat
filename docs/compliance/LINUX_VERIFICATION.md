# Linux Verification Checklist

The deployment target is Linux (multiqueue TUN, systemd, nftables). The
development host is macOS, so these items were run separately on a Linux
host. The results below are the recorded results; an item marked PARTIAL,
or FAIL must not be presented as passed ATO evidence, and
the matching controls in [`NIST_800-53_MAPPING.md`](NIST_800-53_MAPPING.md)
cite exactly what passed.

## Test environment and evidence

- Host: Lima VM `plat-linux`, Ubuntu 24.04.5 LTS aarch64, kernel
  6.8.0-142-generic, systemd 255 (255.4-1ubuntu8.17), 6 vCPU, 8 GiB, root
  file system ext4; extra packages nftables, chrony (replaces
  systemd-timesyncd), xfsprogs, tcpdump, socat, python3-scapy, shellcheck
  0.9.0.
- Dates: 2026-10-28/29 (run 1), 2026-10-29 (runs 2–5).
- Source: run 1 used `main` @ `2e0c6aa`. Runs 2–4 used the working tree of
  branch `fix/linux-validation` (base `cd9f066`, uncommitted, copied into the
  VM without `.git`) at fix rounds 2, 3, 6 and 7 respectively (runs 4 and 5 targeted L5, L12, L13, L15). The installed
  files were `cmp`-identical to that tree and installed per `README.md`;
  nothing was patched (run 1 patched the setup script, see below).
- Config: `config/platd.example.toml` with the syslog destination changed to
  `127.0.0.1:5514`; L9, L10 and L12 used temporary variants (noted per item).
- Topology: netns `cli` (2001:db8:100::2) as IPv6 client, netns `inet`
  (45.0.0.2, 2001:db8:200::2) as the Internet.
- Raw run records (not in the repository):
  `target/agent-workflow/linux-fix/results.md` (run 1), `results-run2.md`,
  `results-run3.md`, `results-run4.md`, `results-run5.md`.
- Workspace tests in the VM: run 4, `cargo test --workspace` twice, 378
  passed, 0 failed, 0 ignored; `CI=true make test-deploy` rc 0 with
  shellcheck (runs 4 and 5).

Run 1 found the shipped setup script failing on every start (it rejected the
`PLAT_FIPS` / `PLAT_MGMT_TLS` keys of `check-config --format env`); that and
the other run-1/run-2 failures were fixed on `fix/linux-validation`
(CHANGELOG, Unreleased). Results below are from the latest run that covered
each item.

## Summary

| ID | Check | Controls | POA&M | Result (2026-10-29) |
|----|-------|----------|-------|--------|
| L1 | `systemd-analyze verify` and `security` on the units | AC-6, CM-7, SC-39 | POAM-006 | PASS (run 3): verify clean; `platd` 1.5 OK, `plat-fwguard` 2.1 OK |
| L2 | No capabilities at run time; all TUN queues attach | AC-6 | POAM-006 | PASS (run 3) |
| L3 | Setup script refuses a foreign-owned or non-multiqueue TUN, and a host without `nft` | AC-6, CM-6 | POAM-006 | PASS (run 2, shipped script) |
| L4 | `ExecStartPre=+` script works despite the service sandbox | AC-6 | POAM-006 | PASS (run 3) |
| L5 | Fresh-host setup: table, routes, forwarding; stale routes replaced | SC-7, CM-7, CM-6 | — | PASS (run 5, README install verbatim on a torn-down host) |
| L6 | Forward policy behaviour, including spoofed client sources | SC-7, SC-7(5), AC-4 | POAM-014 | PASS (run 2); spoofed source accepted as expected (POAM-014) |
| L7 | platd survives the system-call filter, with CPU pinning | SC-39, AC-6 | — | PASS (run 2) |
| L8 | Device policy and sandbox options leave `/dev/net/tun` usable | SC-39 | — | PASS (run 2) |
| L9 | `MemoryMax` / `TasksMax` adequate for the production config | SC-5, SC-39, CP-10 | POAM-021 | PASS (run 2); formula ~14 % conservative |
| L10 | Two-node cluster: each node routes only its own slice | SC-7, SC-5(2) | POAM-017 | PASS (emulated: two netns on one host, not a real two-node cluster; run 2). Legacy `contiguous` mode only; the real multi-VM cluster test is L19–L23 (not yet run) |
| L11 | No other forward drop policy overrides ours; no conntrack from our ruleset | SC-7, CM-7 | — | PASS with note (run 2) |
| L12 | Audit lifecycle on ext4/xfs, `statvfs` under the sandbox, power cut, damaged start | AU-5, AU-5(1), AU-9, AU-11 | POAM-020, POAM-027 | PASS (run 4); by-design residual POAM-027 |
| L13 | Log directory permissions and shipper access | AU-9, AC-6 | — | PASS (runs 3 and 4) |
| L14 | Start waits for clock synchronisation | AU-8 | — | PASS (run 2, chrony + `chrony-wait`) |
| L15 | nftables reload or flush; forward-policy guard | SC-7, CM-7, SC-24 | POAM-019 | PASS with measured residual (runs 3 and 4) |
| L16 | Crash and restart behaviour; start limit | CP-10, SC-24, AU-9 | POAM-009 | PASS (run 3) |
| L17 | TUN back-pressure is counted, not a stall | SC-5, SI-4 | — | PARTIAL (run 2): kernel drops exported; `tx_queue_full` path unexercised |
| L18 | `.deb` and `.rpm` install, upgrade and removal | CM-2, CM-6, AC-6, AU-9 | — | NOT RUN |
| L19 | Cluster HA failover: node crash, VM loss, hook failure (F1, F2, F11) | CP-10, SC-5(2), AU-12, SC-24 | POAM-007, POAM-028 | PASS (three-VM run, round 6 build, 2026-10-29; `target/agent-workflow/cluster-ha/three-vm-report.md` (round 6)). F1 `kill -9`: takeover 3830 ms, TCP 200/200, 10 acquire(takeover) + 8 adopt, 0 attribution violations over 219k packets; F2 VM loss: takeover 3433 ms, TCP 200/200, 231k packets 0 violations; F11 hook failure/timeout PASS. Leader crash: 5 round-6 trials poll median 3748 ms, max 3950 ms (27 trials over rounds 2-6, max 4508 ms, all <= 5 s). Crash route cleanup (`deploy/tests/cluster/route-check.sh`): after `kill -9` the dead node withdraws its IPv4 slices and the IPv6 prefix, and a restarted standby announces nothing until it owns a slice |
| L20 | Cluster HA split brain: peer-link partition, isolation, witness down, clock step (F3, F4, F9, F10) | SC-24, CP-10, AU-10 | POAM-007 | PASS (three-VM run, round 6). F3 partition (one view, no dual-active slice, 176k packets 0 violations), F4 isolation (fenced 1959 ms, B active 1315 ms, 10 withdraw hooks, no packets from A after fence), F9 witness down after the F8 load (TCP 200/200, max gap 115 ms, no takeover without quorum), F10 clock step: all PASS |
| L21 | Cluster HA rejoin, failback and growth (F5, F12) | CP-10, AU-12 | POAM-017(a), POAM-030 | PARTIAL (three-VM run, round 6). F5: A in sync after 833 ms, failback 63.2 s after rejoin, 8 release(handover) records, no `missteered` drops on the standby before failback, UDP max gap 50 ms; but 1/200 TCP flows lost and one flow gapped 26.8 s: the planned handover drops TCP state on the new owner (316 `tcp_no_state` on A in the minute after failback; sessions not replicated, POAM-007(1)/POAM-028). F12 grow: B serves 6/16 after 64.5 s, 6 handed over (6 in flight is the documented deviation POAM-017(a)), TCP 184/200 (92 %) for the same reason |
| L22 | Cluster HA identity and config digest: duplicate id, digest mismatch (F6, F7) | IA-3, CM-6, AC-3 | POAM-017(c), POAM-032 | PASS (three-VM run, round 6). F6 impostor refused `duplicate_id` (witness), serves no slice; F7 digest mismatch refused and audited, no replication, `service_start` digests differ |
| L23 | Cluster HA replication back-pressure and mis-steer (F8, F13) | SC-5, SI-4, SC-7 | POAM-017(b), POAM-029 | PASS (three-VM run, round 6). F8: worker rate within noise (3596 vs 3533 pps), no replication loss, B in sync. F13 fresh /64 (2001:db8:100:336b::/64): mis-steer counted and dropped (13), no block on the non-home node, in steady state and after a platd restart of that node |
| L24 | Multiqueue TUN keeps every fragment of a datagram on one queue (Q2) | SC-5(2), SC-5 | POAM-035 | PASS (2026-10-29, performance review of `feat/protocol-completeness`): 0/64 IPv4 and 0/64 IPv6 datagrams split across 4 queues |
| L25 | Pool-source guard rule and `cross_node_hairpin` start gate on real nftables | SC-7, SC-7(5), AC-4, CM-6 | POAM-024 | PASS (2026-10-29, kernel 6.8, nftables 1.0.9, three network namespaces): pool sources dropped from the external interface in both modes, accepted from the cluster interface only with the switch on; gate passes on real `nft list` output, refuses 4 broken snapshots |

## Procedures, pass criteria and results

### L1 — unit analysis

- `cd /etc/systemd/system; systemd-analyze verify platd.service
  plat-fwguard.service plat-fwguard.timer`: no output.
- `systemd-analyze security platd.service` and `plat-fwguard.service`:
  record the score and review every item not marked as protected.

Result: PASS (run 3). Verify: no output, rc 0. `platd.service` 1.5 OK
(remaining: `~@resources`, `RootDirectory`, `PrivateDevices`, AF_UNIX/AF_INET,
`PrivateNetwork`, `PrivateUsers`, `DeviceAllow`, `IPAddressDeny`, `UMask`).
`plat-fwguard.service` 2.1 OK (run 2: 8.7 EXPOSED before hardening;
`ProtectKernelTunables` deliberately unset because the guard writes
`/proc/sys/net`). The hardened guard writes the sysctls and uses netlink
under `CapabilityBoundingSet=CAP_NET_ADMIN`; no EACCES/EPERM.

### L2 — no capabilities (closes POAM-006 together with L1, L3, L4)

- Start the service with the shipped unit and config.
- `grep Cap /proc/$(pidof platd)/status`: all of `CapInh`, `CapPrm`,
  `CapEff`, `CapBnd`, `CapAmb` are 0.
- Every worker's queue is attached (traffic on each queue under load).

Result: PASS (run 3). All capability sets 0; `plat0` `multi_queue
numqueues 5`, owner `plat:plat`; raw UDP flood: `plat_worker_rx_packets_total`
w0..w4 between 484 206 and 589 020.

### L3 — TUN and tool checks

- TUN pre-created owned by root (or unowned): script exits 1, service does
  not start. TUN without `multi_queue`: exits 1. TUN absent: created owned by
  `plat:plat` with `IFF_MULTI_QUEUE`. `nft` not installed: exits 1.

Result: PASS (run 2, shipped script). Unowned and root-owned TUN: `plat0 is
owned by ...`, rc 1; non-MQ: `tun_flags 0x1801`, rc 1; absent: created
999:988, `tun_flags 0x1901`; without `/usr/sbin/nft`: rc 1. Not repeated in
run 3 (no change to these checks since).

### L4 — `ExecStartPre=+` outside the sandbox

- The setup script runs as root without the service sandbox (`ip`, `nft`,
  `systemd-tmpfiles` work although platd has no AF_NETLINK). The service
  starts. The script parses `check-config --format env` strictly: every line
  must be `PLAT_*=`; unused keys are ignored. Test hooks in the environment
  are honoured only with `PLAT_TEST_MODE=1`.

Result: PASS (run 3). Policy, routes and tmpfiles applied; platd has no
capabilities. Hooks `PLAT_NFT_CONF`, `PLAT_NFT_RULES`, `PLAT_LOG_DIR`,
`PLATD` set without `PLAT_TEST_MODE` were ignored by both scripts. The
parser is covered in CI by `make test-deploy` (with shellcheck,
`deploy/tests/deploy-scripts-test.sh`, real `platd check-config` output).

### L5 — fresh-host setup

- Fresh host, install exactly as `README.md` (creates `plat`, `plat-log`, runs
  `systemd-tmpfiles --create /usr/lib/tmpfiles.d/plat.conf` before the first
  start), `systemctl enable --now platd`.
- `nft list table inet plat`: `forward` chain `policy drop`;
  `/etc/nftables.d/plat.nft` written; `/etc/nftables.conf` holds exactly one
  `include "/etc/nftables.d/*.nft"` (an older exact
  `include "/etc/nftables.d/plat.nft"` is replaced).
- Routes on `plat0`: only this node's slice and the NAT64 prefix; a
  pre-existing route of any protocol (`proto boot`, `proto static`) is
  removed. Forwarding sysctls are 1.

Result: PASS (run 5, 2026-10-29). Fresh-host simulation (units, binary,
scripts, tmpfiles entry, include line, `/etc/plat`, `/var/log/plat`, user
`plat` and group `plat-log` all removed), then the README install steps
executed verbatim: config `root:plat 0640`, `/var/log/plat`
`drwxr-s--- plat:plat-log`, only this node's slice and the NAT64 prefix
routed, forwarding 1/1, exactly one glob include, `plat-fwguard.timer`
active; no edit of the example config was needed. Stale `proto boot` and
`proto static` routes removed (run 3). History: run 3 failed with
`226/NAMESPACE` (no `/var/log/plat`; `ReadWritePaths=` is resolved before
`ExecStartPre=`), fixed by the `systemd-tmpfiles --create` step; run 4
failed because the README installed the config `root:root` before `plat`
existed (`Permission denied`), fixed by installing it after user/group
creation with `-o root -g plat`. `make test-deploy` checks both orders.

### L6 — forward policy behaviour

- Native IPv6 to a destination outside the NAT64 prefix is dropped (counter
  in `nft list chain inet plat forward`); NAT64 traffic and IPv4 return pass;
  an ICMPv6 Packet Too Big from an access router is translated.
- Record the result for a client-prefix source arriving on a non-access
  interface (expected: accepted, POAM-014).

Result: PASS (run 2). Native IPv6 dropped (counter 2); NAT64 ping/UDP pass;
PTB (mtu 1280) translated to `need to frag (mtu 1260)`. Spoofed
`2001:db8:100::99` injected upstream: accepted and attributed, as expected
under POAM-014. SAVI/uRPF at the access edge cannot be shown in this lab.

### L7 — system-call filter

- With the shipped filter and `dataplane.pin_cpus = true`: platd starts, no
  seccomp kill or `EPERM`; `taskset -p` shows each worker pinned.

Result: PASS (run 2). Workers pinned to 1, 2, 4, 8, 10 (masks); no
seccomp/EPERM entries in the journal.

### L8 — device policy and sandbox

- `DevicePolicy=closed`, `DeviceAllow=/dev/net/tun rw`, `ProtectClock`,
  `PrivateIPC`, `ProtectProc=invisible`, `ProcSubset=pid`: platd opens
  `/dev/net/tun` and attaches its queues.

Result: PASS (run 2). 5 queues attached, traffic flows.

### L9 — resource limits

- Under load at the production `nat64.max_sessions` and worker count,
  `MemoryCurrent` / `TasksCurrent` stay below `MemoryMax` / `TasksMax`.
  Compare with the unit's formula
  (`max_sessions × 800 B + queue_capacity × 64 B + 256 MiB`).

Result: PASS (run 2). 4 M sessions configured, 5 workers, queue 1 048 576:
3 916 464 sessions, `MemoryCurrent` 3 046 731 776 B (about 780 B/session),
`TasksCurrent` 11 (limits 8G / 1024). The formula gives 3.47 GB at that
count, about 14 % above the measurement. `MemoryMax=8G` equalled the VM's
RAM, so it was not a backstop on this host (POAM-021).

Since `fix/poam-021` (not yet re-run on Linux): `platd run` reads its cgroup
v2 `memory.max` and RAM and refuses to start when the configured requirement
(formula above plus fragment and HA ring memory) exceeds `memory.max` or 90 %
of RAM. Re-run check: with `MemoryMax=1G` and the example config the start
fails with a `memory.max` error; with 8G it starts and logs `memory sizing OK`.

### L10 — two-node cluster

- Two nodes with `cluster.node_count = 2`: each routes only its own `/25` of
  the example pool; `check-config` slices are disjoint; return traffic
  steered to the wrong node is dropped and counted as `wrong_node`.

Result: PASS, **emulated**: two netns (`n0`, `n1`) on one host, each with its
own TUN and platd (run outside systemd), not a real two-node cluster.
Slices `192.0.2.0/25` / `192.0.2.128/25`, routes match; 5 packets steered to
the wrong node counted `wrong_node 5` on n0, 0 on n1 (locally generated
packets were used because the forward policy correctly drops forwarded
traffic for another node's slice first).

### L11 — interaction with other rulesets

- No other ruleset drops in its own forward hook; our table uses no `ct`
  expressions.

Result: PASS with note (run 2). Only Lima's `table ip nat` besides ours;
firewalld absent, ufw inactive; `nft list table inet plat | grep -c " ct "`
= 0. `nf_conntrack` is loaded by Lima's iptables-nft NAT, not by our
ruleset, so "no conntrack loaded" cannot be shown on this host. Ubuntu's
default `/etc/nftables.conf` adds `table inet filter` (forward `policy
accept`; harmless).

### L12 — audit lifecycle on ext4 / xfs

Run with platd stopped between edits; `L=/var/log/plat`.

1. Threshold and `statvfs` (small loop-mounted ext4 and xfs): no `unknown`
   record at start under the sandbox; below `min_free_bytes` →
   `audit_storage_threshold` `below_threshold`, `/healthz` 503; freed →
   `recovered`.
2. ENOSPC: degraded, new bindings refused, no rotation or pruning during the
   outage; the failed file is cut back to its last checkpoint (ends in `\n`);
   after recovery, strict `platd verify-log $L/nat64-audit.jsonl*` exits 0
   with `OK: accounted gap: N..=M (K lost, audit_output_failure ...)`.
   Editing `lost` in a copy makes verification fail.
3. Rotation bound: no file exceeds `max_bytes` (except the documented
   post-outage recovery batch).
4. Power cut under load (`echo b > /proc/sysrq-trigger`): strict verify exits
   0 before and after the restart; no sequence number reused.
5. Damaged newest file (truncated tail, emptied file, both stacked): start
   writes `audit_recovery` (`truncated_tail` / `empty_file` /
   `missing_header`, `last_checkpoint_seq`, `max_seq`, `lease_state`) and
   resumes above the `.nat64-audit.jsonl.seq` lease; no number is reused.
   `verify-log` prints `RECOVERY GAP N..=M (...)` and exits **3**
   (`--allow-gap` does not cover it; `--allow-recovery` → `WARNING: ...`,
   exit 0); a partial line also needs `--allow-tail`; anything unexplained
   exits 1.
6. Lease file: `-rw-r----- plat:plat-log`, rewritten about once per 2^20
   records. A FIFO, symlink or garbage lease → `lease_state` `corrupt`, no
   hang; `18446744073709551615` → `inflated`, ignored, no wrap; a lease above
   `max_seq + 2^20` → used, `lease_state` `high`. A directory in its place →
   `plat_audit_seq_lease_failures_total` rises, exactly one
   `audit_output_failure` `plat.reason` `seq_lease_failed`.

Result: **PASS (run 4)**, ext4 and xfs.

- ENOSPC: strict exit 0 with an accounted gap; a tampered `lost` count fails.
  Power cut under load: strict exit 0, no reuse.
- `truncated_tail`: strict exit 1, 3 with `--allow-tail`, 0 with
  `--allow-tail --allow-recovery`. `empty_file`: 3, 0 with
  `--allow-recovery`. Double damage: 3 / 0, `lease_state` `high`, no
  sequence reuse.
- Lease `absent`, `corrupt` (FIFO, symlink: no hang), `high`, `inflated`
  (`u64::MAX`: ignored, no wrap) recorded as specified.
- By-design residual (POAM-027): with the lease `absent`, `corrupt` or
  `inflated`, numbers that were in an emptied live file can be reused
  locally; this is visible only through `lease_state` and duplicates in the
  remote copy.

Earlier run 3 (round 3 code), for history:

- PASS in run 3 (ext4 and xfs): items 1 and 2 (strict verify rc 0, ext4
  `OK: accounted gap: 114..=168 (55 lost ...)`, xfs `122..=174 (53 lost)`;
  tampered `lost` → batch hash mismatch, rc 1); item 3 (640 files, largest
  1 048 426 B with `max_bytes` 1 MiB); item 4 (live file ends in `\n`, strict
  verify rc 0 before and after start, `prev_seq 1698908 → next_seq
  1698909`); single truncated tail and isolated emptied file (accounted,
  0 duplicate sequence numbers); lease file mode/group and update rate.
- FAILED in run 3: stacked damage (truncated tail, then the file holding its
  `audit_recovery` emptied) → `verify-log --allow-tail` rc 1. Round 5 accepts
  this sequence as a recovery gap (exit 3); round 4 introduced exit 3 for
  every `audit_recovery` gap; round 6 changed the lease policy so numbers are
  never reused (`high`). Unit tests cover these
  (`verify.rs`, `logger.rs::tests::inflated_lease_is_ignored_and_recorded`,
  `startup_with_an_empty_newest_file_records_audit_recovery`,
  `lease_must_be_a_regular_file`, `lease_write_failure_is_audited_once_and_retried`;
  `services/platd/src/main.rs::tests::verify_log_recovery_gap_has_its_own_exit_code`,
  `verify_log_accepts_an_emptied_truncated_tail_recovery_file`), but not on
  Linux yet.

### L13 — log directory permissions

- After every start and reboot `/var/log/plat` is `drwxr-s--- plat:plat-log`
  (from `/usr/lib/tmpfiles.d/plat.conf`; the unit has no `LogsDirectory=` and
  no ACLs are used); audit files and `.nat64-audit.jsonl.seq` are
  `-rw-r----- plat:plat-log`.
- A member of `plat-log` (not of `plat`) can list the directory and run
  `platd verify-log`.
- Rotated files and subdirectories owned by `plat` are re-grouped; a hard
  link planted in the directory is not.

Result: PASS (run 3; regression re-run PASS in run 4). Mode and group held after 3 restarts and 2 reboots
(the second with platd disabled: created at boot by
`systemd-tmpfiles-setup`); user `shipper` (groups `shipper`, `plat-log`)
listed the directory and `verify-log` exited 0 every time. Planted
subdirectory and rotated file re-grouped; a hard link to `/etc/hostname`
kept its group.

### L14 — clock synchronisation

- The unit has `Wants=`/`After=time-sync.target` only. Enable the time
  daemon's wait unit: `chrony-wait.service` (chrony) or
  `systemd-time-wait-sync.service` (systemd-timesyncd). platd starts after it.

Result: PASS (run 2) with chrony and `chrony-wait.service`: 3 reboots, platd
started each time about 0.1 s after `chrony-wait` finished. Run 1 showed
`systemd-time-wait-sync` can wait indefinitely under chrony (platd did not
start in 2 of 3 boots); that unit is no longer pulled in. Not tested: the
systemd-timesyncd path, and boot with a clock that never synchronises
(`chrony-wait` times out after 180 s and platd then starts: ordering only,
availability over strict AU-8).

### L15 — nftables reload or flush; forward-policy guard

- The policy is in `/etc/nftables.d/plat.nft`, included by the glob, so
  `systemctl reload|restart nftables` restores it.
- `plat-fwguard.sh` (timer every 2 s, `AccuracySec=100ms`, enabled on its
  own; also run synchronously by the `nftables.service` drop-in on start,
  reload and stop) compares the live table with
  `/etc/nftables.d/plat.nft.expected` and turns IPv4/IPv6 forwarding off when
  the table is missing or differs (`missing-table`, `policy-modified`,
  `forward-not-default-drop`), logging an error to the journal.
- Run native IPv6 from the client during the test; record any packet that
  reaches the Internet side.

Result: PASS with the measured POAM-019 residual (run 3; run 4 regression: `nft flush ruleset` → forwarding off in 1.70 s, within the 2 s timer tick).

- `systemctl restart nftables` with the include: table restored, forwarding
  stays on, no trip.
- Include removed, then `systemctl reload|restart|stop nftables`, or
  `plat.nft` moved away and restart: forwarding 0/0 immediately after the
  job returns (guard ran inside `nftables.service`).
- Direct `nft` changes, time to `ip_forward=0` (run 3): `flush ruleset` 0.51 s,
  inserted accept rule 0.49 s, `policy accept` 0.47 s, `delete table`
  0.37 s. With platd stopped (timer alone): 1.58 s.
- 30 s of traffic: no false trip from counter changes.
- **Residual**: 9 native IPv6 echo requests reached the Internet side, 5
  during the `flush ruleset` window and 4 during the `delete table` window
  (table gone, forwarding still on until the guard tick). None during the
  service actions, rule/policy edits or the traffic phase. POAM-019.
- Guard trips are journal-only (no audit record): ship the journal
  (`SIEM_LOGGING.md`).

### L16 — crash and restart

- `kill -9 $(pidof platd)`: restart after 2 s; the new file continues the
  chain (`audit_chain_continue`), no rotated file deleted, strict
  `verify-log` exits 0.
- With `/var/log/plat` immutable: each start fails (in the setup script);
  after 5 failed starts in 60 s (`StartLimitIntervalSec=60`,
  `StartLimitBurst=5`) the unit is `failed`; `systemctl reset-failed platd`
  after fixing the cause. Manual restarts count toward the same limit.

Result: PASS (run 3). Restart 2 s after `status=9/KILL`, `prev_seq 8639 →
next_seq 8640`, files 25 → 26, strict verify rc 0. Immutable directory: 5
failures (`chgrp ... Operation not permitted`), then `Start request repeated
too quickly`, unit failed, file count unchanged; recovered after `chattr -i`
and `reset-failed`. A burst of manual restarts before the crash also hit the
limit after a single crash.

### L17 — TUN back-pressure

- Saturate the TUN: no stall; kernel-side drops are exported as
  `plat_tun_rx_dropped_total{interface}` / `plat_tun_tx_dropped_total{interface}`
  (read from `/sys/class/net/<if>/statistics`); a TUN `write` returning
  `EAGAIN` is dropped at once and counted in `plat_tx_queue_full_total`.

Result: **PARTIAL** (run 2). Flood with `netdev_max_backlog=1`:
`plat_tun_tx_dropped_total` 0 → 406, equal to `ip -s link` TX dropped; no
stall, `plat_io_errors_total` 0. `plat_tx_queue_full_total` stayed 0: a
Linux TUN `write` did not return `EAGAIN` (default send buffer), so that
path is still unexercised on Linux (covered only by
`services/platd/src/run.rs::full_tx_queue_counts_back_pressure`).

### L18 — package install, upgrade and removal

- On Debian/Ubuntu (`apt install ./platd_*.deb`) and RHEL/Rocky
  (`dnf install ./platd-*.rpm`), using the CI artifact for the host
  architecture: the `plat` system user (no login shell) and `plat-log`
  group exist; `/etc/plat` is `root:plat` 0750 and `/etc/plat/platd.toml`
  `root:plat` 0640; `/var/log/plat` is `plat:plat-log` 2750; `platd` and
  `plat-fwguard` are installed but neither enabled nor started;
  `lintian` and `rpmlint` report no errors.
- Edit the config, enable `plat-fwguard.timer` and `platd`, then install a
  newer package: neither is restarted and an edited config is kept
  (conffile / `%config(noreplace)`).
- Remove the package: `platd` and the guard are stopped and disabled; the
  config and `/var/log/plat` remain.

### L19–L23 — cluster HA on three VMs (PLANNED, not yet run)

Branch `feat/cluster-ha` (uncommitted). Nothing below has been executed: the
VM definitions and scripts are authored and pass `sh -n`, shellcheck and the
stubbed `make test-deploy` checks only. These items must not be cited as
evidence until they have a recorded result. (The plan called these L18–L22;
L18 was already taken by the package check, so they are numbered L19–L23.)

Topology (`deploy/lima/plat-linux-2.yaml`, `deploy/lima/plat-edge.yaml`; the
existing `plat-linux` VM is moved to the same network):

- VMs `plat-linux` (node A, member 0), `plat-linux-2` (node B, member 1) and
  `plat-edge` (FRR router with BGP and BFD, netns `cli` and `inet`, `platd
  witness`, traffic server and a UDP syslog sink), Ubuntu 24.04 arm64.
- Lima `user-v2` network (no host prerequisite) with a VXLAN overlay `plha0`
  (VNI 205, MTU 1450): 192.168.205.11/.12/.20, fd00:205::11/12/20.
- Nodes peer with the edge over BGP (BFD); the shipped hooks
  `deploy/hooks/frr-{announce,withdraw}.sh` announce slices; the edge has an
  L3-hashed ECMP route for the NAT64 prefix to both nodes.
- Throw-away test PKI generated on the edge (EC P-256, serverAuth and
  clientAuth EKU); revocation `off` for the test CA.
- Harness: `deploy/tests/cluster/setup.sh`, `run-all.sh`, one script per
  case (`f01-kill-platd.sh` … `f13-missteer.sh`), traffic meter `flows.py`,
  attribution checker `attrib-check.sh` (no `(v4, port range)` allocated or
  adopted on two nodes with overlapping intervals; every adopt precedes the
  first translated packet from that block on the edge capture).

| Item | Case | Pass criteria |
|------|------|---------------|
| L19 | F1 `kill -9 platd` on A | B acquires A's slices within lease + margin + BFD (target ≤ 5 s); ≥ 95 % of TCP flows survive; acquire and adopt records present; zero attribution overlap |
| L19 | F2 `limactl stop -f plat-linux` (VM loss) | as F1 |
| L19 | F11 hook failure or timeout | `cluster_hook` outcome `failure`, counted; slice stays Active and is alerted |
| L20 | F3 peer-link partition only (A↔B cut, both reach the witness) | exactly one view wins; no slice swap churn; no dual-active on the edge capture |
| L20 | F4 full isolation of A (data plane up) | A fences within lease − margin and runs the withdraw hook; B takes over after lease + margin; the edge sees no slice packets from A after A's fence time |
| L20 | F9 witness down | no view change and no disruption; with a subsequent A crash, no takeover (documented) |
| L20 | F10 wall-clock step ±1 h on A | no lease effect (monotonic time only) |
| L21 | F5 rejoin A | A syncs as backup and fails back after `failback_delay_secs` by handover, no flow loss beyond 1 s; release(`handover`) records |
| L21 | F12 grow from 1 to 2 members | about half of the slices handed over; flows survive. Expected deviation: no leader-side batching, so all moved slices go in one view (POAM-017(a)) |
| L22 | F6 duplicate `node.id` | refused `duplicate_id`, audited, `/healthz` degraded, no slice served by the impostor |
| L22 | F7 config digest mismatch (different `port_block_size`) | `digest_mismatch`, no replication, `service_start` digests differ |
| L23 | F8 slow or lossy peer link (netem delay 200 ms, loss 5 %, 1 Mbit) under a flow storm | worker throughput within noise; any loss counted (`plat_cluster_repl_dropped_total` on A or `{reason="gap"}` on B) and repaired by resync after the impairment is lifted, or, when the impairment causes no loss (the replication stream fits the link and the queue does not overflow), no drop, no gap, no resync and B in sync; no attribution violation |
| L23 | F13 mis-steer (edge sends one subscriber to B while it is homed on A) | `missteered` counted and dropped in `drop` mode |

Open timing item for L19: the in-process simulation
(`crates/plat-cluster/tests/sim.rs`, lease 3 s, heartbeat 500 ms, 10 % drift)
bounds a member crash at about 4.7 s but a **leader crash at about 6.2 s**,
above the 5 s target of F1. F1 must be run with the leader as the crashed
node as well; the result decides whether the target or `lease_ms` changes
(POAM-007).

Result: **NOT RUN.**

### L24 — fragment steering on multiqueue TUN (POAM-035, Q2)

- Fragment state is per worker (`crates/plat-nat64/src/frag.rs`). With a
  4-queue TUN and default queue selection, send fragmented IPv4 and IPv6
  datagrams into the TUN and record, for each datagram, whether all its
  fragments were read from the same queue.
- Pass: no datagram is split across queues. A split datagram would be
  dropped as `fragment_unmatched` / `icmp_quote_unmatched` (fail closed).

Result: **PASS** (2026-10-29, Lima VM `plat-linux`, kernel 6.8; performance
reviewer of `feat/protocol-completeness`, run record
`target/agent-workflow/protocol/findings-perf.md`, not in the repository):
0 of 64 IPv4 and 0 of 64 IPv6 fragmented datagrams were split across the 4
queues; the kernel selects the queue for fragments from the addresses only.
The risk recorded in POAM-035 was not observed with default queue
selection. Not covered: other queue-selection settings, other kernels and
other I/O backends (AF_XDP, POAM-016); the harness used for the check is not
in the repository.

### L25 — pool-source guard on real nftables (POAM-024 residual (b))

- Three network namespaces (translator with an external and a cluster
  veth, TUN `plat0`; an external host; a cluster peer). `plat-tun-setup.sh`
  loads the rules with the real `nft`; scapy probes with pool and non-pool
  sources towards a pool address; a reader on the TUN and `tcpdump` record
  what reaches it. Then `platd run` against the real `plat.nft.expected`
  and broken copies of it.
- Pass: pool-sourced IPv4 from the external interface never reaches the
  TUN; from the cluster interface only with `cross_node_hairpin = true`;
  non-pool sources always do; the start gate accepts every real rendering
  (a /32 without prefix length, a one-element interface set without braces,
  merged ranges, multi-interface sets, live counters) and refuses a missing
  guard, a wrong interface, an uncovered pool and a hairpin-off guard.

Result: **PASS** (2026-10-29, Lima VM `plat-linux`, kernel 6.8.0 aarch64,
nftables 1.0.9). Report and scripts: `deploy/tests/nftguard/` (`report.md`;
run with sudo in a disposable VM as described in its `README.md`). The
refusal message in that run was the misleading "accepts IPv4 before the
pool-source guard"; it now reads "has no matching pool-source guard rule"
(`hairpin_guard.rs::missing_guard_is_reported_as_missing_not_shadowed`).
Not covered: `plat-fwguard` live-table sync and a start under the systemd
unit.
