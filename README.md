# usg-plat

Multithreaded **464XLAT PLAT** (RFC 6877): stateful NAT64
(RFC 6146) with SIIT translation (RFC 7915), RFC 6052 address mapping, bulk
port allocation, high-speed SIEM attribution logging, and stateless cluster
scale-out, with FIPS-mode TLS 1.3 for syslog and remote management. The data
plane is pure Rust; cryptography uses the AWS-LC FIPS module through
`aws-lc-rs`. Built for NIST SP 800-53 Rev 5 ATO readiness.

Build requirements: the pinned Rust toolchain plus **CMake, Go ≥ 1.18 and a
C compiler (clang or gcc)** to build the AWS-LC FIPS module
(`aws-lc-fips-sys`); `gcc-aarch64-linux-gnu` for the aarch64 cross-check
(`make check-linux` falls back to a TLS-off lint without it).
`make check-notls` lints the `--no-default-features` build.

<!-- --8<-- [start:quickstart] -->
## Quick start

```bash
make check test
cargo run -p platd -- check-config -c config/platd.example.toml
```

On a Linux host:

```bash
cargo build --release -p platd
sudo install -m 0755 target/release/platd /usr/bin/platd
sudo install -D -m 0755 deploy/systemd/plat-tun-setup.sh /usr/libexec/plat/plat-tun-setup.sh
sudo install -D -m 0755 deploy/systemd/plat-fwguard.sh /usr/libexec/plat/plat-fwguard.sh
sudo install -m 0644 deploy/systemd/platd.service deploy/systemd/plat-fwguard.service \
    deploy/systemd/plat-fwguard.timer /etc/systemd/system/
sudo install -D -m 0644 deploy/systemd/plat.tmpfiles.conf /usr/lib/tmpfiles.d/plat.conf
getent passwd plat >/dev/null || sudo useradd --system --user-group --no-create-home \
    --home-dir /nonexistent --shell /usr/sbin/nologin plat
getent group plat-log >/dev/null || sudo groupadd --system plat-log
sudo install -D -m 0640 -o root -g plat config/platd.example.toml /etc/plat/platd.toml   # then edit
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/plat.conf   # /var/log/plat must exist before the first start
sudo install -D -m 0644 deploy/systemd/nftables.service.d/plat-fwguard.conf \
    /etc/systemd/system/nftables.service.d/plat-fwguard.conf
sudo systemctl daemon-reload
sudo systemctl enable chrony-wait.service    # chrony; with systemd-timesyncd:
# sudo systemctl enable systemd-time-wait-sync.service
sudo systemctl enable --now plat-fwguard.timer   # guards on its own, also while platd is stopped
sudo systemctl enable --now platd
curl -s --retry 10 --retry-connrefused --retry-delay 1 127.0.0.1:9464/healthz   # listener is up a few seconds after start
curl -s 127.0.0.1:9464/metrics
```

Deployment notes:

- `plat-tun-setup.sh` runs as root from `ExecStartPre=+` and takes the config
  path as its argument (the unit passes `/etc/plat/platd.toml`). It needs
  `nft` (nftables) and `platd` at `/usr/bin/platd`, reads the interface, NAT64
  prefix, client prefixes and this node's pool slice from
  `platd check-config --format env`, creates the multiqueue TUN owned by
  `plat:plat`, installs the `table inet plat` forward policy (default drop),
  routes only the NAT64 prefix and this node's slice to the TUN (every other
  route on the TUN, of any protocol, is removed), and enables forwarding
  last. Any mismatch aborts the start. Keys of `check-config --format env`
  it does not use are ignored; a line that is not `PLAT_*=` aborts.
- The forward policy is written to `/etc/nftables.d/plat.nft` and the glob
  line `include "/etc/nftables.d/*.nft"` is added once to
  `/etc/nftables.conf` (an exact `include "/etc/nftables.d/plat.nft"` from an
  earlier version is replaced by it), so `systemctl reload/restart nftables`
  restores the policy, and a missing `plat.nft` cannot break the host
  ruleset. A snapshot of the loaded table is kept in
  `/etc/nftables.d/plat.nft.expected`.
- `plat-fwguard` compares the live `table inet plat` with that snapshot
  (counters ignored; without a snapshot it requires a default-drop forward
  chain) and, if it is missing or different while forwarding is on, turns
  IPv4/IPv6 forwarding off and logs an error to the journal (fail closed).
  It runs every 2 s from `plat-fwguard.timer` (enable it on its own, as
  above, so it also guards while platd is stopped) and at once after
  `nftables.service` starts, reloads or stops (the drop-in above). Restore
  with `systemctl restart platd`.
- Uninstall the forward policy: stop platd; disable the guard first
  (`systemctl disable --now plat-fwguard.timer`, remove
  `/etc/systemd/system/nftables.service.d/plat-fwguard.conf`,
  `systemctl daemon-reload`), otherwise it turns forwarding off when the
  table goes; then `rm /etc/nftables.d/plat.nft
  /etc/nftables.d/plat.nft.expected` and `nft delete table inet plat`.
  The `include "/etc/nftables.d/*.nft"` line can stay.
- Audit logs: `/var/log/plat` is `plat:plat-log` mode 2750, files 0640 group
  `plat-log`. The directory comes from `/usr/lib/tmpfiles.d/plat.conf`
  (not `LogsDirectory=`, which systemd re-applies as `plat:plat` 0750 after
  the setup script); the setup script creates the group, applies that file
  with `systemd-tmpfiles --create` (or sets owner, group and mode itself if
  it is missing) and re-groups existing log files. Log shippers and
  `verify-log` operators join `plat-log`; never add them to `plat`. When
  upgrading from a unit with `LogsDirectory=plat`, install the new unit and
  tmpfiles file, `systemctl daemon-reload`, then restart platd.
  The directory must exist before platd starts: `ReadWritePaths=/var/log/plat`
  is resolved when systemd builds the mount namespace, before `ExecStartPre=`,
  so a missing directory fails the start with `226/NAMESPACE`. Run the
  `systemd-tmpfiles --create` step above (after creating `plat` and
  `plat-log`); at boot `systemd-tmpfiles-setup.service` recreates it.
- Clock: the unit orders after `time-sync.target`. Enable the wait unit of
  your time daemon (`chrony-wait.service` for chrony,
  `systemd-time-wait-sync.service` for systemd-timesyncd);
  `systemd-time-wait-sync` can wait forever under chrony.
- The unit stops restarting after 5 failed starts in 60 s
  (`systemctl reset-failed platd` after fixing the cause).
- The daemon runs with no capabilities. Size `MemoryMax` in the unit for
  your `nat64.max_sessions` (formula in the unit file; the shipped 8G does not
  scale on its own, POAM-021).
- The Linux-specific behaviour (unit sandbox, forward policy and guard, TUN
  attach, audit lifecycle) was verified on one Ubuntu 24.04 / systemd 255
  host; results and open items are in
  `docs/compliance/LINUX_VERIFICATION.md`.
- Verify the audit log chain (live file and rotated files together):
  `platd verify-log /var/log/plat/nat64-audit.jsonl /var/log/plat/nat64-audit.jsonl.*`
  (exit 0 = verified and linked, including gaps announced with their exact
  size; 1 = verification failure, unverified tail or unaccounted gap; 2 = I/O
  error; 3 = recovery gap after a damaged start, check it against the remote
  copy, `--allow-recovery` accepts it; see `docs/compliance/SIEM_LOGGING.md`).

Configuration changes to note when upgrading from an earlier build:

- `translation.allow_non_global_destinations` defaults to `false`: RFC 1918,
  100.64/10, documentation and other RFC 6890 non-global IPv4 space is
  denied as a destination (and as an inbound data source) under every
  prefix. A network-specific-prefix deployment that must reach such space
  sets it to `true`. The Well-Known Prefix cannot be combined with a
  non-global pool.
- `audit.on_overflow = "refuse_new_bindings"` (the default) requires
  `[audit.file]`; a syslog-only config must set `on_overflow =
  "drop_and_alert"`.
- New keys: `translation.lowest_ipv6_mtu`, `icmp_errors_per_sec`, `copy_tos`,
  `wkp_non_global_icmp_errors`, `allow_non_global_destinations`;
  `nat64.max_subscribers`; `audit.file.max_files`, `audit.file.min_free_bytes`.
- SIEM log schema is version 5 (FIPS status on `service_start`, `plat.reason`
  on `audit_remote_loss`, new management and revocation records); audit
  files written by schema 1 (chain v1) no longer verify.
- **FIPS:** `tls.require_fips = true` is the default: `platd` refuses to
  start unless the AWS-LC FIPS module is active, even with no TLS configured.
  `check-config` and `/metrics` (`plat_fips_mode`) show the status.
  The module is AWS-LC-FIPS 4.2.0 (`aws-lc-fips-sys` ~0.14.4) — submitted to
  NIST (Modules In Process), not yet validated. The `aws-lc-fips-sys` README's
  "3.0.x" statement is out of date. Certificates #5298/#5314 (v3.1) do not
  cover this build (POAM-026).
- **Breaking:** `management.tls.allowed_clients` entries must be typed:
  `cn:<CN>`, `dns:<DNS SAN>`, `uri:<URI SAN>` or `sha256:<64 hex>`
  (certificate fingerprint). Bare entries fail validation.
- A non-loopback `management.listen` requires `[management.tls]` (mutual
  TLS, client certificate required); with it there is no plaintext listener.
  `management.tls.max_connections_per_ip` (default 2, 1..=64, capped at
  `max_connections`) counts IPv4 per address and IPv6 per /64; a ClientHello
  must arrive within 2 s.
- `tls.pq_hybrid = true` (default) offers X25519MLKEM768 first. For an NIAP
  NDcPP evaluated configuration set `pq_hybrid = false` (P-256/P-384 only).
- Revocation checking (`tls.revocation.mode = "hard_fail"` by default)
  rejects a peer whose status cannot be determined: make OCSP responders or
  CRL distribution points reachable, or configure `crl.files`/`crl.urls`.
  Prefer IP literals or a local resolver for them (DNS has no timeout,
  POAM-025).
- The unit now sets `StateDirectory=plat/revocation` (0700) for the optional
  `tls.revocation.cache_dir = "/var/lib/plat/revocation"`, which holds
  verified CRLs and `crl-numbers` (cRLNumber rollback marks).
- `check-config` (both formats) loads every TLS file and exits 2 on a
  missing file or bad key permissions; key files with setuid/setgid/sticky
  bits, or that are not regular files, are rejected.
  Install key files owned by `plat` (mode 0600/0400/0640/0440) or by root
  with group `plat` (mode 0640/0440), e.g.
  `sudo install -D -m 0640 -o root -g plat server.key /etc/plat/tls/server.key`;
  certificates may be 0644.
- TLS syslog collectors must support TLS 1.3 (RFC 5425 TLS 1.2 is not
  offered).

<!-- --8<-- [end:quickstart] -->

<!-- --8<-- [start:performance] -->
## Measured performance

Criterion point estimates from the round-2 performance re-check
(`make bench` with `--warm-up-time 1 --measurement-time 3`) on a macOS Apple
Silicon development host (8 performance + 4 efficiency cores).

| Bench | Result |
|-------|--------|
| `xlat/v6_to_v4_udp_1248B` (header translation only) | 27.8 ns/packet |
| `xlat/v4_to_v6_udp_1228B` | 25.1 ns/packet |
| `nat64/v6_to_v4_udp_existing_session` (parse + policy + state + translate) | 56.9 ns/packet |
| `nat64/v6_to_v4_existing_session_under_new_sub_flood_3t` (3 threads flooding new subscribers) | 55.3 ns/packet |
| `nat64/v4_to_v6_df0_fragmented_1428B` (DF=0 packet → 2 IPv6 fragments) | 74.9 ns/packet |
| `nat64/inbound_unsolicited_large_bib` (ADF miss, 4000 sessions in the BIB) | 29.8 ns/packet |
| `nat64/v6_to_v4_parallel_{1,2,4,8}t_x100k` (shared tables, ~100 k packets per run, includes thread spawn) | 9.36 / 5.13 / 2.98 / 2.12 ms (about 10.7 / 19.5 / 33.5 / 47.1 Mpps) |
| `audit/enqueue_try_send` (data-plane cost of a log record) | 16.7 ns |
| `audit/format_json` (logger thread) | 354 ns/record |
| `audit/format_cef` (syslog sender thread) | 194 ns/record |
| Logger end-to-end, file only (2 M records, review harness) | 641–648 k records/s |

In these engine-only benches, shared-table scaling at high thread counts is
limited by per-packet shard locks (POAM-015); with TUN I/O this cost is
negligible (see below). UDP syslog sends one datagram per record, about
310 k records/s per destination (POAM-018).

These are engine numbers without kernel I/O.

### Linux TUN data plane (indicative only)

> **Lima VM on Apple M2 Max, virtio, indicative only; validate on bare-metal
> x86 with a real NIC before sizing.** 6 vCPU, Ubuntu 24.04.5 aarch64, kernel
> 6.8; veth + multiqueue TUN, no NIC/RSS/IRQ cost; kernel pktgen shares the
> vCPUs with `platd`; no hardware PMU; run-to-run noise about ±10%.

Measured 2026-10-29 on `main` @a080417 (release build), UDP, 64 B and 512 B
payloads, 8–49152 flows on one subscriber, `pin_cpus = true`.

| Measurement | Result |
|-------------|--------|
| Per worker, v6→v4, worker at 100% CPU | about 0.45–0.62 Mpps (about 1.6–2.2 µs CPU per packet, kernel TUN work included); 512 B about 8% slower than 64 B |
| Scaling 1 → 2 workers | about 1.75× (0.558 → 0.966 Mpps at 4096 flows; 0.482 → 0.859 at 49152) |
| 4 workers | 1.05–1.60 Mpps; **generator-bound**, not a saturation point |
| Return path v4→v6, 4 workers | 1.20 Mpps translated (workers 95–96%), cost symmetric with v6→v4 |
| Worker CPU split (`perf record`, 1 worker saturated) | kernel 86% (TUN write + synchronous forwarding, TUN read, syscall entry/exit); engine + translation about 10%; lock operations about 0.7%, no futex/slow-path samples |

`platd` drop counters stayed at 0; all loss under overload was counted as
`plat_tun_tx_dropped_total` (kernel TUN queue full). Conclusion: on Linux TUN
the per-packet syscalls dominate (POAM-016), and shard locks are not material
at these rates (POAM-015). Raw results and the harness script are kept as
run evidence (`target/agent-workflow/linux-perf/`), not in the repository.

<!-- --8<-- [end:performance] -->

## Documentation

Browse it as a site with `make docs-serve` (Zensical); it is published to
https://192d-wing.github.io/usg-plat/ from `main`.

- `ARCHITECTURE.md`: data path, concurrency, cluster design
- `docs/compliance/SIEM_LOGGING.md`: log schema and SIEM correlation
- `docs/compliance/NIST_800-53_MAPPING.md`, `RFC_COMPLIANCE.md`, `POAM.md`
- `docs/compliance/LINUX_VERIFICATION.md`: Linux verification results
- `CLAUDE.md` and `.claude/skills/plat-workflow/`: development workflow
