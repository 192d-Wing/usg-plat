# usg-plat

Pure-Rust, multithreaded **464XLAT PLAT** (RFC 6877): stateful NAT64
(RFC 6146) with SIIT translation (RFC 7915), RFC 6052 address mapping, bulk
port allocation, high-speed SIEM attribution logging, and stateless cluster
scale-out. Built for NIST SP 800-53 Rev 5 ATO readiness.

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
sudo install -D -m 0640 config/platd.example.toml /etc/plat/platd.toml   # then edit
sudo install -m 0644 deploy/systemd/platd.service /etc/systemd/system/
sudo systemctl enable --now platd
curl -s 127.0.0.1:9464/metrics
curl -s 127.0.0.1:9464/healthz
```

Deployment notes:

- `plat-tun-setup.sh` runs as root from `ExecStartPre=+` and takes the config
  path as its argument (the unit passes `/etc/plat/platd.toml`). It needs
  `nft` (nftables) and `platd` at `/usr/bin/platd`, reads the interface, NAT64
  prefix, client prefixes and this node's pool slice from
  `platd check-config --format env`, creates the multiqueue TUN owned by
  `plat:plat`, installs the `table inet plat` forward policy (default drop),
  routes only the NAT64 prefix and this node's slice to the TUN, and enables
  forwarding last. Any mismatch aborts the start.
- The daemon runs with no capabilities. Size `MemoryMax` in the unit for
  your `nat64.max_sessions` (formula in the unit file; the shipped 8G does not
  scale on its own, POAM-021).
- None of the Linux-specific behaviour (unit sandbox, forward policy, TUN
  attach) has been run yet; see `docs/compliance/LINUX_VERIFICATION.md`.
- A flush or reload of the host nftables ruleset removes the forward policy
  while forwarding stays on (POAM-019); do not flush the ruleset on a PLAT
  host.
- Verify the audit log chain (live file and rotated files together):
  `platd verify-log /var/log/plat/nat64-audit.jsonl /var/log/plat/nat64-audit.jsonl.*`
  (exit 0 = verified and linked, 1 = verification failure, unverified tail or
  gap, 2 = I/O error; see `docs/compliance/SIEM_LOGGING.md`).

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
- SIEM log schema is version 4; audit files written by schema 1 (chain v1) no
  longer verify.

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

At production flow counts, shared-table scaling is limited by per-packet
shard locks whose cache lines move between workers (POAM-015). UDP syslog sends one
datagram per record, about 310 k records/s per destination (POAM-018).

These are engine numbers without kernel I/O. Linux TUN typically limits a
queue to roughly 1–2 Mpps (general estimate, not measured in this project),
so the engine is not the bottleneck; AF_XDP is the path beyond that
(POAM-016).

<!-- --8<-- [end:performance] -->

## Documentation

Browse it as a site with `make docs-serve` (Zensical); it is published to
https://192d-wing.github.io/usg-plat/ from `main`.

- `ARCHITECTURE.md`: data path, concurrency, cluster design
- `docs/compliance/SIEM_LOGGING.md`: log schema and SIEM correlation
- `docs/compliance/NIST_800-53_MAPPING.md`, `RFC_COMPLIANCE.md`, `POAM.md`
- `docs/compliance/LINUX_VERIFICATION.md`: Linux checks not yet run
- `CLAUDE.md` and `.claude/skills/plat-workflow/`: development workflow
