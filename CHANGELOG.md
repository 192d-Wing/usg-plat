# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and SemVer.

## [Unreleased]

### Added

- Stateful NAT64 / 464XLAT PLAT engine: RFC 6052 mapping, RFC 7915 in-place
  translation, ICMP error translation, RFC 6146 BIB/session tables with
  endpoint-independent mapping, address-dependent filtering, TCP state
  machine, hairpinning.
- Bulk port-block allocation with paired pooling and per-subscriber limits.
- High-speed SIEM attribution logging (log schema v1): non-blocking queue,
  JSON/CEF, RFC 5424 syslog over UDP/TCP, SHA-256 chained local file,
  `platd verify-log`.
- Multithreaded `platd` daemon on Linux multiqueue TUN with CPU pinning,
  sweeper, loopback Prometheus metrics, `check-config`.
- Cluster pool partitioning with route-announcement prefixes.
- `/plat-workflow` multi-agent development skill and subagents.
