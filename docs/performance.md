# Performance

--8<-- "README.md:performance"

See [Architecture](architecture.md) for the run-to-completion worker model and
the [POA&M](compliance/POAM.md) for the tracked scaling items (POAM-015,
POAM-016; POAM-018 is closed).

## Port-block sizing

Each subscriber gets port blocks of `nat64.port_block_size` ports, up to
`nat64.max_blocks_per_subscriber`. `platd check-config` prints the capacity of
this node's share of the pool and, when the pool cannot give every subscriber
one block, suggests smaller uniform blocks with the same maximum ports per
subscriber. For a /24 with ports 1024..=65535:

| Layout | Blocks per address | Subscribers at 1 block | Max ports per subscriber | Subscribers at max | In-block port randomness |
| --- | --- | --- | --- | --- | --- |
| 512 x 4 (default) | 126 | 32 256 | 2 048 | 8 064 | 9 bits |
| 256 x 8 | 252 | 64 512 | 2 048 | 8 064 | 8 bits |
| 128 x 16 | 504 | 129 024 | 2 048 | 8 064 | 7 bits |

Trade-offs of smaller blocks:

- **Port randomness (RFC 6056, RFC 6888 REQ-15).** A port is chosen at
  random within the subscriber's block, so 128-port blocks leave 7 bits for
  an off-path attacker to guess against 9 bits at 512. Smaller blocks weaken
  RFC 6056 port randomisation against off-path spoofing: an attacker who
  knows the subscriber's pool address and block needs about 4x fewer
  guesses (128 against 512 ports) for spoofed-response attacks such as DNS
  cache poisoning of resolvers behind the PLAT or TCP RST injection. **Add
  pool addresses first**; shrink blocks only when that is not possible, and
  prefer 256 x 8 as the middle ground (2x the light-subscriber capacity,
  8 bits).
- **Audit volume (AU-4, AU-5(1)).** A light subscriber still writes one
  allocate and one release record. A subscriber that grows to 2 048 ports
  writes 16 + 16 block records at 128 x 16 instead of 4 + 4, so heavy
  subscribers can write up to 4x the block records. Before shrinking blocks,
  re-size `audit.queue_capacity` and the log volume (`audit.file.max_files`
  x `audit.file.max_bytes` + `audit.file.min_free_bytes`) by that factor for
  the share of heavy subscribers; otherwise bursts reach `min_free_bytes` or
  fill the queue sooner, and the node goes degraded and refuses new bindings
  (fail-closed). Block attribution (RFC 6888 REQ-12, RFC 7422) and the SIEM
  schema are unchanged; SIEM rules that assume 512-port ranges need updating.
- **New-flow cost.** Only the BIB-miss path changes: a new block (pool locks,
  audit record, replication slot with HA) every 128 ports instead of 512,
  and up to 16 blocks to scan. Established flows are unaffected. The
  `nat64_block_layout` criterion group measures it. Scope: engine only
  (`Nat64::process` on one worker); the audit receiver is not drained, so
  record formatting and writing are excluded. The audit queue is 65 536 deep
  for the HA-off cases and 16 384 for the HA cases, so it never overflows.
  Measured on Apple M2 Max, macOS (criterion, 1 s warm-up, 3 s measurement,
  per packet):

  | Case | 512 x 4 | 128 x 16 | Difference |
  | --- | --- | --- | --- |
  | `flow_churn` (2 subscribers x 2 000 flows, HA off) | 254.6 ns | 259.5 ns | +1.9% |
  | `flow_churn_ha` (same, HA on, reserve-ahead 8 / 32) | 255.4 ns | 266.6 ns | +4.4% |
  | `flow_churn_ha_128x16_ra8` (HA on, 128 x 16, reserve-ahead 8) | | 273.1 ns | +6.9% |
  | `block_fill` (each subscriber uses `size` ports, 1 block) | 245.3 ns | 250.3 ns | |
  | `block_spill` (each subscriber uses `size + 1` ports, 2 blocks) | 245.1 ns | 249.7 ns | |

  The churn cases allocate a block every ~500 flows (512 x 4) or ~125
  flows (128 x 16). The fill/spill pair isolates one extra block per
  subscriber. From the means, spill minus fill per subscriber is
  513 x 245.1 - 512 x 245.3 = about +180 ns (512) and
  129 x 249.7 - 128 x 250.3 = about +170 ns (128). Both are less than the
  ~250 ns of the extra flow itself. The confidence intervals give a range
  of about -1.4 to +1.8 µs per subscriber at 512, so with HA off the
  per-block cost is below this bench's resolution.

  With HA on, 128 x 16 with reserve-ahead 32 is about 4% slower per new
  flow than 512 x 4 with reserve-ahead 8. That difference comes from the
  block size (4x the block allocations and replication slots). Keeping
  reserve-ahead at 8 with 128-port blocks (`_ra8`) measured about 2% slower
  again, but its confidence interval (267 to 282 ns) overlaps the
  reserve-ahead 32 case, so the reserve-ahead budget has no resolvable
  effect on this single-node bench. A first run gave 267.0 / 292.4 ns
  for the two HA cases, so treat these as relative figures for one host
  with a few percent of run-to-run variation.
- **HA.** `cluster.ha.reserve_ahead_blocks` counts blocks, so scale it with
  the block size (8 at 512 becomes 32 at 128); `check-config` warns when
  `port_block_size x reserve_ahead_blocks` is below 4 096 ports. The block
  size is part of the config digest: change it on every member together.

The defaults stay 512 x 4. Changing them would change the config digest of
clusters that rely on implicit defaults.
