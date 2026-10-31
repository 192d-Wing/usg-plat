//! `platd` — multithreaded 464XLAT PLAT (RFC 6877) / stateful NAT64 (RFC 6146).

mod cluster;
mod hairpin_guard;
mod metrics;
#[cfg(feature = "tls")]
mod mgmt;
mod run;
#[cfg(all(test, feature = "tls"))]
mod test_pki;
#[cfg(feature = "tls")]
mod tls;

use std::io::BufReader;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use plat_common::Config;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the translator.
    Run {
        #[arg(short, long, default_value = "/etc/plat/platd.toml")]
        config: PathBuf,
    },
    /// Validate a configuration and print this node's pool slice.
    CheckConfig {
        #[arg(short, long, default_value = "/etc/plat/platd.toml")]
        config: PathBuf,
        /// `env`: machine-readable `KEY=value` lines for
        /// `plat-tun-setup.sh` (interface, NAT64 prefix, client prefixes,
        /// owned pool cover).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// systemd unit or drop-in whose `MemoryMax=` is compared with the
        /// required memory (text format; default: the installed unit, if any).
        #[arg(long)]
        unit: Option<PathBuf>,
    },
    /// Run the cluster witness: a tie-breaking voter for two-node HA
    /// clusters (mutual TLS only, no data plane).
    Witness {
        #[arg(short, long, default_value = "/etc/plat/witness.toml")]
        config: PathBuf,
    },
    /// Operator commands for a running HA node (local socket in
    /// `cluster.ha.state_dir`; only root and the daemon's user; audited as
    /// `cluster_operator_command`). `takeover`/`restore` are refused unless
    /// `cluster.ha.auto_failover = false`.
    Cluster {
        #[arg(short, long, default_value = "/etc/plat/platd.toml")]
        config: PathBuf,
        #[command(subcommand)]
        op: ClusterOp,
    },
    /// Verify the hash chain of audit log files (AU-9). Pass the live file
    /// and its rotated predecessors (any order) to check that they link
    /// into one chain.
    ///
    /// Exit codes: 0 verified (a gap is allowed only when an
    /// `audit_output_failure` (recovered) record announces exactly its size,
    /// or with the matching --allow-* flag); 1 verification failed; 2 I/O
    /// error; 3 only a RECOVERY GAP remains (numbers skipped by a restart
    /// after a damaged log, announced by `audit_recovery`: verify that range
    /// against the remote copy, or pass --allow-recovery).
    VerifyLog {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Accept records after the last checkpoint and a truncated final
        /// line (live file, crash, short write).
        #[arg(long)]
        allow_tail: bool,
        /// Accept sequence gaps between files (records lost while the local
        /// file was not writable; see `audit_output_failure`).
        #[arg(long)]
        allow_gap: bool,
        /// Accept a gap announced by an `audit_recovery` record (restart
        /// after a damaged log) once the range was checked against the
        /// remote copy: exit 0 with a warning instead of 3.
        #[arg(long)]
        allow_recovery: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ClusterOp {
    /// Print the view, peers and slice owners (JSON).
    Status,
    /// Declare member <id> lost and take over its slices. The operator
    /// must have stopped that member first: refused while its peer link is
    /// up, unless --force (then the slices are served only after the
    /// takeover wait, lease * (1 + drift margin) + 200 ms).
    Takeover {
        #[arg(long)]
        member: u16,
        /// Take over although the member's peer link is up.
        #[arg(long)]
        force: bool,
    },
    /// Return member <id> to the live set (run before restarting it).
    Restore {
        #[arg(long)]
        member: u16,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Env,
}

/// `check-config --format env`: one `KEY=value` line per item, values
/// space-separated, for `deploy/systemd/plat-tun-setup.sh` (which parses
/// them without `eval`). Refuses an interface name that is not a plain
/// Linux name, so nothing shell-special ever reaches the script.
/// `PLAT_FIPS` / `PLAT_MGMT_TLS` let nodes be compared (POAM-017 procedure).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: CM-6 - host routing and the forward policy are derived
///   from the validated configuration, not edited by hand (SC-7).
fn render_env(cfg: &Config, owned: &[u32], fips: bool) -> Result<String, String> {
    use std::fmt::Write as _;
    let ifname = &cfg.dataplane.interface;
    if ifname.is_empty()
        || ifname.len() > 15
        || !ifname.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(format!("dataplane.interface {ifname:?} is not a valid Linux interface name"));
    }
    if owned.is_empty() {
        return Err("this node owns no pool addresses".into());
    }
    let join = |v: Vec<String>| v.join(" ");
    let mut o = String::new();
    let _ = writeln!(o, "PLAT_IF={ifname}");
    let _ = writeln!(o, "PLAT_NODE_ID={}", cfg.node.id);
    let _ = writeln!(o, "PLAT_NAT64_PREFIX={}", cfg.translation.nat64_prefix);
    let _ = writeln!(
        o,
        "PLAT_CLIENT_PREFIXES={}",
        join(cfg.translation.client_prefixes.iter().map(ToString::to_string).collect())
    );
    let _ =
        writeln!(o, "PLAT_OWNED_POOL={}", join(plat_cluster::cover(owned).iter().map(ToString::to_string).collect()));
    let _ = writeln!(o, "PLAT_FIPS={}", u8::from(fips));
    let _ = writeln!(o, "PLAT_MGMT_TLS={}", u8::from(cfg.management.tls.is_some()));
    // HA: ownership moves at run time, so the whole pool is routed to the
    // TUN and the engine drops what this node does not own.
    let _ = writeln!(o, "PLAT_CLUSTER_HA={}", u8::from(cfg.cluster.ha_enabled()));
    let _ = writeln!(
        o,
        "PLAT_POOL_ALL={}",
        join(plat_cluster::cover(&plat_cluster::pool_addrs(&cfg.nat64.pool)).iter().map(ToString::to_string).collect())
    );
    // POAM-024: pool-sourced IPv4 is admitted only on these interfaces.
    let _ = writeln!(o, "PLAT_CROSS_NODE_HAIRPIN={}", u8::from(cfg.translation.cross_node_hairpin));
    let _ = writeln!(o, "PLAT_CLUSTER_IFACES={}", cfg.translation.cluster_interfaces.join(" "));
    // SC-5 (POAM-021): memory this config needs with this host's workers.
    let req = plat_common::memory::required_bytes(cfg, plat_common::memory::worker_count(cfg));
    let _ = writeln!(o, "PLAT_MEMORY_REQUIRED_BYTES={req}");
    Ok(o)
}

/// Whether the FIPS module is active in this process (`PLAT_FIPS`).
#[cfg(feature = "tls")]
fn fips_active() -> bool {
    plat_tls::init_fips();
    plat_tls::require_fips().is_ok()
}

#[cfg(not(feature = "tls"))]
fn fips_active() -> bool {
    false
}

/// Installed unit paths checked by `check-config` when `--unit` is not given
/// (later entries override earlier ones, as in systemd).
const UNIT_PATHS: [&str; 2] = ["/usr/lib/systemd/system/platd.service", "/etc/systemd/system/platd.service"];

/// The `check-config` held-SYN line (RFC 6146 §3.5.2.2): worst-case
/// memory, or why holding is off.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5, CM-6 - the bound of attacker-creatable held state
///   is visible before start
fn held_syn_summary(cfg: &Config) -> String {
    let n = &cfg.nat64;
    if n.holds_syns() {
        format!(
            "held SYN memory (worst case): {} bytes ({} SYNs, {} per BIB, {} s, expiry ICMP {}; SC-5)\n",
            n.held_syn_memory(),
            n.max_held_syns,
            n.max_held_syns_per_bib,
            n.held_syn_secs,
            if n.held_syn_unreachable { "on" } else { "off" },
        )
    } else if n.tcp_simultaneous_open && n.max_held_syns > 0 {
        "WARNING: nat64.tcp_simultaneous_open has no effect with filtering = \"endpoint_independent\" \
         (inbound SYNs to bound ports are already admitted)\n"
            .into()
    } else {
        "held SYNs: off\n".into()
    }
}

/// The `check-config` memory section: the requirement and, when a unit file
/// is found, a warning if its `MemoryMax=` is lower. `platd run` enforces the
/// limit itself; this only catches a mis-sized unit before a restart.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-5, CP-10 - memory sizing derived from the configured
///   limits (POAM-021).
fn memory_summary(cfg: &Config, unit: Option<&std::path::Path>) -> String {
    use plat_common::memory;
    let workers = memory::worker_count(cfg);
    let req = memory::required_bytes(cfg, workers);
    let mut o = format!("memory required: {req} bytes ({workers} workers; SC-5, see platd.service)\n");
    let path = unit
        .map(std::path::Path::to_path_buf)
        .or_else(|| UNIT_PATHS.iter().rev().map(PathBuf::from).find(|p| p.is_file()));
    if let Some(p) = path {
        match std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(|t| memory::parse_unit_memory_max(&t)) {
            Ok(Some(max)) if max < req => o.push_str(&format!(
                "WARNING: {} MemoryMax={max} is below the required {req} bytes: platd run will refuse to start\n",
                p.display()
            )),
            Ok(_) => {}
            Err(e) => o.push_str(&format!("WARNING: {}: {e}\n", p.display())),
        }
    }
    o
}

/// The `check-config` TLS section (fails closed on unusable TLS files).
#[cfg(feature = "tls")]
fn tls_summary(cfg: &Config) -> Result<String, String> {
    tls::summary(cfg)
}

#[cfg(not(feature = "tls"))]
fn tls_summary(cfg: &Config) -> Result<String, String> {
    if cfg.uses_tls() {
        return Err("TLS is configured but platd was built without TLS support (feature `tls`)".into());
    }
    let mut o = String::from("TLS:\n  not available in this build (feature `tls` off); FIPS: INACTIVE\n");
    if cfg.tls.require_fips {
        o.push_str("WARNING: tls.require_fips = true: platd run will refuse to start\n");
    }
    Ok(o)
}

/// The `check-config` port-block capacity lines, with a warning when this
/// node's share of the pool cannot serve `nat64.max_subscribers` (SC-5, CM-6).
fn capacity_summary(cfg: &Config, owned_addrs: u64) -> String {
    let n = &cfg.nat64;
    let c = n.capacity(owned_addrs);
    let max_subs = u64::from(n.max_subscribers);
    let mut o = format!(
        "port blocks: {} per address x {} addresses = {} ({} ports each)\n\
         \x20 subscribers served: {} at 1 block, {} at {} blocks (max_subscribers = {})\n",
        c.blocks_per_addr,
        owned_addrs,
        c.total_blocks,
        n.port_block_size,
        c.subscribers_at_one_block,
        c.subscribers_at_max_blocks,
        n.max_blocks_per_subscriber,
        max_subs,
    );
    if c.subscribers_at_one_block < max_subs {
        o.push_str(&format!(
            "WARNING: the pool has {} blocks for up to {} subscribers: subscribers beyond that \
             get pool_exhausted; add pool addresses or lower nat64.max_subscribers\n",
            c.total_blocks, max_subs
        ));
        o.push_str(&smaller_blocks_hint(cfg, owned_addrs));
    } else if c.subscribers_at_max_blocks < max_subs {
        o.push_str(&format!(
            "WARNING: only {} of {} subscribers can hold {} blocks each; heavy users may get pool_exhausted\n",
            c.subscribers_at_max_blocks, max_subs, n.max_blocks_per_subscriber
        ));
    }
    if let Some(line) =
        reserve_ahead_advisory(n.port_block_size, cfg.cluster.ha_active().map(|h| h.reserve_ahead_blocks))
    {
        o.push_str(&line);
    }
    o
}

/// Smaller uniform blocks with the same maximum ports per subscriber
/// (`port_block_size x max_blocks_per_subscriber`), for a pool that cannot
/// give every subscriber one block. Advisory only; the config is unchanged.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: CM-6, SC-5 (planning support only, no enforcement) -
///   capacity planning guidance
/// - RFC 6888 REQ-4, RFC 7422 - port-block sizing; RFC 6056 / RFC 6888
///   REQ-15 - smaller blocks give fewer bits of in-block port randomness
fn smaller_blocks_hint(cfg: &Config, owned_addrs: u64) -> String {
    let n = &cfg.nat64;
    let max_ports = u32::from(n.port_block_size) * u32::from(n.max_blocks_per_subscriber);
    let mut o = String::new();
    for size in [256u16, 128] {
        // Only layouts that keep the same maximum exactly.
        if size >= n.port_block_size || max_ports % u32::from(size) != 0 {
            continue;
        }
        let Ok(blocks) = u16::try_from(max_ports / u32::from(size)) else { continue };
        let a = n.capacity_with(size, blocks, owned_addrs);
        o.push_str(&format!(
            "  hint: port_block_size = {size}, max_blocks_per_subscriber = {blocks} (same {max_ports} ports max) \
             serves {} at 1 block ({}-bit in-block port randomness; more block records)\n",
            a.subscribers_at_one_block,
            size.trailing_zeros(),
        ));
    }
    o
}

/// Ports one HA reservation covers by default (512-port blocks x 8).
const DEFAULT_RESERVE_AHEAD_PORTS: u32 = 512 * 8;

/// With HA on, a smaller `port_block_size` uses up the reserve-ahead budget
/// (`cluster.ha.reserve_ahead_blocks`, counted in blocks) in fewer ports, so
/// bursts make more Reserve round trips and `cluster_reserve_starved`
/// records. Warning only (exit code unchanged).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: CP-10, CM-6, SC-5 (planning support only, no
///   enforcement) - HA reservation sizing guidance
fn reserve_ahead_advisory(block_size: u16, reserve_ahead: Option<u16>) -> Option<String> {
    let r = reserve_ahead?;
    let ports = u32::from(block_size) * u32::from(r);
    (ports < DEFAULT_RESERVE_AHEAD_PORTS).then(|| {
        let want = DEFAULT_RESERVE_AHEAD_PORTS.div_ceil(u32::from(block_size.max(1))).min(64);
        format!(
            "WARNING: cluster.ha.reserve_ahead_blocks = {r} x port_block_size = {block_size} reserves {ports} ports \
             ahead (default layout {DEFAULT_RESERVE_AHEAD_PORTS}); consider reserve_ahead_blocks = {want}\n"
        )
    })
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_target(false)
        .init();
    match Cli::parse().cmd {
        Cmd::Run { config } => match Config::load(&config) {
            Ok(cfg) => run::run(cfg),
            Err(e) => {
                tracing::error!("{e}");
                ExitCode::from(2)
            }
        },
        // QA-003 / NIST-002: both formats load and check the TLS files (key
        // permissions included) and fail closed with exit 2.
        Cmd::CheckConfig { config, format: OutputFormat::Env, .. } => match Config::load(&config) {
            Ok(cfg) => {
                match tls_summary(&cfg).and_then(|_| render_env(&cfg, &cluster::owned_addrs(&cfg), fips_active())) {
                    Ok(s) => {
                        print!("{s}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        ExitCode::from(2)
                    }
                }
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(2)
            }
        },
        Cmd::CheckConfig { config, format: OutputFormat::Text, unit } => match Config::load(&config) {
            Ok(cfg) => {
                let owned = cluster::owned_addrs(&cfg);
                println!("config OK: node {} ({}/{})", cfg.node.name, cfg.node.id, cfg.cluster.node_count);
                println!("owned pool addresses: {}", owned.len());
                for p in plat_cluster::cover(&owned) {
                    println!("  announce {p}");
                }
                if let (Some(a), Some(b)) = (owned.first(), owned.last()) {
                    println!("  range {} - {}", Ipv4Addr::from(*a), Ipv4Addr::from(*b));
                }
                print!("{}", capacity_summary(&cfg, owned.len() as u64));
                println!("fragment memory per worker: {} bytes (SC-5)", cfg.translation.fragments.memory_per_worker());
                print!("{}", held_syn_summary(&cfg));
                print!("{}", memory_summary(&cfg, unit.as_deref()));
                if let Some(f) = cfg.audit.file.as_ref() {
                    println!("audit file min_free_bytes: {} (AU-5(1))", f.min_free_bytes);
                }
                print!("{}", cluster::summary(&cfg));
                match tls_summary(&cfg) {
                    Ok(t) => {
                        print!("{t}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        ExitCode::from(2)
                    }
                }
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(2)
            }
        },
        Cmd::Witness { config } => witness(&config),
        Cmd::Cluster { config, op } => cluster_cmd(&config, &op),
        Cmd::VerifyLog { files, allow_tail, allow_gap, allow_recovery } => {
            verify_log(&files, Allow { tail: allow_tail, gap: allow_gap, recovery: allow_recovery })
        }
    }
}

#[cfg(feature = "tls")]
fn witness(config: &std::path::Path) -> ExitCode {
    cluster::witness::run(config)
}

#[cfg(not(feature = "tls"))]
fn witness(_config: &std::path::Path) -> ExitCode {
    eprintln!("platd was built without TLS support (feature `tls`): the witness needs mutual TLS");
    ExitCode::from(2)
}

/// `platd cluster ...`: one request on the running daemon's operator socket.
fn cluster_cmd(config: &std::path::Path, op: &ClusterOp) -> ExitCode {
    let cfg = match Config::load(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let Some(ha) = cfg.cluster.ha_active() else {
        eprintln!("[cluster.ha] is not enabled in {}", config.display());
        return ExitCode::from(2);
    };
    let line = match op {
        ClusterOp::Status => "status".to_string(),
        ClusterOp::Takeover { member, force: false } => format!("takeover {member}"),
        ClusterOp::Takeover { member, force: true } => format!("takeover {member} --force"),
        ClusterOp::Restore { member } => format!("restore {member}"),
    };
    #[cfg(feature = "tls")]
    let r = cluster::control::cli_request(&ha.state_dir, &line);
    #[cfg(not(feature = "tls"))]
    let r: Result<String, String> =
        Err(format!("{line}: platd was built without TLS support; no cluster runtime ({})", ha.state_dir.display()));
    match r {
        Ok(out) if out.starts_with("error") => {
            eprint!("{out}");
            ExitCode::from(1)
        }
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

/// `verify-log` acceptance flags.
#[derive(Debug, Clone, Copy, Default)]
struct Allow {
    tail: bool,
    gap: bool,
    recovery: bool,
}

/// `verify-log` exit code for a recovery gap without `--allow-recovery`.
const EXIT_RECOVERY_GAP: u8 = 3;

/// Exit 0: every file verifies and they form one chain; 1: verification
/// failed (or an unverified tail / unexplained gap without the matching
/// flag); 2: I/O; 3: otherwise verified, but a gap is accounted only by an
/// `audit_recovery` record and `--allow-recovery` was not given (1 wins).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-9, AU-6 - a range skipped after a damaged log is not
///   reported as plain OK: the operator must check it against the remote
///   copy (SEC-301).
fn verify_log(files: &[PathBuf], allow: Allow) -> ExitCode {
    use plat_audit::verify::{GapAccount, LinkIssue, link, verify};
    let (allow_tail, allow_gap) = (allow.tail, allow.gap);
    let mut recovery_gap = false;
    let mut reps = Vec::with_capacity(files.len());
    let mut failed = false;
    for f in files {
        match std::fs::File::open(f).and_then(|h| verify(BufReader::new(h))) {
            Ok(r) if r.ok() => {
                println!(
                    "OK: {}: records {}..={} ({}), {} checkpoints, {} unverified trailing records",
                    f.display(),
                    r.next_seq,
                    r.last_seq,
                    r.records,
                    r.checkpoints,
                    r.unverified_tail
                );
                if r.truncated_tail_bytes > 0 {
                    println!(
                        "{}: {}: truncated tail: final partial line of {} bytes (short write or power cut)",
                        if allow_tail { "TAIL" } else { "FAILED" },
                        f.display(),
                        r.truncated_tail_bytes
                    );
                }
                if r.unverified_tail > 0 && !allow_tail {
                    println!("FAILED: {}: {} records after the last checkpoint", f.display(), r.unverified_tail);
                }
                failed |= r.has_unverified_tail() && !allow_tail;
                reps.push(r);
            }
            Ok(r) => {
                println!("FAILED: {}: {}", f.display(), r.error.unwrap_or_default());
                failed = true;
            }
            Err(e) => {
                eprintln!("{}: {e}", f.display());
                return ExitCode::from(2);
            }
        }
    }
    reps.sort_by_key(|r| r.next_seq);
    for issue in link(&reps) {
        match issue {
            // L12: a gap announced by the chain itself (a checkpointed
            // `audit_output_failure` recovered record with exactly this
            // `lost` count opening the next file) is a recorded loss, not a
            // verification failure; any other gap still needs --allow-gap.
            LinkIssue::Gap { index, first, last, accounted: Some(a @ GapAccount::OutputFailure) } => {
                println!(
                    "OK: accounted gap: {first}..={last} ({} lost, {} (recovered) at record {})",
                    last - first + 1,
                    a.record(),
                    reps[index].next_seq
                );
            }
            // SEC-301: a skip announced only by `audit_recovery` (rule b).
            LinkIssue::Gap { index, first, last, accounted: Some(a @ GapAccount::Recovery) } => {
                println!(
                    "{}RECOVERY GAP {first}..={last} (restart after damaged log; verify against the remote copy): \
                     {} at record {}",
                    if allow.recovery { "WARNING: " } else { "" },
                    a.record(),
                    reps[index].next_seq
                );
                recovery_gap |= !allow.recovery;
            }
            LinkIssue::Gap { first, last, accounted: None, .. } => {
                println!(
                    "{}: records {first}..={last} are not in these files",
                    if allow_gap { "GAP" } else { "FAILED" }
                );
                failed |= !allow_gap;
            }
            LinkIssue::Broken { index, reason } => {
                println!("FAILED: file starting at record {}: {reason}", reps[index].next_seq);
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else if recovery_gap {
        ExitCode::from(EXIT_RECOVERY_GAP)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example(edit: &[(&str, &str)]) -> Config {
        let mut text = include_str!("../../../config/platd.example.toml").to_string();
        for (a, b) in edit {
            assert!(text.contains(a), "{a}");
            text = text.replace(a, b);
        }
        Config::from_toml(&text).unwrap()
    }

    /// Tight pool: the warning names smaller uniform layouts with the same
    /// maximum ports per subscriber; an ample pool gets no hint.
    #[test]
    fn capacity_summary_suggests_smaller_blocks() {
        let s = capacity_summary(&example(&[]), 256);
        assert!(
            s.contains("hint: port_block_size = 256, max_blocks_per_subscriber = 8 (same 2048 ports max) serves 64512 at 1 block (8-bit")
                && s.contains("hint: port_block_size = 128, max_blocks_per_subscriber = 16 (same 2048 ports max) serves 129024 at 1 block (7-bit"),
            "{s}"
        );
        assert!(
            !capacity_summary(&example(&[("max_subscribers = 1000000", "max_subscribers = 8000")]), 256)
                .contains("hint")
        );
        // Already at 128: nothing smaller is suggested.
        let small = example(&[("port_block_size = 512", "port_block_size = 128")]);
        assert!(!capacity_summary(&small, 256).contains("hint"));
    }

    #[test]
    fn reserve_ahead_advisory_scales_with_block_size() {
        assert_eq!(reserve_ahead_advisory(512, None), None);
        assert_eq!(reserve_ahead_advisory(512, Some(8)), None);
        assert_eq!(reserve_ahead_advisory(128, Some(32)), None);
        let w = reserve_ahead_advisory(128, Some(8)).unwrap();
        assert!(
            w.starts_with("WARNING: cluster.ha.reserve_ahead_blocks = 8") && w.contains("reserve_ahead_blocks = 32"),
            "{w}"
        );
        assert!(reserve_ahead_advisory(64, Some(1)).unwrap().contains("reserve_ahead_blocks = 64"));
    }

    /// POAM-021: check-config warns when the unit's MemoryMax is too low.
    #[test]
    fn held_syn_summary_reports_memory_or_why_off() {
        let mut cfg = example(&[]);
        assert!(held_syn_summary(&cfg).starts_with("held SYN memory (worst case): 4456448 bytes"));
        cfg.nat64.filtering = plat_common::config::Filtering::EndpointIndependent;
        assert!(held_syn_summary(&cfg).starts_with("WARNING: nat64.tcp_simultaneous_open has no effect"));
        cfg.nat64.tcp_simultaneous_open = false;
        assert_eq!(held_syn_summary(&cfg), "held SYNs: off\n");
    }

    #[test]
    fn memory_summary_warns_on_small_unit_limit() {
        let cfg = example(&[]);
        let dir = std::env::temp_dir().join(format!("platd-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let unit = dir.join("platd.service");
        std::fs::write(&unit, "[Service]\nMemoryMax=8G\nMemoryMax=64M\n").unwrap();
        let s = memory_summary(&cfg, Some(&unit));
        assert!(
            s.starts_with("memory required: ") && s.contains("WARNING:") && s.contains("MemoryMax=67108864"),
            "{s}"
        );
        std::fs::write(&unit, "[Service]\nMemoryMax=1T\n").unwrap();
        assert!(!memory_summary(&cfg, Some(&unit)).contains("WARNING"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-012: the setup script's routes and forward policy come from the
    /// validated config, for this node's slice of the pool only.
    #[test]
    fn check_config_env_output() {
        let cfg = example(&[]);
        let s = render_env(&cfg, &plat_cluster::owned(&cfg), true).unwrap();
        assert_eq!(
            s,
            format!(
                "PLAT_IF=plat0\nPLAT_NODE_ID=0\nPLAT_NAT64_PREFIX=64:ff9b:1::/96\n\
             PLAT_CLIENT_PREFIXES=2001:db8:100::/40\nPLAT_OWNED_POOL=192.0.2.0/24\nPLAT_FIPS=1\nPLAT_MGMT_TLS=0\n\
             PLAT_CLUSTER_HA=0\nPLAT_POOL_ALL=192.0.2.0/24\n\
             PLAT_CROSS_NODE_HAIRPIN=0\nPLAT_CLUSTER_IFACES=\n\
             PLAT_MEMORY_REQUIRED_BYTES={}\n",
                plat_common::memory::required_bytes(&cfg, plat_common::memory::worker_count(&cfg))
            )
        );
        // Two nodes: node 1 gets only its half of the pool.
        let cfg = example(&[("id = 0", "id = 1"), ("node_count = 1", "node_count = 2")]);
        let s = render_env(&cfg, &plat_cluster::owned(&cfg), false).unwrap();
        assert!(s.contains("PLAT_OWNED_POOL=192.0.2.128/25\n"), "{s}");
        assert!(
            s.contains("PLAT_FIPS=0\nPLAT_MGMT_TLS=0\nPLAT_CLUSTER_HA=0\nPLAT_POOL_ALL=192.0.2.0/24\nPLAT_CROSS_NODE_HAIRPIN=0\nPLAT_CLUSTER_IFACES=\nPLAT_MEMORY_REQUIRED_BYTES="),
            "{s}"
        );
        // Nothing shell-special reaches the script.
        for bad in ["plat0;reboot", "plat 0", "plat$(x)", "averyveryverylongname"] {
            let cfg = example(&[("interface = \"plat0\"", &format!("interface = \"{bad}\""))]);
            assert!(render_env(&cfg, &plat_cluster::owned(&cfg), true).is_err(), "{bad}");
        }
    }

    /// L12: a final partial line is an unverified (truncated) tail: exit 1
    /// without `--allow-tail`, 0 with it; never a chain mismatch.
    #[test]
    fn verify_log_truncated_tail_needs_allow_tail() {
        use plat_audit::{AuditSink, Event, LifecycleKind, Logger, NodeIdent};
        let dir = std::env::temp_dir().join(format!("platd-verify-tail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let mut cfg = example(&[]).audit;
        cfg.syslog.clear();
        cfg.file = Some(plat_common::config::AuditFileConfig {
            path: path.clone(),
            max_bytes: 1 << 30,
            max_files: 0,
            min_free_bytes: 0,
        });
        let (sink, rx) = AuditSink::bounded(64);
        let node = NodeIdent { name: "plat-test".into(), id: 1, pid: 1 };
        let h = Logger::new(cfg, node, rx, sink.stats().clone()).spawn().unwrap();
        for _ in 0..3 {
            sink.emit(Event::Lifecycle { ts_us: 0, kind: LifecycleKind::Start, fips: None, cluster: None });
        }
        drop(sink);
        h.join();
        let files = [path.clone()];
        assert_eq!(verify_log(&files, Allow::default()), ExitCode::SUCCESS);
        let text = std::fs::read(&path).unwrap();
        std::fs::write(&path, &text[..text.len() - 30]).unwrap();
        assert_eq!(verify_log(&files, Allow::default()), ExitCode::from(1));
        assert_eq!(verify_log(&files, Allow { tail: true, ..Allow::default() }), ExitCode::SUCCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// L12: after an ENOSPC outage the next file opens with a recovered
    /// `audit_output_failure` whose `lost` covers the sequence gap: strict
    /// verify-log passes; the same gap without it, or with another count,
    /// fails (and still passes with --allow-gap).
    #[test]
    fn verify_log_accepts_only_a_gap_announced_with_its_exact_size() {
        use plat_audit::logger::{chain_seed, chain_step};
        use plat_audit::verify::verify;
        use plat_audit::{AuditSink, Event, LifecycleKind, Logger, NodeIdent};
        use sha2::{Digest, Sha256};
        let dir = std::env::temp_dir().join(format!("platd-verify-gap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let mut cfg = example(&[]).audit;
        cfg.syslog.clear();
        cfg.file = Some(plat_common::config::AuditFileConfig {
            path: path.clone(),
            max_bytes: 1 << 30,
            max_files: 0,
            min_free_bytes: 0,
        });
        let (sink, rx) = AuditSink::bounded(64);
        let node = NodeIdent { name: "plat-test".into(), id: 1, pid: 1 };
        let h = Logger::new(cfg, node, rx, sink.stats().clone()).spawn().unwrap();
        for _ in 0..3 {
            sink.emit(Event::Lifecycle { ts_us: 0, kind: LifecycleKind::Start, fips: None, cluster: None });
        }
        drop(sink);
        h.join();
        let a = verify(std::io::BufReader::new(std::fs::File::open(&path).unwrap())).unwrap();
        assert!(a.ok() && !a.has_unverified_tail(), "{a:?}");

        // The file opened on recovery, 42 sequence numbers after `a`.
        let next = a.last_seq + 43;
        let recovered = |lost: Option<u64>| {
            let header = format!(
                "{{\"event.action\":\"audit_chain_continue\",\"plat.audit.prev_chain\":\"{}\",\
                 \"plat.audit.prev_seq\":{},\"plat.audit.next_seq\":{next}}}\n",
                a.final_chain, a.last_checkpoint_seq
            );
            let rec = match lost {
                Some(n) => format!(
                    "{{\"event.sequence\":{next},\"event.action\":\"audit_output_failure\",\
                     \"plat.audit.destination\":\"file\",\"plat.audit.state\":\"recovered\",\"plat.audit.lost\":{n}}}\n"
                ),
                None => format!("{{\"event.sequence\":{next},\"event.action\":\"service_start\"}}\n"),
            };
            let digest: [u8; 32] = Sha256::digest(rec.as_bytes()).into();
            let chain = chain_step(&chain_seed(header.as_bytes()), &digest, next, next);
            let cp = format!(
                "{{\"event.action\":\"audit_checkpoint\",\"plat.audit.seq_first\":{next},\"plat.audit.seq_last\":{next},\
                 \"plat.audit.batch_sha256\":\"{}\",\"plat.audit.chain_sha256\":\"{}\"}}\n",
                hex::encode(digest),
                hex::encode(chain)
            );
            let p = dir.join("audit.jsonl.2");
            std::fs::write(&p, format!("{header}{rec}{cp}")).unwrap();
            [path.clone(), p]
        };
        assert_eq!(verify_log(&recovered(Some(42)), Allow::default()), ExitCode::SUCCESS);
        for wrong in [None, Some(41), Some(43)] {
            let files = recovered(wrong);
            assert_eq!(verify_log(&files, Allow::default()), ExitCode::from(1), "{wrong:?}");
            assert_eq!(verify_log(&files, Allow { gap: true, ..Allow::default() }), ExitCode::SUCCESS, "{wrong:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Runs the logger once on `path` with `n` lifecycle records.
    fn log_once(path: &std::path::Path, n: usize) {
        use plat_audit::{AuditSink, Event, LifecycleKind, Logger, NodeIdent};
        let mut cfg = example(&[]).audit;
        cfg.syslog.clear();
        cfg.file = Some(plat_common::config::AuditFileConfig {
            path: path.to_path_buf(),
            max_bytes: 1 << 30,
            max_files: 0,
            min_free_bytes: 0,
        });
        let (sink, rx) = AuditSink::bounded(64);
        let node = NodeIdent { name: "plat-test".into(), id: 1, pid: 1 };
        let h = Logger::new(cfg, node, rx, sink.stats().clone()).spawn().unwrap();
        for _ in 0..n {
            sink.emit(Event::Lifecycle { ts_us: 0, kind: LifecycleKind::Start, fips: None, cluster: None });
        }
        drop(sink);
        h.join();
    }

    /// L12 stacked damage (run 3): the live file is truncated mid-line,
    /// start-up writes `truncated_tail` into a new file, that file is
    /// emptied, start-up writes `empty_file` naming the same checkpoint. The
    /// partial-line predecessor followed by the `empty_file` recovery is a
    /// RECOVERY GAP (3, 0 with --allow-recovery; the partial line still
    /// needs --allow-tail), never an unexplained break.
    #[test]
    fn verify_log_accepts_an_emptied_truncated_tail_recovery_file() {
        let dir = std::env::temp_dir().join(format!("platd-verify-stacked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let audit_files = || {
            let mut v: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.file_name().is_some_and(|n| !n.to_string_lossy().starts_with('.')))
                .collect();
            v.sort();
            v
        };
        log_once(&path, 3);
        // Truncate the live file inside its last line, restart.
        let text = std::fs::read(&path).unwrap();
        std::fs::write(&path, &text[..text.len() - 30]).unwrap();
        log_once(&path, 2);
        let files = audit_files();
        assert_eq!(files.len(), 2, "{files:?}");
        assert_eq!(verify_log(&files, Allow { tail: true, recovery: true, ..Allow::default() }), ExitCode::SUCCESS);
        // Empty the new live file (holds the truncated_tail record), restart.
        std::fs::File::create(&path).unwrap();
        log_once(&path, 2);
        let files = audit_files();
        assert!(files.len() >= 2, "{files:?}");
        assert_eq!(verify_log(&files, Allow::default()), ExitCode::from(1), "partial line needs --allow-tail");
        assert_eq!(verify_log(&files, Allow { tail: true, ..Allow::default() }), ExitCode::from(EXIT_RECOVERY_GAP));
        assert_eq!(
            verify_log(&files, Allow { tail: true, gap: true, ..Allow::default() }),
            ExitCode::from(EXIT_RECOVERY_GAP)
        );
        assert_eq!(verify_log(&files, Allow { tail: true, recovery: true, ..Allow::default() }), ExitCode::SUCCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-301: a gap accounted only by `audit_recovery` (restart after the
    /// newest file was emptied) exits 3, or 0 with --allow-recovery; an
    /// unexplained problem on top still exits 1. Exit 2: unreadable file.
    #[test]
    fn verify_log_recovery_gap_has_its_own_exit_code() {
        let dir = std::env::temp_dir().join(format!("platd-verify-recovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        log_once(&path, 3);
        let old = dir.join("audit.jsonl.1");
        std::fs::rename(&path, &old).unwrap();
        std::fs::File::create(&path).unwrap(); // power cut emptied the live file
        log_once(&path, 2);
        let files = [old.clone(), path.clone()];
        assert_eq!(verify_log(&files, Allow::default()), ExitCode::from(EXIT_RECOVERY_GAP));
        assert_eq!(verify_log(&files, Allow { gap: true, ..Allow::default() }), ExitCode::from(EXIT_RECOVERY_GAP));
        assert_eq!(verify_log(&files, Allow { recovery: true, ..Allow::default() }), ExitCode::SUCCESS);
        // Plus a partial final line (checkpoints intact): failure (1) wins
        // over 3.
        let mut text = std::fs::read(&path).unwrap();
        text.extend_from_slice(b"{\"@timestamp\":\"20");
        std::fs::write(&path, &text).unwrap();
        assert_eq!(verify_log(&files, Allow::default()), ExitCode::from(1));
        assert_eq!(verify_log(&files, Allow { tail: true, ..Allow::default() }), ExitCode::from(EXIT_RECOVERY_GAP));
        // I/O error.
        assert_eq!(verify_log(&[dir.join("missing")], Allow::default()), ExitCode::from(2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
