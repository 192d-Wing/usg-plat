//! `platd` — multithreaded 464XLAT PLAT (RFC 6877) / stateful NAT64 (RFC 6146).

mod cluster;
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
        Cmd::CheckConfig { config, format: OutputFormat::Env } => match Config::load(&config) {
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
        Cmd::CheckConfig { config, format: OutputFormat::Text } => match Config::load(&config) {
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

    /// SEC-012: the setup script's routes and forward policy come from the
    /// validated config, for this node's slice of the pool only.
    #[test]
    fn check_config_env_output() {
        let cfg = example(&[]);
        let s = render_env(&cfg, &plat_cluster::owned(&cfg), true).unwrap();
        assert_eq!(
            s,
            "PLAT_IF=plat0\nPLAT_NODE_ID=0\nPLAT_NAT64_PREFIX=64:ff9b:1::/96\n\
             PLAT_CLIENT_PREFIXES=2001:db8:100::/40\nPLAT_OWNED_POOL=192.0.2.0/24\nPLAT_FIPS=1\nPLAT_MGMT_TLS=0\n\
             PLAT_CLUSTER_HA=0\nPLAT_POOL_ALL=192.0.2.0/24\n"
        );
        // Two nodes: node 1 gets only its half of the pool.
        let cfg = example(&[("id = 0", "id = 1"), ("node_count = 1", "node_count = 2")]);
        let s = render_env(&cfg, &plat_cluster::owned(&cfg), false).unwrap();
        assert!(s.contains("PLAT_OWNED_POOL=192.0.2.128/25\n"), "{s}");
        assert!(s.ends_with("PLAT_FIPS=0\nPLAT_MGMT_TLS=0\nPLAT_CLUSTER_HA=0\nPLAT_POOL_ALL=192.0.2.0/24\n"), "{s}");
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
