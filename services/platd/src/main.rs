//! `platd` — multithreaded 464XLAT PLAT (RFC 6877) / stateful NAT64 (RFC 6146).

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
    /// Verify the hash chain of audit log files (AU-9). Pass the live file
    /// and its rotated predecessors (any order) to check that they link
    /// into one chain.
    VerifyLog {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Accept records after the last checkpoint (live file, crash).
        #[arg(long)]
        allow_tail: bool,
        /// Accept sequence gaps between files (records lost while the local
        /// file was not writable; see `audit_output_failure`).
        #[arg(long)]
        allow_gap: bool,
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
                match tls_summary(&cfg).and_then(|_| render_env(&cfg, &plat_cluster::owned(&cfg), fips_active())) {
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
                let owned = plat_cluster::owned(&cfg);
                println!("config OK: node {} ({}/{})", cfg.node.name, cfg.node.id, cfg.cluster.node_count);
                println!("owned pool addresses: {}", owned.len());
                for p in plat_cluster::cover(&owned) {
                    println!("  announce {p}");
                }
                if let (Some(a), Some(b)) = (owned.first(), owned.last()) {
                    println!("  range {} - {}", Ipv4Addr::from(*a), Ipv4Addr::from(*b));
                }
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
        Cmd::VerifyLog { files, allow_tail, allow_gap } => verify_log(&files, allow_tail, allow_gap),
    }
}

/// Exit 0: every file verifies and they form one chain; 1: verification
/// failed (or an unverified tail / gap without the matching flag); 2: I/O.
fn verify_log(files: &[PathBuf], allow_tail: bool, allow_gap: bool) -> ExitCode {
    use plat_audit::verify::{LinkIssue, link, verify};
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
                if r.unverified_tail > 0 && !allow_tail {
                    println!("FAILED: {}: {} records after the last checkpoint", f.display(), r.unverified_tail);
                    failed = true;
                }
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
            LinkIssue::Gap { first, last, .. } => {
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
    if failed { ExitCode::from(1) } else { ExitCode::SUCCESS }
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
             PLAT_CLIENT_PREFIXES=2001:db8:100::/40\nPLAT_OWNED_POOL=192.0.2.0/24\nPLAT_FIPS=1\nPLAT_MGMT_TLS=0\n"
        );
        // Two nodes: node 1 gets only its half of the pool.
        let cfg = example(&[("id = 0", "id = 1"), ("node_count = 1", "node_count = 2")]);
        let s = render_env(&cfg, &plat_cluster::owned(&cfg), false).unwrap();
        assert!(s.contains("PLAT_OWNED_POOL=192.0.2.128/25\n"), "{s}");
        assert!(s.ends_with("PLAT_FIPS=0\nPLAT_MGMT_TLS=0\n"), "{s}");
        // Nothing shell-special reaches the script.
        for bad in ["plat0;reboot", "plat 0", "plat$(x)", "averyveryverylongname"] {
            let cfg = example(&[("interface = \"plat0\"", &format!("interface = \"{bad}\""))]);
            assert!(render_env(&cfg, &plat_cluster::owned(&cfg), true).is_err(), "{bad}");
        }
    }
}
