//! `plat-xdp-loader`: the one-shot privileged step of the XDP fast path
//! (plan §7). Run by `plat-xdp.service` (`ExecStart=… attach`, `ExecStop=…
//! detach`) as root with only `CAP_BPF` and `CAP_NET_ADMIN`; it creates
//! fresh maps, seeds and freezes them, loads, pins and attaches the
//! embedded program under the dedicated bpffs mount `/run/plat/bpf`, writes
//! `/run/plat/xdp.state`, and exits. Nothing privileged keeps running;
//! `platd` then opens the pins without capabilities.
//!
//! - `attach -c FILE`: the `platd` configuration (same validation as
//!   `platd`, plus `[xdp]`).
//! - `detach`: unpins every link (detaching the program) and every map.
//! - `status`: which pins exist, and the state file.
//!
//! Logs go to stderr (journald). Exit codes: 0 ok, 1 refused or failed,
//! 2 usage or configuration error. A failed attach removes the pins it
//! created and the stale state file (fail closed: `platd` then finds no
//! maps).
//!
//! The program derives the frame length with `bpf_xdp_get_buff_len`, not
//! by subtracting packet pointers, so CAP_BPF and CAP_NET_ADMIN suffice and the verifier keeps its
//! Spectre v1/v4 hardening (no CAP_PERFMON, SEC-001). It refuses kernels
//! below the `[xdp]` minimum 6.6 before creating anything (older verifiers
//! need CAP_PERFMON for this object; closed POAM-040). The state file goes
//! through `plat_xdp::load::StateDir` (owner and mode checked, no link
//! followed), and a state file that cannot be written rolls the attach
//! back.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-6 (Least Privilege), AC-6(1) - privileged loading
//!   isolated in a short-lived binary with no network input
//! - NIST 800-53: AC-6(9) - every action and refusal logged to journald
//! - NIST 800-53: AC-6(10) - refuses unless
//!   `kernel.unprivileged_bpf_disabled ≥ 1` (in `plat_xdp::load`)
//! - NIST 800-53: SI-7 - the embedded object's SHA-256 is printed and
//!   recorded in the state file and the `CONFIG` digest

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "plat-xdp-loader", version, about = "Load, pin and attach the usg-plat XDP fast path")]
struct Cli {
    /// Pin directory (the dedicated bpffs mount; fixed in production).
    #[arg(long, default_value = plat_xdp::PIN_DIR, hide = true)]
    pin_dir: PathBuf,
    /// State file for plat-fwguard and `status`.
    #[arg(long, default_value = plat_xdp::STATE_FILE, hide = true)]
    state_file: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create maps, load, pin and attach (replaces a running program
    /// atomically).
    Attach {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Unpin links and maps (detaches the program).
    Detach,
    /// Show pins and the state file.
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            eprintln!("plat-xdp-loader: {msg}");
            ExitCode::from(code)
        }
    }
}

fn read_params(path: &Path) -> Result<plat_xdp::load::LoadParams, (u8, String)> {
    let cfg = plat_common::Config::load(path).map_err(|e| (2, e.to_string()))?;
    Ok(plat_xdp::load::LoadParams::from_config(&cfg))
}

#[cfg(target_os = "linux")]
fn run(cli: &Cli) -> Result<(), (u8, String)> {
    use plat_xdp::load::Loader;
    let fail = |e: plat_xdp::load::LoadError| (1, e.to_string());
    match &cli.cmd {
        Cmd::Attach { config } => {
            let p = read_params(config)?;
            eprintln!(
                "plat-xdp-loader: attaching object sha256 {} ({} interfaces, mode {}, max_sessions {})",
                plat_xdp::object_sha256_hex(),
                p.xdp.interfaces.len(),
                p.xdp.mode.as_str(),
                p.xdp.max_sessions
            );
            let r = Loader::attach(&p, &cli.pin_dir, Some(&cli.state_file)).map_err(fail)?;
            for i in &r.interfaces {
                eprintln!(
                    "plat-xdp-loader: {} ifindex {} role {} {}",
                    i.name,
                    i.ifindex,
                    i.role.as_str(),
                    if i.replaced { "replaced" } else { "attached" }
                );
            }
            eprintln!("plat-xdp-loader: program id {} tag {}", r.prog_id, r.prog_tag);
            Ok(())
        }
        Cmd::Detach => {
            let gone = Loader::detach(&cli.pin_dir, Some(&cli.state_file)).map_err(fail)?;
            eprintln!("plat-xdp-loader: removed {} pins: {}", gone.len(), gone.join(" "));
            Ok(())
        }
        Cmd::Status => {
            print!("{}", Loader::status(&cli.pin_dir, Some(&cli.state_file)).map_err(fail)?);
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(cli: &Cli) -> Result<(), (u8, String)> {
    if let Cmd::Attach { config } = &cli.cmd {
        read_params(config)?;
    }
    Err((1, "the XDP fast path needs Linux".into()))
}
