//! `platd witness --config <file>`: the tie-breaking voter for two-node
//! clusters. Same binary, mutual TLS only, no data plane: it votes and acks
//! heartbeats, never leads, never serves a slice, and ignores replication.
//!
//! Configuration (TOML, unknown keys refused):
//!
//! ```toml
//! [witness]
//! name = "witness"
//! listen = "192.0.2.20:7946"              # = cluster.ha.witness.addr of the members
//! identity = "dns:witness.cluster.example" # = cluster.ha.witness.identity
//! lease_ms = 3000                          # = cluster.ha.lease_ms (and heartbeat, drift)
//! heartbeat_ms = 500
//! drift_margin_pct = 10
//! state_dir = "/var/lib/plat/witness"      # 0700, votes and terms (cluster.state)
//! members = [
//!     { id = 0, identity = "dns:plat-1.cluster.example", addr = "192.0.2.11:7946" },
//!     { id = 1, identity = "dns:plat-2.cluster.example", addr = "192.0.2.12:7946", weight = 1 },
//! ]
//! [witness.tls]                            # like cluster.ha.tls
//! cert_file = "/etc/plat/tls/witness.crt"
//! key_file = "/etc/plat/tls/witness.key"
//! ca_file = "/etc/plat/tls/ca.crt"
//! [tls]                                    # optional, as in platd.toml (FIPS, revocation)
//! [audit]                                  # required, as in platd.toml, with a
//! [audit.file]                             # file or syslog destination
//! path = "/var/log/plat/witness-audit.jsonl"
//! ```
//!
//! Its voter id is the member count (members are `0..n`). Members and the
//! witness exchange a digest over the voting inputs only (members with
//! identity and weight, witness identity, lease timing), so a witness whose
//! file disagrees with the members is refused (`digest_mismatch`).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-24 - a third voter lets a two-node cluster tell a
//!   partition from a failure (plan decision Q1)
//! - NIST 800-53: IA-3, AC-3 - identity-bound peers; the witness only votes
//! - NIST 800-53: SC-13 - FIPS start gate as for `platd run`
//! - NIST 800-53: AU-2, AU-12 - `[audit]` with a destination is required:
//!   the witness's votes, peer refusals and revocation checks are kept
//!   (NIST-005)

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use plat_audit::{AuditSink, Event, LifecycleKind, Logger, NodeIdent};
use plat_cluster::{DigestMember, MembershipConfig};
use plat_common::Clock;
use plat_common::config::{AuditConfig, ClusterTlsConfig, TlsConfig};
use serde::Deserialize;

use super::control::{Core, Voter, check_state_dir, launch, peer_specs, random_seed};
use super::peer::NetConfig;
use super::voting_digest;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessFile {
    pub witness: WitnessSection,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSection {
    pub name: String,
    pub listen: SocketAddr,
    #[serde(default)]
    pub allow_wildcard: bool,
    pub identity: String,
    #[serde(default = "d_lease")]
    pub lease_ms: u64,
    #[serde(default = "d_hb")]
    pub heartbeat_ms: u64,
    #[serde(default = "d_drift")]
    pub drift_margin_pct: u8,
    #[serde(default = "d_dir")]
    pub state_dir: PathBuf,
    pub members: Vec<WitnessMember>,
    pub tls: ClusterTlsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessMember {
    pub id: u16,
    pub identity: String,
    pub addr: SocketAddr,
    #[serde(default = "d_weight")]
    pub weight: u16,
    #[serde(default)]
    pub name: Option<String>,
}

fn d_lease() -> u64 {
    3000
}
fn d_hb() -> u64 {
    500
}
fn d_drift() -> u8 {
    10
}
fn d_dir() -> PathBuf {
    PathBuf::from("/var/lib/plat/witness")
}
fn d_weight() -> u16 {
    1
}

impl WitnessFile {
    pub fn load(p: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        Self::from_toml(&text)
    }

    /// Parses and validates (same ranges as `[cluster.ha]`).
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let f: WitnessFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let w = &f.witness;
        let bad = |m: &str| Err(format!("witness: {m}"));
        if w.name.is_empty()
            || w.name.len() > 64
            || !w.name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return bad("name must be 1..=64 of [A-Za-z0-9._-]");
        }
        if w.listen.port() == 0 || (w.listen.ip().is_unspecified() && !w.allow_wildcard) {
            return bad("listen needs a non-zero port and no wildcard address unless allow_wildcard = true");
        }
        if !(1000..=30_000).contains(&w.lease_ms) {
            return bad("lease_ms must be 1000..=30000");
        }
        if w.heartbeat_ms < 50 || w.heartbeat_ms > w.lease_ms / 4 {
            return bad("heartbeat_ms must be 50..=lease_ms/4");
        }
        if !(1..=50).contains(&w.drift_margin_pct) {
            return bad("drift_margin_pct must be 1..=50");
        }
        if !w.state_dir.is_absolute() {
            return bad("state_dir must be absolute");
        }
        if w.members.len() < 2 || w.members.len() > 63 {
            return bad("members must list 2..=63 members");
        }
        let mut seen = vec![false; w.members.len()];
        for (i, m) in w.members.iter().enumerate() {
            match seen.get_mut(usize::from(m.id)) {
                Some(s) if !*s => *s = true,
                _ => return bad("member ids must be unique and 0..members"),
            }
            if !(1..=100).contains(&m.weight) {
                return bad("member weight must be 1..=100");
            }
            if m.addr.ip().is_unspecified() || m.addr.port() == 0 {
                return bad("member addr must be unicast with a non-zero port");
            }
            if m.identity == w.identity || w.members[..i].iter().any(|o| o.identity == m.identity || o.addr == m.addr) {
                return bad("member identities and addresses must be unique and differ from the witness");
            }
            plat_tls::AllowList::new(std::slice::from_ref(&m.identity)).map_err(|e| format!("witness: {e}"))?;
        }
        plat_tls::AllowList::new(std::slice::from_ref(&w.identity)).map_err(|e| format!("witness: {e}"))?;
        for p in [&w.tls.cert_file, &w.tls.key_file, &w.tls.ca_file] {
            if !p.is_absolute() {
                return bad("tls files must be absolute paths");
            }
        }
        match &f.audit {
            Some(a) if a.file.is_some() || !a.syslog.is_empty() => {}
            _ => return bad("[audit] with a file or syslog destination is required (AU-12)"),
        }
        Ok(f)
    }

    /// The digest members compute from their `[cluster]` (voting inputs).
    pub fn digest(&self) -> [u8; 32] {
        let w = &self.witness;
        let members: Vec<DigestMember> = w
            .members
            .iter()
            .map(|m| DigestMember { id: m.id, identity: m.identity.clone(), weight: u32::from(m.weight) })
            .collect();
        voting_digest(&members, &w.identity, w.lease_ms, w.heartbeat_ms, w.drift_margin_pct)
    }

    pub fn witness_id(&self) -> u16 {
        u16::try_from(self.witness.members.len()).unwrap_or(u16::MAX)
    }

    fn voters(&self) -> Vec<Voter> {
        let w = &self.witness;
        let mut v: Vec<Voter> = w
            .members
            .iter()
            .map(|m| Voter {
                id: m.id,
                name: m.name.clone().unwrap_or_else(|| format!("member-{}", m.id)),
                identity: m.identity.clone(),
                addr: m.addr,
                witness: false,
            })
            .collect();
        v.push(Voter {
            id: self.witness_id(),
            name: w.name.clone(),
            identity: w.identity.clone(),
            addr: w.listen,
            witness: true,
        });
        v
    }
}

/// Builds and launches the witness voter (also used by tests).
pub fn start(f: &WitnessFile, audit: AuditSink) -> Result<super::ClusterHandle, String> {
    let w = &f.witness;
    check_state_dir(&w.state_dir)?;
    let me = f.witness_id();
    let voters = f.voters();
    let rev = match &w.tls.revocation {
        Some(r) => r.clone(),
        None => f.tls.revocation.clone(),
    };
    let hook: plat_tls::RevocationHook = {
        let a = audit.clone();
        Arc::new(move |r: &plat_tls::RevocationRecord| {
            a.emit(plat_audit::tls::revocation_event(r));
        })
    };
    let checker = plat_tls::RevocationChecker::new(plat_tls::RevocationSettings::from(&rev), hook)
        .map_err(|e| format!("witness revocation: {e}"))?;
    let settings = plat_tls::PeerSettings::from_config(&w.tls, f.tls.pq_hybrid, Some(checker));
    let tls = plat_tls::peer_configs(&settings).map_err(|e| format!("witness.tls: {e}"))?;
    let digest = f.digest();
    let net = NetConfig {
        me,
        name: w.name.clone(),
        listen: w.listen,
        i_am_witness: true,
        peers: peer_specs(&voters, me)?,
        digest_full: digest,
        digest_vote: digest,
        max_frame: 64 << 10,
        queue_bytes: 1 << 20,
        keepalive: Duration::from_millis(w.heartbeat_ms),
        idle_timeout: Duration::from_millis(w.lease_ms * 2),
    };
    let mcfg = MembershipConfig {
        self_id: me,
        members: w.members.iter().map(|m| (m.id, u32::from(m.weight))).collect(),
        witness: Some(me),
        slice_count: 1,
        lease_ms: w.lease_ms,
        heartbeat_ms: w.heartbeat_ms,
        drift_margin_pct: u64::from(w.drift_margin_pct),
        failback_delay_ms: 0,
        auto_failover: true,
        seed: random_seed(),
    };
    launch(Core {
        mcfg,
        voters,
        net,
        tls,
        state_dir: w.state_dir.clone(),
        audit,
        nat: None,
        hub: None,
        shadow: None,
        hooks: None,
        max_handovers: 1,
        shutdown_ms: 0,
        clients: Vec::new(),
        refuse_on_overflow: false,
    })
}

/// `platd witness`: FIPS gate, audit, voter, until SIGTERM/SIGINT.
pub fn run(path: &Path) -> ExitCode {
    let f = match WitnessFile::load(path) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(2);
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        if let Err(e) = signal_hook::flag::register(sig, stop.clone()) {
            tracing::error!("signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }
    let st = plat_tls::init_fips();
    let fips = match plat_tls::require_fips() {
        Ok(()) => true,
        Err(e) if f.tls.require_fips => {
            tracing::error!("{e}; refusing to start (tls.require_fips = true)");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            tracing::warn!("{e}; starting anyway (tls.require_fips = false)");
            false
        }
    };
    let (sink, rx) = AuditSink::bounded(f.audit.as_ref().map_or(65_536, |a| a.queue_capacity));
    let node = NodeIdent { name: f.witness.name.clone(), id: f.witness_id(), pid: std::process::id() };
    let logger = match f.audit.clone() {
        Some(a) => match Logger::new(a, node, rx, sink.stats().clone()).spawn() {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::error!("audit destinations: {e}");
                return ExitCode::FAILURE;
            }
        },
        // Refused by `WitnessFile::from_toml`.
        None => {
            tracing::error!("[audit] is required");
            return ExitCode::FAILURE;
        }
    };
    sink.emit(Event::Lifecycle {
        ts_us: Clock::wall_us(),
        kind: LifecycleKind::Start,
        fips: Some(plat_audit::FipsMark { active: fips, provider: st.provider }),
        cluster: None,
    });
    let code = match start(&f, sink.clone()) {
        Ok(h) => {
            tracing::info!(id = f.witness_id(), listen = %f.witness.listen, "platd witness running");
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
            }
            h.shutdown();
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    };
    sink.emit(Event::Lifecycle { ts_us: Clock::wall_us(), kind: LifecycleKind::Stop, fips: None, cluster: None });
    drop(sink);
    if let Some(l) = logger {
        l.join();
    }
    code
}
