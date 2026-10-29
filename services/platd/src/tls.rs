//! TLS wiring for `platd`: the FIPS start gate, the shared revocation
//! checker (hooks bound to the audit sink), management TLS material, the
//! TLS metric sections, and the `check-config` TLS summary.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-13 (Cryptographic Protection) - `fips_gate` refuses to
//!   start unless the AWS-LC FIPS module is active (`tls.require_fips`,
//!   default true); the state is recorded on `service_start`
//! - NIST 800-53: IA-5(2)(b)(1), AU-2, AU-12 - one shared checker for management
//!   client chains and syslog collector chains; every check and every
//!   refresher state change is audited
//! - NIST 800-53: CM-6 - `check-config` loads every TLS file with the same
//!   code (and permission checks) as the daemon, failing closed

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use plat_audit::FipsMark;
use plat_audit::tls::{TlsOptions, refresh_event, revocation_event};
use plat_common::Config;
use plat_common::config::{RevocationConfig, RevocationMode, SyslogTransport};
use plat_tls::revocation::{RecordStatus, RefreshKind, RefreshTransition, Role, Source};
use plat_tls::{
    AllowList, RefreshHook, RefreshRecord, RevocationChecker, RevocationHook, RevocationRecord, RevocationSettings,
};

use crate::metrics::Section;
use crate::mgmt::{MgmtStats, MgmtTls, RejectLimiter};
use crate::run::HookSink;

/// SC-13 start gate. Installs the FIPS provider (idempotent). With
/// `tls.require_fips` an inactive module is an error (refuse to start);
/// without it the daemon starts and records `plat.fips = false`.
pub fn fips_gate(cfg: &Config) -> Result<FipsMark, String> {
    let st = plat_tls::init_fips();
    let active = match plat_tls::require_fips() {
        Ok(()) => true,
        Err(e) if cfg.tls.require_fips => return Err(format!("{e}; refusing to start (tls.require_fips = true)")),
        Err(e) => {
            tracing::warn!("{e}; starting anyway because tls.require_fips = false (recorded as plat.fips=false)");
            false
        }
    };
    Ok(FipsMark { active, provider: st.provider })
}

const ROLES: usize = 2;
const STATUSES: usize = 5;
const SOURCES: usize = 7;

fn role_ix(r: Role) -> usize {
    match r {
        Role::MgmtClient => 0,
        Role::SyslogServer => 1,
    }
}

const STATUS_NAMES: [&str; STATUSES] = ["good", "revoked", "unavailable", "fatal", "not_checked"];
const SOURCE_NAMES: [&str; SOURCES] =
    ["ocsp_stapled", "ocsp_cache", "ocsp_fetch", "crl_cache", "crl_fetch", "crl_file", "none"];
const ROLE_NAMES: [&str; ROLES] = ["mgmt_client", "syslog_server"];

fn status_ix(s: RecordStatus) -> usize {
    match s {
        RecordStatus::Good => 0,
        RecordStatus::Revoked => 1,
        RecordStatus::Unavailable => 2,
        RecordStatus::Fatal => 3,
        RecordStatus::NotChecked => 4,
    }
}

fn source_ix(s: Source) -> usize {
    match s {
        Source::OcspStapled => 0,
        Source::OcspCache => 1,
        Source::OcspFetch => 2,
        Source::CrlCache => 3,
        Source::CrlFetch => 4,
        Source::CrlFile => 5,
        Source::None => 6,
    }
}

/// Revocation counters (`plat_revocation_*`).
#[derive(Debug, Default)]
pub struct RevocationMetrics {
    checks: [[[AtomicU64; SOURCES]; STATUSES]; ROLES],
    /// Refresher failure transitions: [crl, ocsp].
    refresh_failures: [AtomicU64; 2],
}

impl RevocationMetrics {
    fn check(&self, r: &RevocationRecord) {
        let c = self
            .checks
            .get(role_ix(r.role))
            .and_then(|s| s.get(status_ix(r.status)))
            .and_then(|s| s.get(source_ix(r.source)));
        if let Some(c) = c {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn refresh(&self, r: &RefreshRecord) {
        // State records are counted by `plat_crl_state_errors_total`.
        if matches!(
            r.transition,
            RefreshTransition::Recovered | RefreshTransition::StateRejected | RefreshTransition::StatePersistFailed
        ) {
            return;
        }
        let i = match r.kind {
            RefreshKind::Crl => 0,
            RefreshKind::Ocsp => 1,
        };
        if let Some(c) = self.refresh_failures.get(i) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn render(&self, o: &mut String, checker: Option<&RevocationChecker>) {
        o.push_str("# TYPE plat_revocation_checks_total counter\n");
        for (ri, role) in self.checks.iter().enumerate() {
            for (si, status) in role.iter().enumerate() {
                for (oi, v) in status.iter().enumerate() {
                    let v = v.load(Ordering::Relaxed);
                    if v > 0 {
                        let _ = writeln!(
                            o,
                            "plat_revocation_checks_total{{role=\"{}\",status=\"{}\",source=\"{}\"}} {v}",
                            ROLE_NAMES.get(ri).unwrap_or(&""),
                            STATUS_NAMES.get(si).unwrap_or(&""),
                            SOURCE_NAMES.get(oi).unwrap_or(&""),
                        );
                    }
                }
            }
        }
        let [crl, ocsp] = &self.refresh_failures;
        let _ = write!(
            o,
            "# TYPE plat_revocation_refresh_failures_total counter\n\
             plat_revocation_refresh_failures_total{{kind=\"crl\"}} {}\n\
             plat_revocation_refresh_failures_total{{kind=\"ocsp\"}} {}\n",
            crl.load(Ordering::Relaxed),
            ocsp.load(Ordering::Relaxed),
        );
        if let Some(c) = checker {
            let st = c.cache_stats();
            let _ = write!(
                o,
                "# TYPE plat_ocsp_cache_entries gauge\nplat_ocsp_cache_entries {}\n\
                 # TYPE plat_crl_cache_entries gauge\nplat_crl_cache_entries {}\n\
                 # TYPE plat_crl_cache_bytes gauge\nplat_crl_cache_bytes {}\n\
                 # TYPE plat_crl_state_errors_total counter\nplat_crl_state_errors_total {}\n",
                st.ocsp_entries, st.crl_entries, st.crl_bytes, st.crl_state_errors,
            );
        }
    }
}

/// Everything TLS that `run` owns.
pub struct TlsRuntime {
    /// Shared checker (management + syslog without override); `None` when
    /// no TLS endpoint is configured.
    pub checker: Option<Arc<RevocationChecker>>,
    /// Hook for checkers created by the logger (syslog overrides).
    pub hook: RevocationHook,
    pub metrics: Arc<RevocationMetrics>,
    pub mgmt: Option<MgmtTls>,
    pub mgmt_stats: Arc<MgmtStats>,
    pub limiter: Arc<RejectLimiter>,
    /// `(role, file, notAfter)` for `plat_tls_cert_expiry_seconds`.
    pub expiry: Vec<(&'static str, String, u64)>,
}

impl std::fmt::Debug for TlsRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsRuntime").field("checker", &self.checker).finish_non_exhaustive()
    }
}

/// The revocation hook: counts and queues the record. Never blocks.
///
/// Management-client records are held on the connection thread until the
/// allow-list decision (`mgmt::defer_revocation_event`; emitted all for an
/// authorized client, rate-limited otherwise, SEC-003). Outside a
/// connection thread, rejected management chains share the management
/// rejection bucket.
pub fn revocation_hook(sink: HookSink, metrics: Arc<RevocationMetrics>, limiter: Arc<RejectLimiter>) -> RevocationHook {
    Arc::new(move |r: &RevocationRecord| {
        metrics.check(r);
        let ev = revocation_event(r);
        if r.role == Role::MgmtClient {
            let Some(ev) = crate::mgmt::defer_revocation_event(ev) else { return };
            if !r.allowed && !limiter.admit() {
                return;
            }
            sink.emit(ev);
            return;
        }
        sink.emit(ev);
    })
}

fn first_cert_expiry(path: &Path) -> Result<(String, u64), String> {
    let certs = plat_tls::load_certs(path).map_err(|e| e.to_string())?;
    let s =
        certs.first().and_then(plat_tls::cert_summary).ok_or_else(|| format!("{}: not valid X.509", path.display()))?;
    Ok((s.subject, s.not_after))
}

fn file_label(p: &Path) -> String {
    p.file_name().map_or_else(|| p.display().to_string(), |n| n.to_string_lossy().into_owned())
}

/// Builds the checker (loads `crl.files` and `cache_dir`), the management
/// server config and allow-list, and records certificate expiry. Pure
/// loading, no listener: run before the logger so a bad file fails the
/// start. Records produced meanwhile wait in the audit queue.
pub fn prepare(cfg: &Config, sink: &HookSink) -> Result<TlsRuntime, String> {
    let metrics = Arc::new(RevocationMetrics::default());
    let limiter = Arc::new(RejectLimiter::standard());
    let hook = revocation_hook(sink.clone(), metrics.clone(), limiter.clone());
    let mut rt = TlsRuntime {
        checker: None,
        hook: hook.clone(),
        metrics: metrics.clone(),
        mgmt: None,
        mgmt_stats: Arc::new(MgmtStats::default()),
        limiter,
        expiry: Vec::new(),
    };
    if !cfg.uses_tls() {
        return Ok(rt);
    }
    let refresh: RefreshHook = {
        let (sink, metrics) = (sink.clone(), metrics);
        Arc::new(move |r: &RefreshRecord| {
            metrics.refresh(r);
            sink.emit(refresh_event(r));
        })
    };
    let checker =
        RevocationChecker::new_with_refresh_hook(RevocationSettings::from(&cfg.tls.revocation), hook, refresh)
            .map_err(|e| format!("tls.revocation: {e}"))?;
    if let Some(t) = &cfg.management.tls {
        let settings = plat_tls::ServerSettings::from_config(t, cfg.tls.pq_hybrid, Some(checker.clone()));
        let config = plat_tls::server_config(&settings).map_err(|e| format!("management.tls: {e}"))?;
        let allow = AllowList::new(&t.allowed_clients).map_err(|e| format!("management.tls.allowed_clients: {e}"))?;
        let (_, exp) = first_cert_expiry(&t.cert_file).map_err(|e| format!("management.tls: {e}"))?;
        rt.expiry.push(("mgmt", file_label(&t.cert_file), exp));
        rt.mgmt = Some(MgmtTls {
            config,
            allow,
            max_connections: usize::try_from(t.max_connections).unwrap_or(1),
            max_per_ip: usize::try_from(t.max_connections_per_ip).unwrap_or(1),
            handshake_timeout: Duration::from_millis(t.handshake_timeout_ms),
        });
    }
    for s in cfg.audit.syslog.iter().filter(|s| s.transport == SyslogTransport::Tls) {
        if let Some(c) = s.tls.as_ref().and_then(|t| t.cert_file.as_ref()) {
            let (_, exp) = first_cert_expiry(c).map_err(|e| format!("audit.syslog {}: {e}", s.address))?;
            rt.expiry.push(("syslog_client", file_label(c), exp));
        }
    }
    rt.checker = Some(checker);
    Ok(rt)
}

impl TlsRuntime {
    /// Options for `Logger::with_tls`.
    pub fn logger_options(&self, cfg: &Config) -> TlsOptions {
        TlsOptions {
            pq_hybrid: cfg.tls.pq_hybrid,
            revocation: cfg.tls.revocation.clone(),
            shared: self.checker.clone(),
            hook: self.hook.clone(),
        }
    }

    /// Metric sections for `/metrics`.
    pub fn sections(&self) -> Vec<Section> {
        let mut v: Vec<Section> = Vec::new();
        if self.mgmt.is_some() {
            let s = self.mgmt_stats.clone();
            v.push(Box::new(move |o: &mut String| s.render(o)));
        }
        if let Some(c) = &self.checker {
            let (m, c) = (self.metrics.clone(), c.clone());
            v.push(Box::new(move |o: &mut String| m.render(o, Some(&c))));
        }
        if !self.expiry.is_empty() {
            let e = self.expiry.clone();
            v.push(Box::new(move |o: &mut String| {
                o.push_str("# TYPE plat_tls_cert_expiry_seconds gauge\n");
                for (role, file, t) in &e {
                    let _ = writeln!(o, "plat_tls_cert_expiry_seconds{{role=\"{role}\",file=\"{file}\"}} {t}");
                }
            }));
        }
        v
    }
}

// ------------------------------------------------------- check-config

/// `YYYY-MM-DD` (UTC) of a Unix time (civil-from-days).
fn date(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Expiry warning threshold for `check-config`.
const EXPIRY_WARN_SECS: u64 = 30 * 86_400;

fn describe_cert(o: &mut String, warn: &mut Vec<String>, what: &str, path: &Path, now: u64) -> Result<(), String> {
    let (subject, exp) = first_cert_expiry(path)?;
    let _ = writeln!(o, "    {what}: {subject}, expires {}", date(exp));
    if exp <= now {
        warn.push(format!("{what} {} has EXPIRED", path.display()));
    } else if exp - now < EXPIRY_WARN_SECS {
        warn.push(format!("{what} {} expires in {} days", path.display(), (exp - now) / 86_400));
    }
    Ok(())
}

fn describe_revocation(o: &mut String, warn: &mut Vec<String>, r: &RevocationConfig, indent: &str) {
    let _ = writeln!(
        o,
        "{indent}revocation: {} (budget {} ms, skew {} s)",
        r.mode.as_str(),
        r.budget_ms,
        r.clock_skew_secs
    );
    if r.mode == RevocationMode::Off {
        warn.push("tls.revocation.mode = \"off\": certificate revocation is not checked".into());
        return;
    }
    if r.ocsp.enabled {
        let responder = match &r.ocsp.responder_url {
            Some(u) => format!("{u} (leaf), AIA for intermediates: {}", r.ocsp.use_aia),
            None if r.ocsp.use_aia => "AIA".into(),
            None => "none".into(),
        };
        let _ = writeln!(o, "{indent}  OCSP: enabled, responder {responder}, nonce {}", r.ocsp.nonce);
    } else {
        let _ = writeln!(o, "{indent}  OCSP: disabled");
    }
    if r.crl.enabled {
        let _ = writeln!(
            o,
            "{indent}  CRL: enabled, CDP {}, {} URL(s), {} file(s)",
            r.crl.use_cdp,
            r.crl.urls.len(),
            r.crl.files.len()
        );
    } else {
        let _ = writeln!(o, "{indent}  CRL: disabled");
    }
    let _ = writeln!(
        o,
        "{indent}  cache_dir: {}",
        r.cache_dir.as_ref().map_or_else(|| "none (in-memory only)".into(), |d| d.display().to_string())
    );
}

/// The TLS section of `check-config`: loads and checks every configured
/// TLS file (same loaders and permission checks as the daemon). `Err` on
/// any unusable file (fail closed).
pub fn summary(cfg: &Config) -> Result<String, String> {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let st = plat_tls::init_fips();
    let mut o = String::from("TLS:\n");
    let mut warn = Vec::new();
    let active = plat_tls::require_fips().is_ok();
    let _ = writeln!(
        o,
        "  FIPS: {} ({}; {}), require_fips = {}",
        if active { "active" } else { "INACTIVE" },
        st.provider,
        st.detail,
        cfg.tls.require_fips
    );
    if !active && cfg.tls.require_fips {
        warn.push("the FIPS module is not active: platd run will refuse to start".into());
    }
    let groups = plat_tls::policy::kx_group_names(cfg.tls.pq_hybrid).map_err(|e| e.to_string())?;
    let suites = plat_tls::policy::cipher_suite_names().map_err(|e| e.to_string())?;
    let _ = writeln!(
        o,
        "  policy: TLS 1.3 only; suites {}; groups {} (pq_hybrid = {})",
        suites.join(", "),
        groups.join(", "),
        cfg.tls.pq_hybrid
    );
    match (&cfg.management.listen, &cfg.management.tls) {
        (None, _) => o.push_str("  management: disabled\n"),
        (Some(a), None) => {
            let _ = writeln!(o, "  management: plain-loopback {a}");
        }
        (Some(a), Some(t)) => {
            let _ = writeln!(
                o,
                "  management: mTLS {a}, {} allowed client(s), max_connections {}, handshake_timeout_ms {}",
                t.allowed_clients.len(),
                t.max_connections,
                t.handshake_timeout_ms
            );
            let settings = plat_tls::ServerSettings::from_config(t, cfg.tls.pq_hybrid, None);
            plat_tls::server_config(&settings).map_err(|e| format!("management.tls: {e}"))?;
            describe_cert(&mut o, &mut warn, "server certificate", &t.cert_file, now)?;
            describe_cert(&mut o, &mut warn, "client CA", &t.client_ca_file, now)?;
        }
    }
    for s in &cfg.audit.syslog {
        let Some(t) = s.tls.as_ref().filter(|_| s.transport == SyslogTransport::Tls) else {
            let tr = match s.transport {
                SyslogTransport::Udp => "udp",
                SyslogTransport::Tcp => "tcp",
                SyslogTransport::Tls => "tls",
            };
            let _ = writeln!(o, "  syslog {}: {tr} (plaintext)", s.address);
            continue;
        };
        let _ = writeln!(o, "  syslog {}: tls, server_name {}", s.address, t.server_name);
        let settings = plat_tls::ClientSettings::from_config(t, cfg.tls.pq_hybrid, None);
        plat_tls::client_config(&settings).map_err(|e| format!("audit.syslog {}: {e}", s.address))?;
        plat_tls::policy::server_name(&t.server_name).map_err(|e| e.to_string())?;
        describe_cert(&mut o, &mut warn, "collector CA", &t.ca_file, now)?;
        match &t.cert_file {
            Some(c) => describe_cert(&mut o, &mut warn, "client certificate", c, now)?,
            None => o.push_str("    client certificate: none\n"),
        }
        if let Some(r) = &t.revocation {
            warn.push(format!(
                "audit.syslog {}: revocation override has its own caches and no background refresher",
                s.address
            ));
            describe_revocation(&mut o, &mut warn, r, "    ");
        }
    }
    describe_revocation(&mut o, &mut warn, &cfg.tls.revocation, "  ");
    if let Some(d) = &cfg.tls.revocation.cache_dir {
        plat_tls::check_cache_dir(d).map_err(|e| format!("tls.revocation.cache_dir: {e}"))?;
    }
    for w in warn {
        let _ = writeln!(o, "WARNING: {w}");
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::test_pki::{Ca, TempDir};

    /// CM-6: `check-config` loads every TLS file through the daemon's
    /// loaders, prints the summary, and fails closed on an unusable key.
    #[test]
    fn check_config_tls_summary() {
        let dir = TempDir::new("summary");
        let ca = Ca::new("summary CA");
        let srv = ca.leaf("mgmt.test", true);
        let ca_file = dir.write("ca.pem", ca.pem.as_bytes());
        let cert = dir.write("mgmt.pem", srv.pem.as_bytes());
        let key = dir.write("mgmt.key", srv.key_pem.as_bytes());
        let text = include_str!("../../../config/platd.example.toml")
            .replace("listen = \"127.0.0.1:9464\"", "listen = \"[2001:db8::10]:9464\"")
            .replace(
                "# [management.tls]",
                &format!(
                    "[management.tls]\ncert_file = {cert:?}\nkey_file = {key:?}\nclient_ca_file = {ca_file:?}\n\
                     allowed_clients = [\"dns:prom.test\", \"uri:spiffe://ops/prom\"]\n"
                ),
            )
            .replace(
                "[[audit.syslog]]\naddress = \"198.51.100.10:514\"\ntransport = \"udp\"",
                &format!(
                    "[[audit.syslog]]\naddress = \"192.0.2.10:6514\"\ntransport = \"tls\"\n\
                     tls = {{ server_name = \"siem.example.net\", ca_file = {ca_file:?} }}"
                ),
            );
        let cfg = Config::from_toml(&text).unwrap();
        let _serial = crate::test_pki::FIPS_HOOK.lock();
        let s = summary(&cfg).unwrap();
        assert!(s.contains("FIPS: active (aws-lc-rs-fips"), "{s}");
        assert!(s.contains("management: mTLS [2001:db8::10]:9464, 2 allowed client(s)"), "{s}");
        assert!(s.contains("server certificate: CN=mgmt.test"), "{s}");
        assert!(s.contains("syslog 192.0.2.10:6514: tls, server_name siem.example.net"), "{s}");
        assert!(s.contains("client certificate: none"), "{s}");
        assert!(s.contains("revocation: hard_fail"), "{s}");
        assert!(s.contains("groups X25519MLKEM768, secp256r1, secp384r1"), "{s}");

        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let e = summary(&cfg).unwrap_err();
        assert!(e.contains("management.tls") && e.contains("permissions"), "{e}");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_793_196_960), "2026-10-28");
    }
}
