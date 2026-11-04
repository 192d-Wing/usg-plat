//! Deadline-bounded name resolution for OCSP/CRL fetches (hickory DNS).
//!
//! One long-lived `plat-dns` thread owns a tokio current_thread runtime and
//! one `hickory_resolver::TokioResolver` (plain UDP/TCP DNS, no DNSSEC, no
//! encrypted transports). Synchronous callers (handshake threads, the
//! refresher) queue a job on a bounded channel and wait on their own reply
//! channel until the per-chain deadline. On the DNS thread every lookup runs
//! under `timeout_at(deadline)`, so an abandoned lookup is really cancelled:
//! its future, sockets and slot are dropped at the deadline.
//!
//! IP-literal hosts skip all of this (no queue, no thread).
//!
//! Configuration comes from `[tls.revocation.resolver]` ([`ResolverSettings`]):
//! nameservers override, else `/etc/resolv.conf`; `/etc/hosts` on or off. The
//! files are re-read when their mtime changes (checked at most every 30 s);
//! a file that no longer parses keeps the last good resolver.
//!
//! Behaviour change from `getaddrinfo`: nsswitch is bypassed. Names known
//! only to NSS modules (sss, mdns, nss-resolve, LDAP/NIS, `myhostname`)
//! no longer resolve; the fetch fails and the revocation policy applies.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5 - bounded request queue ([`QUEUE_CAP`]), bounded
//!   concurrent lookups ([`MAX_INFLIGHT`]), one lookup per host name with a
//!   bounded waiter list ([`MAX_DEDUPE_WAITERS`]), bounded cache
//!   ([`CACHE_SIZE`]), one thread, cancellation at the deadline
//! - NIST 800-53: IA-5(2)(b)(1) - a slow or hostile resolver cannot stall
//!   the status check past `revocation.budget_ms`; DNS answers only steer
//!   the fetch of a signed object, whose signature is always checked
//! - RFC 1035 §4.2.1, RFC 7766 (TCP fallback), RFC 5452 (random query ID
//!   and source port), RFC 2308 (negative caching, TTL capped at 60 s)
// POAM: POAM-045 - nsswitch is bypassed (no getaddrinfo fallback); names
// resolvable only through NSS modules fail closed.

use std::cell::RefCell;
use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, mpsc as smpsc};
use std::time::{Duration, Instant, SystemTime};

use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::op::Query;
use hickory_resolver::proto::rr::{Name, RecordType};
use hickory_resolver::{Hosts, TokioResolver};
use parking_lot::Mutex;
use tokio::sync::{Semaphore, mpsc};

use super::http::HttpError;

/// Jobs waiting for the DNS thread, process-wide. A full queue fails the
/// fetch at once (`reason="saturated"`).
pub const QUEUE_CAP: usize = 64;
/// Lookups running at once on the DNS thread.
pub const MAX_INFLIGHT: usize = 32;
/// Callers sharing one in-flight lookup for the same host name.
pub const MAX_DEDUPE_WAITERS: usize = 64;
/// hickory response cache, in responses.
pub const CACHE_SIZE: u64 = 256;
/// Addresses tried per host.
pub const MAX_ADDRS: usize = 4;
/// Nameservers used (glibc `MAXNS`), from config or resolv.conf.
pub const MAX_NAMESERVERS: usize = 3;
/// Longest host name accepted (RFC 1035 §2.3.4, text form).
const MAX_HOST_LEN: usize = 253;
/// DNS thread stack. Lookups are boxed futures on the heap; the stack only
/// carries the runtime loop.
const DNS_STACK: usize = 256 * 1024;
/// At most one spawn attempt per interval after a failure.
const RESPAWN_INTERVAL: Duration = Duration::from_secs(1);
/// resolv.conf and hosts files larger than this are refused.
const MAX_CONF_BYTES: u64 = 1024 * 1024;
const POSITIVE_MAX_TTL: Duration = Duration::from_secs(300);
const NEGATIVE_MAX_TTL: Duration = Duration::from_secs(60);

/// Resolver settings (`[tls.revocation.resolver]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverSettings {
    /// Nameservers to query; empty uses `resolv_conf`.
    pub nameservers: Vec<SocketAddr>,
    /// Per-server query timeout. The caller's deadline is the real bound;
    /// this only stops one slow server from using the whole budget.
    pub timeout: Duration,
    /// Static hosts file, consulted before DNS; `None` disables it.
    pub hosts_file: Option<PathBuf>,
    pub resolv_conf: PathBuf,
    /// How often the files' mtimes are checked for a reload.
    pub reload_interval: Duration,
}

impl Default for ResolverSettings {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            timeout: Duration::from_secs(2),
            hosts_file: Some(PathBuf::from("/etc/hosts")),
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
            reload_interval: Duration::from_secs(30),
        }
    }
}

impl From<&plat_common::config::DnsResolverConfig> for ResolverSettings {
    fn from(c: &plat_common::config::DnsResolverConfig) -> Self {
        Self {
            nameservers: c.nameserver_addrs(),
            timeout: Duration::from_millis(c.timeout_ms),
            hosts_file: c.use_hosts_file.then(|| PathBuf::from("/etc/hosts")),
            ..Self::default()
        }
    }
}

/// Resolver counters (`plat_revocation_resolve_failures_total{reason}` and
/// the `plat_revocation_resolver_*` gauges).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolverStats {
    /// The deadline passed while queued, waiting for a slot or resolving.
    pub timeouts: u64,
    /// The queue was full or too many callers waited on one host name.
    pub saturated: u64,
    /// The `plat-dns` thread, its runtime or its resolver could not start.
    pub spawn_failed: u64,
    /// NXDOMAIN, SERVFAIL, refused, no records or an unusable name.
    pub errors: u64,
    /// Lookups running on the DNS thread.
    pub in_flight: usize,
    /// Jobs queued for the DNS thread.
    pub queued: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fail {
    Timeout,
    Saturated,
    Error,
}

type Reply = Result<Vec<IpAddr>, Fail>;

struct Job {
    host: String,
    deadline: Instant,
    reply: smpsc::SyncSender<Reply>,
}

/// One lookup's future (runs on the DNS thread, need not be `Send`).
pub(crate) type LookupFuture = Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>>>>;

/// Lookup backend owned by the DNS thread (hickory in production, scripted
/// in tests).
pub(crate) trait LookupBackend {
    fn lookup(&mut self, host: &str) -> LookupFuture;
    /// Called before each job; may reload configuration.
    fn maintain(&mut self) {}
}

type Factory = Arc<dyn Fn() -> Result<Box<dyn LookupBackend>, String> + Send + Sync>;

#[derive(Default)]
struct Shared {
    in_flight: AtomicUsize,
    queued: AtomicUsize,
}

struct Spawn {
    tx: Option<mpsc::Sender<Job>>,
    last_attempt: Option<Instant>,
}

/// A resolver: the job queue, the lazily started `plat-dns` thread and its
/// counters. Dropping it closes the queue and the thread ends.
pub struct Dns {
    factory: Factory,
    /// Leaf lock, held only to clone the sender or (re)spawn the thread.
    spawn: Mutex<Spawn>,
    shared: Arc<Shared>,
    timeouts: AtomicU64,
    saturated: AtomicU64,
    spawn_failed: AtomicU64,
    errors: AtomicU64,
}

impl std::fmt::Debug for Dns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dns").field("stats", &self.stats()).finish_non_exhaustive()
    }
}

impl Dns {
    /// A hickory resolver with these settings (thread started on first use).
    pub fn new(settings: ResolverSettings) -> Self {
        Self::with_backend(move || Hickory::new(settings.clone()).map(|h| Box::new(h) as Box<dyn LookupBackend>))
    }

    pub(crate) fn with_backend(f: impl Fn() -> Result<Box<dyn LookupBackend>, String> + Send + Sync + 'static) -> Self {
        Self {
            factory: Arc::new(f),
            spawn: Mutex::new(Spawn { tx: None, last_attempt: None }),
            shared: Arc::new(Shared::default()),
            timeouts: AtomicU64::new(0),
            saturated: AtomicU64::new(0),
            spawn_failed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    pub fn stats(&self) -> ResolverStats {
        ResolverStats {
            timeouts: self.timeouts.load(Ordering::Relaxed),
            saturated: self.saturated.load(Ordering::Relaxed),
            spawn_failed: self.spawn_failed.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            in_flight: self.shared.in_flight.load(Ordering::Relaxed),
            queued: self.shared.queued.load(Ordering::Relaxed),
        }
    }

    /// The live job sender, starting the thread if needed (at most one
    /// attempt per [`RESPAWN_INTERVAL`] after a failure).
    fn sender(&self) -> Option<mpsc::Sender<Job>> {
        let mut g = self.spawn.lock();
        if let Some(tx) = g.tx.as_ref().filter(|t| !t.is_closed()) {
            return Some(tx.clone());
        }
        g.tx = None;
        let now = Instant::now();
        if g.last_attempt.is_some_and(|t| now.saturating_duration_since(t) < RESPAWN_INTERVAL) {
            self.spawn_failed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        g.last_attempt = Some(now);
        let (tx, rx) = mpsc::channel(QUEUE_CAP);
        let (factory, shared) = (self.factory.clone(), self.shared.clone());
        let spawned = std::thread::Builder::new()
            .name("plat-dns".into())
            .stack_size(DNS_STACK)
            .spawn(move || run(rx, &factory, &shared));
        if let Err(e) = spawned {
            tracing::warn!(error = %e, "plat-dns thread could not start; OCSP/CRL fetches by name fail");
            self.spawn_failed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        g.tx = Some(tx.clone());
        Some(tx)
    }

    /// Resolves `host:port` to at most [`MAX_ADDRS`] addresses before
    /// `deadline`, IPv6 first, then IPv4. IP literals (bare or bracketed)
    /// return at once. Deadline or saturation: [`HttpError::Timeout`];
    /// lookup failure or no resolver: [`HttpError::Connect`].
    pub fn resolve(&self, host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, HttpError> {
        let lit = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        if let Ok(ip) = lit.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return Err(HttpError::Timeout);
        }
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return Err(HttpError::Connect);
        }
        let Some(tx) = self.sender() else { return Err(HttpError::Connect) };
        let (rtx, rrx) = smpsc::sync_channel(1);
        // Counted before the send so the DNS thread's decrement never
        // precedes it.
        self.shared.queued.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = tx.try_send(Job { host: host.to_owned(), deadline, reply: rtx }) {
            self.shared.queued.fetch_sub(1, Ordering::Relaxed);
            return Err(match e {
                mpsc::error::TrySendError::Full(_) => {
                    self.saturated.fetch_add(1, Ordering::Relaxed);
                    HttpError::Timeout
                }
                mpsc::error::TrySendError::Closed(_) => {
                    self.spawn_failed.fetch_add(1, Ordering::Relaxed);
                    HttpError::Connect
                }
            });
        }
        let wait = deadline.saturating_duration_since(Instant::now());
        match rrx.recv_timeout(wait) {
            Ok(Ok(v)) => Ok(v.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()),
            Ok(Err(Fail::Timeout)) | Err(smpsc::RecvTimeoutError::Timeout) => {
                self.timeouts.fetch_add(1, Ordering::Relaxed);
                Err(HttpError::Timeout)
            }
            Ok(Err(Fail::Saturated)) => {
                self.saturated.fetch_add(1, Ordering::Relaxed);
                Err(HttpError::Timeout)
            }
            Ok(Err(Fail::Error)) | Err(smpsc::RecvTimeoutError::Disconnected) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                Err(HttpError::Connect)
            }
        }
    }
}

static GLOBAL: OnceLock<Dns> = OnceLock::new();

/// Sets the process-wide resolver's settings. Only the first call (before
/// any lookup) takes effect; returns whether it did.
pub fn configure(settings: ResolverSettings) -> bool {
    let mut set = false;
    GLOBAL.get_or_init(|| {
        set = true;
        Dns::new(settings)
    });
    set
}

fn global() -> &'static Dns {
    GLOBAL.get_or_init(|| Dns::new(ResolverSettings::default()))
}

/// [`Dns::resolve`] on the process-wide resolver used by `http::fetch`.
pub fn resolve(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, HttpError> {
    global().resolve(host, port, deadline)
}

/// Counters of the process-wide resolver.
pub fn stats() -> ResolverStats {
    GLOBAL.get().map(Dns::stats).unwrap_or_default()
}

/// The `plat-dns` thread: one current_thread runtime, no blocking pool use.
fn run(mut rx: mpsc::Receiver<Job>, factory: &Factory, shared: &Arc<Shared>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().max_blocking_threads(1).build();
    let rt = match rt {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!(error = %e, "plat-dns runtime could not start");
            drain(&mut rx, shared);
            return;
        }
    };
    let backend = {
        let _g = rt.enter();
        factory()
    };
    match backend {
        Ok(b) => {
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, serve(&mut rx, b, shared.clone()));
        }
        Err(e) => tracing::warn!(error = %e, "plat-dns resolver could not start; OCSP/CRL fetches by name fail"),
    }
    drain(&mut rx, shared);
}

/// Closes the queue and drops what is left (callers see `Disconnected`).
fn drain(rx: &mut mpsc::Receiver<Job>, shared: &Shared) {
    rx.close();
    while rx.try_recv().is_ok() {
        shared.queued.fetch_sub(1, Ordering::Relaxed);
    }
}

type Pending = Rc<RefCell<Vec<(String, Vec<smpsc::SyncSender<Reply>>)>>>;

async fn serve(rx: &mut mpsc::Receiver<Job>, mut backend: Box<dyn LookupBackend>, shared: Arc<Shared>) {
    // SC-5: at most MAX_INFLIGHT lookups; `pending` holds one entry per
    // running lookup, so it is bounded by the semaphore too.
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    let pending: Pending = Rc::new(RefCell::new(Vec::new()));
    while let Some(job) = rx.recv().await {
        shared.queued.fetch_sub(1, Ordering::Relaxed);
        if job.deadline <= Instant::now() {
            let _ = job.reply.try_send(Err(Fail::Timeout));
            continue;
        }
        backend.maintain();
        let key = job.host.to_ascii_lowercase();
        {
            let mut p = pending.borrow_mut();
            if let Some((_, w)) = p.iter_mut().find(|(k, _)| *k == key) {
                if w.len() < MAX_DEDUPE_WAITERS {
                    w.push(job.reply);
                } else {
                    let _ = job.reply.try_send(Err(Fail::Saturated));
                }
                continue;
            }
        }
        let permit = match tokio::time::timeout_at(job.deadline.into(), sem.clone().acquire_owned()).await {
            Ok(Ok(p)) => p,
            _ => {
                let _ = job.reply.try_send(Err(Fail::Timeout));
                continue;
            }
        };
        pending.borrow_mut().push((key.clone(), vec![job.reply]));
        shared.in_flight.fetch_add(1, Ordering::Relaxed);
        let done = Finish { key, pending: pending.clone(), shared: shared.clone(), result: None, _permit: permit };
        let fut = backend.lookup(&job.host);
        let deadline = job.deadline;
        tokio::task::spawn_local(async move {
            // SC-5: the lookup is dropped (cancelled) at the deadline.
            done.answer(match tokio::time::timeout_at(deadline.into(), fut).await {
                Ok(Ok(v)) if !v.is_empty() => Ok(order(v)),
                Ok(_) => Err(Fail::Error),
                Err(_) => Err(Fail::Timeout),
            });
        });
    }
}

/// Answers every waiter of one lookup and frees its slot, also when the
/// task is cancelled or panics (waiters then see an error).
struct Finish {
    key: String,
    pending: Pending,
    shared: Arc<Shared>,
    result: Option<Reply>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Finish {
    /// Records the result; waiters are answered on drop.
    fn answer(mut self, r: Reply) {
        self.result = Some(r);
    }
}

impl Drop for Finish {
    fn drop(&mut self) {
        let waiters = {
            let Ok(mut p) = self.pending.try_borrow_mut() else { return };
            match p.iter().position(|(k, _)| *k == self.key) {
                Some(i) => p.swap_remove(i).1,
                None => Vec::new(),
            }
        };
        let r = self.result.take().unwrap_or(Err(Fail::Error));
        for w in waiters {
            // A caller that gave up has dropped its receiver; that is fine.
            let _ = w.try_send(r.clone());
        }
        self.shared.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// IPv6 addresses first, then IPv4, without duplicates, at most
/// [`MAX_ADDRS`]; when both families exist the last slot is kept for the
/// first IPv4 address, so a host with broken IPv6 is still reachable.
fn order(v: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut v6: Vec<IpAddr> = Vec::with_capacity(MAX_ADDRS);
    let mut v4: Vec<IpAddr> = Vec::with_capacity(MAX_ADDRS);
    for ip in v {
        let l = if ip.is_ipv6() { &mut v6 } else { &mut v4 };
        if l.len() < MAX_ADDRS && !l.contains(&ip) {
            l.push(ip);
        }
    }
    let n6 = v6.len().min(if v4.is_empty() { MAX_ADDRS } else { MAX_ADDRS - 1 });
    v6.truncate(n6);
    let rest = MAX_ADDRS - v6.len();
    v6.extend(v4.into_iter().take(rest));
    v6
}

/// Modification times of the files a resolver was built from.
type Stamp = (Option<SystemTime>, Option<SystemTime>);

struct Hickory {
    settings: ResolverSettings,
    resolver: TokioResolver,
    /// Static hosts, answered before DNS without waiting for the other
    /// address family (as `files` in nsswitch would).
    hosts: Arc<Hosts>,
    stamp: Stamp,
    next_check: Instant,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

impl Hickory {
    fn new(settings: ResolverSettings) -> Result<Self, String> {
        let stamp = Self::stamp(&settings);
        let (resolver, hosts) = build(&settings)?;
        let next_check = Instant::now() + settings.reload_interval;
        Ok(Self { settings, resolver, hosts, stamp, next_check })
    }

    fn stamp(s: &ResolverSettings) -> Stamp {
        let conf = if s.nameservers.is_empty() { mtime(&s.resolv_conf) } else { None };
        (conf, s.hosts_file.as_deref().and_then(mtime))
    }
}

impl LookupBackend for Hickory {
    fn lookup(&mut self, host: &str) -> LookupFuture {
        if let Ok(name) = Name::from_str(&host.to_ascii_lowercase()) {
            let mut v = Vec::new();
            for t in [RecordType::AAAA, RecordType::A] {
                if let Some(l) = self.hosts.lookup_static_host(&Query::query(name.clone(), t)) {
                    v.extend(l.answers().iter().filter_map(|r| r.data.ip_addr()));
                }
            }
            if !v.is_empty() {
                return Box::pin(std::future::ready(Ok(v)));
            }
        }
        let (r, host) = (self.resolver.clone(), host.to_owned());
        Box::pin(async move { r.lookup_ip(host).await.map(|l| l.iter().collect()).map_err(|e| e.to_string()) })
    }

    /// Re-reads resolv.conf / hosts when their mtime changed; a bad file
    /// keeps the last good resolver (warned once per change).
    fn maintain(&mut self) {
        let now = Instant::now();
        if now < self.next_check {
            return;
        }
        self.next_check = now + self.settings.reload_interval;
        let stamp = Self::stamp(&self.settings);
        if stamp == self.stamp {
            return;
        }
        self.stamp = stamp;
        match build(&self.settings) {
            Ok((r, h)) => {
                self.resolver = r;
                self.hosts = h;
                tracing::info!("plat-dns: resolver configuration reloaded");
            }
            Err(e) => {
                tracing::warn!(error = %e, "plat-dns: new resolver configuration rejected; keeping the last good one")
            }
        }
    }
}

fn read_capped(p: &Path) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    crate::load::open_regular(p)?.take(MAX_CONF_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_CONF_BYTES {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(buf)
}

/// Nameservers, search list and `ndots` from a resolv.conf.
fn read_resolv_conf(p: &Path) -> Result<(ResolverConfig, usize), String> {
    let raw = read_capped(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let c = resolv_conf::Config::parse(&raw).map_err(|e| format!("{}: {e}", p.display()))?;
    let ns: Vec<NameServerConfig> =
        c.nameservers.iter().take(MAX_NAMESERVERS).map(|ip| NameServerConfig::udp_and_tcp(ip.into())).collect();
    if ns.is_empty() {
        return Err(format!("{}: no nameserver", p.display()));
    }
    let search = c.get_last_search_or_domain().filter(|d| *d != "--").filter_map(|d| Name::from_str(d).ok()).collect();
    let ndots = usize::try_from(c.ndots.min(15)).unwrap_or(1);
    Ok((ResolverConfig::from_parts(None, search, ns), ndots))
}

fn build(s: &ResolverSettings) -> Result<(TokioResolver, Arc<Hosts>), String> {
    let (config, ndots) = if s.nameservers.is_empty() {
        read_resolv_conf(&s.resolv_conf)?
    } else {
        let ns = s
            .nameservers
            .iter()
            .take(MAX_NAMESERVERS)
            .map(|a| {
                let mut n = NameServerConfig::udp_and_tcp(a.ip());
                for c in &mut n.connections {
                    c.port = a.port();
                }
                n
            })
            .collect();
        (ResolverConfig::from_parts(None, Vec::new(), ns), 1)
    };
    let mut o = ResolverOpts::default();
    o.ndots = ndots;
    o.timeout = s.timeout;
    o.attempts = 1;
    o.edns0 = false;
    o.ip_strategy = LookupIpStrategy::Ipv6AndIpv4;
    o.cache_size = CACHE_SIZE;
    o.positive_max_ttl = Some(POSITIVE_MAX_TTL);
    o.negative_max_ttl = Some(NEGATIVE_MAX_TTL);
    // The hosts file is loaded here (bounded read, regular file only) and
    // answered in `Hickory::lookup`.
    o.use_hosts_file = ResolveHosts::Never;
    o.num_concurrent_reqs = 2;
    o.preserve_intermediates = false;
    o.server_ordering_strategy = ServerOrderingStrategy::QueryStatistics;
    let r = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(o)
        .build()
        .map_err(|e| e.to_string())?;
    let mut hosts = Hosts::default();
    if let Some(h) = &s.hosts_file {
        match read_capped(h) {
            Ok(raw) => hosts.read_hosts_conf(&raw[..]).map_err(|e| format!("{}: {e}", h.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", h.display())),
        }
    }
    Ok((r, Arc::new(hosts)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    const ADDR: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    /// Scripted backend: `f(host)` is the lookup future.
    struct Script(fn(&str) -> LookupFuture);

    impl LookupBackend for Script {
        fn lookup(&mut self, host: &str) -> LookupFuture {
            (self.0)(host)
        }
    }

    fn dns(f: fn(&str) -> LookupFuture) -> Dns {
        Dns::with_backend(move || Ok(Box::new(Script(f)) as Box<dyn LookupBackend>))
    }

    fn after(ms: u64, r: Result<Vec<IpAddr>, String>) -> LookupFuture {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            r
        })
    }

    fn secs(s: u64) -> Instant {
        Instant::now() + Duration::from_secs(s)
    }

    fn wait_idle(d: &Dns) -> bool {
        let end = secs(5);
        while Instant::now() < end {
            let s = d.stats();
            if s.in_flight == 0 && s.queued == 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    fn sa(ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, 80)
    }

    #[test]
    fn never_answers_times_out_within_deadline_and_cancels() {
        let d = dns(|_| Box::pin(std::future::pending()));
        let t0 = Instant::now();
        assert_eq!(d.resolve("ocsp.example", 80, t0 + Duration::from_millis(100)), Err(HttpError::Timeout));
        assert!(t0.elapsed() < Duration::from_millis(150), "{:?}", t0.elapsed());
        assert_eq!(d.stats().timeouts, 1);
        // Cancelled at the deadline: the slot is free again.
        assert!(wait_idle(&d));
    }

    #[test]
    fn late_answer_is_timeout_and_slot_is_released() {
        let d = dns(|h| after(if h == "late.example" { 400 } else { 0 }, Ok(vec![ADDR])));
        assert_eq!(d.resolve("late.example", 80, Instant::now() + Duration::from_millis(50)), Err(HttpError::Timeout));
        assert!(wait_idle(&d));
        assert_eq!(d.resolve("ok.example", 80, secs(5)), Ok(vec![sa(ADDR)]));
    }

    #[test]
    fn ip_literals_bypass_and_expired_deadline_enqueues_nothing() {
        let d = dns(|_| unreachable!("IP literals must not be resolved"));
        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap_or_else(Instant::now);
        assert_eq!(d.resolve("192.0.2.7", 80, past), Ok(vec![sa("192.0.2.7".parse().unwrap())]));
        let v6: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        assert_eq!(d.resolve("2001:db8::1", 8080, past), Ok(vec![v6]));
        assert_eq!(d.resolve("[2001:db8::1]", 8080, past), Ok(vec![v6]));
        assert_eq!(d.resolve("x.example", 80, past), Err(HttpError::Timeout));
        assert_eq!(d.stats(), ResolverStats::default());
        assert!(d.spawn.lock().tx.is_none(), "no thread started");
    }

    #[test]
    fn addresses_are_capped_ipv6_first_with_one_ipv4() {
        let d = dns(|_| {
            let mut v: Vec<IpAddr> = (1..=5).map(|i| IpAddr::from([192, 0, 2, i])).collect();
            v.extend((1..=5u16).map(|i| IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, i])));
            after(0, Ok(v))
        });
        let r = d.resolve("x.example", 80, secs(5)).unwrap();
        assert_eq!(r.len(), MAX_ADDRS);
        assert!(r[..3].iter().all(|a| a.is_ipv6()) && r[3].is_ipv4(), "{r:?}");
        assert_eq!(order(vec![ADDR, ADDR]), vec![ADDR]);
    }

    #[test]
    fn queue_full_is_saturated_at_once() {
        // The DNS thread stalls on the first job (a never-ready permit is
        // simulated by blocking the runtime thread), so the queue fills.
        let d = dns(|_| {
            std::thread::sleep(Duration::from_millis(500));
            after(0, Ok(vec![ADDR]))
        });
        let d = Arc::new(d);
        let hs: Vec<_> = (0..QUEUE_CAP + 20)
            .map(|i| {
                let d = d.clone();
                std::thread::spawn(move || d.resolve(&format!("h{i}.example"), 80, secs(30)))
            })
            .collect();
        let t0 = Instant::now();
        while d.stats().saturated == 0 && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(d.stats().saturated > 0);
        assert!(d.stats().queued <= QUEUE_CAP);
        drop(hs);
    }

    #[test]
    fn lookup_error_is_connect_and_releases_slot() {
        let d = dns(|_| after(0, Err("nxdomain".into())));
        for _ in 0..3 {
            assert_eq!(d.resolve("x.example", 80, secs(5)), Err(HttpError::Connect));
        }
        assert!(wait_idle(&d));
        assert_eq!(d.stats().errors, 3);
        assert_eq!(d.resolve(&"a".repeat(254), 80, secs(5)), Err(HttpError::Connect));
    }

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);
    static LIVE: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn dedupe_one_backend_call_per_host() {
        let d = Arc::new(dns(|_| {
            CALLS.fetch_add(1, Ordering::Relaxed);
            after(200, Ok(vec![ADDR]))
        }));
        let hs: Vec<_> = (0..20)
            .map(|i| {
                let d = d.clone();
                let h = if i % 2 == 0 { "same.example" } else { "SAME.example" };
                std::thread::spawn(move || d.resolve(h, 80, secs(5)))
            })
            .collect();
        for h in hs {
            assert_eq!(h.join().unwrap(), Ok(vec![sa(ADDR)]));
        }
        assert!(CALLS.load(Ordering::Relaxed) <= 2, "{}", CALLS.load(Ordering::Relaxed));
    }

    /// SC-5: 200 callers on distinct names never run more than
    /// MAX_INFLIGHT lookups, and nothing leaks.
    #[test]
    fn concurrent_callers_respect_cap_without_leak() {
        let d = Arc::new(dns(|_| {
            Box::pin(async {
                let n = LIVE.fetch_add(1, Ordering::Relaxed) + 1;
                PEAK.fetch_max(n, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(20)).await;
                LIVE.fetch_sub(1, Ordering::Relaxed);
                Ok(vec![ADDR])
            })
        }));
        let hs: Vec<_> = (0..200)
            .map(|i| {
                let d = d.clone();
                std::thread::spawn(move || d.resolve(&format!("c{i}.example"), 80, secs(10)))
            })
            .collect();
        let mut ok = 0u64;
        for h in hs {
            match h.join().unwrap() {
                Ok(_) => ok += 1,
                Err(e) => assert_eq!(e, HttpError::Timeout),
            }
        }
        let st = d.stats();
        assert!(PEAK.load(Ordering::Relaxed) <= MAX_INFLIGHT);
        assert_eq!(ok + st.saturated + st.timeouts, 200);
        assert!(ok >= MAX_INFLIGHT as u64, "{ok}");
        assert!(wait_idle(&d));
    }

    static PANICKED: AtomicBool = AtomicBool::new(false);

    #[test]
    fn backend_panic_does_not_kill_the_thread() {
        let d = dns(|h| {
            if h == "boom.example" {
                Box::pin(async {
                    PANICKED.store(true, Ordering::Relaxed);
                    panic!("scripted backend panic")
                })
            } else {
                after(0, Ok(vec![ADDR]))
            }
        });
        assert_eq!(d.resolve("boom.example", 80, secs(5)), Err(HttpError::Connect));
        assert!(PANICKED.load(Ordering::Relaxed));
        assert_eq!(d.resolve("ok.example", 80, secs(5)), Ok(vec![sa(ADDR)]));
        assert!(wait_idle(&d));
    }

    #[test]
    fn backend_start_failure_is_spawn_failed_and_rate_limited() {
        let d = Dns::with_backend(|| Err("no resolv.conf".into()));
        assert_eq!(d.resolve("x.example", 80, secs(5)), Err(HttpError::Connect));
        for _ in 0..5 {
            assert_eq!(d.resolve("x.example", 80, secs(5)), Err(HttpError::Connect));
        }
        let st = d.stats();
        assert!(st.spawn_failed + st.errors >= 6, "{st:?}");
        assert_eq!(st.queued, 0);
    }

    #[test]
    fn resolv_conf_is_parsed_capped_and_bad_files_refused() {
        let dir = std::env::temp_dir().join(format!("plat-dns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("resolv.conf");
        std::fs::write(&p, "nameserver 192.0.2.1\nnameserver 192.0.2.2\nnameserver 192.0.2.3\nnameserver 192.0.2.4\nsearch example.net\noptions ndots:2\n").unwrap();
        let (c, ndots) = read_resolv_conf(&p).unwrap();
        assert_eq!((c.name_servers().len(), ndots, c.search().len()), (3, 2, 1));
        std::fs::write(&p, "search example.net\n").unwrap();
        assert!(read_resolv_conf(&p).is_err());
        assert!(read_resolv_conf(&dir).is_err(), "directory refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_hosts_never_panic_and_meet_the_deadline(host in ".{0,300}") {
            static D: OnceLock<Dns> = OnceLock::new();
            let d = D.get_or_init(|| dns(|_| after(1, Err("x".into()))));
            let t0 = Instant::now();
            let _ = d.resolve(&host, 80, t0 + Duration::from_millis(200));
            proptest::prop_assert!(t0.elapsed() < Duration::from_millis(400));
        }
    }
}
