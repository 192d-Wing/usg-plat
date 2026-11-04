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
//! IP-literal hosts skip all of this (no queue, no thread). Names are
//! looked up exactly as given: no search list, `ndots` 0, and single-label
//! names are refused. Query names use 0x20 case randomisation.
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
//! - NIST 800-53: SC-21 - not implemented here (no DNSSEC); compensated by
//!   OCSP/CRL signature validation, ID/port/0x20 randomisation and an
//!   optional organisational validating resolver (`nameservers`)
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
/// Names being resolved or waiting for one of the [`MAX_INFLIGHT`] slots.
pub const MAX_PENDING: usize = MAX_INFLIGHT + QUEUE_CAP;
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
            // Exact: jobs sitting in the bounded channel.
            queued: self
                .spawn
                .lock()
                .tx
                .as_ref()
                .filter(|t| !t.is_closed())
                .map_or(0, |t| t.max_capacity() - t.capacity()),
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
        // SEC-004: single-label names are refused (no search expansion).
        if host.is_empty() || host.len() > MAX_HOST_LEN || !host.trim_end_matches('.').contains('.') {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return Err(HttpError::Connect);
        }
        let Some(tx) = self.sender() else { return Err(HttpError::Connect) };
        let (rtx, rrx) = smpsc::sync_channel(1);
        if let Err(e) = tx.try_send(Job { host: host.to_owned(), deadline, reply: rtx }) {
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
            drain(&mut rx);
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
    drain(&mut rx);
}

/// Closes the queue and drops what is left (callers see `Disconnected`).
fn drain(rx: &mut mpsc::Receiver<Job>) {
    rx.close();
    // `blocking_recv` also takes a send that got its permit before the
    // close. Never called inside the runtime.
    while rx.blocking_recv().is_some() {}
}

type Pending = Rc<RefCell<Vec<(String, Vec<smpsc::SyncSender<Reply>>)>>>;

async fn serve(rx: &mut mpsc::Receiver<Job>, backend: Box<dyn LookupBackend>, shared: Arc<Shared>) {
    // SC-5: at most MAX_INFLIGHT lookups hold a slot; `pending` (one entry
    // per name being resolved or waiting for a slot) is capped at
    // MAX_PENDING. The loop never waits for a slot (SEC-001): a job for a
    // name already pending joins it; otherwise its task waits for a slot,
    // after one probe poll that answers cache and hosts hits at once, so a
    // job never blocks the jobs queued behind it.
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    let pending: Pending = Rc::new(RefCell::new(Vec::new()));
    // Single-threaded; borrowed only synchronously, never across an await.
    let backend = Rc::new(RefCell::new(backend));
    while let Some(job) = rx.recv().await {
        if job.deadline <= Instant::now() {
            let _ = job.reply.try_send(Err(Fail::Timeout));
            continue;
        }
        backend.borrow_mut().maintain();
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
            if p.len() >= MAX_PENDING {
                let _ = job.reply.try_send(Err(Fail::Saturated));
                continue;
            }
            p.push((key.clone(), vec![job.reply]));
        }
        let deadline = job.deadline;
        let mut done = Finish { key, pending: pending.clone(), shared: shared.clone(), result: None, permit: None };
        if let Ok(permit) = sem.clone().try_acquire_owned() {
            done.hold(permit);
            let fut = backend.borrow_mut().lookup(&job.host);
            tokio::task::spawn_local(async move {
                // SC-5: the lookup is dropped (cancelled) at the deadline.
                done.answer(match tokio::time::timeout_at(deadline.into(), fut).await {
                    Ok(r) => outcome(r),
                    Err(_) => Err(Fail::Timeout),
                });
            });
            continue;
        }
        // All slots busy: probe once, then wait for a slot.
        let probe = backend.borrow_mut().lookup(&job.host);
        let (sem, backend, host) = (sem.clone(), backend.clone(), job.host);
        tokio::task::spawn_local(async move {
            let mut probe = probe;
            let first = std::future::poll_fn(|cx| std::task::Poll::Ready(probe.as_mut().poll(cx))).await;
            if let std::task::Poll::Ready(r) = first {
                return done.answer(outcome(r));
            }
            // A probe that would need the network is dropped (cancelled)
            // before it can hold resources without a slot.
            drop(probe);
            let Ok(Ok(permit)) = tokio::time::timeout_at(deadline.into(), sem.acquire_owned()).await else {
                return done.answer(Err(Fail::Timeout));
            };
            done.hold(permit);
            let Some(fut) = backend.try_borrow_mut().ok().map(|mut b| b.lookup(&host)) else {
                return done.answer(Err(Fail::Error));
            };
            done.answer(match tokio::time::timeout_at(deadline.into(), fut).await {
                Ok(r) => outcome(r),
                Err(_) => Err(Fail::Timeout),
            });
        });
    }
}

fn outcome(r: Result<Vec<IpAddr>, String>) -> Reply {
    match r {
        Ok(v) if !v.is_empty() => Ok(order(v)),
        _ => Err(Fail::Error),
    }
}

/// Answers every waiter of one lookup and frees its slot, also when the
/// task is cancelled or panics (waiters then see an error).
struct Finish {
    key: String,
    pending: Pending,
    shared: Arc<Shared>,
    result: Option<Reply>,
    /// The slot, once taken (counted in `in_flight` while held).
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Finish {
    fn hold(&mut self, p: tokio::sync::OwnedSemaphorePermit) {
        self.shared.in_flight.fetch_add(1, Ordering::Relaxed);
        self.permit = Some(p);
    }

    /// Records the result; waiters are answered on drop.
    fn answer(mut self, r: Reply) {
        self.result = Some(r);
    }
}

impl Drop for Finish {
    fn drop(&mut self) {
        // SEC-005: released first, whatever happens below.
        if self.permit.take().is_some() {
            self.shared.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
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
    }
}

// POAM: POAM-046 - resolved addresses are not filtered (loopback,
// link-local, metadata); fetches of signed objects only, fail closed.
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
    /// Result of a reload running on the blocking pool (SEC-003).
    reload: Option<smpsc::Receiver<Reload>>,
}

type Reload = (Stamp, Result<(TokioResolver, Arc<Hosts>), String>);

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

impl Hickory {
    fn new(settings: ResolverSettings) -> Result<Self, String> {
        let stamp = Self::stamp(&settings);
        let (resolver, hosts) = build(&settings)?;
        let next_check = Instant::now() + settings.reload_interval;
        Ok(Self { settings, resolver, hosts, stamp, next_check, reload: None })
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
    /// keeps the last good resolver (warned once per change). The stat and
    /// the reads run on the runtime's blocking pool (one thread at most,
    /// `max_blocking_threads(1)`), never on the thread serving lookups; the
    /// result is swapped in by a later call.
    fn maintain(&mut self) {
        if let Some(rx) = &self.reload {
            match rx.try_recv() {
                Ok((stamp, res)) => {
                    self.reload = None;
                    self.stamp = stamp;
                    match res {
                        Ok((r, h)) => {
                            self.resolver = r;
                            self.hosts = h;
                            tracing::info!("plat-dns: resolver configuration reloaded");
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "plat-dns: new resolver configuration rejected; keeping the last good one"
                        ),
                    }
                }
                Err(smpsc::TryRecvError::Empty) => return,
                Err(smpsc::TryRecvError::Disconnected) => self.reload = None,
            }
        }
        let now = Instant::now();
        if now < self.next_check {
            return;
        }
        self.next_check = now + self.settings.reload_interval;
        let (tx, rx) = smpsc::sync_channel(1);
        let (settings, old) = (self.settings.clone(), self.stamp);
        tokio::task::spawn_blocking(move || {
            let stamp = Hickory::stamp(&settings);
            if stamp != old {
                let _ = tx.try_send((stamp, build(&settings)));
            }
        });
        self.reload = Some(rx);
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

/// Nameservers from a resolv.conf. `search`, `domain` and `ndots` are
/// ignored on purpose (SEC-004): CA-supplied names are never expanded.
fn read_resolv_conf(p: &Path) -> Result<ResolverConfig, String> {
    let raw = read_capped(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let c = resolv_conf::Config::parse(&raw).map_err(|e| format!("{}: {e}", p.display()))?;
    let ns: Vec<NameServerConfig> =
        c.nameservers.iter().take(MAX_NAMESERVERS).map(|ip| NameServerConfig::udp_and_tcp(ip.into())).collect();
    if ns.is_empty() {
        return Err(format!("{}: no nameserver", p.display()));
    }
    Ok(ResolverConfig::from_parts(None, Vec::new(), ns))
}

fn build(s: &ResolverSettings) -> Result<(TokioResolver, Arc<Hosts>), String> {
    let config = if s.nameservers.is_empty() {
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
        ResolverConfig::from_parts(None, Vec::new(), ns)
    };
    let mut o = ResolverOpts::default();
    // SEC-004: every name is tried as given (no search list, ndots 0).
    o.ndots = 0;
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
    // SEC-002: 0x20 query-name case randomisation (UDP); a reply whose
    // question case differs is rejected.
    o.case_randomization = true;
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
    /// MAX_INFLIGHT lookups (plus the one synchronous first-poll probe of a
    /// job refused while the slots are full), and nothing leaks.
    #[test]
    fn concurrent_callers_respect_cap_without_leak() {
        let d = Arc::new(dns(|_| {
            Box::pin(async {
                // Decremented on drop too (a refused probe is dropped).
                struct Live;
                impl Drop for Live {
                    fn drop(&mut self) {
                        LIVE.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                let n = LIVE.fetch_add(1, Ordering::Relaxed) + 1;
                let _live = Live;
                PEAK.fetch_max(n, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(20)).await;
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
        assert!(PEAK.load(Ordering::Relaxed) <= MAX_INFLIGHT + 1);
        assert_eq!(ok + st.saturated + st.timeouts, 200);
        assert!(ok >= MAX_INFLIGHT as u64, "{ok}");
        assert!(wait_idle(&d));
    }

    static SLOW_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// SEC-001: with every slot held by never-answering names, a job for a
    /// name already in flight joins it (no new lookup) and a cache/hosts
    /// hit queued behind a job waiting for a slot is answered at once.
    #[test]
    fn full_slots_do_not_block_joins_or_cache_hits() {
        let d = Arc::new(dns(|h| {
            if h == "cached.example" {
                Box::pin(std::future::ready(Ok(vec![ADDR])))
            } else {
                SLOW_CALLS.fetch_add(1, Ordering::Relaxed);
                Box::pin(std::future::pending())
            }
        }));
        let busy: Vec<_> = (0..MAX_INFLIGHT)
            .map(|i| {
                let d = d.clone();
                std::thread::spawn(move || d.resolve(&format!("busy{i}.example"), 80, secs(3)))
            })
            .collect();
        let end = secs(5);
        while d.stats().in_flight < MAX_INFLIGHT && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(d.stats().in_flight, MAX_INFLIGHT);
        // A job waiting for a slot, far deadline.
        let waiter = {
            let d = d.clone();
            std::thread::spawn(move || d.resolve("waiting.example", 80, secs(3)))
        };
        std::thread::sleep(Duration::from_millis(20));
        let calls = SLOW_CALLS.load(Ordering::Relaxed);
        // Join an in-flight name: answered at its own (short) deadline.
        let t0 = Instant::now();
        assert_eq!(d.resolve("busy0.example", 80, t0 + Duration::from_millis(150)), Err(HttpError::Timeout));
        assert!(t0.elapsed() < Duration::from_millis(200), "{:?}", t0.elapsed());
        assert_eq!(SLOW_CALLS.load(Ordering::Relaxed), calls, "joined, no new lookup");
        // A cache hit behind the waiting job: answered well before its deadline.
        let t1 = Instant::now();
        assert_eq!(d.resolve("cached.example", 80, t1 + Duration::from_millis(500)), Ok(vec![sa(ADDR)]));
        assert!(t1.elapsed() < Duration::from_millis(100), "{:?}", t1.elapsed());
        assert_eq!(waiter.join().unwrap(), Err(HttpError::Timeout));
        for h in busy {
            assert_eq!(h.join().unwrap(), Err(HttpError::Timeout));
        }
        assert!(wait_idle(&d));
        assert!(d.stats().in_flight <= MAX_INFLIGHT);
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
        let c = read_resolv_conf(&p).unwrap();
        // SEC-004: search/ndots ignored.
        assert_eq!((c.name_servers().len(), c.search().len()), (3, 0));
        std::fs::write(&p, "search example.net\n").unwrap();
        assert!(read_resolv_conf(&p).is_err());
        assert!(read_resolv_conf(&dir).is_err(), "directory refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// QA: with the DNS thread stalled and QUEUE_CAP jobs queued, the next
    /// caller (the 65th) is refused at once as saturated, not at its deadline.
    #[test]
    fn qa_caller_past_queue_cap_is_refused_at_once() {
        let d = Arc::new(dns(|h| {
            if h == "stall.example" {
                std::thread::sleep(Duration::from_millis(1500));
            }
            after(0, Ok(vec![ADDR]))
        }));
        let s = {
            let d = d.clone();
            std::thread::spawn(move || d.resolve("stall.example", 80, secs(10)))
        };
        let t0 = Instant::now();
        while d.stats().in_flight == 0 && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(50));
        let hs: Vec<_> = (0..QUEUE_CAP)
            .map(|i| {
                let d = d.clone();
                std::thread::spawn(move || d.resolve(&format!("q{i}.example"), 80, secs(10)))
            })
            .collect();
        let t0 = Instant::now();
        while d.stats().queued < QUEUE_CAP && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(d.stats().queued, QUEUE_CAP);
        let before = d.stats().saturated;
        let t1 = Instant::now();
        assert_eq!(d.resolve("overflow.example", 80, secs(10)), Err(HttpError::Timeout));
        assert!(t1.elapsed() < Duration::from_millis(50), "{:?}", t1.elapsed());
        assert_eq!(d.stats().saturated, before + 1);
        // Once the stall ends every queued caller is answered.
        assert_eq!(s.join().unwrap(), Ok(vec![sa(ADDR)]));
        for h in hs {
            assert_eq!(h.join().unwrap(), Ok(vec![sa(ADDR)]));
        }
        assert!(wait_idle(&d));
    }

    /// QA (SC-5): a flood of distinct never-answering names does not delay
    /// any caller past its own deadline, and a fast name submitted while
    /// the cap is filled by slow ones is either answered promptly or
    /// refused at once, never held past its deadline.
    #[test]
    fn qa_flood_of_distinct_names_meets_every_deadline() {
        let d = Arc::new(dns(|h| {
            if h.starts_with("fast") { after(5, Ok(vec![ADDR])) } else { Box::pin(std::future::pending()) }
        }));
        let hs: Vec<_> = (0..300u64)
            .map(|i| {
                let d = d.clone();
                std::thread::spawn(move || {
                    let dl = Instant::now() + Duration::from_millis(100 + (i % 7) * 50);
                    let r = d.resolve(&format!("slow{i}.example"), 80, dl);
                    (r, Instant::now().saturating_duration_since(dl))
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(20));
        let t0 = Instant::now();
        let r = d.resolve("fast.example", 80, t0 + Duration::from_millis(300));
        assert!(t0.elapsed() < Duration::from_millis(350), "{:?}", t0.elapsed());
        assert!(matches!(r, Ok(_) | Err(HttpError::Timeout)), "{r:?}");
        for h in hs {
            let (r, late) = h.join().unwrap();
            assert_eq!(r, Err(HttpError::Timeout));
            assert!(late < Duration::from_millis(50), "overshoot {late:?}");
        }
        assert!(wait_idle(&d));
        assert_eq!(d.resolve("fast2.example", 80, secs(5)), Ok(vec![sa(ADDR)]));
    }

    /// QA (Q4): ordering for single-family and mixed answers.
    #[test]
    fn qa_order_single_family_and_mixed() {
        let v4 = |i: u8| IpAddr::from([192, 0, 2, i]);
        let v6 = |i: u16| IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, i]);
        assert_eq!(order((1..=6).map(v4).collect()), (1..=4).map(v4).collect::<Vec<_>>());
        assert_eq!(order((1..=6).map(v6).collect()), (1..=4).map(v6).collect::<Vec<_>>());
        // v4 first in the answer: v6 still leads, v4 fills the rest.
        assert_eq!(order(vec![v4(1), v4(2), v6(1), v4(3), v4(4)]), vec![v6(1), v4(1), v4(2), v4(3)]);
        // Many v6, one v4 last: the v4 keeps the 4th slot.
        let mut a: Vec<IpAddr> = (1..=8).map(v6).collect();
        a.push(v4(9));
        assert_eq!(order(a), vec![v6(1), v6(2), v6(3), v4(9)]);
        assert_eq!(order(vec![v6(1), v6(1), v4(1), v4(1)]), vec![v6(1), v4(1)]);
        assert!(order(Vec::new()).is_empty());
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
