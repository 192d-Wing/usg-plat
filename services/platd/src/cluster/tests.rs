//! In-process cluster tests: two and three members (plus the witness) over
//! loopback mutual TLS with a per-test PKI. Short leases (1 s, heartbeat
//! 100 ms) keep each scenario to a few seconds.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use plat_audit::{
    AcquireReason as AuditAcquire, AuditSink, BlockReleaseReason, Event, MemberState, OperatorRefusal,
    PeerRejectReason, SliceReleaseReason, TryEmit, ViewReason,
};
use plat_cluster::{Msg, RejectReason, SliceId, WireBlock};
use plat_common::{Clock, Config, Counters};
use plat_nat64::SliceState;
use plat_nat64::{Nat64, ReplHub, ReplProducer, Verdict, WorkerCtx};
use plat_packet::{be16, be32, checksum as ck, proto, put16};
use plat_xlat::HEADROOM;
use plat_xlat::siit::{write_v4_header, write_v6_header};

use super::control::{ClusterHandle, Command, cli_request};
use super::witness::WitnessFile;
use crate::test_pki::{Ca, TempDir};

const LEASE_MS: u64 = 1000;
const PREFIX: u128 = 0x0064_ff9b_0001_0000_0000_0000_0000_0000;
const SERVER: u32 = 0xcb00_7105; // 203.0.113.5

/// A free port that is none of the layout's member or witness ports.
fn free_port_besides(l: &Layout) -> u16 {
    loop {
        let p = free_ports(1)[0];
        if !l.ports.contains(&p) && l.witness != Some(p) {
            return p;
        }
    }
}

/// `n` distinct free ports. Every listener stays open until all are picked:
/// the kernel may hand out a just-closed ephemeral port again, and a witness
/// port equal to a member's peer port fails config validation.
fn free_ports(n: usize) -> Vec<u16> {
    let held: Vec<TcpListener> = (0..n).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    held.iter().map(|l| l.local_addr().unwrap().port()).collect()
}

/// A short private directory (the operator socket path must stay under
/// the 104-byte `sun_path` limit).
struct ShortDir(PathBuf);

impl ShortDir {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = PathBuf::from(format!("/tmp/pc{}-{tag}{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}

impl Drop for ShortDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Pki {
    dir: TempDir,
    ca: Ca,
    ca_file: PathBuf,
}

impl Pki {
    fn new() -> Self {
        let dir = TempDir::new("cluster-pki");
        let ca = Ca::new("cluster test CA");
        let ca_file = dir.write("ca.pem", ca.pem.as_bytes());
        Self { dir, ca, ca_file }
    }

    /// (cert, key) files for `name` (identity `dns:<name>`).
    fn leaf(&self, name: &str) -> (PathBuf, PathBuf) {
        let l = self.ca.peer_leaf(name);
        (
            self.dir.write(&format!("{name}.pem"), l.pem.as_bytes()),
            self.dir.write(&format!("{name}.key"), l.key_pem.as_bytes()),
        )
    }
}

/// The cluster layout shared by every node of a test.
#[derive(Clone)]
struct Layout {
    ports: Vec<u16>,
    witness: Option<u16>,
    auto: Option<bool>,
}

impl Layout {
    fn new(members: usize, witness: bool) -> Self {
        let mut ports = free_ports(members + usize::from(witness));
        let witness = witness.then(|| ports.pop().unwrap());
        Self { ports, witness, auto: None }
    }
}

fn ident(id: u16) -> String {
    format!("plat-{id}.cluster.test")
}

fn hook_script(dir: &Path, name: &str, log: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\necho \"{name} $1 $2 $3\" >> {}\n", log.display())).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// A member's config: the example with slices, the member list and HA.
fn member_cfg(
    l: &Layout,
    id: u16,
    listen: u16,
    pki: &Pki,
    state: &Path,
    extra_nat: &str,
    hooks: Option<(&Path, &Path)>,
) -> Config {
    let (cert, key) = pki.leaf(&ident(id));
    let n = l.ports.len();
    let mut t = include_str!("../../../../config/platd.example.toml")
        .replace("id = 0\nname = \"plat-01\"", &format!("id = {id}\nname = \"plat-{id}\""))
        .replace("node_count = 1", &format!("node_count = {n}\npartition = \"slices\"\nslice_prefix_len = 28"))
        .replace("allow_non_global_destinations = false", "allow_non_global_destinations = true")
        .replace("filtering = \"address_dependent\"", "filtering = \"endpoint_independent\"");
    if !extra_nat.is_empty() {
        t = t.replace("port_block_size = 512", extra_nat);
    }
    for (m, p) in l.ports.iter().enumerate() {
        t.push_str(&format!(
            "\n[[cluster.members]]\nid = {m}\nname = \"plat-{m}\"\npeer_addr = \"127.0.0.1:{p}\"\nidentity = \"dns:{}\"\n",
            ident(m as u16)
        ));
    }
    t.push_str(&format!("\n[cluster.ha]\nenabled = true\nlisten = \"127.0.0.1:{listen}\"\n"));
    if let Some(w) = l.witness {
        t.push_str(&format!("witness = {{ addr = \"127.0.0.1:{w}\", identity = \"dns:witness.cluster.test\" }}\n"));
    }
    if let Some(a) = l.auto {
        t.push_str(&format!("auto_failover = {a}\n"));
    }
    t.push_str(&format!(
        "lease_ms = {LEASE_MS}\nheartbeat_ms = 100\nfailback_delay_secs = 1\nhook_timeout_ms = 2000\n\
         shutdown_handover_ms = 3000\nstate_dir = {:?}\n",
        state.display().to_string()
    ));
    if let Some((a, w)) = hooks {
        t.push_str(&format!("[cluster.ha.hooks]\nannounce = {a:?}\nwithdraw = {w:?}\n"));
    }
    t.push_str(&format!(
        "[cluster.ha.tls]\ncert_file = {cert:?}\nkey_file = {key:?}\nca_file = {:?}\nrevocation = {{ mode = \"off\" }}\n",
        pki.ca_file
    ));
    Config::from_toml(&t).unwrap_or_else(|e| panic!("{e}\n{t}"))
}

fn peer_configs(cfg: &Config) -> plat_tls::PeerConfigs {
    let ha = cfg.cluster.ha_active().unwrap();
    plat_tls::peer_configs(&plat_tls::PeerSettings::from_config(&ha.tls, cfg.tls.pq_hybrid, None)).unwrap()
}

type Events = Arc<Mutex<Vec<Event>>>;

/// A collector that stops draining while `gate` is false (a full audit
/// queue on demand).
fn gated_collector(cap: usize) -> (AuditSink, Events, Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (sink, rx) = AuditSink::bounded(cap);
    let ev: Events = Arc::default();
    let gate = Arc::new(AtomicBool::new(true));
    let (e, g) = (ev.clone(), gate.clone());
    std::thread::spawn(move || {
        loop {
            if !g.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            match rx.recv_timeout(Duration::from_millis(20)) {
                Ok(x) => e.lock().push(x),
                Err(e) if e.is_timeout() => {}
                Err(_) => break,
            }
        }
    });
    (sink, ev, gate)
}

fn collector(cap: usize) -> (AuditSink, Events) {
    let (sink, rx) = AuditSink::bounded(cap);
    let ev: Events = Arc::default();
    let e = ev.clone();
    std::thread::spawn(move || {
        while let Ok(x) = rx.recv() {
            e.lock().push(x);
        }
    });
    (sink, ev)
}

struct Node {
    nat: Arc<Nat64>,
    /// The engine clock (not ticked: tests advance it).
    clock: Clock,
    ctx: WorkerCtx,
    handle: Option<ClusterHandle>,
    events: Events,
}

impl Node {
    fn start(cfg: Config) -> Self {
        let (sink, events) = collector(1 << 16);
        Self::start_with(cfg, sink, events)
    }

    fn start_with(cfg: Config, sink: AuditSink, events: Events) -> Self {
        let clock = Clock::new();
        let (nat, repl) = crate::run::build_engine(&cfg, 1, &sink, &clock).unwrap();
        let nat = Arc::new(nat);
        let (hub, mut prods): (Arc<ReplHub>, Vec<ReplProducer>) = repl.unwrap();
        let ctx = WorkerCtx::new(Arc::new(Counters::default()), 1).with_repl(prods.remove(0));
        let handle = super::start(&cfg, nat.clone(), hub, sink, peer_configs(&cfg)).unwrap();
        Self { nat, clock, ctx, handle: Some(handle), events }
    }

    fn h(&self) -> &ClusterHandle {
        self.handle.as_ref().unwrap()
    }

    fn active(&self) -> usize {
        self.h().shared.active_slices()
    }

    fn kill(&mut self) {
        if let Some(h) = self.handle.take() {
            h.kill();
        }
    }

    fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown();
        }
    }

    fn has(&self, f: impl Fn(&Event) -> bool) -> bool {
        self.events.lock().iter().any(f)
    }

    /// Translates one UDP packet from `client`; returns the IPv4 source
    /// (address, port) it was mapped to.
    fn send(&mut self, client: u128, sport: u16) -> Option<(u32, u16)> {
        self.process(&udp6(client, sport, b"x"))
    }

    /// One TCP segment from the client; the IPv4 side of the mapping.
    fn tcp_out(&mut self, client: u128, sport: u16, flags: u8) -> Option<(u32, u16)> {
        self.process(&tcp6(client, sport, flags))
    }

    /// One TCP segment from the server to `(v4, port)`; the IPv6
    /// destination port when forwarded.
    fn tcp_in(&mut self, v4: u32, port: u16, flags: u8) -> Option<u16> {
        let pkt = tcp4(v4, port, flags);
        let mut buf = vec![0u8; HEADROOM + 2048];
        buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(&pkt);
        match self.nat.process(&mut buf, HEADROOM, pkt.len(), &mut self.ctx) {
            Verdict::Forward { start, len } => Some(be16(&buf[start..start + len], 42)),
            _ => None,
        }
    }

    fn process(&mut self, pkt: &[u8]) -> Option<(u32, u16)> {
        let mut buf = vec![0u8; HEADROOM + 2048];
        buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(pkt);
        match self.nat.process(&mut buf, HEADROOM, pkt.len(), &mut self.ctx) {
            Verdict::Forward { start, len } => {
                let v4 = &buf[start..start + len];
                Some((be32(v4, 12), be16(v4, 20)))
            }
            _ => None,
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.kill();
    }
}

fn tcp6(src: u128, sport: u16, flags: u8) -> Vec<u8> {
    let mut p = vec![0u8; 60];
    let dst = PREFIX | u128::from(SERVER);
    write_v6_header(&mut p, 0, 20, proto::TCP, 64, src, dst);
    put16(&mut p, 40, sport);
    put16(&mut p, 42, 443);
    p[52] = 5 << 4;
    p[53] = flags;
    let c = ck::finish(ck::pseudo_v6(src, dst, proto::TCP, 20) + ck::sum(&p[40..]));
    put16(&mut p, 56, c);
    p
}

fn tcp4(dst: u32, dport: u16, flags: u8) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    write_v4_header(&mut p, 0, 40, 0, true, false, 0, 64, proto::TCP, SERVER, dst);
    put16(&mut p, 20, 443);
    put16(&mut p, 22, dport);
    p[32] = 5 << 4;
    p[33] = flags;
    let c = ck::finish(ck::pseudo_v4(SERVER, dst, proto::TCP, 20) + ck::sum(&p[20..]));
    put16(&mut p, 36, c);
    p
}

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

fn udp6(src: u128, sport: u16, payload: &[u8]) -> Vec<u8> {
    let l = 8 + payload.len();
    let mut p = vec![0u8; 40 + l];
    let dst = PREFIX | u128::from(SERVER);
    write_v6_header(&mut p, 0, l as u16, proto::UDP, 64, src, dst);
    put16(&mut p, 40, sport);
    put16(&mut p, 42, 5353);
    put16(&mut p, 44, l as u16);
    p[48..].copy_from_slice(payload);
    let c = ck::finish(ck::pseudo_v6(src, dst, proto::UDP, l as u32) + ck::sum(&p[40..]));
    put16(&mut p, 46, ck::udp_nonzero(c));
    p
}

/// A UDP datagram from `SERVER:5353` to `(dst, dport)`.
fn udp4(dst: u32, dport: u16) -> Vec<u8> {
    let mut p = vec![0u8; 29];
    write_v4_header(&mut p, 0, 29, 0, true, false, 0, 64, proto::UDP, SERVER, dst);
    put16(&mut p, 20, 5353);
    put16(&mut p, 22, dport);
    put16(&mut p, 24, 9);
    p[28] = b'r';
    let c = ck::finish(ck::pseudo_v4(SERVER, dst, proto::UDP, 9) + ck::sum(&p[20..]));
    put16(&mut p, 26, ck::udp_nonzero(c));
    p
}

fn wait(what: &str, limit: Duration, mut f: impl FnMut() -> bool) -> Duration {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < limit, "timed out after {limit:?} waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
    t.elapsed()
}

fn witness_file(l: &Layout, pki: &Pki, state: &Path) -> WitnessFile {
    let (cert, key) = pki.leaf("witness.cluster.test");
    let mut t = format!(
        "[witness]\nname = \"witness\"\nlisten = \"127.0.0.1:{}\"\nidentity = \"dns:witness.cluster.test\"\n\
         lease_ms = {LEASE_MS}\nheartbeat_ms = 100\nstate_dir = {:?}\nmembers = [\n",
        l.witness.unwrap(),
        state.display().to_string()
    );
    for (m, p) in l.ports.iter().enumerate() {
        t.push_str(&format!("  {{ id = {m}, identity = \"dns:{}\", addr = \"127.0.0.1:{p}\" }},\n", ident(m as u16)));
    }
    t.push_str(&format!(
        "]\n[witness.tls]\ncert_file = {cert:?}\nkey_file = {key:?}\nca_file = {:?}\n[tls.revocation]\nmode = \"off\"\n\
         [audit.file]\npath = {:?}\n",
        pki.ca_file,
        state.join("witness-audit.jsonl")
    ));
    WitnessFile::from_toml(&t).unwrap()
}

fn total_active(nodes: &[&Node]) -> usize {
    nodes.iter().map(|n| n.active()).sum()
}

/// B-2: every Active slice has an in-sync backup, no node waits for a
/// backup copy, and every node has free blocks.
fn wait_protected(nodes: &[&Node]) {
    let state = || {
        nodes
            .iter()
            .map(|n| {
                let c = n.h().shared.repl.as_ref().unwrap().lock().slice_counts();
                (c, n.nat.state().pool.free_blocks(), n.nat.state().pool.held_blocks())
            })
            .collect::<Vec<_>>()
    };
    let t = Instant::now();
    while !state().iter().all(|(c, free, _)| c[3] == 0 && c[4] == 0 && *free > 0) {
        assert!(t.elapsed() < Duration::from_secs(15), "not protected: {:?}", state());
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// CP-10, AU-10, SC-24: two members and a witness join and split the 16
/// slices; a flow's block and BIB replicate to the backup; killing the
/// owner moves its slices to the backup within the lease bound with the
/// same mapping and acquire(takeover) records; the restarted member syncs
/// as backup and gets its slices back by handover (failback); hooks run
/// in order.
#[test]
fn join_replicate_takeover_rejoin_failback() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let hookdir = TempDir::new("hooks");
    let log = hookdir.path().join("hooks.log");
    let ann = hook_script(hookdir.path(), "announce", &log);
    let wd = hook_script(hookdir.path(), "withdraw", &log);
    let (wsink, _wev) = collector(4096);
    let w = super::witness::start(&witness_file(&l, &pki, &sw.0), wsink).unwrap();
    let cfg_a = member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", Some((&ann, &wd)));
    let mut a = Node::start(cfg_a.clone());
    let mut b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));

    wait("16 slices served once", Duration::from_secs(15), || {
        a.active() > 0 && b.active() > 0 && total_active(&[&a, &b]) == 16
    });
    assert!(a.has(|e| matches!(e, Event::ClusterViewChange { .. })));
    // The announce hook ran for A's slices and wrote the announce dir.
    wait("announce hooks", Duration::from_secs(5), || {
        std::fs::read_to_string(&log)
            .is_ok_and(|s| s.lines().filter(|l| l.starts_with("announce")).count() == a.active())
    });
    assert_eq!(std::fs::read_dir(sa.0.join("announce.d")).unwrap().count(), a.active());

    // A flow on A, replicated to B.
    let mut mapped = None;
    for i in 0..64u128 {
        let client = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 72) | 1;
        if let Some(m) = a.send(client, 40000) {
            mapped = Some((client, m));
            break;
        }
    }
    let (client, (v4, port)) = mapped.expect("A translates for its own slices");
    let s = a.nat.state().slice_map().unwrap().slice_of(v4).unwrap();
    // POAM-028: an established TCP connection of the same subscriber whose
    // server speaks next (no packet from the client after the takeover).
    let (tv4, tport) = a.tcp_out(client, 40001, SYN).unwrap();
    assert_eq!(a.tcp_in(tv4, tport, SYN | ACK), Some(40001));
    assert!(a.tcp_out(client, 40001, ACK).is_some());
    let ts = a.nat.state().slice_map().unwrap().slice_of(tv4).unwrap();
    let repl_b = b.h().shared.repl.clone().unwrap();
    wait("session hint on the backup", Duration::from_secs(5), || repl_b.lock().shadow.hint_count(ts) == 1);
    let tcp_bibs = usize::from(ts == s);
    wait("block and BIB on the backup", Duration::from_secs(5), || repl_b.lock().shadow_counts(s) == (1, 1 + tcp_bibs));
    wait("backup in sync", Duration::from_secs(5), || b.h().shared.repl.as_ref().unwrap().lock().slice_counts()[2] > 0);
    // NIST-006: the primary records its backup's replication state.
    wait("in_sync member state", Duration::from_secs(5), || {
        a.has(|e| matches!(e, Event::ClusterMemberState { member, .. } if member.peer_id == 1 && member.state == MemberState::InSync))
    });
    assert!(a.has(
        |e| matches!(e, Event::ClusterMemberState { member, .. } if member.peer_id == 1 && member.state == MemberState::Syncing)
    ));

    // Crash A: B takes every slice within the lease bound.
    // Only acquires after the crash count: under load B can miss a view
    // while the cluster forms, and slices adopted across that gap are
    // (conservatively) recorded as takeovers too.
    let a_slices = a.active();
    let mark = b.events.lock().len();
    let counted = b.h().shared.takeovers("takeover");
    a.kill();
    let took = wait("takeover by B", Duration::from_secs(6), || b.active() == 16);
    let bound = Duration::from_millis(LEASE_MS * 11 / 10 + 200 + 5 * 100 + 1000);
    assert!(took <= bound, "takeover took {took:?}, bound {bound:?}");
    // Acquire records reach `b.events` through the collector thread, so they
    // can trail `active()`: wait for them before comparing.
    let count_takeovers = || {
        b.events
            .lock()
            .iter()
            .skip(mark)
            .filter(
                |e| matches!(e, Event::ClusterSliceAcquire { acquire, .. } if acquire.reason == AuditAcquire::Takeover),
            )
            .count()
    };
    wait("takeover records", Duration::from_secs(5), || count_takeovers() >= a_slices);
    let takeovers = count_takeovers();
    let rs: Vec<_> = b
        .events
        .lock()
        .iter()
        .skip(mark)
        .filter_map(|e| match e {
            Event::ClusterSliceAcquire { acquire, .. } => Some((acquire.reason, acquire.prev_owner, acquire.in_sync)),
            _ => None,
        })
        .collect();
    assert_eq!(takeovers, a_slices, "{rs:?}");
    // The counter is bumped at the end of the acquire path (after the hook),
    // so it can trail `active()` by the last slice.
    wait("takeover counter", Duration::from_secs(5), || {
        b.h().shared.takeovers("takeover") - counted >= a_slices as u64
    });
    assert_eq!(b.h().shared.takeovers("takeover") - counted, a_slices as u64);
    wait("adopt record", Duration::from_secs(5), || {
        b.has(|e| matches!(e, Event::PortBlockAdopt { adopt, .. } if adopt.v4 == v4 && adopt.prev_owner == Some(0)))
    });
    // Same subscriber, same mapping on B (RFC 6146 §3.5.1.1).
    assert_eq!(b.send(client, 40000), Some((v4, port)));
    // The server speaks first on the restored session (ADF, no SYN).
    assert_eq!(b.tcp_in(tv4, tport, ACK), Some(40001), "restored TCP session survives the crash takeover");
    assert!(b.nat.state().strict_tcp(ts), "in sync and hinted: strict pickup");
    assert_eq!(b.tcp_out(client, 40002, ACK), None, "un-hinted non-SYN refused after a hinted adoption");

    // Rejoin A: standby, sync, failback by handover.
    drop(a);
    let mut a = Node::start(cfg_a);
    wait("failback to A", Duration::from_secs(20), || a.active() > 0 && total_active(&[&a, &b]) == 16);
    wait("failback record", Duration::from_secs(5), || {
        a.has(|e| matches!(e, Event::ClusterSliceAcquire { acquire, .. } if acquire.reason == AuditAcquire::Failback))
    });
    wait("release record", Duration::from_secs(5), || {
        b.has(|e| matches!(e, Event::PortBlockRelease { reason: Some(_), .. }))
    });
    // B-3: failback only to a member whose backup copies were in sync.
    let fb: Vec<bool> = a
        .events
        .lock()
        .iter()
        .filter_map(|e| match e {
            Event::ClusterSliceAcquire { acquire, .. } if acquire.reason == AuditAcquire::Failback => {
                Some(acquire.in_sync)
            }
            _ => None,
        })
        .collect();
    assert!(!fb.is_empty() && fb.iter().all(|x| *x), "failback acquires in sync: {fb:?}");
    // B-2: after the handover both directions are protected again and no
    // block is held back.
    wait_protected(&[&a, &b]);
    // Planned failback carried the (now ESTABLISHED on B) session back.
    assert_eq!(a.nat.state().slice_state(ts), Some(SliceState::Active), "A's slice failed back");
    assert_eq!(a.tcp_in(tv4, tport, ACK), Some(40001), "restored TCP session survives the failback");

    // Auto mode refuses the manual commands.
    assert!(b.h().command(Command::Takeover(0, false)).starts_with("error"));
    // Operator socket: status JSON.
    let st = cli_request(&sb.0, "status").unwrap();
    assert!(st.contains("\"node_id\":1") && st.contains("\"slices\":["), "{st}");

    a.stop();
    assert!(std::fs::read_to_string(&log).unwrap().contains("withdraw"), "withdraw hooks at A's orderly stop");
    b.stop();
    w.shutdown();
}

/// SC-24: with the witness and one member gone, the survivor is a minority
/// (1 of 3 voters): it fences and takes nothing over.
#[test]
fn minority_member_fences_without_witness() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let w = super::witness::start(&witness_file(&l, &pki, &sw.0), collector(4096).0).unwrap();
    let mut a = Node::start(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None));
    let b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));
    wait("16 slices", Duration::from_secs(15), || total_active(&[&a, &b]) == 16);
    w.kill();
    a.kill();
    wait("B fences", Duration::from_secs(5), || b.active() == 0);
    std::thread::sleep(Duration::from_millis(2 * LEASE_MS));
    assert_eq!(b.active(), 0, "no takeover without quorum");
    assert!(b.has(|e| matches!(e, Event::ClusterSliceRelease { .. })));
}

/// IA-3, CM-6 (POAM-017c): a second live member with the same id (same
/// certificate, another connection) is refused `duplicate_id` and reported
/// degraded; a member with another config digest is refused
/// `digest_mismatch`. Both refusals are audited.
#[test]
fn duplicate_id_and_digest_mismatch_are_refused() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sb2, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("c"), ShortDir::new("w"));
    let (wsink, wev) = collector(4096);
    let w = super::witness::start(&witness_file(&l, &pki, &sw.0), wsink).unwrap();
    let _a = Node::start(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None));
    let _b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));
    wait("B up at the witness", Duration::from_secs(10), || w.shared.net.is_up(1));
    // A clone of member 1 on another port dials the witness too.
    let _b2 = Node::start(member_cfg(&l, 1, free_port_besides(&l), &pki, &sb2.0, "", None));
    wait("duplicate refused", Duration::from_secs(10), || w.shared.net.stats.rejected(RejectReason::DuplicateId) > 0);
    assert!(w.shared.health_problem().is_some());
    // The refusal is counted before its audit record is emitted, and the
    // collector thread moves records into `wev` asynchronously: wait for it.
    wait("duplicate refusal record", Duration::from_secs(10), || {
        wev.lock().iter().any(|e| {
            matches!(e, Event::ClusterPeerRejected { rejected, .. }
            if rejected.reason == PeerRejectReason::DuplicateId && rejected.claimed_id == Some(1))
        })
    });
    drop(w);

    // Digest mismatch: two members (manual mode), different block size.
    let l2 = Layout::new(2, false);
    let (sc, sd) = (ShortDir::new("c"), ShortDir::new("d"));
    let c = Node::start(member_cfg(&l2, 0, l2.ports[0], &pki, &sc.0, "", None));
    let d = Node::start(member_cfg(&l2, 1, l2.ports[1], &pki, &sd.0, "port_block_size = 256", None));
    wait("digest mismatch refused", Duration::from_secs(10), || {
        c.h().shared.net.stats.rejected(RejectReason::DigestMismatch)
            + d.h().shared.net.stats.rejected(RejectReason::DigestMismatch)
            > 0
    });
    assert!(!c.h().shared.net.is_up(1));
    wait("digest mismatch refusal record", Duration::from_secs(10), || {
        c.has(|e| matches!(e, Event::ClusterPeerRejected { rejected, .. } if rejected.reason == PeerRejectReason::DigestMismatch))
            || d.has(|e| matches!(e, Event::ClusterPeerRejected { rejected, .. } if rejected.reason == PeerRejectReason::DigestMismatch))
    });
}

fn operator_records(n: &Node) -> Vec<(plat_audit::OperatorCommandKind, bool, Option<OperatorRefusal>, Option<u32>)> {
    n.events
        .lock()
        .iter()
        .filter_map(|e| match e {
            Event::ClusterOperatorCommand { cmd, .. } => Some((cmd.command, cmd.force, cmd.refused, cmd.peer_uid)),
            _ => None,
        })
        .collect()
}

/// Q4, SEC-2, SEC-5: two members without a witness run in manual mode. A
/// takeover of a connected member is refused unless forced, and a forced
/// one serves the slices only after the takeover wait; after the operator
/// stopped the peer, takeover moves its slices (manual view change and
/// acquires); restore gives them back. Every command is audited with the
/// client's uid, refusals included; other uids are refused.
#[test]
fn manual_takeover_and_restore() {
    use plat_audit::OperatorCommandKind as K;
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, false);
    let (sa, sb) = (ShortDir::new("a"), ShortDir::new("b"));
    let a = Node::start(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None));
    let mut b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));
    wait("primaries served", Duration::from_secs(5), || total_active(&[&a, &b]) == 16);
    wait("peer link", Duration::from_secs(5), || a.h().shared.net.is_up(1));
    let mine = a.active();
    let uid = a.h().shared.daemon_uid();

    // SEC-2: B is connected.
    let r = cli_request(&sa.0, "takeover 1").unwrap();
    assert!(r.starts_with("error") && r.contains("--force"), "{r}");
    assert_eq!(a.active(), mine);
    // Forced: acquired only after safe = lease * 1.1 + 200 ms.
    let t = Instant::now();
    let r = cli_request(&sa.0, "takeover 1 --force").unwrap();
    assert!(r.starts_with("ok"), "{r}");
    wait("forced takeover", Duration::from_secs(5), || a.active() == 16);
    assert!(t.elapsed() >= Duration::from_millis(LEASE_MS), "forced takeover waited only {:?}", t.elapsed());
    assert!(a.h().command(Command::Restore(1)).starts_with("ok"));
    wait("restore", Duration::from_secs(5), || a.active() == mine);

    // The operator stops B, then takes over.
    b.kill();
    wait("link down", Duration::from_secs(5), || !a.h().shared.net.is_up(1));
    // SEC-R1-1: a link-down takeover is held for `safe` too (B may only
    // be partitioned and still serving until its lease lapses).
    let t = Instant::now();
    let r = cli_request(&sa.0, "takeover 1").unwrap();
    assert!(r.starts_with("ok"), "{r}");
    wait("takeover", Duration::from_secs(5), || a.active() == 16);
    assert!(t.elapsed() >= Duration::from_millis(LEASE_MS), "link-down takeover waited only {:?}", t.elapsed());
    assert!(a.has(|e| matches!(e, Event::ClusterViewChange { view, .. } if view.reason == ViewReason::Manual)));
    assert!(
        a.has(|e| matches!(e, Event::ClusterSliceAcquire { acquire, .. } if acquire.reason == AuditAcquire::Manual))
    );
    assert!(a.h().command(Command::Restore(1)).starts_with("ok"));
    wait("restore", Duration::from_secs(5), || a.active() < 16);
    assert!(a.h().command(Command::Takeover(9, false)).starts_with("error"));

    // SEC-5: peer credentials; other uids and missing credentials refused.
    let other = plat_io::cred::PeerCred { uid: uid.wrapping_add(4242).max(1), pid: Some(1) };
    let sh = &a.h().shared;
    assert!(super::control::cli_handle(sh, "status", Some(other)).starts_with("error: not authorized"));
    assert!(super::control::cli_handle(sh, "takeover 1", None).starts_with("error"));
    assert!(
        super::control::cli_handle(sh, "bogus", Some(plat_io::cred::PeerCred { uid, pid: None })).starts_with("error")
    );
    wait("operator records", Duration::from_secs(2), || operator_records(&a).len() >= 9);
    let recs = operator_records(&a);
    let me = Some(uid);
    let expect = [
        (K::Takeover, false, Some(OperatorRefusal::MemberUp), me),
        (K::Takeover, true, None, me),
        (K::Restore, false, None, me),
        (K::Takeover, false, None, me),
        (K::Restore, false, None, me),
        (K::Takeover, false, Some(OperatorRefusal::UnknownMember), me),
        (K::Status, false, Some(OperatorRefusal::NotAuthorized), Some(other.uid)),
        (K::Takeover, false, Some(OperatorRefusal::NoCredentials), None),
        (K::Invalid, false, Some(OperatorRefusal::Invalid), me),
    ];
    assert_eq!(recs, expect);
}

/// SEC-1, SEC-3, SEC-9, NIST-004: with three members, a member that does
/// not own a slice cannot feed its backup: a forged snapshot, record and
/// subscriber home are refused and audited (`not_allowed`) and leave the
/// shadow and directory as they were. The owner's records outside the
/// client prefixes close the link (`invalid_input`), a stray Hello closes
/// it (`protocol`). The takeover then adopts exactly the real state.
#[test]
fn non_owner_replication_is_refused() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(3, false);
    let dirs: Vec<ShortDir> = (0..3).map(|i| ShortDir::new(&format!("o{i}"))).collect();
    let mut nodes: Vec<Node> = (0..3u16)
        .map(|i| Node::start(member_cfg(&l, i, l.ports[usize::from(i)], &pki, &dirs[usize::from(i)].0, "", None)))
        .collect();
    wait("16 slices", Duration::from_secs(15), || {
        nodes.iter().map(Node::active).sum::<usize>() == 16 && nodes.iter().all(|n| n.active() > 0)
    });
    // A flow on member 0.
    let mut mapped = None;
    for i in 0..64u128 {
        let client = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 72) | 1;
        if let Some(m) = nodes[0].send(client, 40000) {
            mapped = Some((client, m));
            break;
        }
    }
    let (client, (v4, port)) = mapped.expect("member 0 translates for its slices");
    let s: SliceId = nodes[0].nat.state().slice_map().unwrap().slice_of(v4).unwrap();
    let view = nodes[0].h().shared.view().unwrap();
    let (p, b) = view.owners(s, &[1, 1, 1]).unwrap();
    let b = b.unwrap();
    assert_eq!(p, 0);
    let z = (0..3u16).find(|i| *i != p && *i != b).unwrap();
    let (bi, zi) = (usize::from(b), usize::from(z));
    let repl_b = nodes[bi].h().shared.repl.clone().unwrap();
    let synced = |r: &Arc<Mutex<super::replicator::Replicator>>| {
        let g = r.lock();
        g.shadow_counts(s) == (1, 1) && g.shadow.in_sync(s)
    };
    wait("backup in sync", Duration::from_secs(10), || synced(&repl_b));
    wait("links", Duration::from_secs(5), || nodes[zi].h().shared.net.is_up(b) && nodes[0].h().shared.net.is_up(b));

    // Forged by member z, which neither owns nor backs up the slice.
    let stranger: u128 = 0x2001_0db8_01ff_0000_0000_0000_0000_0000;
    let znet = nodes[zi].h().shared.net.clone();
    assert!(znet.send(b, &Msg::SnapshotBegin { slice: s, seq: 1 }));
    assert!(znet.send(
        b,
        &Msg::BlockAlloc { slice: s, seq: 2, sub: stranger, block: WireBlock { addr: v4, block: 3 }, wall_us: 1 }
    ));
    assert!(znet.send(b, &Msg::SnapshotEnd { slice: s, seq: 3, hints: false }));
    assert!(znet.send(b, &Msg::SubHome { sub: stranger, slice: s }));
    // POAM-028: a session hint from a non-owner is refused the same way.
    let hint = plat_cluster::WireHint { proto: 6, v4, port4: port, raddr: SERVER, rport: 443 };
    assert!(znet.send(b, &Msg::SessHint { slice: s, seq: 4, hint }));
    let bnet = nodes[bi].h().shared.net.clone();
    wait("forgeries refused", Duration::from_secs(5), || bnet.stats.rejected(RejectReason::NotAllowed) >= 5);
    assert!(synced(&repl_b), "shadow untouched");
    assert_eq!(repl_b.lock().shadow.hint_count(s), 0, "no forged hint");
    assert_ne!(nodes[bi].nat.state().directory().unwrap().home_of(stranger).map(|h| h.node), Some(z));
    assert!(bnet.is_up(z), "a lagging view is not a reason to drop the link");
    assert!(nodes[bi].has(|e| matches!(e, Event::ClusterPeerRejected { rejected, .. }
        if rejected.reason == PeerRejectReason::NotAllowed && rejected.claimed_id == Some(z))));

    // The owner itself, with a subscriber outside the client prefixes.
    let outside: u128 = 0x2001_0db9_0000_0000_0000_0000_0000_0000;
    let pnet = nodes[0].h().shared.net.clone();
    assert!(pnet.send(
        b,
        &Msg::BlockAlloc { slice: s, seq: 99, sub: outside, block: WireBlock { addr: v4, block: 4 }, wall_us: 1 }
    ));
    wait("invalid input refused", Duration::from_secs(5), || bnet.stats.rejected(RejectReason::InvalidInput) >= 1);
    // A Hello on an established link.
    assert!(znet.send(b, &Msg::HelloAck(None)));
    wait("protocol refused", Duration::from_secs(5), || bnet.stats.rejected(RejectReason::Protocol) >= 1);
    // Links come back; the backup resyncs from the owner.
    wait("backup in sync again", Duration::from_secs(10), || synced(&repl_b));

    // Takeover: exactly the real block, same mapping.
    nodes[0].kill();
    wait("takeover", Duration::from_secs(8), || nodes[bi].nat.state().slice_state(s) == Some(SliceState::Active));
    let cidr = super::slice_cidr(nodes[bi].nat.state().slice_map().unwrap().cidr(s).unwrap());
    let acq: Vec<_> = nodes[bi]
        .events
        .lock()
        .iter()
        .filter_map(|e| match e {
            Event::ClusterSliceAcquire { acquire, .. } if acquire.slice == cidr => Some(acquire.clone()),
            _ => None,
        })
        .collect();
    let last = acq.last().unwrap();
    assert_eq!(
        (last.reason, last.prev_owner, last.blocks_adopted, last.in_sync),
        (AuditAcquire::Takeover, Some(0), 1, true)
    );
    assert_eq!(nodes[bi].send(client, 40000), Some((v4, port)));
    for (i, n) in nodes.iter_mut().enumerate() {
        if i != 0 {
            n.stop();
        }
    }
}

/// SEC-4, NIST-004: unauthenticated connections from a member's address
/// get at most two pending handshakes; the next is refused `capacity`
/// before TLS, and the member's own link is unaffected.
#[test]
fn pending_handshakes_are_capped_per_source() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, false);
    let (sa, sb) = (ShortDir::new("a"), ShortDir::new("b"));
    let _a = Node::start(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None));
    let b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));
    let net = b.h().shared.net.clone();
    wait("peer link", Duration::from_secs(5), || net.is_up(0));
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], l.ports[1]));
    let held: Vec<_> = (0..4).map(|_| std::net::TcpStream::connect(addr).unwrap()).collect();
    wait("capacity refusal", Duration::from_secs(3), || net.stats.rejected(RejectReason::Capacity) >= 2);
    assert!(b.has(
        |e| matches!(e, Event::ClusterPeerRejected { rejected, .. } if rejected.reason == PeerRejectReason::Capacity)
    ));
    assert!(net.is_up(0));
    drop(held);
}

/// NIST-R1-01: with `refuse_new_bindings`, an accepted operator command
/// whose record cannot be queued is refused and does not act.
#[test]
fn operator_command_waits_for_audit_room() {
    use std::sync::atomic::Ordering;
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, false);
    let (sa, sb) = (ShortDir::new("qa"), ShortDir::new("qb"));
    let (sink, ev, gate) = gated_collector(4096);
    let a = Node::start_with(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None), sink.clone(), ev);
    let mut b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));
    wait("primaries served", Duration::from_secs(5), || total_active(&[&a, &b]) == 16);
    let mine = a.active();
    b.kill();
    wait("link down", Duration::from_secs(5), || !a.h().shared.net.is_up(1));
    gate.store(false, Ordering::Release);
    std::thread::sleep(Duration::from_millis(100));
    while matches!(sink.try_emit(Event::Counter { ts_us: 0, name: "fill", value: 0 }), TryEmit::Queued) {}
    let r = a.h().command(Command::Takeover(1, false));
    assert!(r.starts_with("error") && r.contains("audit"), "{r}");
    std::thread::sleep(Duration::from_millis(2 * LEASE_MS));
    assert_eq!(a.active(), mine, "a refused command does not act");
    gate.store(true, Ordering::Release);
    wait("audit drained", Duration::from_secs(5), || sink.has_room());
    assert!(a.h().command(Command::Takeover(1, false)).starts_with("ok"));
    wait("takeover", Duration::from_secs(5), || a.active() == 16);
}

/// NIST-001, NIST-004: a follower that lost its lease when the leader died
/// regains its own slices only once its acquire record can be queued
/// (`refuse_new_bindings`), and logs each acquire once per slice and epoch.
#[test]
fn regain_waits_for_audit_room() {
    use std::sync::atomic::Ordering;
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(3, false);
    let dirs: Vec<ShortDir> = (0..3).map(|i| ShortDir::new(&format!("r{i}"))).collect();
    let mut gates = Vec::new();
    let mut nodes: Vec<Node> = (0..3u16)
        .map(|i| {
            let (sink, ev, gate) = gated_collector(4096);
            gates.push((sink.clone(), gate));
            let cfg = member_cfg(&l, i, l.ports[usize::from(i)], &pki, &dirs[usize::from(i)].0, "", None);
            Node::start_with(cfg, sink, ev)
        })
        .collect();
    wait("16 slices", Duration::from_secs(15), || {
        nodes.iter().map(Node::active).sum::<usize>() == 16 && nodes.iter().all(|n| n.active() > 0)
    });
    let leader = usize::from(nodes[0].h().shared.view().unwrap().leader);
    let f = (0..3).find(|i| *i != leader).unwrap();
    // Fill F's audit queue.
    let (sink, gate) = &gates[f];
    gate.store(false, Ordering::Release);
    std::thread::sleep(Duration::from_millis(100));
    while matches!(sink.try_emit(Event::Counter { ts_us: 0, name: "fill", value: 0 }), TryEmit::Queued) {}
    nodes[leader].kill();
    wait("F fenced", Duration::from_secs(5), || nodes[f].active() == 0);
    std::thread::sleep(Duration::from_millis(4 * LEASE_MS));
    assert_eq!(nodes[f].active(), 0, "nothing served before its acquire record is queued");
    gate.store(true, Ordering::Release);
    let rest: Vec<usize> = (0..3).filter(|i| *i != leader).collect();
    wait("all served", Duration::from_secs(10), || {
        nodes[f].active() > 0 && rest.iter().map(|i| nodes[*i].active()).sum::<usize>() == 16
    });
    let me = Some(f as u16);
    assert!(
        nodes[f].has(|e| matches!(e, Event::ClusterSliceAcquire { acquire, .. } if acquire.prev_owner == me)),
        "F regained its own slices"
    );
    let mut seen = std::collections::HashSet::new();
    for e in nodes[f].events.lock().iter() {
        if let Event::ClusterSliceAcquire { acquire, .. } = e {
            assert!(
                seen.insert((acquire.slice.net, acquire.slice.len, acquire.epoch)),
                "acquire logged twice: {acquire:?}"
            );
        }
    }
    for i in rest {
        nodes[i].stop();
    }
}

/// Three members, no witness: losing the leader still leaves a majority;
/// its slices move to their backups.
#[test]
fn three_members_survive_leader_loss() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(3, false);
    let dirs: Vec<ShortDir> = (0..3).map(|i| ShortDir::new(&format!("m{i}"))).collect();
    let mut nodes: Vec<Node> = (0..3u16)
        .map(|i| Node::start(member_cfg(&l, i, l.ports[usize::from(i)], &pki, &dirs[usize::from(i)].0, "", None)))
        .collect();
    wait("16 slices", Duration::from_secs(15), || {
        nodes.iter().map(Node::active).sum::<usize>() == 16 && nodes.iter().all(|n| n.active() > 0)
    });
    let leader = nodes[0].h().shared.view().unwrap().leader;
    nodes[usize::from(leader)].kill();
    let rest: Vec<usize> = (0..3).filter(|i| *i != usize::from(leader)).collect();
    wait("takeover", Duration::from_secs(8), || rest.iter().map(|i| nodes[*i].active()).sum::<usize>() == 16);
    for i in rest {
        nodes[i].stop();
    }
}

/// NIST-005: the witness refuses a configuration without an audit
/// destination.
#[test]
fn witness_requires_audit() {
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let sw = ShortDir::new("wa");
    let f = witness_file(&l, &pki, &sw.0);
    assert!(f.audit.is_some());
    let (cert, key) = pki.leaf("witness.cluster.test");
    let mut t = format!(
        "[witness]\nname = \"witness\"\nlisten = \"127.0.0.1:{}\"\nidentity = \"dns:witness.cluster.test\"\n\
         state_dir = \"/var/lib/plat/witness\"\nmembers = [\n",
        l.witness.unwrap()
    );
    for (m, p) in l.ports.iter().enumerate() {
        t.push_str(&format!("  {{ id = {m}, identity = \"dns:{}\", addr = \"127.0.0.1:{p}\" }},\n", ident(m as u16)));
    }
    t.push_str(&format!("]\n[witness.tls]\ncert_file = {cert:?}\nkey_file = {key:?}\nca_file = {:?}\n", pki.ca_file));
    let e = WitnessFile::from_toml(&t).unwrap_err();
    assert!(e.contains("[audit]"), "{e}");
    // An [audit] section without a destination is not enough.
    let e = WitnessFile::from_toml(&format!("{t}[audit]\nmode = \"port_block\"\n")).unwrap_err();
    assert!(e.contains("[audit]"), "{e}");
}

/// B-1 (AU-12, CP-10): an orderly stop with replication on releases every
/// `AuditSink` clone, so the daemon's logger sees the queue disconnect and
/// drains (no wait for the service manager's stop timeout).
#[test]
fn orderly_stop_releases_every_audit_sink() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let w = super::witness::start(&witness_file(&l, &pki, &sw.0), collector(4096).0).unwrap();
    let (sink, rx) = AuditSink::bounded(1 << 16);
    let ev: Events = Arc::default();
    let closed = Arc::new(AtomicBool::new(false));
    {
        let (e, c) = (ev.clone(), closed.clone());
        std::thread::spawn(move || {
            while let Ok(x) = rx.recv() {
                e.lock().push(x);
            }
            c.store(true, Ordering::Release);
        });
    }
    let mut a = Node::start_with(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None), sink, ev);
    let mut b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));
    wait("16 slices", Duration::from_secs(15), || a.active() > 0 && total_active(&[&a, &b]) == 16);
    // Replication running in both directions.
    for i in 0..32u128 {
        let _ = a.send(0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 72) | 1, 40000);
    }
    wait("A's backup in sync", Duration::from_secs(10), || {
        a.h().shared.repl.as_ref().unwrap().lock().slice_counts()[2] > 0
    });
    let t = Instant::now();
    a.stop();
    drop(a);
    // The orderly stop waits at most shutdown_handover_ms (3 s) for the
    // handover view; the sinks drop right after.
    wait("A's audit queue disconnected", Duration::from_secs(2), || closed.load(Ordering::Acquire));
    assert!(t.elapsed() < Duration::from_secs(6), "stop took {:?}", t.elapsed());
    b.stop();
    w.shutdown();
}

/// S-1 (IA-3): an impostor that claims the id of a connected member with
/// another member's certificate (and address) is refused `duplicate_id`,
/// not just `id_mismatch`, and health reports degraded; the live member's
/// connection stays up.
#[test]
fn impostor_of_a_live_member_is_a_duplicate_id() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sx, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("x"), ShortDir::new("w"));
    let (wsink, wev) = collector(4096);
    let w = super::witness::start(&witness_file(&l, &pki, &sw.0), wsink).unwrap();
    let _a = Node::start(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None));
    let _b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));
    wait("A up at the witness", Duration::from_secs(10), || w.shared.net.is_up(0));
    assert!(w.shared.health_problem().is_none());
    // Id 0 again, but with member 1's certificate.
    let mut cfg = member_cfg(&l, 0, free_port_besides(&l), &pki, &sx.0, "", None);
    let (cert, key) = pki.leaf(&ident(1));
    let ha = cfg.cluster.ha.as_mut().unwrap();
    ha.tls.cert_file = cert;
    ha.tls.key_file = key;
    let _x = Node::start(cfg);
    wait("impostor refused", Duration::from_secs(10), || w.shared.net.stats.rejected(RejectReason::DuplicateId) > 0);
    assert!(w.shared.health_problem().is_some());
    assert!(w.shared.net.is_up(0), "the authenticated member stays connected");
    assert!(wev.lock().iter().any(|e| matches!(e, Event::ClusterPeerRejected { rejected, .. }
        if rejected.reason == PeerRejectReason::DuplicateId && rejected.claimed_id == Some(0))));
}

/// B-2, B-4 (CP-10, SI-4): a gap on the backup (a lost or refused record)
/// is counted and makes the backup ask for a new snapshot; a backup
/// restarted twice, once while its snapshot is in flight, syncs again;
/// afterwards every slice is protected and both pools have free blocks.
#[test]
fn backup_gap_and_restart_mid_snapshot_resync() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let w = super::witness::start(&witness_file(&l, &pki, &sw.0), collector(4096).0).unwrap();
    let mut a = Node::start(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None));
    let cfg_b = member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None);
    let mut b = Node::start(cfg_b.clone());
    wait("16 slices", Duration::from_secs(15), || a.active() > 0 && b.active() > 0 && total_active(&[&a, &b]) == 16);
    let mut flows = 0;
    for i in 0..256u128 {
        for p in 0..4u16 {
            flows +=
                usize::from(a.send(0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 72) | 1, 40000 + p).is_some());
        }
    }
    assert!(flows > 0);
    wait_protected(&[&a, &b]);

    // A gap on B for one of A's slices.
    let repl_a = a.h().shared.repl.clone().unwrap();
    let repl_b = b.h().shared.repl.clone().unwrap();
    let s = (0..16u16).find(|s| repl_a.lock().owners(*s) == (Some(0), Some(1))).unwrap();
    let resyncs = repl_a.lock().stats.resync_total.load(std::sync::atomic::Ordering::Relaxed);
    // Gaps may already have been counted while the cluster formed (a
    // snapshot racing live records); only the injected one is asserted.
    let gaps = repl_b.lock().stats.rx_gaps.load(std::sync::atomic::Ordering::Relaxed);
    repl_b.lock().on_data(0, Msg::BibDelete { slice: s, seq: u64::MAX / 2, proto: 17, v4: 0, port4: 1 }).unwrap();
    assert_eq!(repl_b.lock().stats.rx_gaps.load(std::sync::atomic::Ordering::Relaxed), gaps + 1);
    wait("A resyncs on B's request", Duration::from_secs(5), || {
        repl_a.lock().stats.resync_total.load(std::sync::atomic::Ordering::Relaxed) > resyncs
    });
    wait_protected(&[&a, &b]);

    // Restart B, cut it again right after its link comes up (snapshot in
    // flight), then restart it for good.
    b.kill();
    drop(b);
    wait("A takes over", Duration::from_secs(6), || a.active() == 16);
    let b2 = Node::start(cfg_b.clone());
    wait("B linked", Duration::from_secs(10), || a.h().shared.net.is_up(1));
    std::thread::sleep(Duration::from_millis(30));
    drop(b2);
    let b = Node::start(cfg_b);
    wait("failback to B", Duration::from_secs(20), || b.active() > 0 && total_active(&[&a, &b]) == 16);
    wait_protected(&[&a, &b]);
    drop(b);
    drop(a);
    w.shutdown();
}

/// B-9 (SC-7, AU-10): after takeover/failback churn, a member that
/// restarted (empty directory) still knows the home of a long-lived
/// subscriber of its peer: the peer re-announces its homes on link-up and
/// after acquiring slices. A flow of that subscriber steered to the
/// restarted member is counted `missteered` and dropped; no block is
/// allocated there.
#[test]
fn restarted_member_relearns_homes_and_refuses_missteered() {
    use plat_common::{Counter, DropReason};
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let w = super::witness::start(&witness_file(&l, &pki, &sw.0), collector(4096).0).unwrap();
    let mut a = Node::start(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None));
    let cfg_b = member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None);
    let mut b = Node::start(cfg_b.clone());
    wait("16 slices", Duration::from_secs(15), || a.active() > 0 && b.active() > 0 && total_active(&[&a, &b]) == 16);
    // A long-lived subscriber homed on A.
    let mut client = None;
    for i in 0..64u128 {
        let c = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 72) | 1;
        if a.send(c, 40000).is_some() {
            client = Some(c);
            break;
        }
    }
    let client = client.expect("A translates for its own slices");
    wait_protected(&[&a, &b]);

    // Churn: B crashes (A takes over B's slices), restarts with an empty
    // directory and gets its slices back by failback.
    b.kill();
    drop(b);
    wait("A takes over", Duration::from_secs(6), || a.active() == 16);
    let mut b = Node::start(cfg_b);
    wait("failback to B", Duration::from_secs(20), || b.active() > 0 && total_active(&[&a, &b]) == 16);
    let dir_b = b.nat.state().directory().unwrap().clone();
    let sub = client & !((1u128 << 64) - 1);
    wait("B learns the subscriber's home", Duration::from_secs(5), || dir_b.home_of(sub).is_some_and(|h| h.node == 0));

    // Mis-steered to B: counted and dropped, nothing allocated on B.
    // Not `free_blocks`: that moves with the background reservation
    // top-up (free -> pending until A acknowledges) and hold-back expiry.
    let unallocated = |n: &Node| n.nat.state().pool.unallocated_blocks();
    let before = unallocated(&b);
    assert_eq!(b.send(client, 40001), None);
    assert_eq!(b.ctx.counters.get(Counter::ClusterSteerMissteered), 1);
    assert_eq!(b.ctx.counters.drops(DropReason::Missteered), 1);
    assert_eq!(unallocated(&b), before);
    assert!(!b.has(|e| matches!(e, Event::PortBlockAlloc { sub: s, .. } if *s == sub)));
    drop(b);
    drop(a);
    w.shutdown();
}

/// A stand-in for the witness whose peer channel is owned by the test: it
/// votes and acks through a real `Membership` in the witness role and
/// records when each `Heartbeat` arrives. Nothing in the members changes.
struct HeartbeatProbe {
    net: Arc<super::peer::Net>,
    beats: Arc<Mutex<Vec<(u16, Instant)>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    driver: Option<std::thread::JoinHandle<()>>,
}

struct ProbeInbound {
    tx: std::sync::mpsc::SyncSender<(u16, Msg)>,
    beats: Arc<Mutex<Vec<(u16, Instant)>>>,
}

impl super::peer::Inbound for ProbeInbound {
    fn control(&self, from: u16, msg: Msg) {
        if matches!(msg, Msg::Heartbeat { .. }) {
            self.beats.lock().push((from, Instant::now()));
        }
        let _ = self.tx.try_send((from, msg));
    }

    fn data(&self, _from: u16, _msg: Msg) -> Result<(), super::peer::Refusal> {
        Ok(())
    }

    fn link(&self, _peer: u16, _up: bool) {}
}

impl HeartbeatProbe {
    fn start(l: &Layout, pki: &Pki, state: &Path) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};

        use plat_cluster::{Action, Membership, MembershipConfig, Persisted};

        use super::control::{Voter, peer_specs};
        use super::replicator::mono_ms;

        let f = witness_file(l, pki, state);
        let (w, me) = (&f.witness, f.witness_id());
        let mut voters: Vec<Voter> = w
            .members
            .iter()
            .map(|m| Voter {
                id: m.id,
                name: format!("plat-{}", m.id),
                identity: m.identity.clone(),
                addr: m.addr,
                witness: false,
            })
            .collect();
        voters.push(Voter {
            id: me,
            name: w.name.clone(),
            identity: w.identity.clone(),
            addr: w.listen,
            witness: true,
        });
        let tls = plat_tls::peer_configs(&plat_tls::PeerSettings::from_config(&w.tls, f.tls.pq_hybrid, None)).unwrap();
        let digest = f.digest();
        let cfg = super::peer::NetConfig {
            me,
            name: w.name.clone(),
            listen: w.listen,
            i_am_witness: true,
            peers: peer_specs(&voters, me).unwrap(),
            digest_full: digest,
            digest_vote: digest,
            max_frame: 64 << 10,
            queue_bytes: 1 << 20,
            keepalive: Duration::from_millis(w.heartbeat_ms),
            idle_timeout: Duration::from_millis(w.lease_ms * 2),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let net = super::peer::Net::new(cfg, tls, collector(4096).0, stop.clone()).unwrap();
        let beats: Arc<Mutex<Vec<(u16, Instant)>>> = Arc::default();
        let (tx, rx) = std::sync::mpsc::sync_channel(1024);
        net.set_inbound(Arc::new(ProbeInbound { tx, beats: beats.clone() }));
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
            seed: 7,
        };
        // Votes are kept in memory only: the probe never restarts.
        let (mut m, initial) = Membership::new(mcfg, Persisted::default(), mono_ms()).unwrap();
        net.spawn().unwrap();
        let (dnet, dstop) = (net.clone(), stop.clone());
        let driver = std::thread::spawn(move || {
            let exec = |actions: Vec<Action>| {
                for a in actions {
                    if let Action::Send { to, msg } = a {
                        dnet.send(to, &msg);
                    }
                }
            };
            exec(initial);
            let tick = Duration::from_millis(m.tick_interval_ms());
            let mut next = Instant::now();
            while !dstop.load(Ordering::Relaxed) {
                if let Ok((from, msg)) = rx.recv_timeout(next.saturating_duration_since(Instant::now())) {
                    exec(m.on_msg(mono_ms(), from, &msg));
                }
                if Instant::now() >= next {
                    next = Instant::now() + tick;
                    exec(m.on_tick(mono_ms()));
                }
            }
        });
        Self { net, beats, stop, driver: Some(driver) }
    }

    /// Arrival times of the heartbeats `from` sent, oldest first.
    fn beats_from(&self, from: u16) -> Vec<Instant> {
        self.beats.lock().iter().filter(|b| b.0 == from).map(|b| b.1).collect()
    }
}

impl Drop for HeartbeatProbe {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(d) = self.driver.take() {
            let _ = d.join();
        }
        self.net.wake_all();
        self.net.join();
    }
}

/// Longest interval between consecutive instants, counting only intervals
/// that end inside `[from, to]`.
fn longest_gap(beats: &[Instant], from: Instant, to: Instant) -> Duration {
    beats
        .windows(2)
        .filter_map(|w| match w {
            [a, b] if *b >= from && *b <= to => Some(b.duration_since(*a)),
            _ => None,
        })
        .max()
        .unwrap_or_default()
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Load on the victim: `subs` subscribers with one block and `ports` UDP
/// mappings each. A new subscriber waits for a block reserved with the
/// backup, so a refused first packet is retried. Returns the load time.
fn hb_load(n: &mut Node, subs: usize, ports: usize) -> Duration {
    let fill = Instant::now();
    for i in 0..subs as u128 {
        let client = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 64) | 1;
        let t = Instant::now();
        while n.send(client, 40000).is_none() {
            assert!(t.elapsed() < Duration::from_secs(10), "no block for subscriber {i}");
            std::thread::sleep(Duration::from_millis(1));
        }
        for p in 1..ports as u16 {
            assert!(n.send(client, 40000 + p).is_some(), "subscriber {i} port {p}");
        }
    }
    fill.elapsed()
}

/// Waits until the leader's shadow holds every block and BIB, in sync.
fn hb_wait_synced(leader: &Node, subs: usize, ports: usize) -> Duration {
    let repl = leader.h().shared.repl.clone().unwrap();
    wait("backup holds every block and BIB, in sync", Duration::from_secs(120), || {
        let g = repl.lock();
        let (mut blocks, mut bibs) = (0, 0);
        for s in 0..16 {
            let c = g.shadow_counts(s);
            blocks += c.0;
            bibs += c.1;
            if c.0 > 0 && !g.shadow.in_sync(s) {
                return false;
            }
        }
        (blocks, bibs) == (subs, subs * ports)
    })
}

/// When each victim slice was first seen Adopting and Active on the leader.
struct HbTimeline {
    first_adopting: Vec<Option<Duration>>,
    active_at: Vec<Option<Duration>>,
    max_adopting: usize,
    took: Duration,
}

/// Samples the leader every 0.5 ms until it serves all 16 slices.
fn hb_timeline(leader: &Node, theirs: &[SliceId], killed: Instant) -> HbTimeline {
    let (mut first_adopting, mut active_at) = (vec![None; 16], vec![None; 16]);
    let mut max_adopting = 0;
    let st = leader.nat.state();
    while leader.active() < 16 {
        assert!(killed.elapsed() < Duration::from_secs(30), "timed out waiting for the takeover");
        let now = killed.elapsed();
        let mut adopting = 0;
        for &x in theirs {
            match st.slice_state(x) {
                Some(SliceState::Adopting) => {
                    adopting += 1;
                    first_adopting[usize::from(x)].get_or_insert(now);
                }
                Some(SliceState::Active) => {
                    active_at[usize::from(x)].get_or_insert(now);
                }
                _ => {}
            }
        }
        max_adopting = max_adopting.max(adopting);
        std::thread::sleep(Duration::from_micros(500));
    }
    let took = killed.elapsed();
    for &x in theirs {
        active_at[usize::from(x)].get_or_insert(took);
    }
    HbTimeline { first_adopting, active_at, max_adopting, took }
}

/// Sums the takeover acquire records after `mark`: (blocks, BIBs, slices).
fn hb_acquired(leader: &Node, mark: usize, victim_slices: usize) -> (u64, u64, usize) {
    let (mut blocks, mut bibs, mut slices) = (0u64, 0u64, 0usize);
    wait("acquire records", Duration::from_secs(5), || {
        (blocks, bibs, slices) = (0, 0, 0);
        for e in leader.events.lock().iter().skip(mark) {
            if let Event::ClusterSliceAcquire { acquire, .. } = e
                && acquire.reason == AuditAcquire::Takeover
            {
                blocks += u64::from(acquire.blocks_adopted);
                bibs += acquire.bibs_adopted;
                slices += 1;
            }
        }
        slices >= victim_slices
    });
    (blocks, bibs, slices)
}

/// Each slice went Active when its own adoption ended, in turn: the next
/// one is first seen Adopting no earlier than the previous Active (within
/// one sample).
fn hb_check_in_turn(order: &[(Duration, Option<Duration>, SliceId)]) {
    for w in order.windows(2) {
        if let (Some(a1), Some(a2)) = (w[0].1, w[1].1) {
            assert!(a1 <= a2 && w[0].0 <= a2 + Duration::from_millis(2), "not one after the other: {w:?}");
        }
    }
}

/// POAM-047, POAM-007 (2): the `plat-cluster-ctl` thread adopts every
/// slice of a crashed member in bounded steps between the leader's
/// heartbeats. The leader adopts the other member's slices (one block per
/// subscriber, `PLAT_HB_GAP_SUBS` x `PLAT_HB_GAP_PORTS` BIBs) while a
/// test-owned witness records when its heartbeats arrive. Prints the
/// longest gap before the crash and during the adoption, and asserts the
/// gap budget (heartbeat + tick + step, with margin) and that the leader
/// kept its lease (one view, no slice released).
#[test]
fn heartbeat_gap_during_large_adoption() {
    const HEARTBEAT: Duration = Duration::from_millis(100);
    const GAP_BUDGET: Duration = Duration::from_millis(150);
    let subs = env_usize("PLAT_HB_GAP_SUBS", 2000);
    let ports = env_usize("PLAT_HB_GAP_PORTS", 16).clamp(1, 256);
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let probe = HeartbeatProbe::start(&l, &pki, &sw.0);
    // QA (flake at 4M): with 512-port blocks a /28 holds 2016 blocks, so a
    // victim that drew 6 of the 16 slices could not hold 15624 one-block
    // subscribers. 256-port blocks (4032 per /28, still one block and up
    // to 256 mappings per subscriber) fit 4M BIBs in 4 slices; the split is
    // checked below, before the load.
    let nat = "port_block_size = 256";
    let mut nodes = [
        Node::start(member_cfg(&l, 0, l.ports[0], &pki, &sa.0, nat, None)),
        Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, nat, None)),
    ];
    wait("16 slices", Duration::from_secs(15), || {
        nodes.iter().all(|n| n.active() > 0) && total_active(&[&nodes[0], &nodes[1]]) == 16
    });
    // The leader survives, so its heartbeats to the witness never stop.
    let leader = nodes[0].h().shared.view().unwrap().leader;
    let (li, vi) = (usize::from(leader), usize::from(1 - leader));
    wait_protected(&[&nodes[0], &nodes[1]]);
    let room = nodes[vi].nat.state().pool.free_blocks();
    assert!(
        room as usize >= subs,
        "fixture: the victim owns {} slices ({room} free blocks) for {subs} one-block subscribers",
        nodes[vi].active()
    );

    // Load on the victim: `subs` subscribers with one block and `ports`
    // UDP mappings each. A new subscriber waits for a block reserved with
    // the backup, so a refused first packet is retried.
    let fill = hb_load(&mut nodes[vi], subs, ports);
    let victim_slices = nodes[vi].active();
    let synced = hb_wait_synced(&nodes[li], subs, ports);
    wait_protected(&[&nodes[0], &nodes[1]]);

    // Baseline: one second of undisturbed heartbeats.
    std::thread::sleep(Duration::from_secs(1));
    let mark = nodes[li].events.lock().len();
    let killed = Instant::now();
    let baseline = longest_gap(&probe.beats_from(leader), killed.checked_sub(Duration::from_secs(1)).unwrap(), killed);
    let killed_wall = Clock::wall_us();
    let theirs: Vec<SliceId> =
        (0..16).filter(|&x| nodes[vi].nat.state().slice_state(x) == Some(SliceState::Active)).collect();
    nodes[vi].kill();
    // Timeline (QA): when each of the victim's slices first shows
    // Adopting and Active on the leader, sampled every 0.5 ms; at most one
    // Adopting at a time (decision 3).
    let HbTimeline { first_adopting, active_at, max_adopting, took } = hb_timeline(&nodes[li], &theirs, killed);
    // Heartbeats delayed by the adoption arrive after it ends.
    std::thread::sleep(3 * HEARTBEAT);
    let gap = longest_gap(&probe.beats_from(leader), killed, Instant::now());

    let (blocks, bibs, slices) = hb_acquired(&nodes[li], mark, victim_slices);
    let view_us = nodes[li].events.lock().iter().skip(mark).find_map(|e| match e {
        Event::ClusterViewChange { ts_us, .. } => Some(ts_us.saturating_sub(killed_wall)),
        _ => None,
    });
    let start = theirs.iter().filter_map(|&x| first_adopting[usize::from(x)]).min();
    let mut order: Vec<(Duration, Option<Duration>, SliceId)> =
        theirs.iter().map(|&x| (active_at[usize::from(x)].unwrap(), first_adopting[usize::from(x)], x)).collect();
    order.sort_unstable();
    println!(
        "heartbeat_gap timeline: view after {:?}, first Adopting {start:?}, all Active {took:?}, adoption window {:?}, \
         max concurrent Adopting {max_adopting}; per slice (Adopting seen, Active): {:?}",
        view_us.map(Duration::from_micros),
        start.map(|s| took.saturating_sub(s)),
        order.iter().map(|o| (o.1, o.0)).collect::<Vec<_>>()
    );
    let mut m = String::new();
    nodes[li].h().shared.render_metrics(&mut m);
    let steps: Vec<&str> = m.lines().filter(|l| l.starts_with("plat_cluster_adopt_step")).collect();
    println!("heartbeat_gap steps: {steps:?}");
    assert!(max_adopting <= 1, "{max_adopting} slices Adopting at once (decision 3)");
    hb_check_in_turn(&order);
    // A stall longer than the lease costs the leader its own lease: it
    // then fences what it serves and a new view follows.
    let (views, released) = nodes[li].events.lock().iter().skip(mark).fold((0, 0), |(v, r), e| match e {
        Event::ClusterViewChange { .. } => (v + 1, r),
        Event::ClusterSliceRelease { .. } => (v, r + 1),
        _ => (v, r),
    });
    println!(
        "heartbeat_gap_during_large_adoption: adopted {slices} slices, {blocks} blocks, {bibs} BIBs \
         (load {fill:?}, backup in sync after {synced:?}); crash to all slices Active {took:?}; \
         longest heartbeat gap: {baseline:?} before the crash, {gap:?} during the takeover; \
         after the crash the leader adopted {views} views and released {released} slices \
         (heartbeat {HEARTBEAT:?}, lease {LEASE_MS} ms; this host, {} build)",
        if cfg!(debug_assertions) { "debug" } else { "release" }
    );
    assert_eq!((blocks, bibs), (subs as u64, (subs * ports) as u64), "the whole load was adopted");
    assert!(baseline > Duration::ZERO && gap > Duration::ZERO, "the probe saw the leader's heartbeats");
    // POAM-047: adoption runs in steps of ADOPT_STEP_BUDGET between the
    // ctl thread's ticks, so the longest gap stays within one heartbeat,
    // one tick and one step (100 + ~10 + 5 ms, asserted with margin), and
    // the leader keeps its lease: no new view, nothing released.
    assert!(gap <= GAP_BUDGET, "heartbeat gap {gap:?} over {GAP_BUDGET:?}");
    assert_eq!((views, released), (1, 0), "the leader kept its lease while adopting");
    for n in &mut nodes {
        n.stop();
    }
}

/// `plat_cluster_release_*` lines of `n`'s metrics, and the steps total.
fn release_metrics(n: &Node) -> (Vec<String>, u64) {
    let mut m = String::new();
    n.h().shared.render_metrics(&mut m);
    let lines: Vec<String> = m.lines().filter(|l| l.starts_with("plat_cluster_releas")).map(str::to_owned).collect();
    let steps = lines
        .iter()
        .find_map(|l| l.strip_prefix("plat_cluster_release_steps_total "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    (lines, steps)
}

/// Per slice: the last `handover` release record of `old` and the first
/// failback acquire record of `new` (wall µs), after the marks.
fn handover_order(old: &Node, new: &Node, mark: usize) -> Vec<(SliceId, u64, u64)> {
    let map = old.nat.state().slice_map().unwrap().clone();
    let mut last_rel = [0u64; 16];
    for e in old.events.lock().iter().skip(mark) {
        if let Event::PortBlockRelease { ts_us, v4, reason: Some(BlockReleaseReason::Handover), .. } = e
            && let Some(x) = map.slice_of(*v4)
        {
            last_rel[usize::from(x)] = last_rel[usize::from(x)].max(*ts_us);
        }
    }
    let mut out = Vec::new();
    for e in new.events.lock().iter() {
        if let Event::ClusterSliceAcquire { ts_us, acquire, .. } = e
            && acquire.reason == AuditAcquire::Failback
            && let Some(x) = map.slice_of(acquire.slice.net)
            && last_rel[usize::from(x)] > 0
        {
            out.push((x, last_rel[usize::from(x)], *ts_us));
        }
    }
    out
}

/// POAM-048: the `plat-cluster-ctl` thread releases large Active slices in
/// bounded steps between its heartbeats. The leader serves every slice
/// with the load (`PLAT_HB_GAP_SUBS` x `PLAT_HB_GAP_PORTS` BIBs) after the
/// other member crashed; the member restarts, syncs, and the leader hands
/// its slices back (failback: release cursors with `handover` records,
/// then `HandoverFence`). A test-owned witness records the leader's
/// heartbeats. Asserts the gap budget, that the leader kept its lease (no
/// lease-loss release), that every handed-over block got one `handover`
/// release record, and that the new owner acquired each slice only after
/// the old owner's last release record of it (`HandoverFence` after the
/// release, Q3), when the release finished within `safe`.
#[test]
fn heartbeat_gap_during_large_release() {
    const HEARTBEAT: Duration = Duration::from_millis(100);
    const GAP_BUDGET: Duration = Duration::from_millis(150);
    let subs = env_usize("PLAT_HB_GAP_SUBS", 2000);
    let ports = env_usize("PLAT_HB_GAP_PORTS", 16).clamp(1, 256);
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let probe = HeartbeatProbe::start(&l, &pki, &sw.0);
    let nat = "port_block_size = 256";
    let cfgs =
        [member_cfg(&l, 0, l.ports[0], &pki, &sa.0, nat, None), member_cfg(&l, 1, l.ports[1], &pki, &sb.0, nat, None)];
    let mut nodes = [Node::start(cfgs[0].clone()), Node::start(cfgs[1].clone())];
    wait("16 slices", Duration::from_secs(15), || {
        nodes.iter().all(|n| n.active() > 0) && total_active(&[&nodes[0], &nodes[1]]) == 16
    });
    let leader = nodes[0].h().shared.view().unwrap().leader;
    let (li, fi) = (usize::from(leader), usize::from(1 - leader));
    let own = nodes[li].active();
    wait_protected(&[&nodes[0], &nodes[1]]);
    nodes[fi].kill();
    wait("leader serves every slice", Duration::from_secs(10), || nodes[li].active() == 16);

    // Load on the leader, over all 16 slices.
    let fill = hb_load(&mut nodes[li], subs, ports);
    std::thread::sleep(Duration::from_secs(1));
    let mark = nodes[li].events.lock().len();
    let restart = Instant::now();
    let baseline =
        longest_gap(&probe.beats_from(leader), restart.checked_sub(Duration::from_secs(1)).unwrap(), restart);
    let (_, steps_before) = release_metrics(&nodes[li]);
    nodes[fi] = Node::start(cfgs[fi].clone());
    // Failback: the leader is back to its own slices, none releasing.
    let took = wait("failback", Duration::from_secs(120), || {
        let st = nodes[li].nat.state();
        nodes[li].active() == own && nodes[fi].active() == 16 - own && (0..16).all(|x| !st.slice_releasing(x))
    });
    std::thread::sleep(3 * HEARTBEAT);
    let gap = longest_gap(&probe.beats_from(leader), restart, Instant::now());
    let (lines, steps) = release_metrics(&nodes[li]);

    let (mut handover_blocks, mut lease_lost) = (0u64, 0usize);
    for e in nodes[li].events.lock().iter().skip(mark) {
        match e {
            Event::PortBlockRelease { reason: Some(BlockReleaseReason::Handover), .. } => handover_blocks += 1,
            Event::ClusterSliceRelease { reason: SliceReleaseReason::LeaseLost, .. } => lease_lost += 1,
            _ => {}
        }
    }
    let order = handover_order(&nodes[li], &nodes[fi], mark);
    let span = order.iter().map(|o| o.1).max().zip(order.iter().map(|o| o.1).min());
    println!(
        "heartbeat_gap_during_large_release: released {} slices, {handover_blocks} blocks with `handover` \
         (load {subs} x {ports} BIBs in {fill:?}); restart to failback done {took:?}; \
         longest heartbeat gap: {baseline:?} before, {gap:?} during the release; \
         release steps {}; {lines:?}; release records span {:?} ms; \
         per slice (last release, failback acquire) us: {order:?} (this host, {} build)",
        order.len(),
        steps - steps_before,
        span.map(|(a, b)| a.saturating_sub(b) / 1000),
        if cfg!(debug_assertions) { "debug" } else { "release" }
    );
    assert!(baseline > Duration::ZERO && gap > Duration::ZERO, "the probe saw the leader's heartbeats");
    assert_eq!(lease_lost, 0, "the leader kept its lease while releasing");
    assert!(steps > steps_before, "the release ran in steps");
    assert!(handover_blocks > 0, "handover release records");
    assert!(!order.is_empty(), "failback acquires");
    // Q3: the new owner stops waiting `safe` only on `HandoverFence`,
    // sent after the old owner's last release record of the slice. A
    // release longer than `safe` lets the new owner proceed first (still
    // SC-24-safe: the old owner was fenced throughout).
    let safe_us = (LEASE_MS * 11 / 10 + 200) * 1000;
    for (x, rel, acq) in &order {
        if rel.saturating_sub(span.map_or(0, |s| s.1)) < safe_us {
            assert!(rel <= acq, "slice {x}: acquired at {acq} before the last release record at {rel}");
        }
    }
    // POAM-048: one release step between two ticks.
    assert!(gap <= GAP_BUDGET, "heartbeat gap {gap:?} over {GAP_BUDGET:?}");
    for n in &mut nodes {
        n.stop();
    }
}

// ------------------------------------------- POAM-047 abandoned adoptions (QA)

/// An inbound UDP packet from the server to `(v4, port)`; true when `n`
/// forwards it.
fn inbound_forwards(n: &mut Node, v4: u32, port: u16) -> bool {
    use plat_xlat::siit::write_v4_header;
    let mut p = vec![0u8; 29];
    write_v4_header(&mut p, 0, 29, 1, true, false, 0, 64, proto::UDP, SERVER, v4);
    put16(&mut p, 20, 5353);
    put16(&mut p, 22, port);
    put16(&mut p, 24, 9);
    p[28] = b'r';
    let c = ck::finish(ck::pseudo_v4(SERVER, v4, proto::UDP, 9) + ck::sum(&p[20..]));
    put16(&mut p, 26, ck::udp_nonzero(c));
    let mut buf = vec![0u8; HEADROOM + 2048];
    buf[HEADROOM..HEADROOM + p.len()].copy_from_slice(&p);
    matches!(n.nat.process(&mut buf, HEADROOM, p.len(), &mut n.ctx), Verdict::Forward { .. })
}

/// `plat_cluster_adoptions_abandoned_total{reason=...}` of `n`.
fn abandoned(sh: &super::control::Shared, reason: &str) -> u64 {
    let mut o = String::new();
    sh.render_metrics(&mut o);
    let key = format!("plat_cluster_adoptions_abandoned_total{{reason=\"{reason}\"}} ");
    o.lines().find_map(|l| l.strip_prefix(&key)).and_then(|v| v.trim().parse().ok()).unwrap_or(0)
}

/// Blocks of `slice` in adopt / release records of `n` (from `mark`).
/// `(v4, port_lo)` of port blocks.
type Blocks = Vec<(u32, u16)>;

fn slice_records(n: &Node, slice: SliceId, mark: usize) -> (Blocks, Blocks) {
    let map = n.nat.state().slice_map().unwrap().clone();
    let (mut ad, mut rel) = (Vec::new(), Vec::new());
    for e in n.events.lock().iter().skip(mark) {
        match e {
            Event::PortBlockAdopt { adopt, .. } if map.slice_of(adopt.v4) == Some(slice) => {
                ad.push((adopt.v4, adopt.port_lo));
            }
            Event::PortBlockRelease { v4, port_lo, .. } if map.slice_of(*v4) == Some(slice) => {
                rel.push((*v4, *port_lo));
            }
            _ => {}
        }
    }
    ad.sort_unstable();
    rel.sort_unstable();
    (ad, rel)
}

/// Two members and a witness, both with an audit queue of 64, smaller
/// than the records of any slice the victim serves (> 64 blocks each), so
/// under `refuse_new_bindings` the leader's takeover of the victim's first
/// slice reaches the log phase and waits there: a deterministic
/// half-adopted slice (imported, not logged, not Active). The other slices
/// wait behind it (decision 3). The leader survives (it keeps its lease),
/// the other member is the victim. `b` is the survivor, `a` the victim.
struct Stuck {
    pki: Pki,
    l: Layout,
    dirs: [ShortDir; 3],
    w: Option<ClusterHandle>,
    a: Node,
    b: Node,
    /// Member id of `a`.
    ai: u16,
    slice: SliceId,
    /// The victim's slices (those holding its load).
    theirs: std::collections::BTreeSet<SliceId>,
    /// The victim's mappings in `slice`.
    mapped: Vec<(u32, u16)>,
    /// `b.events` length at the crash.
    mark: usize,
}

fn stuck_adoption(auto: bool) -> Stuck {
    let pki = Pki::new();
    let mut l = Layout::new(2, true);
    l.auto = Some(auto);
    let dirs = [ShortDir::new("sa"), ShortDir::new("sb"), ShortDir::new("sw")];
    let w = super::witness::start(&witness_file(&l, &pki, &dirs[2].0), collector(4096).0).unwrap();
    let start = |i: u16| {
        let (sink, ev) = collector(64);
        Node::start_with(member_cfg(&l, i, l.ports[usize::from(i)], &pki, &dirs[usize::from(i)].0, "", None), sink, ev)
    };
    let mut nodes = vec![start(0), start(1)];
    wait("16 slices", Duration::from_secs(15), || {
        nodes.iter().all(|n| n.active() > 0) && total_active(&[&nodes[0], &nodes[1]]) == 16
    });
    wait_protected(&[&nodes[0], &nodes[1]]);
    let leader = nodes[0].h().shared.view().unwrap().leader;
    let ai = 1 - leader;
    let b = nodes.remove(usize::from(leader));
    let mut a = nodes.remove(0);
    let subs = 120 * a.active();
    let mut v4s = Vec::new();
    for i in 0..subs as u128 {
        let client = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 64) | 1;
        let t = Instant::now();
        loop {
            if let Some(m) = a.send(client, 40000) {
                v4s.push(m);
                break;
            }
            assert!(t.elapsed() < Duration::from_secs(10), "no block for subscriber {i}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let repl = b.h().shared.repl.clone().unwrap();
    wait("the survivor's shadow holds every block, in sync", Duration::from_secs(60), || {
        let g = repl.lock();
        let n: usize = (0..16).map(|s| g.shadow_counts(s).0).sum();
        n == subs && (0..16).all(|s| g.shadow_counts(s).0 == 0 || g.shadow.in_sync(s))
    });
    wait_protected(&[&a, &b]);
    let mark = b.events.lock().len();
    a.kill();
    if !auto {
        wait("link down", Duration::from_secs(5), || !b.h().shared.net.is_up(ai));
        let r = b.h().command(Command::Takeover(ai, false));
        assert!(r.starts_with("ok"), "{r}");
    }
    let st = b.nat.state();
    let mut slice = None;
    wait("the survivor adopting a slice", Duration::from_secs(15), || {
        slice = (0..16).find(|&s| st.slice_state(s) == Some(SliceState::Adopting));
        slice.is_some()
    });
    let slice = slice.unwrap();
    // It stays half-adopted: the queue can never take its records at once.
    std::thread::sleep(Duration::from_millis(1500));
    let adopting: Vec<_> = (0..16).filter(|&s| st.slice_state(s) == Some(SliceState::Adopting)).collect();
    assert_eq!(adopting, vec![slice], "one adoption at a time (decision 3)");
    let map = st.slice_map().unwrap().clone();
    let theirs: std::collections::BTreeSet<SliceId> = v4s.iter().filter_map(|m| map.slice_of(m.0)).collect();
    assert!(theirs.contains(&slice));
    let served: Vec<_> = theirs.iter().filter(|&&x| st.slice_state(x) == Some(SliceState::Active)).collect();
    assert!(served.is_empty(), "victim slices {served:?} Active while the first is adopted");
    let mapped: Vec<_> = v4s.into_iter().filter(|m| map.slice_of(m.0) == Some(slice)).collect();
    assert!(mapped.len() > 64, "{} blocks in slice {slice}", mapped.len());
    Stuck { pki, l, dirs, w: Some(w), a, b, ai, slice, theirs, mapped, mark }
}

impl Stuck {
    /// Nothing of the slice serves on B and no adopt or release record of
    /// it was queued (none was logged, so none may be released).
    fn check_nothing_served_or_logged(&mut self, what: &str) {
        let (ad, rel) = slice_records(&self.b, self.slice, self.mark);
        assert!(ad.is_empty(), "{what}: adopt records {ad:?}");
        assert!(rel.is_empty(), "{what}: release records for blocks never logged: {rel:?}");
        let mapped = self.mapped.clone();
        for (v4, p) in mapped {
            assert!(!inbound_forwards(&mut self.b, v4, p), "{what}: {v4:x}:{p} served");
        }
    }
}

/// SC-24, AU-12 (plan §5 shutdown row): an orderly stop in the middle of an
/// adoption abandons it first: nothing of the slice served or logged, no
/// release record for unlogged blocks, the slice not Active, the abandon
/// counted `shutdown`.
#[test]
fn adoption_abandoned_on_shutdown() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let mut s = stuck_adoption(true);
    s.check_nothing_served_or_logged("adopting");
    let sh = s.b.h().shared.clone();
    s.b.stop();
    assert_eq!(abandoned(&sh, "shutdown"), 1);
    assert_ne!(s.b.nat.state().slice_state(s.slice), Some(SliceState::Active));
    assert_eq!(s.b.nat.state().subscriber_count(), 0, "every imported subscriber removed");
    // Records reach `events` through the collector thread.
    std::thread::sleep(Duration::from_millis(200));
    s.check_nothing_served_or_logged("after the stop");
    if let Some(w) = s.w.take() {
        w.shutdown();
    }
}

/// SC-24 (plan §5 lease-lost row): the witness goes away while the
/// survivor adopts, so it (one vote of three) loses its lease: the adoption
/// is abandoned (`lease_lost`), the slice ends Inactive (not Fenced),
/// nothing of it was served or released. When the witness is back the
/// slice must be adopted again in full: here that cannot finish (the queue
/// is too small), so it must not be Active, or if Active, with every
/// replicated block adopted.
///
/// FAILS (QA, POAM-047 finding): the abandon dropped the detached shadow
/// slice, so the regain adopts an empty, out-of-sync shadow: the slice goes
/// Active at once with 0 blocks adopted and every block held back; the
/// victim's subscribers lose their mappings. See
/// `regain_after_lease_lost_abandon_readopts_in_full` (plat-nat64).
#[test]
fn adoption_abandoned_on_lease_lost() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let mut s = stuck_adoption(true);
    s.w.take().unwrap().kill();
    let sh = s.b.h().shared.clone();
    wait("abandoned on lease loss", Duration::from_secs(10), || abandoned(&sh, "lease_lost") == 1);
    let st = s.b.nat.state();
    wait("slice Inactive", Duration::from_secs(5), || st.slice_state(s.slice) == Some(SliceState::Inactive));
    std::thread::sleep(Duration::from_millis(200));
    s.check_nothing_served_or_logged("lease lost");
    let mark = s.b.events.lock().len();
    // Witness back: the survivor regains the slice.
    s.w = Some(super::witness::start(&witness_file(&s.l, &s.pki, &s.dirs[2].0), collector(4096).0).unwrap());
    let st = s.b.nat.state();
    wait("regain", Duration::from_secs(15), || {
        s.theirs.iter().any(|&x| st.slice_state(x) == Some(SliceState::Adopting))
            || st.slice_state(s.slice) == Some(SliceState::Active)
    });
    std::thread::sleep(Duration::from_millis(500));
    let net = st.slice_map().unwrap().cidr(s.slice).unwrap().network();
    let acq: Vec<(u32, u32)> =
        s.b.events
            .lock()
            .iter()
            .skip(mark)
            .filter_map(|e| match e {
                Event::ClusterSliceAcquire { acquire, .. } if acquire.slice.net == net => {
                    Some((acquire.blocks_adopted, acquire.blocks_quarantined))
                }
                _ => None,
            })
            .collect();
    if st.slice_state(s.slice) == Some(SliceState::Active) {
        assert_eq!(
            acq.first().map(|a| a.0 as usize),
            Some(s.mapped.len()),
            "regained slice Active without its replicated blocks (adopted, quarantined): {acq:?}"
        );
    }
    s.b.stop();
    s.w.take().unwrap().shutdown();
}

/// POAM-047 F3: while a takeover is stuck in its log phase, the survivor
/// loses its lease (witness gone) and regains it (witness back). Its own
/// fenced slices need one record and no import, so they are Active again
/// at once instead of waiting behind the stuck adoption (decision 3 orders
/// imports only).
#[test]
fn own_slices_regain_while_a_takeover_is_stuck() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let mut s = stuck_adoption(true);
    let st = s.b.nat.state();
    let own: Vec<SliceId> =
        (0..16).filter(|x| !s.theirs.contains(x) && st.slice_state(*x) == Some(SliceState::Active)).collect();
    assert!(!own.is_empty());
    s.w.take().unwrap().kill();
    wait("own slices fenced", Duration::from_secs(10), || {
        own.iter().all(|&x| st.slice_state(x) == Some(SliceState::Fenced))
    });
    s.w = Some(super::witness::start(&witness_file(&s.l, &s.pki, &s.dirs[2].0), collector(4096).0).unwrap());
    wait("own slices Active again while a takeover is pending", Duration::from_secs(15), || {
        own.iter().all(|&x| st.slice_state(x) == Some(SliceState::Active))
    });
    let victim_active = s.theirs.iter().filter(|&&x| st.slice_state(x) == Some(SliceState::Active)).count();
    assert!(victim_active < s.theirs.len(), "the stuck takeover is still not done");
    s.b.stop();
    s.w.take().unwrap().shutdown();
}

/// Plan §5 reassigned / handed-back rows (decision 2): manual failover.
/// The operator has the survivor take over the crashed member; the member
/// restarts and the operator restores its slices while the survivor is
/// still adopting the first one: the survivor abandons it (`reassigned` or
/// `handover`), never serves it, and releases none of its unlogged blocks.
#[test]
fn adoption_abandoned_on_view_change_reassign() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let mut s = stuck_adoption(false);
    let sh = s.b.h().shared.clone();
    s.a = Node::start(member_cfg(
        &s.l,
        s.ai,
        s.l.ports[usize::from(s.ai)],
        &s.pki,
        &s.dirs[usize::from(s.ai)].0,
        "",
        None,
    ));
    wait("peer link", Duration::from_secs(10), || s.b.h().shared.net.is_up(s.ai));
    let r = s.b.h().command(Command::Restore(s.ai));
    assert!(r.starts_with("ok"), "{r}");
    let t = Instant::now();
    while abandoned(&sh, "reassigned") + abandoned(&sh, "handover") != 1 {
        let mut m = String::new();
        sh.render_metrics(&mut m);
        let m: Vec<_> = m.lines().filter(|l| l.contains("abandon") || l.contains("adopting")).collect();
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "abandon: {m:?}\n{}\n{}",
            sh.view_json(),
            s.a.h().shared.view_json()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_ne!(s.b.nat.state().slice_state(s.slice), Some(SliceState::Active));
    std::thread::sleep(Duration::from_millis(200));
    s.check_nothing_served_or_logged("reassigned");
    s.a.stop();
    s.b.stop();
    s.w.take().unwrap().shutdown();
}

// ------------------------------------------- POAM-048 chunked release (QA)

/// Value of the unlabelled series `name` in `n`'s metrics.
fn metric(n: &Node, name: &str) -> u64 {
    let mut o = String::new();
    n.h().shared.render_metrics(&mut o);
    let key = format!("{name} ");
    o.lines().find_map(|l| l.strip_prefix(&key)).and_then(|v| v.trim().parse().ok()).unwrap_or(0)
}

/// A record queued by the test (fills an audit queue).
fn filler() -> Event {
    Event::ClusterSliceAcquire {
        ts_us: 0,
        acquire: Arc::new(plat_audit::SliceAcquire {
            slice: plat_audit::SliceCidr { net: 0, len: 32 },
            epoch: 0,
            prev_owner: None,
            reason: AuditAcquire::Startup,
            blocks_adopted: 0,
            bibs_adopted: 0,
            blocks_quarantined: 0,
            in_sync: true,
        }),
    }
}

/// `(v4, port_lo)` of each `PortBlockRelease` of `n` after `mark`, with the
/// number of records per block.
fn release_counts(n: &Node, mark: usize) -> std::collections::BTreeMap<(u32, u16), usize> {
    let mut m = std::collections::BTreeMap::new();
    for e in n.events.lock().iter().skip(mark) {
        if let Event::PortBlockRelease { v4, port_lo, .. } = e {
            *m.entry((*v4, *port_lo)).or_insert(0) += 1;
        }
    }
    m
}

/// Two members and a real witness. The other member crashed, the leader
/// adopted its slices and was loaded (`subs` subscribers, one block each,
/// over all 16 slices) under `refuse_new_bindings`. Then the leader's
/// audit queue is filled and no longer drained (gate closed) and the other
/// member restarts: the failback handover gives the leader release
/// cursors that pause on the full queue (Q1). Returned once at least one
/// slice is releasing and a paused step was counted.
struct Releasing {
    /// Kept alive for the test: certificates and state directories.
    _pki: Pki,
    _dirs: [ShortDir; 3],
    w: Option<ClusterHandle>,
    leader: Node,
    other: Node,
    gate: Arc<std::sync::atomic::AtomicBool>,
    /// Slices the leader is handing back (the other member's).
    theirs: std::collections::BTreeSet<SliceId>,
    /// `(v4, port_lo)` of every subscriber's block, per slice.
    blocks: std::collections::BTreeMap<SliceId, Vec<(u32, u16)>>,
    /// `leader.events` length before the restart.
    mark: usize,
}

fn releasing_fixture(subs: usize) -> Releasing {
    use std::sync::atomic::Ordering;
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let dirs = [ShortDir::new("ra"), ShortDir::new("rb"), ShortDir::new("rw")];
    let w = super::witness::start(&witness_file(&l, &pki, &dirs[2].0), collector(4096).0).unwrap();
    let nat = "port_block_size = 256";
    let cfgs = [
        member_cfg(&l, 0, l.ports[0], &pki, &dirs[0].0, nat, None),
        member_cfg(&l, 1, l.ports[1], &pki, &dirs[1].0, nat, None),
    ];
    let gates: Vec<_> = (0..2).map(|_| gated_collector(256)).collect();
    let mut nodes: Vec<Node> = gates
        .iter()
        .zip(&cfgs)
        .map(|((sink, ev, _), c)| Node::start_with(c.clone(), sink.clone(), ev.clone()))
        .collect();
    wait("16 slices", Duration::from_secs(15), || {
        nodes.iter().all(|n| n.active() > 0) && total_active(&[&nodes[0], &nodes[1]]) == 16
    });
    wait_protected(&[&nodes[0], &nodes[1]]);
    let li = usize::from(nodes[0].h().shared.view().unwrap().leader);
    let fi = 1 - li;
    let st = nodes[li].nat.state();
    let theirs: std::collections::BTreeSet<SliceId> =
        (0..16).filter(|&x| st.slice_state(x) != Some(SliceState::Active)).collect();
    nodes[fi].kill();
    wait("leader serves every slice", Duration::from_secs(10), || nodes[li].active() == 16);
    let mut blocks: std::collections::BTreeMap<SliceId, Vec<(u32, u16)>> = Default::default();
    let map = nodes[li].nat.state().slice_map().unwrap().clone();
    for i in 0..subs as u128 {
        let client = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 64) | 1;
        let t = Instant::now();
        let m = loop {
            if let Some(m) = nodes[li].send(client, 40000) {
                break m;
            }
            assert!(t.elapsed() < Duration::from_secs(10), "no block for subscriber {i}");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(nodes[li].send(client, 40001).is_some());
        let lo = 1024 + (m.1 - 1024) / 256 * 256;
        blocks.entry(map.slice_of(m.0).unwrap()).or_default().push((m.0, lo));
    }
    for v in blocks.values_mut() {
        v.sort_unstable();
    }
    std::thread::sleep(Duration::from_millis(500));
    let gate = gates[li].2.clone();
    gate.store(false, Ordering::Release);
    std::thread::sleep(Duration::from_millis(50));
    let mark = nodes[li].events.lock().len();
    let audit = nodes[li].nat.state().audit().clone();
    while audit.emit(filler()) {}
    let leader = nodes.remove(li);
    drop(nodes);
    let other = Node::start_with(cfgs[fi].clone(), gates[fi].0.clone(), gates[fi].1.clone());
    let st = leader.nat.state();
    wait("a release paused on the full queue", Duration::from_secs(30), || {
        (0..16).any(|x| st.slice_releasing(x)) && metric(&leader, "plat_cluster_release_audit_paused_total") > 0
    });
    // It stays paused while the queue is full.
    std::thread::sleep(Duration::from_millis(500));
    let rel: Vec<_> = (0..16).filter(|&x| st.slice_releasing(x)).collect();
    assert!(!rel.is_empty() && rel.iter().all(|x| theirs.contains(x)), "releasing {rel:?}, theirs {theirs:?}");
    for &x in &rel {
        assert_ne!(st.slice_state(x), Some(SliceState::Active), "slice {x} Active while releasing");
    }
    Releasing { _pki: pki, _dirs: dirs, w: Some(w), leader, other, gate, theirs, blocks, mark }
}

impl Releasing {
    fn open(&self) {
        self.gate.store(true, std::sync::atomic::Ordering::Release);
    }

    fn releasing(&self) -> Vec<SliceId> {
        let st = self.leader.nat.state();
        (0..16).filter(|&x| st.slice_releasing(x)).collect()
    }

    /// No block got two release records; returns the per-slice records.
    fn check_released_once(&self) -> std::collections::BTreeMap<(u32, u16), usize> {
        let c = release_counts(&self.leader, self.mark);
        let twice: Vec<_> = c.iter().filter(|e| *e.1 > 1).collect();
        assert!(twice.is_empty(), "blocks released twice: {twice:?}");
        c
    }
}

/// POAM-048 (plan §8), SEC-001: an orderly stop while release cursors are
/// paused on a full queue finishes them before the membership shutdown
/// (no slice left releasing, every subscriber removed, nothing Active) and
/// the membership shutdown never releases a block a second time. The
/// queue stays full past the `shutdown_handover_ms` budget (3 s here): the
/// stop waits for room that long, then emits the rest, which is counted
/// lost (reported by the logger as `audit_queue_overflow`).
#[test]
fn shutdown_completes_release_in_progress() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let mut s = releasing_fixture(400);
    let rel = s.releasing();
    let st = s.leader.nat.state();
    let lost0 = st.audit().stats().lost.load(std::sync::atomic::Ordering::Relaxed);
    let t = Instant::now();
    s.leader.stop();
    let took = t.elapsed();
    let st = s.leader.nat.state();
    assert!(s.releasing().is_empty(), "releasing after the stop: {:?}", s.releasing());
    assert_eq!(st.subscriber_count(), 0, "every subscriber removed");
    assert!((0..16).all(|x| st.slice_state(x) != Some(SliceState::Active)));
    let lost = st.audit().stats().lost.load(std::sync::atomic::Ordering::Relaxed) - lost0;
    assert!(lost > 0, "the queue never drained: records counted lost");
    assert!(took >= Duration::from_millis(2900), "waited for room within the budget: {took:?}");
    assert!(took < Duration::from_secs(10), "bounded by the budget: {took:?}");
    s.open();
    std::thread::sleep(Duration::from_millis(500));
    let c = s.check_released_once();
    println!(
        "shutdown_completes_release_in_progress: {} slices releasing at the stop, {} release records seen, \
         {lost} records lost at shutdown (full queue), stop took {took:?}",
        rel.len(),
        c.len()
    );
    s.other.stop();
    s.w.take().unwrap().shutdown();
}

/// SEC-001: the queue drains during the stop, within the budget: the
/// paused release cursors wait for room, every block of each releasing
/// slice gets its one release record and nothing is lost.
#[test]
fn shutdown_waits_for_audit_room_within_budget() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let mut s = releasing_fixture(400);
    let rel = s.releasing();
    let st = s.leader.nat.state();
    let lost0 = st.audit().stats().lost.load(std::sync::atomic::Ordering::Relaxed);
    let gate = s.gate.clone();
    let opener = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        gate.store(true, std::sync::atomic::Ordering::Release);
    });
    s.leader.stop();
    let _ = opener.join();
    let st = s.leader.nat.state();
    assert!(s.releasing().is_empty(), "releasing after the stop: {:?}", s.releasing());
    assert_eq!(st.subscriber_count(), 0, "every subscriber removed");
    let lost = st.audit().stats().lost.load(std::sync::atomic::Ordering::Relaxed) - lost0;
    assert_eq!(lost, 0, "the queue drained within the budget: nothing lost");
    std::thread::sleep(Duration::from_millis(500));
    let c = s.check_released_once();
    let map = st.slice_map().unwrap().clone();
    for &x in &rel {
        let got: Vec<_> = c.keys().filter(|k| map.slice_of(k.0) == Some(x)).copied().collect();
        assert_eq!(Some(&got), s.blocks.get(&x), "slice {x}: one record per block");
    }
    s.other.stop();
    s.w.take().unwrap().shutdown();
}

/// NIST-004: a slice handed over and handed back before its release
/// cursor finished. The other member is killed while the leader's
/// failback cursors are paused on its full queue, so the leader takes
/// those slices back: each waits (never Active, never Adopting) while it
/// is releasing, and once the queue drains its release finishes first
/// and it is then adopted and served.
#[test]
fn regain_mid_release_waits_then_adopts() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let mut s = releasing_fixture(400);
    let rel = s.releasing();
    let st = s.leader.nat.state();
    s.other.kill();
    // The leader keeps its majority with the witness and takes the slices
    // back; the releasing ones wait for their cursor.
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(3) {
        for &x in &rel {
            if st.slice_releasing(x) {
                let state = st.slice_state(x);
                assert!(
                    !matches!(state, Some(SliceState::Active | SliceState::Adopting)),
                    "slice {x} {state:?} while releasing"
                );
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!s.releasing().is_empty(), "the cursors wait on the full queue");
    s.open();
    wait("every slice served again", Duration::from_secs(30), || s.leader.active() == 16);
    assert!(s.releasing().is_empty());
    std::thread::sleep(Duration::from_millis(300));
    s.check_released_once();
    // Per slice: its acquire record comes after its last release record.
    let map = st.slice_map().unwrap().clone();
    let ev = s.leader.events.lock();
    for &x in &rel {
        let cidr = map.cidr(x).unwrap();
        let last_rel = ev
            .iter()
            .enumerate()
            .skip(s.mark)
            .filter(|(_, e)| matches!(e, Event::PortBlockRelease { v4, .. } if map.slice_of(*v4) == Some(x)))
            .map(|(i, _)| i)
            .max();
        let acq = ev.iter().enumerate().skip(s.mark).find_map(|(i, e)| match e {
            Event::ClusterSliceAcquire { acquire, .. } if acquire.slice.net == cidr.network() => Some(i),
            _ => None,
        });
        let (Some(r), Some(a)) = (last_rel, acq) else { panic!("slice {x}: release {last_rel:?}, acquire {acq:?}") };
        assert!(a > r, "slice {x}: acquire at {a} before its last release record at {r}");
    }
    drop(ev);
    s.leader.stop();
    s.w.take().unwrap().shutdown();
}

/// POAM-048 (plan §8): the leader loses its lease (witness and the other
/// member gone) while its handover release cursors are paused on a full
/// queue. The cursors are kept: once the queue drains they finish, each
/// released slice ends Inactive with exactly one release record per
/// block, and the lease loss neither drops nor restarts them.
#[test]
fn lease_lost_during_release_keeps_going() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let mut s = releasing_fixture(400);
    let rel = s.releasing();
    let st = s.leader.nat.state();
    let own: Vec<SliceId> =
        (0..16).filter(|x| !s.theirs.contains(x) && st.slice_state(*x) == Some(SliceState::Active)).collect();
    assert!(!own.is_empty());
    s.w.take().unwrap().kill();
    s.other.kill();
    wait("lease lost: own slices fenced", Duration::from_secs(10), || {
        own.iter().all(|&x| st.slice_state(x) == Some(SliceState::Fenced))
    });
    assert_eq!(s.releasing(), rel, "the cursors survive the lease loss");
    s.open();
    wait("releases done", Duration::from_secs(30), || s.releasing().is_empty());
    std::thread::sleep(Duration::from_millis(300));
    let c = s.check_released_once();
    let map = st.slice_map().unwrap().clone();
    for &x in &rel {
        assert_eq!(st.slice_state(x), Some(SliceState::Inactive), "slice {x}");
        let got: Vec<_> = c.keys().filter(|k| map.slice_of(k.0) == Some(x)).copied().collect();
        assert_eq!(Some(&got), s.blocks.get(&x), "slice {x}: one record per block");
    }
    assert_eq!(metric(&s.leader, "plat_cluster_releasing_slices"), 0);
    s.leader.stop();
}

fn live(n: &[Option<Node>]) -> Vec<&Node> {
    n.iter().flatten().collect()
}

/// POAM-048 Q4 (plan §8): three members. Member X (the leader) is handing
/// a restarted member's slices back (release cursors) when a third member
/// crashes and X takes over some of its slices (an adoption cursor), both
/// held on X's full audit queue. Once the queue drains both progress on
/// the one control thread: every release finishes, X adopts its share and
/// serves it, never more than one slice Adopting at a time.
#[test]
fn release_and_adoption_interleave() {
    use std::sync::atomic::Ordering;
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(3, false);
    let dirs = [ShortDir::new("ia"), ShortDir::new("ib"), ShortDir::new("ic")];
    let nat = "port_block_size = 256";
    let cfgs: Vec<Config> =
        (0..3).map(|i| member_cfg(&l, i, l.ports[usize::from(i)], &pki, &dirs[usize::from(i)].0, nat, None)).collect();
    let gates: Vec<_> = (0..3).map(|_| gated_collector(256)).collect();
    let start = |i: usize| Node::start_with(cfgs[i].clone(), gates[i].0.clone(), gates[i].1.clone());
    let mut nodes: Vec<Option<Node>> = (0..3).map(|i| Some(start(i))).collect();
    wait("16 slices", Duration::from_secs(20), || {
        let v = live(&nodes);
        v.iter().all(|n| n.active() > 0) && total_active(&v) == 16
    });
    wait_protected(&live(&nodes));
    let xi = usize::from(nodes[0].as_ref().unwrap().h().shared.view().unwrap().leader);
    let (yi, zi) = ((xi + 1) % 3, (xi + 2) % 3);
    // Y crashes; X (and Z) take its slices; load X.
    nodes[yi].take().unwrap().kill();
    wait("Y's slices taken over", Duration::from_secs(15), || total_active(&live(&nodes)) == 16);
    {
        let x = nodes[xi].as_mut().unwrap();
        for i in 0..600u128 {
            let client = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 64) | 1;
            let t = Instant::now();
            while x.send(client, 40000).is_none() {
                assert!(t.elapsed() < Duration::from_secs(10), "no block for subscriber {i}");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    // Load Z too (its slices are what X adopts later).
    {
        let z = nodes[zi].as_mut().unwrap();
        for i in 1000..1600u128 {
            let client = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 64) | 1;
            let t = Instant::now();
            while z.send(client, 40000).is_none() {
                assert!(t.elapsed() < Duration::from_secs(10), "no block for subscriber {i}");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    wait_protected(&live(&nodes));
    let x_steps =
        |n: &Node| (metric(n, "plat_cluster_release_steps_total"), metric(n, "plat_cluster_adopt_steps_total"));
    // Close X's queue, restart Y: X's failback release cursors pause.
    gates[xi].2.store(false, Ordering::Release);
    std::thread::sleep(Duration::from_millis(50));
    {
        let x = nodes[xi].as_ref().unwrap();
        let audit = x.nat.state().audit().clone();
        while audit.emit(filler()) {}
    }
    nodes[yi] = Some(start(yi));
    {
        let x = nodes[xi].as_ref().unwrap();
        let st = x.nat.state();
        wait("X releasing", Duration::from_secs(30), || (0..16).any(|s| st.slice_releasing(s)));
    }
    // Z crashes: X takes some of its slices while still releasing.
    nodes[zi].take().unwrap().kill();
    let x = nodes[xi].as_ref().unwrap();
    let st = x.nat.state();
    let t = Instant::now();
    let mut both = false;
    while t.elapsed() < Duration::from_secs(15) && !both {
        let adopting = (0..16).any(|s| st.slice_state(s) == Some(SliceState::Adopting));
        both = adopting && (0..16).any(|s| st.slice_releasing(s));
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(both, "X never held a release and an adoption at once");
    let before = x_steps(x);
    gates[xi].2.store(true, Ordering::Release);
    let mut max_adopting = 0;
    wait("X done releasing and adopting", Duration::from_secs(60), || {
        let a = (0..16).filter(|&s| st.slice_state(s) == Some(SliceState::Adopting)).count();
        max_adopting = max_adopting.max(a);
        a == 0 && !(0..16).any(|s| st.slice_releasing(s))
    });
    let after = x_steps(x);
    assert!(after.0 > before.0 && after.1 > before.1, "both progressed: {before:?} -> {after:?}");
    assert!(max_adopting <= 1, "{max_adopting} slices Adopting at once");
    let c = release_counts(x, 0);
    let twice: Vec<_> = c.iter().filter(|e| *e.1 > 1).collect();
    assert!(twice.is_empty(), "released twice: {twice:?}");
    println!("release_and_adoption_interleave: steps {before:?} -> {after:?}, X active {}", x.active());
    for n in nodes.iter_mut().flatten() {
        n.stop();
    }
}

/// Dials `port` as member 0 over mutual TLS, sends a `Hello` with
/// `version`, and returns every message the member answers until it
/// closes (or 5 s pass).
fn raw_hello(pki: &Pki, port: u16, version: u16) -> Vec<Msg> {
    use std::io::{Read, Write};

    use plat_cluster::{Hello, PartitionScheme, codec};
    let (l, s) = (Layout::new(2, false), ShortDir::new("r"));
    let cfg = member_cfg(&l, 0, l.ports[0], pki, &s.0, "", None);
    let tls = peer_configs(&cfg);
    let name = plat_tls::peer_server_name(&format!("dns:{}", ident(1)), "127.0.0.1".parse().unwrap()).unwrap();
    let conn = rustls::ClientConnection::new(tls.client.clone(), name).unwrap();
    let sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let hello = Msg::Hello(Hello {
        proto_version: version,
        node_id: 0,
        name: "plat-0".into(),
        config_digest: [0; 32],
        epoch: 0,
        scheme: PartitionScheme::Slices,
        owned: Vec::new(),
    });
    let mut out = Vec::new();
    codec::encode(&hello, 64 << 10, &mut out).unwrap();
    tls.write_all(&out).unwrap();
    tls.flush().unwrap();
    let (mut buf, mut got, mut chunk) = (Vec::new(), Vec::new(), [0u8; 4096]);
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        while let Ok(Some((m, used))) = codec::decode(&buf, 64 << 10) {
            buf.drain(..used);
            got.push(m);
        }
    }
    got
}

/// QA (CM-3, plan §8): protocol 2 has no negotiation. A peer whose `Hello`
/// carries protocol 1 (a node not yet upgraded) or any other version is
/// refused `version` (counted, answered with `HelloAck(version)`, audited)
/// and never comes up.
#[test]
fn qa_hello_with_other_protocol_version_is_refused() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    assert_eq!(plat_cluster::PROTO_VERSION, 2);
    let pki = Pki::new();
    let l = Layout::new(2, false);
    let sb = ShortDir::new("b");
    let b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));
    let mut want = 0;
    for v in [1u16, 3, 0, u16::MAX] {
        let got = raw_hello(&pki, l.ports[1], v);
        want += 1;
        assert!(
            got.iter().any(|m| matches!(m, Msg::HelloAck(Some(RejectReason::Version)))),
            "version {v}: answered {got:?}"
        );
        assert!(!got.iter().any(|m| matches!(m, Msg::HelloAck(None))), "version {v} accepted");
        wait("version refusal counted", Duration::from_secs(5), || {
            b.h().shared.net.stats.rejected(RejectReason::Version) >= want
        });
        assert!(!b.h().shared.net.is_up(0), "version {v}: the peer must not come up");
    }
    // Control: the same harness at protocol 2 passes the version check and
    // is refused later, on the (zero) config digest.
    let got = raw_hello(&pki, l.ports[1], plat_cluster::PROTO_VERSION);
    assert!(got.iter().any(|m| matches!(m, Msg::HelloAck(Some(RejectReason::DigestMismatch)))), "{got:?}");
    assert_eq!(b.h().shared.net.stats.rejected(RejectReason::Version), want);
    wait("version refusal record", Duration::from_secs(10), || {
        b.has(|e| {
            matches!(e, Event::ClusterPeerRejected { rejected, .. }
            if rejected.reason == PeerRejectReason::Version && rejected.claimed_id == Some(0))
        })
    });
}

/// QA (plan §8 `snapshot_end_hints_flag_follows_primary_config`): the
/// `SnapshotEnd.hints` byte is the primary's own `session_hints`. With A
/// `"off"` and B `"tcp"` (the setting is per node, not in the digest),
/// B's shadow of A's slices is in sync but not hinted, and A's shadow of
/// B's slices is in sync and hinted; A's slices are never strict on B.
#[test]
fn qa_snapshot_end_hints_flag_follows_primary_config() {
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let (wsink, _wev) = collector(4096);
    let _w = super::witness::start(&witness_file(&l, &pki, &sw.0), wsink).unwrap();
    let mut cfg_a = member_cfg(&l, 0, l.ports[0], &pki, &sa.0, "", None);
    cfg_a.cluster.ha.as_mut().unwrap().session_hints = plat_common::config::SessionHints::Off;
    let a = Node::start(cfg_a);
    let b = Node::start(member_cfg(&l, 1, l.ports[1], &pki, &sb.0, "", None));
    wait("16 slices served once", Duration::from_secs(15), || {
        a.active() > 0 && b.active() > 0 && total_active(&[&a, &b]) == 16
    });
    let owned = |n: &Node| -> Vec<SliceId> {
        (0..16).filter(|&s| n.nat.state().slice_state(s) == Some(SliceState::Active)).collect()
    };
    let (sa_, sb_) = (owned(&a), owned(&b));
    let (repl_a, repl_b) = (a.h().shared.repl.clone().unwrap(), b.h().shared.repl.clone().unwrap());
    wait("both shadows in sync", Duration::from_secs(15), || {
        sa_.iter().all(|&s| repl_b.lock().shadow.in_sync(s)) && sb_.iter().all(|&s| repl_a.lock().shadow.in_sync(s))
    });
    for &s in &sa_ {
        assert!(!repl_b.lock().shadow.hinted(s), "slice {s}: primary A has hints off");
    }
    for &s in &sb_ {
        assert!(repl_a.lock().shadow.hinted(s), "slice {s}: primary B has hints on");
    }
}

/// POAM-028 (a), CP-10: with `session_hints = "tcp_udp"` and ADF, an aged
/// bidirectional UDP flow (QUIC-like) of A is hinted to B, and after A
/// crashes B delivers the server's next datagram inbound-first (no
/// packet from the client after the takeover).
#[test]
fn udp_hint_keeps_inbound_first_across_takeover() {
    use plat_common::config::{Filtering, SessionHints};
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let (wsink, _wev) = collector(4096);
    let _w = super::witness::start(&witness_file(&l, &pki, &sw.0), wsink).unwrap();
    let cfg = |id: u16, st: &Path| {
        let mut c = member_cfg(&l, id, l.ports[usize::from(id)], &pki, st, "", None);
        c.nat64.filtering = Filtering::AddressDependent;
        c.cluster.ha.as_mut().unwrap().session_hints = SessionHints::TcpUdp;
        c
    };
    let mut a = Node::start(cfg(0, &sa.0));
    let mut b = Node::start(cfg(1, &sb.0));
    wait("16 slices served once", Duration::from_secs(15), || {
        a.active() > 0 && b.active() > 0 && total_active(&[&a, &b]) == 16
    });
    let mut mapped = None;
    for i in 0..64u128 {
        let client = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 72) | 1;
        if let Some(m) = a.send(client, 40000) {
            mapped = Some((client, m));
            break;
        }
    }
    let (client, (v4, port)) = mapped.expect("A translates for its own slices");
    let s = a.nat.state().slice_map().unwrap().slice_of(v4).unwrap();
    let inbound = |n: &mut Node| {
        let pkt = udp4(v4, port);
        let mut buf = vec![0u8; HEADROOM + 2048];
        buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(&pkt);
        matches!(n.nat.process(&mut buf, HEADROOM, pkt.len(), &mut n.ctx), Verdict::Forward { .. })
    };
    assert!(inbound(&mut a), "the reply passes ADF on A");
    a.clock.advance(Duration::from_millis(3_100));
    assert!(a.send(client, 40000).is_some());
    let repl_b = b.h().shared.repl.clone().unwrap();
    wait("UDP hint on the backup", Duration::from_secs(5), || repl_b.lock().shadow.hint_count(s) == 1);
    wait("backup in sync", Duration::from_secs(5), || repl_b.lock().shadow.in_sync(s));
    a.kill();
    wait("takeover by B", Duration::from_secs(6), || b.active() == 16);
    assert!(inbound(&mut b), "the server speaks first after the takeover");
}

/// QA, CP-10, SC-7(5): planned-failback variant of
/// `udp_hint_keeps_inbound_first_across_takeover`. After the crash
/// takeover B confirms the restored UDP session (the server's datagram);
/// A rejoins, syncs from B, fails back by planned handover and then
/// delivers the server's next datagram inbound-first, still with no
/// packet from the client since the crash.
#[test]
fn qa_udp_hint_keeps_inbound_first_across_planned_failback() {
    use plat_common::config::{Filtering, SessionHints};
    let _serial = crate::test_pki::FIPS_HOOK.lock();
    let pki = Pki::new();
    let l = Layout::new(2, true);
    let (sa, sb, sw) = (ShortDir::new("a"), ShortDir::new("b"), ShortDir::new("w"));
    let (wsink, _wev) = collector(4096);
    let _w = super::witness::start(&witness_file(&l, &pki, &sw.0), wsink).unwrap();
    let cfg = |id: u16, st: &Path| {
        let mut c = member_cfg(&l, id, l.ports[usize::from(id)], &pki, st, "", None);
        c.nat64.filtering = Filtering::AddressDependent;
        c.cluster.ha.as_mut().unwrap().session_hints = SessionHints::TcpUdp;
        c
    };
    let mut a = Node::start(cfg(0, &sa.0));
    let mut b = Node::start(cfg(1, &sb.0));
    wait("16 slices served once", Duration::from_secs(15), || {
        a.active() > 0 && b.active() > 0 && total_active(&[&a, &b]) == 16
    });
    let mut mapped = None;
    for i in 0..64u128 {
        let client = 0x2001_0db8_0100_0000_0000_0000_0000_0000 | (i << 72) | 1;
        if let Some(m) = a.send(client, 40000) {
            mapped = Some((client, m));
            break;
        }
    }
    let (client, (v4, port)) = mapped.expect("A translates for its own slices");
    let s = a.nat.state().slice_map().unwrap().slice_of(v4).unwrap();
    let inbound = |n: &mut Node| {
        let pkt = udp4(v4, port);
        let mut buf = vec![0u8; HEADROOM + 2048];
        buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(&pkt);
        matches!(n.nat.process(&mut buf, HEADROOM, pkt.len(), &mut n.ctx), Verdict::Forward { .. })
    };
    assert!(inbound(&mut a), "the reply passes ADF on A");
    a.clock.advance(Duration::from_millis(3_100));
    assert!(a.send(client, 40000).is_some());
    let repl_b = b.h().shared.repl.clone().unwrap();
    wait("UDP hint on the backup", Duration::from_secs(5), || repl_b.lock().shadow.hint_count(s) == 1);
    wait("backup in sync", Duration::from_secs(5), || repl_b.lock().shadow.in_sync(s));
    a.kill();
    wait("takeover by B", Duration::from_secs(6), || b.active() == 16);
    assert!(inbound(&mut b), "the server speaks first after the takeover");
    drop(a);
    let mut a = Node::start(cfg(0, &sa.0));
    wait("failback to A", Duration::from_secs(20), || a.active() > 0 && total_active(&[&a, &b]) == 16);
    wait("failback record", Duration::from_secs(5), || {
        a.has(|e| matches!(e, Event::ClusterSliceAcquire { acquire, .. } if acquire.reason == AuditAcquire::Failback))
    });
    wait("slice back on A", Duration::from_secs(10), || a.nat.state().slice_state(s) == Some(SliceState::Active));
    assert!(inbound(&mut a), "the server speaks first after the planned failback");
    // B no longer serves the slice.
    assert!(!inbound(&mut b), "B released the slice");
}
