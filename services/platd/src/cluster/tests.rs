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
    AcquireReason as AuditAcquire, AuditSink, Event, MemberState, OperatorRefusal, PeerRejectReason, TryEmit,
    ViewReason,
};
use plat_cluster::{Msg, RejectReason, SliceId, WireBlock};
use plat_common::{Clock, Config, Counters};
use plat_nat64::SliceState;
use plat_nat64::{Nat64, ReplHub, ReplProducer, Verdict, WorkerCtx};
use plat_packet::{be16, be32, checksum as ck, proto, put16};
use plat_xlat::HEADROOM;
use plat_xlat::siit::write_v6_header;

use super::control::{ClusterHandle, Command, cli_request};
use super::witness::WitnessFile;
use crate::test_pki::{Ca, TempDir};

const LEASE_MS: u64 = 1000;
const PREFIX: u128 = 0x0064_ff9b_0001_0000_0000_0000_0000_0000;
const SERVER: u32 = 0xcb00_7105; // 203.0.113.5

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
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
        Self { ports: (0..members).map(|_| free_port()).collect(), witness: witness.then(free_port), auto: None }
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
        let (nat, repl) = crate::run::build_engine(&cfg, 1, &sink, &Clock::new()).unwrap();
        let nat = Arc::new(nat);
        let (hub, mut prods): (Arc<ReplHub>, Vec<ReplProducer>) = repl.unwrap();
        let ctx = WorkerCtx::new(Arc::new(Counters::default()), 1).with_repl(prods.remove(0));
        let handle = super::start(&cfg, nat.clone(), hub, sink, peer_configs(&cfg)).unwrap();
        Self { nat, ctx, handle: Some(handle), events }
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
        let pkt = udp6(client, sport, b"x");
        let mut buf = vec![0u8; HEADROOM + 2048];
        buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(&pkt);
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
    let repl_b = b.h().shared.repl.clone().unwrap();
    wait("block and BIB on the backup", Duration::from_secs(5), || repl_b.lock().shadow_counts(s) == (1, 1));
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
    let takeovers = b
        .events
        .lock()
        .iter()
        .skip(mark)
        .filter(|e| matches!(e, Event::ClusterSliceAcquire { acquire, .. } if acquire.reason == AuditAcquire::Takeover))
        .count();
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
    assert_eq!(b.h().shared.takeovers("takeover") - counted, a_slices as u64);
    assert!(
        b.has(|e| matches!(e, Event::PortBlockAdopt { adopt, .. } if adopt.v4 == v4 && adopt.prev_owner == Some(0)))
    );
    // Same subscriber, same mapping on B (RFC 6146 §3.5.1.1).
    assert_eq!(b.send(client, 40000), Some((v4, port)));

    // Rejoin A: standby, sync, failback by handover.
    drop(a);
    let mut a = Node::start(cfg_a);
    wait("failback to A", Duration::from_secs(20), || a.active() > 0 && total_active(&[&a, &b]) == 16);
    assert!(
        a.has(|e| matches!(e, Event::ClusterSliceAcquire { acquire, .. } if acquire.reason == AuditAcquire::Failback))
    );
    assert!(b.has(|e| matches!(e, Event::PortBlockRelease { reason: Some(_), .. })));
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
    let _b2 = Node::start(member_cfg(&l, 1, free_port(), &pki, &sb2.0, "", None));
    wait("duplicate refused", Duration::from_secs(10), || w.shared.net.stats.rejected(RejectReason::DuplicateId) > 0);
    assert!(w.shared.health_problem().is_some());
    assert!(wev.lock().iter().any(|e| matches!(e, Event::ClusterPeerRejected { rejected, .. }
        if rejected.reason == PeerRejectReason::DuplicateId && rejected.claimed_id == Some(1))));
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
    assert!(c.has(|e| matches!(e, Event::ClusterPeerRejected { rejected, .. } if rejected.reason == PeerRejectReason::DigestMismatch))
        || d.has(|e| matches!(e, Event::ClusterPeerRejected { rejected, .. } if rejected.reason == PeerRejectReason::DigestMismatch)));
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
    assert!(znet.send(b, &Msg::SnapshotEnd { slice: s, seq: 3 }));
    assert!(znet.send(b, &Msg::SubHome { sub: stranger, slice: s }));
    let bnet = nodes[bi].h().shared.net.clone();
    wait("forgeries refused", Duration::from_secs(5), || bnet.stats.rejected(RejectReason::NotAllowed) >= 4);
    assert!(synced(&repl_b), "shadow untouched");
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
    let mut cfg = member_cfg(&l, 0, free_port(), &pki, &sx.0, "", None);
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
    repl_b.lock().on_data(0, Msg::BibDelete { slice: s, seq: u64::MAX / 2, proto: 17, v4: 0, port4: 1 }).unwrap();
    assert_eq!(repl_b.lock().stats.rx_gaps.load(std::sync::atomic::Ordering::Relaxed), 1);
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
