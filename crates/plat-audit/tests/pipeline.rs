#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufReader, Read};
use std::net::UdpSocket;
use std::time::Duration;

use plat_audit::verify::verify;
use plat_audit::{AuditSink, Event, Logger, NodeIdent};
use plat_common::config::{
    AuditConfig, AuditFileConfig, AuditMode, LogFormat, OverflowPolicy, SyslogConfig, SyslogTransport,
};

fn cfg(path: std::path::PathBuf, syslog: Vec<SyslogConfig>) -> AuditConfig {
    AuditConfig {
        mode: AuditMode::PortBlock,
        queue_capacity: 1024,
        on_overflow: OverflowPolicy::RefuseNewBindings,
        batch_max: 64,
        flush_interval_ms: 10,
        summary_interval_secs: 0,
        file: Some(AuditFileConfig { path, max_bytes: 1 << 30, max_files: 0, min_free_bytes: 0 }),
        syslog,
    }
}

fn ev(i: u16) -> Event {
    Event::PortBlockAlloc {
        ts_us: 1_793_196_960_000_000,
        sub: 0x2001_0db8 << 96,
        sub_len: 64,
        v4: 0xc000_0201,
        port_lo: i,
        port_hi: i + 511,
    }
}

fn node() -> NodeIdent {
    NodeIdent { name: "plat-test".into(), id: 0, pid: 1 }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("plat-audit-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d.join("audit.jsonl")
}

#[test]
fn file_and_syslog_records_with_valid_chain() {
    let rx_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    rx_sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let syslog = SyslogConfig {
        address: rx_sock.local_addr().unwrap(),
        transport: SyslogTransport::Udp,
        format: LogFormat::Cef,
        app_name: "platd".into(),
        tls: None,
    };
    let path = tmp("chain");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(path.clone(), vec![syslog]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..300u16 {
        assert!(sink.emit(ev(1024 + i)));
    }
    drop(sink);
    h.join();

    let rep = verify(BufReader::new(std::fs::File::open(&path).unwrap())).unwrap();
    assert!(rep.ok(), "{rep:?}");
    assert_eq!(rep.records, 300);
    assert!(rep.checkpoints >= 5, "batch_max 64 -> several checkpoints");
    assert_eq!(rep.unverified_tail, 0);

    let mut b = [0u8; 2048];
    let n = rx_sock.recv(&mut b).unwrap();
    let s = std::str::from_utf8(&b[..n]).unwrap();
    assert!(
        s.starts_with("<134>1 2026-10-28T14:16:00.000000Z plat-test platd 1 nat_port_block_allocate - CEF:0|"),
        "{s}"
    );
}

#[test]
fn tampering_is_detected() {
    let path = tmp("tamper");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(path.clone(), vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..50u16 {
        sink.emit(ev(1024 + i));
    }
    drop(sink);
    h.join();
    let mut text = String::new();
    std::fs::File::open(&path).unwrap().read_to_string(&mut text).unwrap();

    let edited = text.replacen("192.0.2.1", "192.0.2.9", 1);
    assert!(!verify(edited.as_bytes()).unwrap().ok(), "edited record");

    let mut lines: Vec<&str> = text.lines().collect();
    lines.remove(3);
    let deleted = lines.join("\n") + "\n";
    assert!(!verify(deleted.as_bytes()).unwrap().ok(), "deleted record");
}

#[test]
fn overflow_is_counted_and_reported() {
    let (sink, _rx) = AuditSink::bounded(2);
    assert!(sink.emit(ev(1)));
    assert!(sink.emit(ev(2)));
    assert!(!sink.has_room());
    assert!(!sink.emit(ev(3)));
    assert_eq!(sink.stats().lost.load(std::sync::atomic::Ordering::Relaxed), 1);
}

/// Schema 7: cluster records flow through the logger and `verify-log`
/// accepts them (chain format unchanged); tampering is still detected.
#[test]
fn cluster_records_verify() {
    use plat_audit::{
        AcquireReason, AuditText, BlockAdopt, BlockReleaseReason, ClusterView, HookKind, HookRun, PeerRejectReason,
        PeerRejected, SliceAcquire, SliceCidr, SliceReleaseReason, ViewReason,
    };
    use std::sync::Arc;
    let ts = 1_793_196_960_000_000;
    let slice = SliceCidr { net: 0xc000_0210, len: 28 };
    let evs = vec![
        Event::ClusterViewChange {
            ts_us: ts,
            view: Arc::new(ClusterView { epoch: 4, leader: 0, members_live: vec![0, 1], reason: ViewReason::Election }),
        },
        Event::ClusterSliceAcquire {
            ts_us: ts,
            acquire: Arc::new(SliceAcquire {
                slice,
                epoch: 4,
                prev_owner: Some(1),
                reason: AcquireReason::Takeover,
                blocks_adopted: 1,
                bibs_adopted: 3,
                blocks_quarantined: 0,
                in_sync: true,
            }),
        },
        Event::PortBlockAdopt {
            ts_us: ts,
            adopt: Arc::new(BlockAdopt {
                sub: 0x2001_0db8 << 96,
                sub_len: 64,
                v4: 0xc000_0211,
                port_lo: 1024,
                port_hi: 1535,
                allocated_us: ts - 5_000_000,
                prev_owner: Some(1),
                epoch: 4,
            }),
        },
        Event::PortBlockRelease {
            ts_us: ts,
            sub: 0x2001_0db8 << 96,
            sub_len: 64,
            v4: 0xc000_0211,
            port_lo: 1024,
            port_hi: 1535,
            held_secs: 5,
            reason: Some(BlockReleaseReason::Handover),
        },
        Event::ClusterSliceRelease {
            ts_us: ts,
            slice,
            epoch: 5,
            new_owner: Some(1),
            reason: SliceReleaseReason::Handover,
        },
        Event::ClusterPeerRejected {
            ts_us: ts,
            rejected: Arc::new(PeerRejected {
                ip: "198.51.100.99".parse().unwrap(),
                port: 1,
                identity: Some(AuditText::new("dns:x\"},\"event.sequence\":0", AuditText::SUBJECT_MAX)),
                claimed_id: Some(1),
                reason: PeerRejectReason::NotAllowed,
            }),
        },
        Event::ClusterPeerSuppressed { ts_us: ts, suppressed: 3, window_secs: 60 },
        Event::ClusterReplicationGap { ts_us: ts, slice, lost: 2 },
        Event::ClusterHook {
            ts_us: ts,
            run: Arc::new(HookRun {
                hook: HookKind::Withdraw,
                slice,
                epoch: 5,
                exit_code: Some(1),
                duration_us: 9,
                success: false,
            }),
        },
    ];
    let n = evs.len() as u64;
    let path = tmp("cluster7");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(path.clone(), vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for e in evs {
        assert!(sink.emit(e));
    }
    drop(sink);
    h.join();
    let mut text = String::new();
    std::fs::File::open(&path).unwrap().read_to_string(&mut text).unwrap();
    let rep = verify(text.as_bytes()).unwrap();
    assert!(rep.ok(), "{rep:?}\n{text}");
    assert_eq!(rep.records, n);
    for a in ["cluster_view_change", "nat_port_block_adopt", "cluster_peer_rejected", "cluster_hook"] {
        assert!(text.contains(&format!("\"event.action\":\"{a}\"")), "{a}");
    }
    assert!(text.contains("\"plat.schema\":7"));
    let edited = text.replacen("\"cluster.epoch\":4", "\"cluster.epoch\":3", 1);
    assert!(!verify(edited.as_bytes()).unwrap().ok(), "edited epoch");
}
