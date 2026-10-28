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
