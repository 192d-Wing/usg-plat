//! QA: audit file rotation, startup move-aside, TCP syslog octet-counting
//! framing (RFC 6587 §3.4.1), and the AU-5 overflow record.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufReader, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use plat_audit::verify::verify;
use plat_audit::{AuditSink, Event, Logger, NodeIdent};
use plat_common::config::{
    AuditConfig, AuditFileConfig, AuditMode, LogFormat, OverflowPolicy, SyslogConfig, SyslogTransport,
};

fn cfg(file: Option<(PathBuf, u64)>, syslog: Vec<SyslogConfig>, batch_max: usize) -> AuditConfig {
    AuditConfig {
        mode: AuditMode::PortBlock,
        queue_capacity: 1024,
        on_overflow: OverflowPolicy::RefuseNewBindings,
        batch_max,
        flush_interval_ms: 10,
        summary_interval_secs: 0,
        file: file.map(|(path, max_bytes)| AuditFileConfig { path, max_bytes, max_files: 0, min_free_bytes: 0 }),
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
        port_hi: i.wrapping_add(511),
    }
}

fn node() -> NodeIdent {
    NodeIdent { name: "plat-qa".into(), id: 3, pid: 77 }
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("plat-audit-qa-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Audit files in `dir`, oldest first (rotated names carry a timestamp
/// suffix; the live file has none and is newest).
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut rotated: Vec<(u64, PathBuf)> = Vec::new();
    let mut live = None;
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        match name.strip_prefix("audit.jsonl.") {
            Some(ts) => rotated.push((ts.parse().unwrap(), p)),
            None if name == "audit.jsonl" => live = Some(p),
            None => panic!("unexpected file {name}"),
        }
    }
    rotated.sort();
    let mut v: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
    v.extend(live);
    v
}

fn seqs(path: &Path) -> Vec<u64> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.contains("audit_checkpoint") && !l.contains("audit_chain_continue"))
        .map(|l| {
            let i = l.find("\"event.sequence\":").unwrap() + 17;
            l[i..].split(',').next().unwrap().parse().unwrap()
        })
        .collect()
}

#[test]
fn file_rotation_keeps_every_file_verifiable_and_sequence_continuous() {
    let dir = tmpdir("rotate");
    let path = dir.join("audit.jsonl");
    let (sink, rx) = AuditSink::bounded(1024);
    let c = cfg(Some((path.clone(), 4096)), vec![], 8);
    let h = Logger::new(c, node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..400u16 {
        assert!(sink.emit(ev(1024 + i)));
    }
    let stats = sink.stats().clone();
    drop(sink);
    h.join();
    assert_eq!(stats.output_errors.load(Ordering::Relaxed), 0);

    let fs = files(&dir);
    assert!(fs.len() >= 3, "4 KiB limit must rotate several times, got {}", fs.len());
    let mut all = Vec::new();
    for f in &fs {
        let rep = verify(BufReader::new(std::fs::File::open(f).unwrap())).unwrap();
        assert!(rep.ok(), "{}: {rep:?}", f.display());
        assert_eq!(rep.unverified_tail, 0, "{}", f.display());
        let len = std::fs::metadata(f).unwrap().len();
        // A file may exceed the limit by at most one batch (8 records + checkpoint).
        assert!(len < 4096 + 9 * 600, "{} is {len} bytes", f.display());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode & 0o027, 0, "{} mode {mode:o}: no group write, no world access", f.display());
        }
        all.extend(seqs(f));
    }
    assert_eq!(all, (1..=400).collect::<Vec<u64>>(), "no gap or duplicate across rotated files");
}

#[test]
fn existing_file_is_moved_aside_on_start() {
    let dir = tmpdir("aside");
    let path = dir.join("audit.jsonl");
    std::fs::write(&path, b"previous run, unverifiable tail\n").unwrap();
    let (sink, rx) = AuditSink::bounded(1024);
    let h =
        Logger::new(cfg(Some((path.clone(), 1 << 30)), vec![], 64), node(), rx, sink.stats().clone()).spawn().unwrap();
    sink.emit(ev(1));
    drop(sink);
    h.join();
    let fs = files(&dir);
    assert_eq!(fs.len(), 2);
    assert_eq!(std::fs::read(&fs[0]).unwrap(), b"previous run, unverifiable tail\n", "old content preserved");
    let rep = verify(BufReader::new(std::fs::File::open(&path).unwrap())).unwrap();
    assert!(rep.ok() && rep.records == 1, "{rep:?}");
}

#[test]
fn tcp_syslog_uses_octet_counting_framing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let reader = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        buf
    });
    let syslog = SyslogConfig {
        address: addr,
        transport: SyslogTransport::Tcp,
        format: LogFormat::Json,
        app_name: "platd".into(),
        tls: None,
    };
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(None, vec![syslog], 16), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..100u16 {
        assert!(sink.emit(ev(1024 + i)));
    }
    let stats = sink.stats().clone();
    drop(sink);
    h.join();
    let buf = reader.join().unwrap();
    assert_eq!(stats.output_errors.load(Ordering::Relaxed), 0);

    // MSG-LEN SP SYSLOG-MSG, repeated, nothing else.
    let mut frames = Vec::new();
    let mut rest = &buf[..];
    while !rest.is_empty() {
        let sp = rest.iter().position(|&b| b == b' ').expect("length prefix");
        let len: usize = std::str::from_utf8(&rest[..sp]).unwrap().parse().expect("decimal length");
        assert!(!rest[..sp].starts_with(b"0"), "no leading zero");
        let body = &rest[sp + 1..sp + 1 + len];
        frames.push(std::str::from_utf8(body).unwrap().to_owned());
        rest = &rest[sp + 1 + len..];
    }
    assert_eq!(frames.len(), 100);
    for (i, f) in frames.iter().enumerate() {
        assert!(
            f.starts_with("<134>1 2026-10-28T14:16:00.000000Z plat-qa platd 77 nat_port_block_allocate - {"),
            "{f}"
        );
        assert!(f.contains(&format!("\"event.sequence\":{}", i + 1)), "in order: {f}");
        assert!(f.ends_with('}') && !f.contains('\n'), "one record per frame");
    }
}

#[test]
fn tcp_syslog_unreachable_counts_output_errors_without_blocking() {
    // Bind then drop to get a port with no listener.
    let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let syslog = SyslogConfig {
        address: addr,
        transport: SyslogTransport::Tcp,
        format: LogFormat::Cef,
        app_name: "platd".into(),
        tls: None,
    };
    let dir = tmpdir("remote-loss");
    let path = dir.join("audit.jsonl");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(Some((path.clone(), 1 << 30)), vec![syslog], 16), node(), rx, sink.stats().clone())
        .spawn()
        .unwrap();
    let t = std::time::Instant::now();
    for i in 0..20u16 {
        assert!(sink.emit(ev(i)), "emit never blocks or fails while the queue has room");
    }
    let stats = sink.stats().clone();
    drop(sink);
    h.join();
    assert!(t.elapsed() < Duration::from_secs(10));
    assert!(stats.output_errors.load(Ordering::Relaxed) > 0, "delivery failure is counted");
    assert!(!stats.degraded(), "a remote failure does not degrade the local file");

    // AU-5 / AU-9(2): every undelivered record is accounted for in the local file.
    let text = std::fs::read_to_string(&path).unwrap();
    let reported: u64 = text
        .lines()
        .filter(|l| l.contains("\"event.action\":\"audit_remote_loss\""))
        .map(|l| {
            assert!(
                l.contains(&format!("\"destination.ip\":\"127.0.0.1\",\"destination.port\":{}", addr.port())),
                "{l}"
            );
            // Schema 5: the connection failures carry their cause.
            assert!(l.contains("\"plat.reason\":\"io\"") || !l.contains("plat.reason"), "{l}");
            let i = l.find("\"plat.audit.lost\":").unwrap() + 18;
            l[i..].chars().take_while(char::is_ascii_digit).collect::<String>().parse::<u64>().unwrap()
        })
        .sum();
    let remote_lost = stats.remote_lost.load(Ordering::Relaxed);
    assert!(remote_lost >= 20, "all 20 records undelivered, got {remote_lost}");
    assert_eq!(reported, remote_lost, "{text}");
    assert_eq!(stats.written.load(Ordering::Relaxed), seqs(&path).len() as u64);
    let rep = verify(text.as_bytes()).unwrap();
    assert!(rep.ok() && rep.unverified_tail == 0, "{rep:?}");
}

#[test]
fn queue_overflow_produces_an_audit_record() {
    let dir = tmpdir("overflow");
    let path = dir.join("audit.jsonl");
    let (sink, rx) = AuditSink::bounded(4);
    for i in 0..10u16 {
        sink.emit(ev(i));
    }
    assert_eq!(sink.stats().lost.load(Ordering::Relaxed), 6);
    let h =
        Logger::new(cfg(Some((path.clone(), 1 << 30)), vec![], 64), node(), rx, sink.stats().clone()).spawn().unwrap();
    drop(sink);
    h.join();
    let text = std::fs::read_to_string(&path).unwrap();
    let overflow: Vec<&str> = text.lines().filter(|l| l.contains("audit_queue_overflow")).collect();
    assert_eq!(overflow.len(), 1, "{text}");
    assert!(overflow[0].contains("\"plat.audit.lost\":6"), "{}", overflow[0]);
    assert!(verify(text.as_bytes()).unwrap().ok());
}
