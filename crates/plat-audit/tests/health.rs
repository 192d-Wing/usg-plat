//! Audit pipeline health: local file failure fails closed and recovers
//! (AU-5), the chain continues across files and restarts (AU-9), retention
//! (AU-4/AU-11), and a stalled collector never stalls the local file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::BufReader;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use plat_audit::verify::{GapAccount, LinkIssue, VerifyReport, link, verify};
use plat_audit::{AuditSink, AuditStats, Event, Logger, NodeIdent};
use plat_common::config::{
    AuditConfig, AuditFileConfig, AuditMode, LogFormat, OverflowPolicy, SyslogConfig, SyslogTransport,
};

fn cfg(path: &Path, max_bytes: u64, max_files: u32, syslog: Vec<SyslogConfig>) -> AuditConfig {
    AuditConfig {
        mode: AuditMode::PortBlock,
        queue_capacity: 1024,
        on_overflow: OverflowPolicy::RefuseNewBindings,
        batch_max: 8,
        flush_interval_ms: 10,
        summary_interval_secs: 0,
        file: Some(AuditFileConfig { path: path.into(), max_bytes, max_files, min_free_bytes: 0 }),
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
    NodeIdent { name: "plat-health".into(), id: 5, pid: 9 }
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("plat-audit-health-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn wait(what: &str, f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(10), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Every audit file in `dir`, verified, oldest first.
fn reports(dir: &Path) -> Vec<(PathBuf, VerifyReport)> {
    let mut v: Vec<(PathBuf, VerifyReport)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("audit.jsonl"))
        .map(|p| {
            let r = verify(BufReader::new(std::fs::File::open(&p).unwrap())).unwrap();
            assert!(r.ok(), "{}: {r:?}", p.display());
            (p, r)
        })
        .collect();
    v.sort_by_key(|(_, r)| r.next_seq);
    v
}

fn issues(v: &[(PathBuf, VerifyReport)]) -> Vec<LinkIssue> {
    link(&v.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>())
}

fn written(s: &AuditStats) -> u64 {
    s.written.load(Ordering::Relaxed)
}

#[test]
fn file_failure_degrades_fails_closed_and_recovers() {
    let dir = tmpdir("degraded");
    let sub = dir.join("sub");
    let path = sub.join("audit.jsonl");
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let syslog = SyslogConfig {
        address: collector.local_addr().unwrap(),
        transport: SyslogTransport::Udp,
        format: LogFormat::Json,
        app_name: "platd".into(),
        tls: None,
    };
    let (sink, rx) = AuditSink::bounded(4096);
    let stats = sink.stats().clone();
    let h = Logger::new(cfg(&path, 4096, 0, vec![syslog]), node(), rx, stats.clone()).spawn().unwrap();
    for i in 0..4 {
        assert!(sink.emit(ev(i)));
    }
    wait("first records", || written(&stats) >= 4);
    assert!(sink.has_room() && !stats.degraded());

    // Make the log directory unusable: the next rotation cannot open a file.
    std::fs::rename(&sub, dir.join("sub.bak")).unwrap();
    std::fs::write(&sub, b"not a directory").unwrap();
    for i in 0..40 {
        sink.emit(ev(100 + i));
    }
    wait("degraded", || stats.degraded());
    assert!(!sink.has_room(), "AU-5: refuse_new_bindings must engage while the file is down");
    let before = written(&stats);
    for i in 0..10 {
        assert!(sink.emit(ev(200 + i)), "the queue still accepts records for the other destinations");
    }
    wait("file loss counted", || stats.file_lost.load(Ordering::Relaxed) >= 10);
    assert_eq!(written(&stats), before, "written counts only durable records");

    // The collector is told while the file is down.
    let mut got_failure = false;
    let mut b = [0u8; 2048];
    let t = Instant::now();
    while !got_failure && t.elapsed() < Duration::from_secs(5) {
        if let Ok(n) = collector.recv(&mut b) {
            let s = String::from_utf8_lossy(&b[..n]);
            got_failure = s.contains("\"event.action\":\"audit_output_failure\"") && s.contains("\"degraded\"");
        }
    }
    assert!(got_failure, "audit_output_failure (degraded) sent to syslog");

    // Repair; the logger reopens within about a second.
    std::fs::remove_file(&sub).unwrap();
    std::fs::rename(dir.join("sub.bak"), &sub).unwrap();
    wait("recovered", || !stats.degraded());
    assert!(sink.has_room());
    for i in 0..5 {
        assert!(sink.emit(ev(300 + i)));
    }
    drop(sink);
    h.join();

    let lost = stats.file_lost.load(Ordering::Relaxed);
    let files = reports(&sub);
    // The file written on recovery (later ones may follow: rotation).
    let texts: Vec<String> = files.iter().map(|(p, _)| std::fs::read_to_string(p).unwrap()).collect();
    let first_record = texts
        .iter()
        .filter_map(|t| t.lines().nth(1))
        .find(|l| l.contains("\"event.action\":\"audit_output_failure\""))
        .expect("a file starts with audit_output_failure");
    assert!(first_record.contains("\"plat.audit.state\":\"recovered\""), "{first_record}");
    assert!(first_record.contains(&format!("\"plat.audit.lost\":{lost}")), "{first_record} lost={lost}");
    // Exactly one gap, of exactly the reported size; otherwise one chain.
    let is = issues(&files);
    assert_eq!(is.len(), 1, "{is:?}");
    match &is[0] {
        LinkIssue::Gap { first, last, accounted, .. } => {
            assert!(last - first + 1 == lost && *accounted == Some(GapAccount::OutputFailure), "{is:?}")
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn restart_continues_chain_and_sequence() {
    let dir = tmpdir("restart");
    let path = dir.join("audit.jsonl");
    for run in 0..3u16 {
        let (sink, rx) = AuditSink::bounded(1024);
        let h = Logger::new(cfg(&path, 1 << 30, 0, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
        for i in 0..10 {
            sink.emit(ev(run * 100 + i));
        }
        drop(sink);
        h.join();
    }
    let files = reports(&dir);
    assert_eq!(files.len(), 3);
    assert_eq!(files.iter().map(|(_, r)| r.next_seq).collect::<Vec<_>>(), vec![1, 11, 21]);
    assert_eq!(files[0].1.prev_chain, "0".repeat(64), "first file has no predecessor");
    assert!(issues(&files).is_empty(), "{:?}", issues(&files));

    // Removing the middle file breaks the link.
    let ends = [files[0].1.clone(), files[2].1.clone()];
    assert!(matches!(link(&ends)[..], [LinkIssue::Broken { index: 1, .. }]));
}

#[test]
fn restart_after_crash_skips_unverified_tail_sequences() {
    let dir = tmpdir("crash");
    let path = dir.join("audit.jsonl");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(&path, 1 << 30, 0, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..8 {
        sink.emit(ev(i));
    }
    drop(sink);
    h.join();
    // Simulate a crash: two records written after the last checkpoint.
    let text = std::fs::read_to_string(&path).unwrap();
    let rec = text.lines().nth(1).unwrap().to_string();
    let tail = format!(
        "{}\n{}\n",
        rec.replace("\"event.sequence\":1,", "\"event.sequence\":9,"),
        rec.replace("\"event.sequence\":1,", "\"event.sequence\":10,")
    );
    std::fs::write(&path, format!("{text}{tail}")).unwrap();
    let r = verify(text.as_bytes()).unwrap();
    assert_eq!(r.last_seq, 8);

    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(&path, 1 << 30, 0, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    sink.emit(ev(50));
    drop(sink);
    h.join();
    let files = reports(&dir);
    assert_eq!(files[0].1.unverified_tail, 2);
    assert_eq!(files[1].1.next_seq, 11, "sequence numbers are never reused");
    assert_eq!(files[1].1.prev_seq, 8, "chain continues from the last checkpoint");
    assert!(issues(&files).is_empty(), "{:?}", issues(&files));
}

#[test]
fn header_and_checkpoint_metadata_are_bound_into_the_chain() {
    let dir = tmpdir("bound");
    let path = dir.join("audit.jsonl");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(&path, 1 << 30, 0, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..20 {
        sink.emit(ev(i));
    }
    drop(sink);
    h.join();
    let text = std::fs::read_to_string(&path).unwrap();
    let r = verify(text.as_bytes()).unwrap();
    assert!(r.ok() && r.checkpoints >= 1, "{r:?}");

    let cp = text.lines().find(|l| l.contains("audit_checkpoint")).unwrap();
    let schema = format!("\"plat.schema\":{}", plat_audit::LOG_SCHEMA_VERSION);
    for want in [schema.as_str(), "\"plat.node_id\":5", "\"observer.name\":\"plat-health\""] {
        assert!(cp.contains(want), "{want} in {cp}");
    }
    let edits = [
        ("\"plat.audit.prev_seq\":0", "\"plat.audit.prev_seq\":1", "header prev_seq"),
        ("\"plat.audit.next_seq\":1", "\"plat.audit.next_seq\":2", "header next_seq"),
        ("\"plat.audit.seq_first\":1,", "\"plat.audit.seq_first\":2,", "checkpoint seq_first"),
        (
            "\"observer.name\":\"plat-health\",\"plat.node_id\":5,\"plat.audit.prev_chain",
            "\"observer.name\":\"plat-other\",\"plat.node_id\":5,\"plat.audit.prev_chain",
            "header node",
        ),
    ];
    for (a, b, what) in edits {
        assert!(text.contains(a), "{what}: fixture");
        let r = verify(text.replacen(a, b, 1).as_bytes()).unwrap();
        assert!(!r.ok(), "{what} edit must be detected");
    }
    // A file without its header is rejected.
    let headless: String = text.lines().skip(1).map(|l| format!("{l}\n")).collect();
    assert!(!verify(headless.as_bytes()).unwrap().ok());
    // Two files concatenated are rejected.
    assert!(!verify(format!("{text}{text}").as_bytes()).unwrap().ok());
}

#[test]
fn retention_keeps_at_most_max_files() {
    let dir = tmpdir("retention");
    let path = dir.join("audit.jsonl");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(&path, 4096, 2, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..400 {
        sink.emit(ev(i));
    }
    let stats = sink.stats().clone();
    drop(sink);
    h.join();
    assert_eq!(stats.output_errors.load(Ordering::Relaxed), 0);
    let files = reports(&dir);
    assert_eq!(files.len(), 3, "live file + 2 rotated");
    assert_eq!(files.last().unwrap().0, path);
    assert!(issues(&files).is_empty(), "the newest files still form one chain");
}

fn run_once(path: &Path, max_files: u32, base: u16, n: u16) {
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(path, 1 << 30, max_files, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..n {
        sink.emit(ev(base + i));
    }
    drop(sink);
    h.join();
}

/// SEC-103: restarts (and start-failure loops) never consume retention
/// slots or delete records: a header-only live file is replaced in place,
/// and nothing is pruned at start-up.
#[test]
fn restarts_never_consume_retention() {
    let dir = tmpdir("restart-loop");
    let path = dir.join("audit.jsonl");
    run_once(&path, 3, 0, 50);
    for _ in 0..6 {
        run_once(&path, 3, 0, 0);
    }
    let files = reports(&dir);
    assert_eq!(files.iter().map(|(_, r)| r.records).sum::<u64>(), 50, "every record is still on disk");
    assert_eq!(files.len(), 2, "one file with the records + one header-only live file: {files:?}");
    assert!(issues(&files).is_empty(), "{:?}", issues(&files));
    // Traffic after the restarts continues the same chain.
    run_once(&path, 3, 100, 5);
    let files = reports(&dir);
    assert_eq!(files.last().unwrap().1.next_seq, 51);
    assert!(issues(&files).is_empty(), "{:?}", issues(&files));
}

/// SEC-105: with the live file gone (moved by tooling, or a crash between
/// the two renames of a rotation), start-up continues the chain and
/// sequence numbers of the newest rotated file instead of genesis and 1.
#[test]
fn missing_live_file_resumes_from_newest_rotated_file() {
    let dir = tmpdir("missing-live");
    let path = dir.join("audit.jsonl");
    run_once(&path, 0, 0, 5);
    run_once(&path, 0, 10, 5);
    std::fs::rename(&path, dir.join("audit.jsonl.99999999999999999")).unwrap();
    run_once(&path, 0, 20, 5);
    let files = reports(&dir);
    assert_eq!(files.iter().map(|(_, r)| r.next_seq).collect::<Vec<_>>(), vec![1, 6, 11]);
    assert!(issues(&files).is_empty(), "{:?}", issues(&files));
}

/// NIST-104: every retention deletion is preceded by an
/// `audit_retention_prune` record in the live chain; the newest one names
/// exactly the predecessor of the oldest retained file.
#[test]
fn retention_records_every_deletion() {
    let dir = tmpdir("prune-records");
    let path = dir.join("audit.jsonl");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(&path, 4096, 2, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..400 {
        sink.emit(ev(i));
    }
    drop(sink);
    h.join();
    let files = reports(&dir);
    assert_eq!(files.len(), 3, "live file + 2 rotated");
    let oldest = &files[0].1;
    let mut prunes: Vec<(u64, u64, u64, String)> = Vec::new();
    // NIST-202: (sequence, seq range, state, outcome) of every prune record.
    let mut states: Vec<(u64, u64, String, String)> = Vec::new();
    for (p, _) in &files {
        for l in std::fs::read_to_string(p).unwrap().lines().filter(|l| l.contains("audit_retention_prune")) {
            let text = |k: &str| -> String {
                let i = l.find(&format!("\"{k}\":\"")).unwrap() + k.len() + 4;
                l[i..].split('"').next().unwrap().to_string()
            };
            let num = |k: &str| -> u64 {
                let i = l.find(&format!("\"{k}\":")).unwrap() + k.len() + 3;
                l[i..].split([',', '}']).next().unwrap().parse().unwrap()
            };
            let i = l.find("\"plat.audit.pruned_chain_prefix\":\"").unwrap() + 34;
            states.push((
                num("event.sequence"),
                num("plat.audit.pruned_seq_first"),
                text("plat.audit.state"),
                text("event.outcome"),
            ));
            prunes.push((
                num("event.sequence"),
                num("plat.audit.pruned_seq_first"),
                num("plat.audit.pruned_seq_last"),
                l[i..i + 16].to_string(),
            ));
        }
    }
    assert!(!prunes.is_empty(), "retention ran and was recorded");
    for (_, first, last, _) in &prunes {
        assert!(first <= last && *last < oldest.next_seq, "pruned range {first}..={last} is older than retained");
    }
    // The scheduled record claims nothing; each one is followed by a
    // `deleted` result for the same file (NIST-202).
    for (seq, first, state, outcome) in &states {
        match state.as_str() {
            "scheduled" => {
                assert_eq!(outcome, "unknown");
                assert!(
                    states.iter().any(|(s2, f2, st2, _)| s2 > seq && f2 == first && st2 == "deleted"),
                    "scheduled prune of {first} at {seq} has a deleted result: {states:?}"
                );
            }
            "deleted" => assert_eq!(outcome, "success"),
            other => panic!("unexpected prune state {other}: {states:?}"),
        }
    }
    let newest = prunes.iter().max_by_key(|p| p.0).unwrap();
    assert_eq!(newest.2, oldest.prev_seq, "newest prune record names the oldest retained file's predecessor");
    assert_eq!(newest.3, oldest.prev_chain[..16], "and its final chain");
}

/// Shifts every rotated file's name (`audit.jsonl.<µs>`) by `delta_us`, as
/// if those files had been rotated before a backward wall-clock step of
/// that size. With `reverse`, the name order is also inverted.
fn shift_rotated_names(dir: &Path, delta_us: u64, reverse: bool) {
    let mut v: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter_map(|p| {
            let ts = p.file_name()?.to_str()?.strip_prefix("audit.jsonl.")?.parse::<u64>().ok()?;
            Some((ts, p))
        })
        .collect();
    v.sort();
    let names: Vec<u64> = v.iter().map(|(ts, _)| ts + delta_us).collect();
    for (i, (_, p)) in v.iter().enumerate() {
        let ts = if reverse { names[names.len() - 1 - i] } else { names[i] };
        std::fs::rename(p, dir.join(format!(".shift.{ts}"))).unwrap();
    }
    for ts in names {
        std::fs::rename(dir.join(format!(".shift.{ts}")), dir.join(format!("audit.jsonl.{ts}"))).unwrap();
    }
}

/// NIST-203 / SEC-201: after a backward clock step, files rotated later
/// have smaller names. Retention must still delete the oldest *records*
/// (by header `next_seq`), so the retained files form one unbroken chain
/// ending at the newest record.
#[test]
fn retention_follows_the_chain_after_a_backward_clock_step() {
    let dir = tmpdir("clockstep");
    let path = dir.join("audit.jsonl");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(&path, 4096, 0, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..60 {
        sink.emit(ev(i));
    }
    drop(sink);
    h.join();
    let before = reports(&dir);
    assert!(before.len() >= 4, "several rotated files: {}", before.len());
    let run1_last = before.last().unwrap().1.last_seq;
    shift_rotated_names(&dir, 86_400_000_000, false); // one day in the future

    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(&path, 4096, 2, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..70 {
        sink.emit(ev(1000 + i));
    }
    drop(sink);
    h.join();
    let files = reports(&dir);
    assert_eq!(files.len(), 3, "live file + 2 rotated");
    assert!(issues(&files).is_empty(), "retained files are contiguous: {:?}", issues(&files));
    assert!(files[0].1.next_seq > run1_last, "only run-2 records are retained, oldest {}", files[0].1.next_seq);
}

/// NIST-203: with the live file missing and rotated names out of chain
/// order, start-up resumes from the file with the highest `next_seq` and
/// never reuses a sequence number.
#[test]
fn resume_follows_the_chain_when_names_are_out_of_order() {
    let dir = tmpdir("clockresume");
    let path = dir.join("audit.jsonl");
    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(&path, 4096, 0, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    for i in 0..60 {
        sink.emit(ev(i));
    }
    drop(sink);
    h.join();
    let run1 = reports(&dir);
    let run1_last = run1.iter().map(|(_, r)| r.last_seq).max().unwrap();
    // A restart moves a live file holding records aside, so the live file
    // removed below holds none (whatever the rotation boundaries were).
    let (sink, rx) = AuditSink::bounded(16);
    let h = Logger::new(cfg(&path, 4096, 0, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    drop(sink);
    h.join();
    std::fs::remove_file(&path).unwrap(); // live file lost
    shift_rotated_names(&dir, 0, true); // newest records under the oldest name

    let (sink, rx) = AuditSink::bounded(1024);
    let h = Logger::new(cfg(&path, 1 << 30, 0, vec![]), node(), rx, sink.stats().clone()).spawn().unwrap();
    sink.emit(ev(999));
    drop(sink);
    h.join();
    let files = reports(&dir);
    let live = &files.last().unwrap().1;
    assert_eq!(live.next_seq, run1_last + 1, "no sequence number is reused");
    assert!(issues(&files).is_empty(), "chain continues from the newest file: {:?}", issues(&files));
}

#[test]
fn stalled_collector_never_stalls_the_local_file() {
    // Accepts connections (kernel backlog) but never reads: writes block
    // once the socket buffers fill.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let syslog = SyslogConfig {
        address: listener.local_addr().unwrap(),
        transport: SyslogTransport::Tcp,
        format: LogFormat::Json,
        app_name: "platd".into(),
        tls: None,
    };
    // Writes 8000 records and returns how long the file took to hold them.
    // Every checkpoint is synced (L12): use realistic batches so the
    // timing measures the collector hand-off, not 1000 fsyncs.
    let run = |tag: &str, syslog: Vec<SyslogConfig>| {
        let dir = tmpdir(tag);
        let path = dir.join("audit.jsonl");
        let (sink, rx) = AuditSink::bounded(1 << 14);
        let stats = sink.stats().clone();
        let mut c = cfg(&path, 1 << 30, 0, syslog);
        c.batch_max = 256;
        let h = Logger::new(c, node(), rx, stats.clone()).spawn().unwrap();
        let t = Instant::now();
        for i in 0..8000u16 {
            assert!(sink.emit(ev(i)));
        }
        wait("file keeps up", || written(&stats) >= 8000);
        let took = t.elapsed();
        drop(sink);
        h.join();
        assert!(!stats.degraded());
        took
    };
    // The same load with no collector is the baseline for this host's disk.
    // Waiting on the stalled collector would add at least one stream
    // timeout (2 s); a slow runner only scales both runs.
    let baseline = run("stalled-baseline", vec![]);
    let stalled = run("stalled", vec![syslog]);
    drop(listener);
    assert!(
        stalled < baseline + Duration::from_secs(1),
        "file waited on the collector: {stalled:?} (baseline {baseline:?})"
    );
}
