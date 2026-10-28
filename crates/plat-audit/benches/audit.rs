//! Logger-side cost per record, data-plane enqueue cost, and end-to-end
//! logger throughput to the hash-chained file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use plat_audit::format;
use plat_audit::{AuditSink, Event, Logger, NodeIdent};
use plat_common::config::{AuditConfig, AuditFileConfig, AuditMode, OverflowPolicy};

fn bench(c: &mut Criterion) {
    let node = NodeIdent { name: "plat-01".into(), id: 0, pid: 1 };
    let ev = Event::BibCreate {
        ts_us: 1_793_196_960_000_000,
        proto: 6,
        v6: 0x2001_0db8 << 96 | 1,
        v6_port: 40000,
        v4: 0xc000_020a,
        v4_port: 2048,
    };
    let mut g = c.benchmark_group("audit");
    g.throughput(Throughput::Elements(1));
    let mut buf = Vec::with_capacity(512);
    g.bench_function("format_json", |b| {
        b.iter(|| {
            buf.clear();
            format::json(&mut buf, 1, &node, black_box(&ev));
        })
    });
    g.bench_function("format_cef", |b| {
        b.iter(|| {
            buf.clear();
            format::cef(&mut buf, 1, &node, black_box(&ev));
        })
    });
    let (sink, rx) = AuditSink::bounded(1 << 17);
    g.bench_function("enqueue_try_send", |b| {
        b.iter(|| {
            sink.emit(black_box(ev));
            let _ = rx.try_recv();
        })
    });
    g.finish();

    // End to end: 100 000 records through the logger thread into the local
    // file (format, SHA-256, checkpoint per 4096-record batch, flush), with
    // the default batch size. Includes thread start and file open/close.
    const N: u64 = 100_000;
    let dir = std::env::temp_dir().join(format!("plat-audit-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = AuditConfig {
        mode: AuditMode::PortBlock,
        queue_capacity: 1 << 16,
        on_overflow: OverflowPolicy::RefuseNewBindings,
        batch_max: 4096,
        flush_interval_ms: 100,
        summary_interval_secs: 0,
        file: Some(AuditFileConfig {
            path: dir.join("audit.jsonl"),
            max_bytes: 1 << 30,
            max_files: 2,
            min_free_bytes: 0,
        }),
        syslog: vec![],
    };
    let mut g = c.benchmark_group("audit_logger");
    g.throughput(Throughput::Elements(N));
    g.sample_size(10);
    g.bench_function("file_e2e_100k", |b| {
        b.iter(|| {
            let (sink, rx) = AuditSink::bounded(1 << 17);
            let h = Logger::new(cfg.clone(), node.clone(), rx, sink.stats().clone()).spawn().unwrap();
            for _ in 0..N {
                sink.emit(black_box(ev));
            }
            drop(sink);
            h.join();
        })
    });
    g.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

criterion_group!(benches, bench);
criterion_main!(benches);
