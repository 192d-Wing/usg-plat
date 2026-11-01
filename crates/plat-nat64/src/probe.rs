//! `bib4` shard lock hold-time probe (feature `hold-probe`; measurement
//! builds only, never in a production build).
//!
//! The XDP WU5 gate (POAM-016) bounds how much the session mirror adds to
//! a `bib4` hold. With the feature on, every worker critical section of
//! `bib4` (BIB create, outbound and inbound session update or create) and
//! every sweeper `bib4` hold records its length into a per-thread
//! histogram (10 ns buckets up to 100 µs, then one overflow bucket, plus
//! the exact maximum). Without the feature the call sites compile to
//! nothing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Bucket width in nanoseconds.
pub const BUCKET_NS: u64 = 10;
/// Buckets (the last one counts everything at or above its start).
pub const BUCKETS: usize = 10_001;

/// Who held the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    Worker = 0,
    Sweeper = 1,
    /// Time spent in session-mirror calls (recorded by a measuring
    /// wrapper, not by the engine): the part of a hold the mirror adds.
    Mirror = 2,
}

const HOLDERS: usize = 3;

/// One thread's histograms.
#[derive(Debug)]
pub struct Hist {
    counts: [Box<[AtomicU64]>; HOLDERS],
    max: [AtomicU64; HOLDERS],
}

impl Hist {
    fn new() -> Self {
        let b = || (0..BUCKETS).map(|_| AtomicU64::new(0)).collect::<Box<[AtomicU64]>>();
        Self { counts: [b(), b(), b()], max: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)] }
    }

    fn record(&self, who: Holder, ns: u64) {
        let i = ((ns / BUCKET_NS) as usize).min(BUCKETS - 1);
        if let (Some(c), Some(b)) = (self.counts.get(who as usize), self.max.get(who as usize)) {
            if let Some(a) = c.get(i) {
                a.fetch_add(1, Ordering::Relaxed);
            }
            b.fetch_max(ns, Ordering::Relaxed);
        }
    }
}

static REGISTRY: Mutex<Vec<Arc<Hist>>> = Mutex::new(Vec::new());

thread_local! {
    static MINE: Arc<Hist> = {
        let h = Arc::new(Hist::new());
        if let Ok(mut r) = REGISTRY.lock() {
            r.push(h.clone());
        }
        h
    };
}

/// Records one hold of `ns` nanoseconds.
pub fn record(who: Holder, ns: u64) {
    MINE.with(|h| h.record(who, ns));
}

/// Times a hold from construction to drop (declare it right after the
/// guard, so it is dropped just before the guard).
#[derive(Debug)]
pub struct Probe(Holder, Instant);

impl Probe {
    pub fn start(who: Holder) -> Self {
        Self(who, Instant::now())
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        record(self.0, self.1.elapsed().as_nanos() as u64);
    }
}

/// Summary of all threads' holds by `who`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub n: u64,
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub max_ns: u64,
    /// Holds of 20 µs or more.
    pub over_20us: u64,
}

/// Merges every thread's histogram for `who`.
pub fn summary(who: Holder) -> Summary {
    let mut sum = vec![0u64; BUCKETS];
    let mut max = 0;
    if let Ok(r) = REGISTRY.lock() {
        for h in r.iter() {
            if let Some(c) = h.counts.get(who as usize) {
                for (s, a) in sum.iter_mut().zip(c.iter()) {
                    *s += a.load(Ordering::Relaxed);
                }
            }
            max = max.max(h.max.get(who as usize).map_or(0, |m| m.load(Ordering::Relaxed)));
        }
    }
    let n: u64 = sum.iter().sum();
    let q = |p: f64| {
        let want = ((n as f64) * p).ceil() as u64;
        let mut acc = 0;
        for (i, c) in sum.iter().enumerate() {
            acc += c;
            if acc >= want.max(1) {
                return (i as u64 + 1) * BUCKET_NS;
            }
        }
        0
    };
    let over = sum.iter().skip((20_000 / BUCKET_NS) as usize).sum();
    Summary { n, p50_ns: q(0.5), p99_ns: q(0.99), p999_ns: q(0.999), max_ns: max, over_20us: over }
}

/// Clears every histogram.
pub fn reset() {
    if let Ok(r) = REGISTRY.lock() {
        for h in r.iter() {
            for c in &h.counts {
                for a in c.iter() {
                    a.store(0, Ordering::Relaxed);
                }
            }
            for m in &h.max {
                m.store(0, Ordering::Relaxed);
            }
        }
    }
}
