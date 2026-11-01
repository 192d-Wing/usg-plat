//! Fast-path counters (plan §4.7): per-CPU `STATS` (pass reasons, aborts)
//! and `FWD` (forwarded packets and bytes per direction), summed over CPUs
//! with one lookup syscall per index (about 26 per scrape, in the metrics
//! thread, never on a packet path), and the `plat_xdp_*` metric text.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-4 (System Monitoring) - every pass reason, aborts,
//!   forwarded packets and bytes, writer and control-thread counters as
//!   separate `plat_xdp_*` families (decision Q7); existing families stay
//!   slow-path only

use std::fmt::Write as _;
use std::sync::atomic::Ordering;

use plat_xdp_core::abi::{FwdCounters, FwdDir, PassReason};

use crate::control::ControlCounters;
use crate::mirror::XdpMirror;

/// Counters summed over CPUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Indexed by `PassReason as usize`.
    pub pass: [u64; PassReason::COUNT as usize],
    pub aborted: u64,
    /// Indexed by `FwdDir as usize`.
    pub fwd: [FwdCounters; 2],
}

impl Default for Snapshot {
    fn default() -> Self {
        Self { pass: [0; PassReason::COUNT as usize], aborted: 0, fwd: [FwdCounters::default(); 2] }
    }
}

/// Sum of the per-CPU `u64` values of one `STATS` lookup (8-byte slots).
pub fn sum_u64(buf: &[u8]) -> u64 {
    buf.as_chunks::<8>().0.iter().fold(0u64, |a, c| a.wrapping_add(u64::from_ne_bytes(*c)))
}

/// Sum of the per-CPU [`FwdCounters`] of one `FWD` lookup (16-byte slots).
pub fn sum_fwd(buf: &[u8]) -> FwdCounters {
    buf.as_chunks::<16>().0.iter().map(FwdCounters::from_bytes).fold(FwdCounters::default(), |a, c| FwdCounters {
        packets: a.packets.wrapping_add(c.packets),
        bytes: a.bytes.wrapping_add(c.bytes),
    })
}

/// `STATS` / `FWD` reader over `platd`'s read-only pins.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct XdpStats<'a> {
    maps: &'a crate::maps::XdpMaps,
}

#[cfg(target_os = "linux")]
impl<'a> XdpStats<'a> {
    pub fn new(maps: &'a crate::maps::XdpMaps) -> Self {
        Self { maps }
    }

    /// One snapshot (allocates the per-CPU buffers once per call).
    pub fn snapshot(&self) -> std::io::Result<Snapshot> {
        let mut s = Snapshot::default();
        let mut b = vec![0u8; self.maps.stats.value_len()];
        let mut get = |idx: u32| -> std::io::Result<u64> {
            Ok(if self.maps.stats.lookup(&idx.to_ne_bytes(), &mut b)? { sum_u64(&b) } else { 0 })
        };
        for r in PassReason::ALL {
            if let Some(d) = s.pass.get_mut(r as usize) {
                *d = get(r.stat_idx())?;
            }
        }
        s.aborted = get(plat_xdp_core::abi::StatIdx::Aborted as u32)?;
        let mut f = vec![0u8; self.maps.fwd.value_len()];
        for d in FwdDir::ALL {
            if let Some(o) = s.fwd.get_mut(d as usize)
                && self.maps.fwd.lookup(&(d as u32).to_ne_bytes(), &mut f)?
            {
                *o = sum_fwd(&f);
            }
        }
        Ok(s)
    }
}

/// Appends the `plat_xdp_*` families (Prometheus text format) for a
/// configured fast path.
pub fn render(out: &mut String, enabled: bool, s: &Snapshot, m: &XdpMirror, c: &ControlCounters) {
    let mut fam = |name: &str, kind: &str, help: &str| {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    };
    fam("plat_xdp_enabled", "gauge", "1 when the XDP fast path may forward");
    fam("plat_xdp_packets_total", "counter", "Packets forwarded by the XDP fast path");
    fam("plat_xdp_bytes_total", "counter", "Output bytes forwarded by the XDP fast path");
    fam("plat_xdp_pass_total", "counter", "Packets the XDP fast path passed to the slow path, by reason");
    fam("plat_xdp_aborted_total", "counter", "Packets dropped after a failed post-rewrite check");
    fam("plat_xdp_sessions", "gauge", "Sessions installed in the fast-path maps");
    fam("plat_xdp_installs_total", "counter", "Fast-path session installs");
    fam("plat_xdp_install_failures_total", "counter", "Fast-path install failures, by reason");
    fam("plat_xdp_retires_total", "counter", "Fast-path session retires");
    fam("plat_xdp_retire_not_live_total", "counter", "Retires refused because the slot was not live");
    fam("plat_xdp_revalidated_total", "counter", "Slow-path expiries extended by fast-path activity");
    fam("plat_xdp_slots_quarantined", "gauge", "Slots waiting for an RCU grace period");
    fam("plat_xdp_gc_deleted_total", "counter", "Stale-generation entries deleted");
    fam("plat_xdp_heartbeat_stalls_total", "counter", "Heartbeats withheld because platd made no progress");
    let k = m.counters();
    let ld = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
    let _ = writeln!(out, "plat_xdp_enabled {}", u8::from(enabled));
    for d in FwdDir::ALL {
        let f = s.fwd.get(d as usize).copied().unwrap_or_default();
        let _ = writeln!(out, "plat_xdp_packets_total{{dir=\"{}\"}} {}", d.as_str(), f.packets);
        let _ = writeln!(out, "plat_xdp_bytes_total{{dir=\"{}\"}} {}", d.as_str(), f.bytes);
    }
    for r in PassReason::ALL {
        let _ =
            writeln!(out, "plat_xdp_pass_total{{reason=\"{}\"}} {}", r.as_str(), s.pass.get(r as usize).unwrap_or(&0));
    }
    let _ = writeln!(out, "plat_xdp_aborted_total {}", s.aborted);
    let _ = writeln!(out, "plat_xdp_sessions {}", k.sessions.get());
    let _ = writeln!(out, "plat_xdp_installs_total {}", k.installs.get());
    for (r, v) in [("map_full", &k.install_map_full), ("slots", &k.install_slots), ("error", &k.install_error)] {
        let _ = writeln!(out, "plat_xdp_install_failures_total{{reason=\"{r}\"}} {}", v.get());
    }
    let _ = writeln!(out, "plat_xdp_retires_total {}", k.retires.get());
    let _ = writeln!(out, "plat_xdp_retire_not_live_total {}", k.retire_not_live.get());
    let _ = writeln!(out, "plat_xdp_revalidated_total {}", k.revalidated.get());
    let _ = writeln!(out, "plat_xdp_slots_quarantined {}", m.slot_allocator().quarantined());
    let _ = writeln!(out, "plat_xdp_gc_deleted_total {}", k.gc_deleted.get());
    let _ = writeln!(out, "plat_xdp_heartbeat_stalls_total {}", ld(&c.heartbeat_stalls));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_cpu_sums() {
        let mut b = Vec::new();
        for v in [1u64, 2, 3, u64::MAX] {
            b.extend_from_slice(&v.to_ne_bytes());
        }
        assert_eq!(sum_u64(&b), 5); // wraps like the kernel counters
        let mut f = Vec::new();
        for (p, by) in [(1u64, 100u64), (2, 200)] {
            f.extend_from_slice(&p.to_ne_bytes());
            f.extend_from_slice(&by.to_ne_bytes());
        }
        assert_eq!(sum_fwd(&f), FwdCounters { packets: 3, bytes: 300 });
    }

    #[test]
    fn metric_text_has_every_family_and_reason() {
        let (_t, m) = crate::mirror::tests::mirror(4, 4);
        let mut s = Snapshot::default();
        s.pass[PassReason::NoSession as usize] = 9;
        s.fwd[FwdDir::V4ToV6 as usize] = FwdCounters { packets: 2, bytes: 120 };
        let mut out = String::new();
        render(&mut out, true, &s, &m, &ControlCounters::default());
        assert!(out.contains("plat_xdp_enabled 1\n"));
        assert!(out.contains("plat_xdp_pass_total{reason=\"no_session\"} 9\n"));
        assert!(out.contains("plat_xdp_packets_total{dir=\"v4_to_v6\"} 2\n"));
        assert!(out.contains("plat_xdp_bytes_total{dir=\"v4_to_v6\"} 120\n"));
        assert!(out.contains("plat_xdp_install_failures_total{reason=\"map_full\"} 0\n"));
        for r in PassReason::ALL {
            assert!(out.contains(&format!("reason=\"{}\"", r.as_str())));
        }
        assert_eq!(out.matches("# TYPE").count(), 14);
        assert!(out.contains("plat_xdp_retire_not_live_total 0\n"));
    }
}
