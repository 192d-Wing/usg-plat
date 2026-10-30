//! Steady-state instruction-count harness for the hot path (PERF-002).
//!
//! Runs `N` packets of one direction (`v6`: outbound UDP, `v4`: the reply)
//! through an existing session. Measure under cachegrind and take the
//! difference of two runs to cancel setup cost:
//!
//! ```sh
//! cargo build --release -p plat-nat64 --example ir
//! valgrind --tool=cachegrind --cache-sim=no target/release/examples/ir 100000 v6
//! valgrind --tool=cachegrind --cache-sim=no target/release/examples/ir 200000 v6
//! # instructions per packet = (I(200000) - I(100000)) / 100000
//! ```
//!
//! `make ir` runs both directions this way (Linux with valgrind).

#[path = "../tests/common/mod.rs"]
mod common;

use std::hint::black_box;

use common::*;
use plat_xlat::HEADROOM;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: u64 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(100_000);
    let dir = args.get(2).map_or("v6", String::as_str);
    let mut fx = fixture(&[]);
    let pkt = udp6(sub(1, 1), 5000, 0xc633_6407, 53, &[0u8; 512]);
    let Ok(out) = run(&mut fx, &pkt) else {
        eprintln!("setup packet was dropped");
        std::process::exit(1);
    };
    let (ia, ip) = (plat_packet::be32(&out, 12), plat_packet::be16(&out, 20));
    let reply = udp4(0xc633_6407, 53, ia, ip, &[0u8; 512]);
    let p = if dir == "v6" { pkt } else { reply };
    let mut buf = vec![0u8; HEADROOM + 2048];
    let t = std::time::Instant::now();
    for _ in 0..n {
        buf[HEADROOM..HEADROOM + p.len()].copy_from_slice(&p);
        black_box(fx.nat.process(&mut buf, HEADROOM, p.len(), &mut fx.ctx));
    }
    eprintln!("{dir} {:.2} ns/pkt", t.elapsed().as_nanos() as f64 / n as f64);
}
