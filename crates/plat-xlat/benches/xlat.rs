//! Per-packet translation cost (no NAT state). Run: `cargo bench -p plat-xlat`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use plat_packet::{checksum as ck, parse_v4, parse_v6, put16};
use plat_xlat::{HEADROOM, Map4, Map6, v4_to_v6, v6_to_v4};
use std::hint::black_box;

fn udp6(payload: usize) -> Vec<u8> {
    let l4 = 8 + payload;
    let mut p = vec![0u8; 40 + l4];
    p[0] = 0x60;
    put16(&mut p, 4, l4 as u16);
    p[6] = 17;
    p[7] = 64;
    p[8] = 0x20;
    p[23] = 1;
    p[24] = 0x00;
    p[25] = 0x64;
    p[26] = 0xff;
    p[27] = 0x9b;
    p[36..40].copy_from_slice(&[198, 51, 100, 7]);
    put16(&mut p, 40, 40000);
    put16(&mut p, 42, 53);
    put16(&mut p, 44, l4 as u16);
    let h = parse_v6(&p).unwrap();
    let c = ck::finish(ck::pseudo_v6(h.src, h.dst, 17, l4 as u32) + ck::sum(&p[40..]));
    put16(&mut p, 46, c);
    p
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("xlat");
    g.throughput(Throughput::Elements(1));
    let pkt = udp6(1200);
    let m4 = Map4 { src: 0xc000_020a, dst: 0xc633_6407, sport: 2048, dport: 53 };
    let mut buf = vec![0u8; HEADROOM + 2048];
    g.bench_function("v6_to_v4_udp_1248B", |b| {
        b.iter(|| {
            buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(&pkt);
            let h = parse_v6(&buf[HEADROOM..HEADROOM + pkt.len()]).unwrap();
            black_box(v6_to_v4(&mut buf, HEADROOM, &h, &m4, 1, 1500).unwrap());
        })
    });
    let (s, l) = {
        buf[HEADROOM..HEADROOM + pkt.len()].copy_from_slice(&pkt);
        let h = parse_v6(&buf[HEADROOM..HEADROOM + pkt.len()]).unwrap();
        v6_to_v4(&mut buf, HEADROOM, &h, &m4, 1, 1500).unwrap()
    };
    let v4pkt = buf[s..s + l].to_vec();
    let m6 = Map6 {
        src: 0x0064_ff9b_0000_0000_0000_0000_c633_6407,
        dst: 0x2001_0db8_0000_0000_0000_0000_0000_0001,
        sport: 53,
        dport: 40000,
    };
    g.bench_function("v4_to_v6_udp_1228B", |b| {
        b.iter(|| {
            buf[HEADROOM..HEADROOM + v4pkt.len()].copy_from_slice(&v4pkt);
            let h = parse_v4(&buf[HEADROOM..HEADROOM + v4pkt.len()]).unwrap();
            black_box(v4_to_v6(&mut buf, HEADROOM, &h, &m6, 1500).unwrap());
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
