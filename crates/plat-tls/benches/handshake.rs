//! Full mutual-TLS 1.3 handshake time (client and server in one thread, in
//! memory) for the hybrid X25519MLKEM768 and classical P-256 key exchange,
//! with P-256 and P-384 leaves. Control plane only: informational, not a
//! hot-path budget (CRYPTO_INVENTORY.md "Hybrid handshake cost").

#[path = "../tests/support/handshake_pair.rs"]
mod handshake_pair;

use criterion::{Criterion, criterion_group, criterion_main};
use handshake_pair::Pair;
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("tls13_handshake");
    for (name, pq, alg) in [
        ("hybrid_p256_leaf", true, &rcgen::PKCS_ECDSA_P256_SHA256),
        ("p256_p256_leaf", false, &rcgen::PKCS_ECDSA_P256_SHA256),
        ("hybrid_p384_leaf", true, &rcgen::PKCS_ECDSA_P384_SHA384),
        ("p256_p384_leaf", false, &rcgen::PKCS_ECDSA_P384_SHA384),
    ] {
        let pair = Pair::new(pq, alg);
        g.bench_function(name, |b| b.iter(|| black_box(pair.handshake().total())));
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
