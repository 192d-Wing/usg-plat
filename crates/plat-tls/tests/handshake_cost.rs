//! Control-plane cost of the hybrid X25519MLKEM768 key exchange in bytes on
//! the wire (CRYPTO_INVENTORY.md "Hybrid handshake cost"). The packet path
//! never handshakes; this covers management, syslog and cluster peer TLS.
//!
//! `cargo test -p plat-tls --test handshake_cost -- --nocapture` prints the
//! table used in the docs.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-8(1), SC-13 - hybrid post-quantum key establishment
//!   (FIPS 203 ML-KEM-768 sizes: 1184 B encapsulation key, 1088 B ciphertext)
//! - RFC 8446 §4.2.8 (key_share), draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768)

#[path = "support/handshake_pair.rs"]
mod handshake_pair;

use handshake_pair::{Flights, Pair};

fn measure(pq_hybrid: bool, alg: &'static rcgen::SignatureAlgorithm) -> Flights {
    Pair::new(pq_hybrid, alg).handshake()
}

#[test]
fn hybrid_key_share_cost() {
    let hybrid = measure(true, &rcgen::PKCS_ECDSA_P256_SHA256);
    let classical = measure(false, &rcgen::PKCS_ECDSA_P256_SHA256);
    println!("| policy | ClientHello | server flight | client Finished flight | total |");
    println!("|---|---|---|---|---|");
    for (name, f) in [("X25519MLKEM768 (pq_hybrid = true)", hybrid), ("secp256r1 (pq_hybrid = false)", classical)] {
        println!("| {name} | {} | {} | {} | {} |", f.client_hello, f.server_flight, f.client_finish, f.total());
    }
    // Same policy on both ends: the first key share is accepted, no HRR.
    assert_eq!(hybrid.server_flights, 1, "{hybrid:?}");
    assert_eq!(classical.server_flights, 1, "{classical:?}");
    // 1216 B vs 65 B key share, plus one more supported_groups entry.
    let ch = hybrid.client_hello - classical.client_hello;
    assert!((1100..=1400).contains(&ch), "ClientHello delta {ch}");
    // 1120 B vs 65 B key share in ServerHello.
    let sh = hybrid.server_flight - classical.server_flight;
    assert!((1000..=1200).contains(&sh), "server flight delta {sh}");
    // The client's second flight carries no key share.
    assert!(hybrid.client_finish.abs_diff(classical.client_finish) < 64, "{hybrid:?} {classical:?}");
}

#[test]
fn p384_leaf_handshakes() {
    let f = measure(true, &rcgen::PKCS_ECDSA_P384_SHA384);
    assert_eq!(f.server_flights, 1, "{f:?}");
    println!("X25519MLKEM768 with P-384 leaves: {f:?} total {}", f.total());
}
