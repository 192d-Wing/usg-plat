# Cryptographic inventory

The machine-readable inventory is the CycloneDX 1.6 CBOM
[`cbom.cdx.json`](cbom.cdx.json) (44 components). It is checked against the
code in both directions by `crates/plat-tls/tests/cbom.rs` (T1, `make test`:
`cbom_matches_code`, `quantum_classification_present`,
`no_ffdhe_and_no_rsa_key_transport`, `no_fips_certification_claimed`,
`every_reference_resolves`, `cbom_side_mutations_detected`,
`code_side_additions_detected`) and by
`deploy/tests/supply-chain/check-cbom.py` (T3-T5, `make cbom-check`, with
`test_drift_negative.py`). A change to the TLS policy or to the `sig.rs`
table fails T1 until the CBOM is re-blessed (`PLAT_CBOM_BLESS=1`, refused when
`CI=true`) and a human classifies any new component.

The CBOM claims no FIPS 140-3 certification level: AWS-LC-FIPS 4.2.0 is CMVP
"Modules In Process" with no certificate (POAM-026).

## Inventory

Policy owner: `crates/plat-tls/src/policy.rs` (`fips_provider`). OCSP/CRL
signature set: `crates/plat-tls/src/revocation/sig.rs` (`ACCEPTED`,
`PSS_HASHES`). Every use site carries a `// CBOM: <bom-ref>` marker (T4).

| Class | CBOM bom-refs | Where |
|-------|---------------|-------|
| Protocol | `crypto/protocol/tls13` (TLS 1.3 only, no resumption) | `policy.rs` |
| Key establishment | `x25519mlkem768` (default, `tls.pq_hybrid = true`), `ml-kem-768`, `x25519`, `ecdh-p256`, `ecdh-p384` | `policy.rs` `fips_provider` |
| Bulk / KDF | `aes-128-gcm`, `aes-256-gcm`, `hkdf-sha256`, `hkdf-sha384` | TLS 1.3 FIPS suites |
| TLS signatures (`sig/*`, 8) | ECDSA P-384/SHA-384, ECDSA P-256/SHA-256, RSA-PSS SHA-512/384/256, RSA PKCS#1 SHA-512/384/256 | `policy.rs` `SIG_SCHEMES`, `SIG_KEY_ALGS` |
| OCSP/CRL signatures (`x509sig/*`, 12) | ECDSA P-256/P-384 with SHA-256/384/512; RSA PKCS#1 and RSA-PSS with SHA-256/384/512 | `revocation/sig.rs` |
| Hashes | `sha-256/aws-lc-fips`, `sha-384`, `sha-512`, `sha-256/rustcrypto-sha2` (audit chain, cluster config digest, XDP digests), `sha-1/aws-lc-fips-legacy` (opt-in OCSP CertID; RFC 6960 ResponderID byKey match; identification only) | `plat-tls`, `plat-audit`, `plat-cluster`, `plat-xdp` |
| RNG | `ctr-drbg` | AWS-LC FIPS module |
| Related material | `material/private-key`, `material/x509-certificate` (operator supplied) | `plat-tls/src/load.rs` |
| Libraries | `lib/aws-lc-fips`, `lib/aws-lc-rs`, `lib/rustls`, `lib/rustls-webpki`, `lib/rustcrypto-sha2`, `lib/aws-lc-nonfips` (linked, not installed as provider) | `Cargo.lock` |

**Accepted signature set (behaviour change, SEC-001/NIST-004).**
`fips_provider` replaces the provider's verification set with the subset that
`sig.rs` can also verify for OCSP/CRL: the 8 schemes above over P-256, P-384
and rsaEncryption keys. ML-DSA-44/65/87, Ed25519 and ECDSA P-521 certificates
(in a chain or in CertificateVerify) are refused; start fails if a listed
scheme is missing from the provider. Evidence: `policy.rs::tests::signature_schemes`
(exact 8 names, key-algorithm whitelist, `fips()`),
`sig.rs::tests::unsupported_curves_and_params_refused`,
`table_refuses_sha1_dsa_unknown_and_wrong_key`. Post-quantum authentication
is POAM-041.

**No finite-field DH and no RSA key transport**; asserted by
`no_ffdhe_and_no_rsa_key_transport`.

## Quantum classification and migration targets

Each asymmetric CBOM asset carries `usg-plat:quantum-vulnerability` and
`usg-plat:pqc-migration-target`; T1 (`quantum_classification_present`)
requires both on every key-agree, signature, KEM and PKE primitive.

| Asset | Class | Exposure | Migration target |
|-------|-------|----------|------------------|
| ECDHE P-256/P-384 | shor-broken | Harvest-now-decrypt-later when negotiated (`pq_hybrid = false`, the NDcPP evaluated configuration, or a HelloRetryRequest to a classical peer) | X25519MLKEM768 (default); ML-KEM-1024 or P-384 + ML-KEM-1024 if CNSA 2.0 applies (POAM-042) |
| X25519 (hybrid half) | shor-broken alone | None while ML-KEM-768 holds in the combiner | Keep; drop only for pure ML-KEM (POAM-042) |
| ML-KEM-768, X25519MLKEM768 | pq-resistant | — | ML-KEM-1024 if CNSA applies (POAM-042) |
| TLS signatures `sig/*`, operator keys/certs | shor-broken | Real-time impersonation only, no retroactive disclosure | ML-DSA-65/87 or composite certificates (POAM-041) |
| OCSP/CRL `x509sig/*` | shor-broken | Forged revocation data with a CRQC | ML-DSA rows in `sig.rs` (POAM-041) |
| AES-128-GCM | grover-reduced | Not broken | AES-256-only suite list if CNSA applies (POAM-042) |
| AES-256-GCM, SHA-384/512, HKDF | grover-reduced, adequate | — | None |
| SHA-256 (module and `sha2`) | grover-reduced | Adequate integrity margin | SHA-384 under CNSA (POAM-042, POAM-043) |
| SHA-1 (CertID opt-in, ResponderID byKey) | classically-weak, identification only | — | SHA-256 CertID is the default; remove the option at the next config-breaking release |
| CTR-DRBG | pq-resistant | — | None |

## Crypto-agility

Assessment only; no wire, log-schema or config change was made. Residuals are
POAM-043, with CNSA 2.0 (POAM-042) as the main trigger.

| # | Hard-coded item | Agility | Later |
|---|-----------------|---------|-------|
| A1 | Audit chain SHA-256, `CHAIN_GENESIS` "usg-plat audit chain v2" (`plat-audit/src/logger.rs`, `verify.rs`); fields `plat.audit.batch_sha256`/`chain_sha256` | Partial: the genesis version string is the algorithm identifier; a new hash needs new fields and a schema bump. That `verify-log` refuses an unknown genesis is **not yet tested** (QA item open). | Chain v3 with an explicit algorithm field, together with POAM-003 |
| A2 | Cluster `Hello.config_digest` `[u8; 32]`, `PROTO_VERSION = 1` (`plat-cluster/src/codec.rs`, `digest.rs`) | Adequate: versioned; mismatches refused | `PROTO_VERSION = 2` with SHA-384 if CNSA applies |
| A3 | `…hash.sha256` audit fields (schema 8) | Adequate: additive ECS field, needs a schema bump | Add `…hash.sha384` if CNSA applies |
| A4 | XDP object SHA-256 and `CONFIG` digest v3 (`plat-xdp/src/lib.rs`, `load.rs`) | Adequate: version bump; stale pins refused | As A2 |
| A5 | mTLS allow-list `sha256:` (`plat-tls/src/identity.rs`) | Good: typed prefix, additive | Add `sha384:` if CNSA applies |
| A6 | `tls.pq_hybrid: bool` | Poor: cannot express a CNSA or pure ML-KEM profile | `tls.kx_profile` enum with `pq_hybrid` as deprecated alias |
| A7 | `sig.rs` signature set | Improved: table-driven (`ACCEPTED`, `PSS_HASHES`); tests `table_rows_round_trip`, `every_ecdsa_row_verifies_real_signature`, `every_rsa_row_verifies_real_signature` | ML-DSA rows (POAM-041) |
| A8 | Suites and groups in `fips_provider` | Good: one location, T1 forces review | — |

## Hybrid handshake cost

Control plane only; the packet path never handshakes. Measured on macOS
aarch64 with an in-memory mTLS 1.3 handshake, rcgen P-256 PKI, no revocation
(`crates/plat-tls/tests/handshake_cost.rs::hybrid_key_share_cost`, which
asserts the size deltas and no HelloRetryRequest between same-policy
endpoints; `p384_leaf_handshakes`):

| Policy | ClientHello | Server flight | Client Finished flight | Total |
|--------|-------------|---------------|------------------------|-------|
| X25519MLKEM768 (`pq_hybrid = true`) | 1409 B | 1836 B | 530 B | 3775 B |
| secp256r1 (`pq_hybrid = false`) | 256 B | 781 B | 529 B | 1566 B |

That is about **+2.2 KB per handshake** (+1153 B ClientHello, +1055 B server
flight). With P-384 leaves the hybrid total is 3896 B. Time
(`crates/plat-tls/benches/handshake.rs`, short run, same host): P-256 leaf
383.5 µs hybrid vs 376.6 µs classical (about +2 %); P-384 leaf 748.5 µs vs
721.6 µs (about +4 %). Signatures, not ML-KEM, dominate. Not measured on Linux
or x86_64. A peer without the hybrid group costs one HelloRetryRequest round
trip. Management has no resumption, so the scrape interval sets the handshake
rate.

## Excluded

These use keyed or randomised hashing but make **no SC-13 claim**. They are
not cryptographic protection of data and are therefore not CBOM components.

| Item | Where | Purpose | Why excluded |
|------|-------|---------|--------------|
| Release signing (cosign keyless: Fulcio-issued ephemeral ECDSA P-256 key, SHA-256, Rekor transparency log) | `.github/workflows/packages.yml` `release` job, `scripts/verify-release.sh` | Signs release files in CI (SI-7, SR-11; POAM-044) | Runs in CI and on the verifier's host, not in the TOE; not a CBOM component. |
| Install-time verifier on hosts (`usg-plat-verify` calls operator-installed upstream cosign >= 3.0.3: ECDSA P-256 / SHA-256 signature over `SHA256SUMS`, Fulcio X.509 chain, Rekor Merkle inclusion proofs and SCTs, checked offline against the pinned `trusted_root.json`) | `deploy/verify/libexec/verify-pkg`, `deploy/verify/trusted-root.sh`, `deploy/verify/trusted_root.sha256` | Install-time code authentication of `platd` / `usg-plat-verify` (SI-7(15), CM-14, SR-11; POAM-044) | cosign is a host tool that the operator installs and checks against the pinned SHA-256 (`docs/install-verify.md`). It is never bundled or shipped, so it is not a CBOM component. The `usg-plat-verify` package is shell and Python only, with no crypto library, and it is outside the cargo graph and CBOM. The SHA-256 of the package file is computed by `sha256sum` (apt) or Python `hashlib` (dnf) on the host. Host SC-13 residual: cosign runs with `GODEBUG=fips140=only` (Go native FIPS 140-3 module; R03 checks the default, and R04–R08 verify under it). Whether that Go module version is CMVP validated is an organisational determination. The trust-root pin changes only through a reviewed PR (`make trusted-root-update`). |
| `ahash` (randomly keyed `RandomState`) | `crates/plat-nat64/src/shard.rs` and other hash maps | HashDoS-resistant table hashing (SC-5) | Not a cryptographic primitive; keys are per process and never leave memory. Allowed in `deploy/tests/supply-chain/crypto-allow.toml`. |
| `chacha20` 0.10.2 (ChaCha12 `StdRng` behind `rand` 0.10, forced by hickory-proto/hickory-net `std_rng`) | `crates/plat-tls/src/revocation/dns.rs` (hickory resolver for OCSP/CRL host names); also the proptest RNG in tests | DNS query IDs and UDP source ports (RFC 5452 spoofing resistance) | Security-relevant (spoofing resistance, SC-21 compensation) but not SC-13 protection, and outside the FIPS boundary. No key, nonce or secret is derived from it, and it is excluded from any FCS_RBG_EXT.1 claim. If the RNG were weak or predictable, the worst case is a DoS or a fetch redirected to an attacker; the attacker's response is then rejected by FIPS signature verification (fail-closed under `hard_fail`). Also: DNS answers only steer the fetch of OCSP responses and CRLs, which are signature-checked through the FIPS provider whatever DNS returns (IA-5(2)(b)(1)). User decision 2026-11-03. It is listed in the CBOM as `lib/chacha20` (status `non-crypto-rng-dns-ids-only`) for traceability, with no algorithm attached, and allowed as `non-crypto` in `deploy/tests/supply-chain/crypto-allow.toml` (dependents `proptest`, `rand`). The existing proptest entry was reclassified from `test-only` to `non-crypto`, because the crate now ships in `platd`. No other crate may use it. |
| RFC 7739 IPv4 Identification key | `crates/plat-nat64/src/ident.rs` `IdentKey` (boot-random, from `ahash`), `crates/plat-xdp-core/src/ident.rs` | Picks the per-flow counter and offset for the IPv4 ID (RFC 7739 §5.3, SC-7 side channel) | Unpredictability aid, not confidentiality or integrity; no SC-13 claim (see the module comment). |
