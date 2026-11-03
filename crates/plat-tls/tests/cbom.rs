//! CBOM drift test (T1): the TLS policy facts computed from the real
//! `fips_provider`, the OCSP/CRL signature table and the AWS-LC version must
//! equal `docs/compliance/cbom.cdx.json`.
//!
//! `PLAT_CBOM_BLESS=1` rewrites only the policy-derived fields (kx group and
//! signature-scheme lists, cipher-suite names and identifiers). It refuses to
//! run when `CI=true`. Components for a new algorithm are never generated:
//! they need a human classification, so the test names what is missing.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-8 (System Component Inventory), SA-11 (Developer
//!   Testing), SC-13 (Cryptographic Protection) - inventory checked against
//!   the code on every `make test`
//! - NIST 800-53: SR-3 (Supply Chain Controls)

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

const GROUPS_PQ: &str = "usg-plat:kx-groups:pq_hybrid=true";
const GROUPS_CLASSICAL: &str = "usg-plat:kx-groups:pq_hybrid=false";
const SIG_SCHEMES: &str = "usg-plat:tls13:sig-schemes";
const TLS13: &str = "crypto/protocol/tls13";
const SIG_PREFIX: &str = "crypto/algorithm/sig/";
const X509_PREFIX: &str = "crypto/algorithm/x509sig/";
const QV: &str = "usg-plat:quantum-vulnerability";
const TARGET: &str = "usg-plat:pqc-migration-target";

fn cbom_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/compliance/cbom.cdx.json")
}

fn load() -> Value {
    let text =
        std::fs::read_to_string(cbom_path()).unwrap_or_else(|e| panic!("read docs/compliance/cbom.cdx.json: {e:?}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cbom.cdx.json is JSON: {e:?}"))
}

/// Facts derived from the code.
struct Facts {
    groups_pq: Vec<String>,
    groups_classical: Vec<String>,
    /// (Debug name, IANA identifier bytes as "0xNN").
    suites: Vec<(String, [String; 2])>,
    sig_schemes: Vec<String>,
    x509sig: Vec<String>,
    awslc_version: String,
}

fn facts() -> Facts {
    let p = plat_tls::policy::fips_provider(true).unwrap_or_else(|e| panic!("FIPS provider: {e:?}"));
    let suites = p
        .cipher_suites
        .iter()
        .map(|s| {
            let id = u16::from(s.suite()).to_be_bytes();
            (format!("{:?}", s.suite()), [format!("0x{:02X}", id[0]), format!("0x{:02X}", id[1])])
        })
        .collect();
    Facts {
        groups_pq: plat_tls::policy::kx_group_names(true).unwrap_or_else(|e| panic!("groups: {e:?}")),
        groups_classical: plat_tls::policy::kx_group_names(false).unwrap_or_else(|e| panic!("groups: {e:?}")),
        suites,
        sig_schemes: plat_tls::signature_scheme_names().unwrap_or_else(|e| panic!("schemes: {e:?}")),
        x509sig: plat_tls::revocation::sig::accepted_signature_algorithms().map(str::to_owned).collect(),
        awslc_version: aws_lc_rs::awslc_version().to_string(),
    }
}

fn components(bom: &Value) -> &[Value] {
    bom["components"].as_array().map_or(&[], Vec::as_slice)
}

fn component<'a>(bom: &'a Value, bom_ref: &str) -> Option<&'a Value> {
    components(bom).iter().find(|c| c["bom-ref"] == bom_ref)
}

fn prop<'a>(c: &'a Value, name: &str) -> Option<&'a str> {
    c["properties"].as_array()?.iter().find(|p| p["name"] == name)?["value"].as_str()
}

fn refs_with_prefix(bom: &Value, prefix: &str) -> BTreeSet<String> {
    components(bom)
        .iter()
        .filter_map(|c| c["bom-ref"].as_str())
        .filter_map(|r| r.strip_prefix(prefix))
        .map(str::to_owned)
        .collect()
}

/// Every difference between the code facts and the CBOM (empty = in sync).
fn compare(bom: &Value, f: &Facts) -> Vec<String> {
    let mut errs = Vec::new();
    let Some(tls) = component(bom, TLS13) else {
        return vec![format!("missing component {TLS13}")];
    };
    for (name, want) in
        [(GROUPS_PQ, &f.groups_pq), (GROUPS_CLASSICAL, &f.groups_classical), (SIG_SCHEMES, &f.sig_schemes)]
    {
        let want = want.join(",");
        if prop(tls, name) != Some(want.as_str()) {
            errs.push(format!("{TLS13} {name}: CBOM {:?}, code {want:?}", prop(tls, name)));
        }
    }
    let cbom_suites: Vec<(String, Vec<String>)> = tls["cryptoProperties"]["protocolProperties"]["cipherSuites"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .map(|s| {
            let ids = s["identifiers"].as_array().map_or(&[][..], Vec::as_slice);
            (
                s["name"].as_str().unwrap_or_default().to_owned(),
                ids.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
            )
        })
        .collect();
    let code_suites: Vec<(String, Vec<String>)> = f.suites.iter().map(|(n, id)| (n.clone(), id.to_vec())).collect();
    if cbom_suites != code_suites {
        errs.push(format!("{TLS13} cipherSuites: CBOM {cbom_suites:?}, code {code_suites:?}"));
    }
    // One component per provider signature scheme and per sig.rs row, no extras.
    for (prefix, want) in [(SIG_PREFIX, &f.sig_schemes), (X509_PREFIX, &f.x509sig)] {
        let want: BTreeSet<String> = want.iter().cloned().collect();
        let have = refs_with_prefix(bom, prefix);
        for m in want.difference(&have) {
            errs.push(format!("missing component {prefix}{m} (classify it by hand)"));
        }
        for x in have.difference(&want) {
            errs.push(format!("component {prefix}{x} is no longer produced by the code"));
        }
    }
    // The protocol references every TLS signature scheme.
    let crypto_refs: BTreeSet<&str> = tls["cryptoProperties"]["protocolProperties"]["cryptoRefArray"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for s in &f.sig_schemes {
        if !crypto_refs.contains(format!("{SIG_PREFIX}{s}").as_str()) {
            errs.push(format!("{TLS13} cryptoRefArray lacks {SIG_PREFIX}{s}"));
        }
    }
    match component(bom, "lib/aws-lc-fips").and_then(|c| prop(c, "usg-plat:module-version")) {
        Some(v) if f.awslc_version.contains(v) => {}
        other => errs.push(format!("lib/aws-lc-fips module-version {other:?} not in AWS-LC {}", f.awslc_version)),
    }
    errs
}

/// Rewrites the policy-derived fields in place (bless mode).
fn bless(bom: &mut Value, f: &Facts) {
    let Some(tls) = bom["components"].as_array_mut().and_then(|cs| cs.iter_mut().find(|c| c["bom-ref"] == TLS13))
    else {
        return;
    };
    if let Some(props) = tls["properties"].as_array_mut() {
        for p in props.iter_mut() {
            let v = match p["name"].as_str() {
                Some(GROUPS_PQ) => f.groups_pq.join(","),
                Some(GROUPS_CLASSICAL) => f.groups_classical.join(","),
                Some(SIG_SCHEMES) => f.sig_schemes.join(","),
                _ => continue,
            };
            p["value"] = Value::String(v);
        }
    }
    let pp = &mut tls["cryptoProperties"]["protocolProperties"];
    let old = pp["cipherSuites"].as_array().cloned().unwrap_or_default();
    pp["cipherSuites"] = Value::Array(
        f.suites
            .iter()
            .map(|(name, id)| {
                let mut s = old
                    .iter()
                    .find(|o| o["name"] == name.as_str())
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({ "name": name, "algorithms": [] }));
                s["identifiers"] = serde_json::json!(id);
                s
            })
            .collect(),
    );
    let mut refs: Vec<Value> = pp["cryptoRefArray"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| !r.as_str().is_some_and(|s| s.starts_with(SIG_PREFIX)))
        .collect();
    refs.extend(f.sig_schemes.iter().map(|s| Value::String(format!("{SIG_PREFIX}{s}"))));
    pp["cryptoRefArray"] = Value::Array(refs);
}

#[test]
fn cbom_matches_code() {
    let f = facts();
    let mut bom = load();
    if std::env::var_os("PLAT_CBOM_BLESS").is_some() {
        assert_ne!(std::env::var("CI").as_deref(), Ok("true"), "PLAT_CBOM_BLESS is refused when CI=true");
        bless(&mut bom, &f);
        let text = serde_json::to_string_pretty(&bom).unwrap_or_else(|e| panic!("serialise: {e:?}")) + "\n";
        std::fs::write(cbom_path(), text).unwrap_or_else(|e| panic!("write cbom.cdx.json: {e:?}"));
    }
    let errs = compare(&bom, &f);
    assert!(errs.is_empty(), "CBOM drift (re-bless with PLAT_CBOM_BLESS=1 after review):\n{}", errs.join("\n"));
}

#[test]
fn comparator_detects_a_removed_group() {
    let f = facts();
    let bom = load();
    assert!(compare(&bom, &f).is_empty());
    let mut fewer = Facts { groups_pq: f.groups_pq.clone(), ..facts() };
    fewer.groups_pq.retain(|g| g != "secp384r1");
    assert!(!compare(&bom, &fewer).is_empty(), "removing a group must be detected");
    let mut extra = facts();
    extra.x509sig.push("ml-dsa-65".into());
    assert!(compare(&bom, &extra).iter().any(|e| e.contains("x509sig/ml-dsa-65")));
}

#[test]
fn no_fips_certification_claimed() {
    // AWS-LC-FIPS 4.x has no CMVP certificate yet (POAM-026).
    for c in components(&load()) {
        let levels = &c["cryptoProperties"]["algorithmProperties"]["certificationLevel"];
        if let Some(levels) = levels.as_array() {
            assert!(
                levels.iter().all(|l| !l.as_str().unwrap_or_default().starts_with("fips140")),
                "{} claims {levels:?}",
                c["bom-ref"]
            );
        }
    }
}

#[test]
fn every_reference_resolves() {
    let bom = load();
    let refs: BTreeSet<&str> = components(&bom).iter().filter_map(|c| c["bom-ref"].as_str()).collect();
    let tls = component(&bom, TLS13).expect("tls13");
    let pp = &tls["cryptoProperties"]["protocolProperties"];
    let mut used: Vec<&str> = pp["cryptoRefArray"].as_array().expect("refs").iter().filter_map(Value::as_str).collect();
    for s in pp["cipherSuites"].as_array().expect("suites") {
        used.extend(s["algorithms"].as_array().expect("algorithms").iter().filter_map(Value::as_str));
    }
    for r in used {
        assert!(refs.contains(r), "{r} is referenced but not defined");
    }
}

#[test]
fn quantum_classification_present() {
    for c in components(&load()) {
        let Some(ap) = c["cryptoProperties"]["algorithmProperties"].as_object() else { continue };
        let primitive = ap.get("primitive").and_then(Value::as_str).unwrap_or_default();
        let r = c["bom-ref"].as_str().unwrap_or_default();
        let class = prop(c, QV);
        assert!(class.is_some(), "{r} has no {QV}");
        if ["key-agree", "signature", "pke", "kem"].contains(&primitive) {
            let target = prop(c, TARGET).unwrap_or_else(|| panic!("{r} has no {TARGET}"));
            if class == Some("shor-broken") {
                assert!(target.contains("POAM-"), "{r}: shor-broken without a POAM in {target:?}");
            }
        }
    }
}

#[test]
fn no_ffdhe_and_no_rsa_key_transport() {
    let f = facts();
    for g in f.groups_pq.iter().chain(&f.groups_classical) {
        assert!(!g.to_ascii_uppercase().starts_with("FFDHE"), "{g}");
    }
    let bom = load();
    let tls = component(&bom, TLS13).expect("tls13");
    for r in tls["cryptoProperties"]["protocolProperties"]["cryptoRefArray"].as_array().expect("refs") {
        let r = r.as_str().unwrap_or_default();
        let Some(c) = component(&bom, r) else { continue };
        let primitive = c["cryptoProperties"]["algorithmProperties"]["primitive"].as_str().unwrap_or_default();
        assert!(!["pke", "key-wrap"].contains(&primitive), "{r} is key transport");
        assert!(!r.contains("ffdhe") && !r.contains("/dh-"), "{r} is finite-field DH");
    }
    assert_eq!(
        prop(tls, "usg-plat:key-establishment"),
        Some("ecdhe-or-hybrid-kem-only; no ffdhe; no rsa key transport")
    );
}

// --- QA (run 20261103-081215-sbom-cbom): agreement in both directions ---

fn tls_mut(bom: &mut Value) -> &mut Value {
    bom["components"]
        .as_array_mut()
        .and_then(|cs| cs.iter_mut().find(|c| c["bom-ref"] == TLS13))
        .unwrap_or_else(|| panic!("{TLS13} present"))
}

/// CBOM side: removing or adding a component, editing a suite id, dropping
/// a cryptoRef, or changing the AWS-LC version is each detected.
#[test]
fn cbom_side_mutations_detected() {
    let f = facts();
    let base = load();
    assert!(compare(&base, &f).is_empty());
    type Mutation = (&'static str, fn(&mut Value), &'static str);
    let cases: [Mutation; 7] = [
        (
            "drop sig component",
            |b| {
                let cs = b["components"].as_array_mut().unwrap();
                let i =
                    cs.iter().position(|c| c["bom-ref"].as_str().is_some_and(|r| r.starts_with(SIG_PREFIX))).unwrap();
                cs.remove(i);
            },
            "missing component crypto/algorithm/sig/",
        ),
        (
            "extra x509sig component",
            |b| {
                b["components"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"bom-ref": "crypto/algorithm/x509sig/rsa-pkcs1-sha1"}));
            },
            "x509sig/rsa-pkcs1-sha1 is no longer produced",
        ),
        (
            "extra sig component",
            |b| {
                b["components"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"bom-ref": "crypto/algorithm/sig/RSA_PKCS1_SHA1"}));
            },
            "sig/RSA_PKCS1_SHA1 is no longer produced",
        ),
        (
            "suite id edited",
            |b| {
                tls_mut(b)["cryptoProperties"]["protocolProperties"]["cipherSuites"][0]["identifiers"][1] =
                    Value::String("0xFF".into());
            },
            "cipherSuites",
        ),
        (
            "cryptoRef dropped",
            |b| {
                let refs =
                    tls_mut(b)["cryptoProperties"]["protocolProperties"]["cryptoRefArray"].as_array_mut().unwrap();
                let i = refs.iter().position(|r| r.as_str().is_some_and(|s| s.starts_with(SIG_PREFIX))).unwrap();
                refs.remove(i);
            },
            "cryptoRefArray lacks",
        ),
        (
            "groups reordered",
            |b| {
                let p = tls_mut(b)["properties"].as_array_mut().unwrap();
                let g = p.iter_mut().find(|p| p["name"] == GROUPS_CLASSICAL).unwrap();
                let mut v: Vec<&str> = g["value"].as_str().unwrap().split(',').collect();
                v.reverse();
                g["value"] = Value::String(v.join(","));
            },
            GROUPS_CLASSICAL,
        ),
        (
            "aws-lc version",
            |b| {
                let c = b["components"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|c| c["bom-ref"] == "lib/aws-lc-fips")
                    .unwrap();
                let p = c["properties"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|p| p["name"] == "usg-plat:module-version")
                    .unwrap();
                p["value"] = Value::String("99.99.99".into());
            },
            "lib/aws-lc-fips module-version",
        ),
    ];
    for (what, mutate, needle) in cases {
        let mut b = base.clone();
        mutate(&mut b);
        let errs = compare(&b, &f);
        assert!(errs.iter().any(|e| e.contains(needle)), "{what}: {errs:?}");
    }
}

/// Code side: a new TLS signature scheme, group or suite with no CBOM entry
/// is detected (classification is never generated).
#[test]
fn code_side_additions_detected() {
    let base = load();
    let mut f = facts();
    f.sig_schemes.push("ML_DSA_1024".into());
    let errs = compare(&base, &f);
    assert!(errs.iter().any(|e| e.contains("missing component crypto/algorithm/sig/ML_DSA_1024")), "{errs:?}");
    assert!(errs.iter().any(|e| e.contains(SIG_SCHEMES)), "{errs:?}");
    let mut f = facts();
    f.groups_classical.push("FFDHE2048".into());
    assert!(!compare(&base, &f).is_empty());
    let mut f = facts();
    f.suites.push(("TLS13_CHACHA20_POLY1305_SHA256".into(), ["0x13".into(), "0x03".into()]));
    assert!(compare(&base, &f).iter().any(|e| e.contains("cipherSuites")));
    let mut f = facts();
    f.x509sig.pop();
    assert!(compare(&base, &f).iter().any(|e| e.contains("no longer produced")));
}

/// Bless repairs only policy-derived fields and is idempotent on an in-sync CBOM.
#[test]
fn bless_is_idempotent_and_does_not_invent_components() {
    let f = facts();
    let base = load();
    let mut b = base.clone();
    bless(&mut b, &f);
    assert_eq!(b, base, "bless on an in-sync CBOM must be a no-op");
    let mut f2 = facts();
    f2.sig_schemes.push("ML_DSA_1024".into());
    bless(&mut b, &f2);
    assert!(compare(&b, &f2).iter().any(|e| e.contains("missing component crypto/algorithm/sig/ML_DSA_1024")));
}
