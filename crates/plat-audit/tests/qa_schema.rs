//! QA: schema v5 record formatting under hostile certificate text
//! (AU-3, SI-10): JSON stays one valid object per line and round-trips the
//! (sanitised) value; CEF extension values cannot introduce a new key,
//! a line break, or an unescaped `=`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use plat_audit::NodeIdent;
use plat_audit::event::{
    AuditText, Event, MgmtConnection, MgmtReason, RefreshKind, RefreshTransition, RevocationCheck, RevocationRefresh,
    RevocationSource, RevocationStatus, TlsRole,
};
use plat_audit::format::{cef, json};
use proptest::prelude::*;

fn node() -> NodeIdent {
    NodeIdent { name: "plat-01".into(), id: 3, pid: 42 }
}

/// Minimal strict JSON validator for one flat object with string, number,
/// bool or null values. Returns the decoded `key -> raw value` pairs.
fn parse_flat_json(s: &str) -> Result<Vec<(String, String)>, String> {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let ws = |i: &mut usize| {
        while *i < b.len() && b[*i] == ' ' {
            *i += 1;
        }
    };
    let string = |i: &mut usize| -> Result<String, String> {
        if b.get(*i) != Some(&'"') {
            return Err(format!("expected string at {i}"));
        }
        *i += 1;
        let mut out = String::new();
        loop {
            let c = *b.get(*i).ok_or("eof in string")?;
            *i += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let e = *b.get(*i).ok_or("eof in escape")?;
                    *i += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'u' => {
                            let h: String = b.get(*i..*i + 4).ok_or("short \\u")?.iter().collect();
                            *i += 4;
                            let v = u32::from_str_radix(&h, 16).map_err(|e| e.to_string())?;
                            out.push(char::from_u32(v).ok_or("surrogate")?);
                        }
                        _ => return Err(format!("bad escape {e:?}")),
                    }
                }
                c if (c as u32) < 0x20 => return Err(format!("raw control {:#x}", c as u32)),
                c => out.push(c),
            }
        }
    };
    let mut kv = Vec::new();
    if b.first() != Some(&'{') {
        return Err("no {".into());
    }
    i += 1;
    loop {
        ws(&mut i);
        let k = string(&mut i)?;
        ws(&mut i);
        if b.get(i) != Some(&':') {
            return Err(format!("no colon after {k}"));
        }
        i += 1;
        ws(&mut i);
        let v = if b.get(i) == Some(&'"') {
            string(&mut i)?
        } else {
            let st = i;
            while i < b.len() && !matches!(b[i], ',' | '}') {
                i += 1;
            }
            let v: String = b[st..i].iter().collect();
            if !(v == "true" || v == "false" || v == "null" || v.parse::<f64>().is_ok()) {
                return Err(format!("bad literal {v:?}"));
            }
            v
        };
        kv.push((k, v));
        ws(&mut i);
        match b.get(i) {
            Some(',') => i += 1,
            Some('}') => {
                i += 1;
                break;
            }
            _ => return Err(format!("unexpected at {i}")),
        }
    }
    while i < b.len() && (b[i] == '\n' || b[i] == '\r') {
        i += 1;
    }
    if i != b.len() {
        return Err("trailing data".into());
    }
    Ok(kv)
}

/// CEF extension parse: `key=value` pairs where an unescaped `=` ends the
/// previous value at the preceding space-delimited token.
fn cef_ext_keys(line: &str) -> Vec<String> {
    let ext = line.splitn(8, '|').nth(7).unwrap();
    let mut keys = Vec::new();
    let chars: Vec<char> = ext.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '=' {
            let mut bs = 0;
            let mut j = i;
            while j > 0 && chars[j - 1] == '\\' {
                bs += 1;
                j -= 1;
            }
            if bs % 2 == 0 {
                let mut k = i;
                while k > 0 && chars[k - 1] != ' ' {
                    k -= 1;
                }
                keys.push(chars[k..i].iter().collect());
            }
        }
        i += 1;
    }
    keys
}

fn mgmt(subject: &str) -> Event {
    Event::ManagementConnection {
        ts_us: 1,
        conn: Arc::new(MgmtConnection {
            ip: "2001:db8::7".parse().unwrap(),
            port: 4242,
            subject: Some(AuditText::new(subject, AuditText::SUBJECT_MAX)),
            cert_sha256: Some([7; 32]),
            reason: MgmtReason::NotAllowlisted,
            path: None,
            allow_entry: None,
            sans: Vec::new(),
        }),
    }
}

fn revcheck(serial: &str, dn: &str, src: &str) -> Event {
    Event::RevocationCheck {
        ts_us: 1,
        check: Arc::new(RevocationCheck {
            role: TlsRole::MgmtClient,
            cert_sha256: [1; 32],
            serial_hex: AuditText::new(serial, AuditText::SHORT_MAX),
            issuer_dn: AuditText::new(dn, AuditText::DN_MAX),
            chain_index: 0,
            status: RevocationStatus::Unavailable,
            source: RevocationSource::None,
            ocsp_reason: Some("timeout"),
            crl_reason: Some("connect"),
            revocation_reason: None,
            revocation_date_us: None,
            ocsp_responder: Some(AuditText::new(src, AuditText::SHORT_MAX)),
            crl_source: Some(AuditText::new(src, AuditText::SHORT_MAX)),
            policy: "soft_fail",
            allowed: true,
        }),
    }
}

fn refresh(src: &str) -> Event {
    Event::RevocationRefresh {
        ts_us: 1,
        refresh: Arc::new(RevocationRefresh {
            kind: RefreshKind::Crl,
            source: AuditText::new(src, AuditText::SHORT_MAX),
            transition: RefreshTransition::Failing,
            reason: Some("timeout"),
        }),
    }
}

fn render(ev: &Event) -> (String, String) {
    let (mut j, mut c) = (Vec::new(), Vec::new());
    json(&mut j, 9, &node(), ev);
    cef(&mut c, 9, &node(), ev);
    (String::from_utf8(j).unwrap(), String::from_utf8(c).unwrap())
}

fn expected_keys(ev: &Event) -> (Vec<String>, Vec<String>) {
    let (j, c) = render(ev);
    let jk = parse_flat_json(j.trim_end()).unwrap().into_iter().map(|(k, _)| k).collect();
    (jk, cef_ext_keys(c.trim_end()))
}

fn check_record(ev: &Event, clean: &Event, field: &str, want: &str) -> Result<(), TestCaseError> {
    let (j, c) = render(ev);
    let body = j.trim_end_matches(['\n', '\r']);
    prop_assert!(!body.contains(['\n', '\r']), "raw line break in JSON: {j:?}");
    let kv = parse_flat_json(body).map_err(|e| TestCaseError::fail(format!("{e}: {j}")))?;
    let (clean_jk, clean_ck) = expected_keys(clean);
    let jk: Vec<String> = kv.iter().map(|(k, _)| k.clone()).collect();
    prop_assert_eq!(&jk, &clean_jk, "JSON key set changed by hostile text");
    let got = kv.iter().find(|(k, _)| k == field).map(|(_, v)| v.clone());
    prop_assert_eq!(got.as_deref(), Some(want));
    let cl = c.trim_end_matches(['\n', '\r']);
    prop_assert!(!cl.contains(['\n', '\r']), "raw line break in CEF");
    prop_assert_eq!(cl.matches('|').count() >= 7, true);
    prop_assert_eq!(cef_ext_keys(cl), clean_ck, "CEF key set changed by hostile text: {}", cl);
    Ok(())
}

fn hostile() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        prop::collection::vec(
            prop::sample::select(vec![
                "\"",
                "\\",
                "=",
                " ",
                "|",
                "\n",
                "\r",
                "\t",
                "\u{0}",
                "\u{7f}",
                "\u{85}",
                "\u{2028}",
                "\u{202e}",
                "\u{200b}",
                "cs1=",
                " suser=",
                "\",\"x\":\"",
                "}",
                "{",
                "é",
                "😀",
                "CN=",
                "a",
            ]),
            0..80
        )
        .prop_map(|v| v.concat()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

    #[test]
    fn mgmt_subject_injection(s in hostile()) {
        let at = AuditText::new(&s, AuditText::SUBJECT_MAX);
        prop_assert!(at.as_str().len() <= AuditText::SUBJECT_MAX);
        prop_assert!(!at.as_str().chars().any(char::is_control));
        check_record(&mgmt(&s), &mgmt("x"), "tls.client.subject", at.as_str())?;
    }

    #[test]
    fn revocation_check_injection(serial in hostile(), dn in hostile(), src in hostile()) {
        let want = AuditText::new(&dn, AuditText::DN_MAX);
        prop_assert!(want.as_str().len() <= AuditText::DN_MAX);
        check_record(&revcheck(&serial, &dn, &src), &revcheck("1", "x", "h:80"), "x509.issuer.distinguished_name", want.as_str())?;
    }

    #[test]
    fn refresh_source_injection(src in hostile()) {
        let want = AuditText::new(&src, AuditText::SHORT_MAX);
        check_record(&refresh(&src), &refresh("h:80"), "plat.crl.source", want.as_str())?;
    }
}

#[test]
fn cap_never_splits_utf8_and_trailing_backslash_is_escaped() {
    let s = "é".repeat(200);
    let t = AuditText::new(&s, AuditText::SUBJECT_MAX);
    assert_eq!(t.as_str().len(), 128);
    let (_, c) = render(&mgmt("abc\\"));
    assert!(c.contains(" suser=abc\\\\ cs1="), "{c}");
    // Bidi override and zero-width are neutralised (Trojan Source in SIEM UIs).
    let (j, _) = render(&mgmt("a\u{202e}b\u{200b}c"));
    assert!(j.contains("\"tls.client.subject\":\"a?b?c\""), "{j}");
}

#[test]
fn schema_version_is_7() {
    assert_eq!(plat_audit::LOG_SCHEMA_VERSION, 7);
}
