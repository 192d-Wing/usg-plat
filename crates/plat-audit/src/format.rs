//! Record formatting: JSON lines (ECS-style dotted keys), ArcSight CEF, and
//! the RFC 5424 syslog header.
//!
//! Data-plane records hold no attacker-controlled text: values are IP
//! addresses, numbers, and static strings; the node name is restricted to
//! `[A-Za-z0-9-_.]` at config load, so the hot formatting path needs no
//! escaping. The TLS/management records (schema 5) carry certificate text
//! as [`AuditText`] (control and bidi characters already replaced, length
//! capped) and escape it here: JSON `"`/`\`, CEF `\`/`=` (CWE-117).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-3 (Content of Audit Records), SI-10 (log injection)

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::LOG_SCHEMA_VERSION;
use crate::event::{AuditText, Event, RefreshKind, StorageState, TlsRole};
use crate::logger::NodeIdent;

/// Writes `ts_us` as RFC 3339 UTC with microseconds: `2026-10-28T14:16:00.123456Z`.
pub fn rfc3339(out: &mut Vec<u8>, ts_us: u64) {
    let secs = ts_us / 1_000_000;
    let micros = ts_us % 1_000_000;
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let _ = write!(out, "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}Z", sod / 3600, (sod / 60) % 60, sod % 60);
}

fn proto_name(p: u8) -> &'static str {
    match p {
        6 => "tcp",
        17 => "udp",
        1 | 58 => "icmp",
        _ => "other",
    }
}

/// Subscriber prefix as an address (host bits already zero).
fn sub_addr(sub: u128) -> Ipv6Addr {
    Ipv6Addr::from(sub)
}

/// Appends `s` as a JSON string body (no quotes). Control characters are
/// escaped as well, although [`AuditText`] has already replaced them.
fn json_str(out: &mut Vec<u8>, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
}

/// Appends `,"key":"<escaped text>"`.
fn json_text(out: &mut Vec<u8>, key: &str, t: &AuditText) {
    let _ = write!(out, ",\"{key}\":\"");
    json_str(out, t.as_str());
    out.push(b'"');
}

/// Appends a CEF extension value: `\` and `=` escaped, line breaks as
/// `\n`/`\r` (CEF rev 25).
fn cef_str(out: &mut Vec<u8>, s: &str) {
    for c in s.chars() {
        match c {
            '\\' => out.extend_from_slice(b"\\\\"),
            '=' => out.extend_from_slice(b"\\="),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if c.is_control() => out.push(b'?'),
            c => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
}

/// Appends 32 bytes as lowercase hex.
fn hex32(out: &mut Vec<u8>, h: &[u8; 32]) {
    for b in h {
        let _ = write!(out, "{b:02x}");
    }
}

/// Appends one JSON object (no trailing newline).
pub fn json(out: &mut Vec<u8>, seq: u64, node: &NodeIdent, ev: &Event) {
    out.extend_from_slice(b"{\"@timestamp\":\"");
    rfc3339(out, ev.ts_us());
    let _ = write!(
        out,
        "\",\"plat.schema\":{LOG_SCHEMA_VERSION},\"event.sequence\":{seq},\"event.kind\":\"event\",\
         \"event.category\":\"network\",\"event.action\":\"{}\",\"observer.type\":\"nat64\",\
         \"observer.name\":\"{}\",\"plat.node_id\":{}",
        ev.action(),
        node.name,
        node.id
    );
    match *ev {
        Event::PortBlockAlloc { sub, sub_len, v4, port_lo, port_hi, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"success\",\"source.ip\":\"{}\",\"plat.subscriber.prefix\":\"{}/{sub_len}\",\
                 \"source.nat.ip\":\"{}\",\"plat.nat.port_start\":{port_lo},\"plat.nat.port_end\":{port_hi}",
                sub_addr(sub),
                sub_addr(sub),
                Ipv4Addr::from(v4)
            );
        }
        Event::PortBlockRelease { sub, sub_len, v4, port_lo, port_hi, held_secs, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"success\",\"source.ip\":\"{}\",\"plat.subscriber.prefix\":\"{}/{sub_len}\",\
                 \"source.nat.ip\":\"{}\",\"plat.nat.port_start\":{port_lo},\"plat.nat.port_end\":{port_hi},\
                 \"event.duration\":{}",
                sub_addr(sub),
                sub_addr(sub),
                Ipv4Addr::from(v4),
                u64::from(held_secs) * 1_000_000_000
            );
        }
        Event::BibCreate { proto, v6, v6_port, v4, v4_port, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"success\",\"network.transport\":\"{}\",\"source.ip\":\"{}\",\
                 \"source.port\":{v6_port},\"source.nat.ip\":\"{}\",\"source.nat.port\":{v4_port}",
                proto_name(proto),
                Ipv6Addr::from(v6),
                Ipv4Addr::from(v4)
            );
        }
        Event::BibDelete { proto, v6, v6_port, v4, v4_port, held_secs, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"success\",\"network.transport\":\"{}\",\"source.ip\":\"{}\",\
                 \"source.port\":{v6_port},\"source.nat.ip\":\"{}\",\"source.nat.port\":{v4_port},\
                 \"event.duration\":{}",
                proto_name(proto),
                Ipv6Addr::from(v6),
                Ipv4Addr::from(v4),
                u64::from(held_secs) * 1_000_000_000
            );
        }
        Event::Limit { kind, sub, sub_len, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"failure\",\"event.reason\":\"{}\",\"source.ip\":\"{}\",\
                 \"plat.subscriber.prefix\":\"{}/{sub_len}\"",
                kind.as_str(),
                sub_addr(sub),
                sub_addr(sub)
            );
        }
        Event::Lifecycle { fips, .. } => {
            let _ = write!(out, ",\"event.outcome\":\"success\",\"service.version\":\"{}\"", env!("CARGO_PKG_VERSION"));
            if let Some(f) = fips {
                let _ = write!(out, ",\"plat.fips\":{},\"plat.fips_provider\":\"{}\"", f.active, f.provider);
            }
        }
        Event::Counter { name, value, .. } => {
            let _ = write!(out, ",\"plat.counter.name\":\"{name}\",\"plat.counter.value\":{value}");
        }
        Event::QueueOverflow { lost, .. } => {
            let _ = write!(out, ",\"event.outcome\":\"failure\",\"plat.audit.lost\":{lost}");
        }
        Event::OutputFailure { lost, recovered, reason, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"failure\",\"plat.audit.destination\":\"file\",\"plat.audit.state\":\"{}\",\
                 \"plat.audit.lost\":{lost}",
                if recovered { "recovered" } else { "degraded" }
            );
            if let Some(r) = reason {
                let _ = write!(out, ",\"plat.reason\":\"{}\"", r.as_str());
            }
        }
        Event::RemoteLoss { ip, port, lost, reason, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"failure\",\"plat.audit.destination\":\"syslog\",\"destination.ip\":\"{ip}\",\
                 \"destination.port\":{port},\"plat.audit.lost\":{lost}"
            );
            if let Some(r) = reason {
                let _ = write!(out, ",\"plat.reason\":\"{}\"", r.as_str());
            }
        }
        Event::StorageThreshold { available, threshold, state, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"{}\",\"plat.audit.destination\":\"file\",\"plat.audit.state\":\"{}\"",
                ev.outcome().unwrap_or("unknown"),
                state.as_str()
            );
            if state != StorageState::Unknown {
                let _ = write!(out, ",\"plat.audit.available_bytes\":{available}");
            }
            let _ = write!(out, ",\"plat.audit.min_free_bytes\":{threshold}");
        }
        Event::RetentionPrune { rotated_us, seq_first, seq_last, chain_prefix, state, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"{}\",\"plat.audit.state\":\"{}\",\"plat.audit.pruned_rotated_us\":{rotated_us},\
                 \"plat.audit.pruned_seq_first\":{seq_first},\"plat.audit.pruned_seq_last\":{seq_last},\
                 \"plat.audit.pruned_chain_prefix\":\"{chain_prefix:016x}\"",
                ev.outcome().unwrap_or("unknown"),
                state.as_str()
            );
        }
        Event::AuditRecovery { reason, last_checkpoint_seq, max_seq, lease_state, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"failure\",\"plat.audit.destination\":\"file\",\"plat.reason\":\"{}\",\
                 \"plat.audit.last_checkpoint_seq\":{last_checkpoint_seq},\"plat.audit.max_seq\":{max_seq},\
                 \"plat.audit.lease_state\":\"{}\"",
                reason.as_str(),
                lease_state.as_str()
            );
        }
        Event::ManagementConnection { ref conn, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"{}\",\"source.ip\":\"{}\",\"source.port\":{},\"plat.mgmt.reason\":\"{}\"",
                ev.outcome().unwrap_or("unknown"),
                conn.ip,
                conn.port,
                conn.reason.as_str()
            );
            if let Some(s) = &conn.subject {
                json_text(out, "tls.client.subject", s);
            }
            if let Some(h) = &conn.cert_sha256 {
                out.extend_from_slice(b",\"tls.client.hash.sha256\":\"");
                hex32(out, h);
                out.push(b'"');
            }
            if let Some(p) = conn.path {
                let _ = write!(out, ",\"url.path\":\"{}\"", p.as_str());
            }
            if let Some(a) = &conn.allow_entry {
                json_text(out, "plat.mgmt.allow_entry", a);
            }
            if !conn.sans.is_empty() {
                out.extend_from_slice(b",\"tls.client.x509.alternative_names\":[");
                for (i, n) in conn.sans.iter().take(crate::event::MgmtConnection::SANS_MAX).enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.push(b'"');
                    json_str(out, n.as_str());
                    out.push(b'"');
                }
                out.push(b']');
            }
        }
        Event::ManagementSuppressed { suppressed, window_secs, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"failure\",\"plat.mgmt.suppressed\":{suppressed},\"plat.mgmt.window_secs\":{window_secs}"
            );
        }
        Event::RevocationCheck { ref check, .. } => {
            let c = &**check;
            let side = match c.role {
                TlsRole::MgmtClient => "client",
                TlsRole::SyslogServer => "server",
            };
            let _ = write!(
                out,
                ",\"event.outcome\":\"{}\",\"plat.tls.role\":\"{}\",\"tls.{side}.hash.sha256\":\"",
                ev.outcome().unwrap_or("unknown"),
                c.role.as_str()
            );
            hex32(out, &c.cert_sha256);
            out.push(b'"');
            json_text(out, "x509.serial_number", &c.serial_hex);
            json_text(out, "x509.issuer.distinguished_name", &c.issuer_dn);
            let _ = write!(
                out,
                ",\"plat.revocation.chain_index\":{},\"plat.revocation.status\":\"{}\",\
                 \"plat.revocation.source\":\"{}\",\"plat.revocation.policy\":\"{}\"",
                c.chain_index,
                c.status.as_str(),
                c.source.as_str(),
                c.policy
            );
            if let Some(r) = c.ocsp_reason {
                let _ = write!(out, ",\"plat.ocsp.reason\":\"{r}\"");
            }
            if let Some(r) = c.crl_reason {
                let _ = write!(out, ",\"plat.crl.reason\":\"{r}\"");
            }
            if let Some(r) = c.revocation_reason {
                let _ = write!(out, ",\"plat.revocation.reason\":\"{r}\"");
            }
            if let Some(d) = c.revocation_date_us {
                out.extend_from_slice(b",\"plat.revocation.date\":\"");
                rfc3339(out, d);
                out.push(b'"');
            }
            if let Some(r) = &c.ocsp_responder {
                json_text(out, "plat.ocsp.responder", r);
            }
            if let Some(r) = &c.crl_source {
                json_text(out, "plat.crl.source", r);
            }
        }
        Event::RevocationRefresh { ref refresh, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"{}\",\"plat.revocation.transition\":\"{}\"",
                ev.outcome().unwrap_or("unknown"),
                refresh.transition.as_str()
            );
            let key = match refresh.kind {
                RefreshKind::Crl => "plat.crl.source",
                RefreshKind::Ocsp => "plat.ocsp.key",
            };
            json_text(out, key, &refresh.source);
            if let Some(r) = refresh.reason {
                let _ = write!(out, ",\"event.reason\":\"{r}\"");
            }
        }
    }
    out.push(b'}');
}

/// CEF address key: `src` for IPv4, `c6a2` for IPv6 (as data-plane records).
fn cef_addr(out: &mut Vec<u8>, ip: std::net::IpAddr) {
    let _ = match ip {
        std::net::IpAddr::V4(a) => write!(out, " src={a}"),
        std::net::IpAddr::V6(a) => write!(out, " c6a2={a}"),
    };
}

/// Appends `v` in decimal.
fn put_u64(out: &mut Vec<u8>, mut v: u64) {
    let mut b = [0u8; 20];
    let mut i = b.len();
    loop {
        i -= 1;
        b[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.extend_from_slice(&b[i..]);
}

/// Appends one CEF:0 record (no trailing newline).
pub fn cef(out: &mut Vec<u8>, seq: u64, node: &NodeIdent, ev: &Event) {
    let sev: u64 = match ev.severity() {
        ..=3 => 9,
        4 => 7,
        5 => 4,
        _ => 3,
    };
    // Header and common extension fields without `fmt` machinery: this runs
    // once per record per CEF destination.
    out.extend_from_slice(concat!("CEF:0|USG|usg-plat|", env!("CARGO_PKG_VERSION"), "|").as_bytes());
    out.extend_from_slice(ev.action().as_bytes());
    out.push(b'|');
    out.extend_from_slice(ev.action().as_bytes());
    out.push(b'|');
    put_u64(out, sev);
    out.extend_from_slice(b"|rt=");
    put_u64(out, ev.ts_us() / 1000);
    out.extend_from_slice(b" dvchost=");
    out.extend_from_slice(node.name.as_bytes());
    out.extend_from_slice(b" cn1=");
    put_u64(out, seq);
    out.extend_from_slice(b" cn1Label=sequence cn4=");
    put_u64(out, u64::from(node.id));
    out.extend_from_slice(b" cn4Label=nodeId cs6=");
    put_u64(out, u64::from(LOG_SCHEMA_VERSION));
    out.extend_from_slice(b" cs6Label=schema");
    // NIST 800-53: AU-3 - outcome of the event.
    if let Some(o) = ev.outcome() {
        out.extend_from_slice(b" outcome=");
        out.extend_from_slice(o.as_bytes());
    }
    match *ev {
        Event::PortBlockAlloc { sub, sub_len, v4, port_lo, port_hi, .. }
        | Event::PortBlockRelease { sub, sub_len, v4, port_lo, port_hi, .. } => {
            let _ = write!(
                out,
                " c6a2={} cn2={sub_len} cn2Label=subscriberPrefixLen sourceTranslatedAddress={} \
                 cs1={port_lo}-{port_hi} cs1Label=portRange",
                sub_addr(sub),
                Ipv4Addr::from(v4)
            );
        }
        Event::BibCreate { proto, v6, v6_port, v4, v4_port, .. }
        | Event::BibDelete { proto, v6, v6_port, v4, v4_port, .. } => {
            let _ = write!(
                out,
                " proto={} c6a2={} spt={v6_port} sourceTranslatedAddress={} sourceTranslatedPort={v4_port}",
                proto_name(proto),
                Ipv6Addr::from(v6),
                Ipv4Addr::from(v4)
            );
        }
        Event::Limit { kind, sub, sub_len, .. } => {
            let _ = write!(
                out,
                " reason={} c6a2={} cn2={sub_len} cn2Label=subscriberPrefixLen",
                kind.as_str(),
                sub_addr(sub)
            );
        }
        Event::Counter { name, value, .. } => {
            let _ = write!(out, " cs2={name} cs2Label=counter cn3={value} cn3Label=value");
        }
        Event::QueueOverflow { lost, .. } => {
            let _ = write!(out, " cn3={lost} cn3Label=lost");
        }
        Event::OutputFailure { lost, recovered, reason, .. } => {
            let _ = write!(
                out,
                " cs3=file cs3Label=destination cs4={} cs4Label=state cn3={lost} cn3Label=lost",
                if recovered { "recovered" } else { "degraded" }
            );
            if let Some(r) = reason {
                let _ = write!(out, " reason={}", r.as_str());
            }
        }
        Event::RemoteLoss { ip, port, lost, reason, .. } => {
            let _ = write!(
                out,
                " cs3=syslog cs3Label=destination cs5={} cs5Label=collector cn3={lost} cn3Label=lost",
                std::net::SocketAddr::new(ip, port)
            );
            if let Some(r) = reason {
                let _ = write!(out, " reason={}", r.as_str());
            }
        }
        Event::StorageThreshold { available, threshold, state, .. } => {
            let _ = write!(out, " cs3=file cs3Label=destination cs4={} cs4Label=state", state.as_str());
            if state != StorageState::Unknown {
                let _ = write!(out, " cn3={available} cn3Label=availableBytes");
            }
            let _ = write!(out, " cn2={threshold} cn2Label=minFreeBytes");
        }
        Event::RetentionPrune { rotated_us, seq_first, seq_last, chain_prefix, state, .. } => {
            let _ = write!(
                out,
                " act={} cs3=file cs3Label=destination cn3={rotated_us} cn3Label=prunedRotatedUs \
                 cs5={seq_first}-{seq_last} cs5Label=prunedSeqRange cs4={chain_prefix:016x} cs4Label=prunedChainPrefix",
                state.as_str()
            );
        }
        Event::AuditRecovery { reason, last_checkpoint_seq, max_seq, lease_state, .. } => {
            let _ = write!(
                out,
                " cs3=file cs3Label=destination reason={} cn3={last_checkpoint_seq} cn3Label=lastCheckpointSeq \
                 cn2={max_seq} cn2Label=maxSeq cs4={} cs4Label=leaseState",
                reason.as_str(),
                lease_state.as_str()
            );
        }
        Event::Lifecycle { fips, .. } => {
            if let Some(f) = fips {
                let _ =
                    write!(out, " cs1={} cs1Label=fipsProvider cn2={} cn2Label=fips", f.provider, u8::from(f.active));
            }
        }
        Event::ManagementConnection { ref conn, .. } => {
            let accepted = conn.reason == crate::event::MgmtReason::Accepted;
            let _ = write!(out, " act={}", if accepted { "accept" } else { "reject" });
            cef_addr(out, conn.ip);
            let _ = write!(out, " spt={} reason={}", conn.port, conn.reason.as_str());
            if let Some(s) = &conn.subject {
                out.extend_from_slice(b" suser=");
                cef_str(out, s.as_str());
            }
            if let Some(h) = &conn.cert_sha256 {
                out.extend_from_slice(b" cs1=");
                hex32(out, h);
                out.extend_from_slice(b" cs1Label=clientCertSha256");
            }
            if let Some(p) = conn.path {
                let _ = write!(out, " request={}", p.as_str());
            }
            if let Some(a) = &conn.allow_entry {
                out.extend_from_slice(b" cs2=");
                cef_str(out, a.as_str());
                out.extend_from_slice(b" cs2Label=allowEntry");
            }
            if !conn.sans.is_empty() {
                out.extend_from_slice(b" cs3=");
                for (i, n) in conn.sans.iter().take(crate::event::MgmtConnection::SANS_MAX).enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    cef_str(out, n.as_str());
                }
                out.extend_from_slice(b" cs3Label=subjectAltNames");
            }
        }
        Event::ManagementSuppressed { suppressed, window_secs, .. } => {
            let _ = write!(out, " cn3={suppressed} cn3Label=suppressed cn2={window_secs} cn2Label=windowSecs");
        }
        Event::RevocationCheck { ref check, .. } => {
            let c = &**check;
            let _ = write!(
                out,
                " act={} cs1={} cs1Label=tlsRole cs2={} cs2Label=revocationSource cn2={} cn2Label=chainIndex cs5=",
                c.status.as_str(),
                c.role.as_str(),
                c.source.as_str(),
                c.chain_index
            );
            hex32(out, &c.cert_sha256);
            out.extend_from_slice(b" cs5Label=certSha256 cs3=");
            cef_str(out, c.serial_hex.as_str());
            out.extend_from_slice(b" cs3Label=serialNumber cs4=");
            cef_str(out, c.issuer_dn.as_str());
            let _ = write!(out, " cs4Label=issuer flexString1={} flexString1Label=policy", c.policy);
            if let Some(r) = c.revocation_reason.or(c.ocsp_reason).or(c.crl_reason) {
                let _ = write!(out, " reason={r}");
            }
            if c.ocsp_reason.is_some() || c.crl_reason.is_some() {
                let _ = write!(out, " msg=ocsp:{} crl:{}", c.ocsp_reason.unwrap_or("-"), c.crl_reason.unwrap_or("-"));
            }
        }
        Event::RevocationRefresh { ref refresh, .. } => {
            let _ = write!(out, " act={} cs1=", refresh.transition.as_str());
            cef_str(out, refresh.source.as_str());
            let label = match refresh.kind {
                RefreshKind::Crl => "crlSource",
                RefreshKind::Ocsp => "ocspKey",
            };
            let _ = write!(out, " cs1Label={label}");
            if let Some(r) = refresh.reason {
                let _ = write!(out, " reason={r}");
            }
        }
    }
}

/// RFC 5424 header: `<PRI>1 TIMESTAMP HOST APP PROCID MSGID - `.
/// Facility local0 (16).
pub fn syslog_header(out: &mut Vec<u8>, node: &NodeIdent, app: &str, ev: &Event) {
    let pri = 16 * 8 + u32::from(ev.severity());
    let _ = write!(out, "<{pri}>1 ");
    rfc3339(out, ev.ts_us());
    let _ = write!(out, " {} {app} {} {} - ", node.name, node.pid, ev.action());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::PruneState;

    fn node() -> NodeIdent {
        NodeIdent { name: "plat-01".into(), id: 3, pid: 42 }
    }

    #[test]
    fn timestamps() {
        let mut v = Vec::new();
        rfc3339(&mut v, 0);
        assert_eq!(v, b"1970-01-01T00:00:00.000000Z");
        v.clear();
        // 2026-10-28T14:16:00.123456Z
        rfc3339(&mut v, 1_793_196_960_123_456);
        assert_eq!(String::from_utf8(v).unwrap(), "2026-10-28T14:16:00.123456Z");
        let mut v = Vec::new();
        rfc3339(&mut v, 951_782_400_000_000); // 2000-02-29 leap day
        assert_eq!(String::from_utf8(v).unwrap(), "2000-02-29T00:00:00.000000Z");
    }

    #[test]
    fn json_port_block_record() {
        let ev = Event::PortBlockAlloc {
            ts_us: 1_793_196_960_000_001,
            sub: 0x2001_0db8_0100_0001_0000_0000_0000_0000,
            sub_len: 64,
            v4: 0xc000_020a,
            port_lo: 1024,
            port_hi: 1535,
        };
        let mut v = Vec::new();
        json(&mut v, 7, &node(), &ev);
        let s = String::from_utf8(v).unwrap();
        assert!(s.starts_with("{\"@timestamp\":\"2026-10-28T14:16:00.000001Z\""));
        for want in [
            "\"event.sequence\":7",
            "\"event.action\":\"nat_port_block_allocate\"",
            "\"plat.subscriber.prefix\":\"2001:db8:100:1::/64\"",
            "\"source.nat.ip\":\"192.0.2.10\"",
            "\"plat.nat.port_start\":1024",
            "\"plat.nat.port_end\":1535",
            "\"observer.name\":\"plat-01\"",
        ] {
            assert!(s.contains(want), "{want} in {s}");
        }
        assert!(s.ends_with('}'));
    }

    #[test]
    fn cef_and_syslog() {
        let ev = Event::Limit { ts_us: 1_000_000, kind: crate::LimitKind::PoolExhausted, sub: 1 << 64, sub_len: 64 };
        let mut v = Vec::new();
        syslog_header(&mut v, &node(), "platd", &ev);
        cef(&mut v, 1, &node(), &ev);
        let s = String::from_utf8(v).unwrap();
        assert!(s.starts_with(
            "<132>1 1970-01-01T00:00:01.000000Z plat-01 platd 42 nat_resource_limit - CEF:0|USG|usg-plat|"
        ));
        assert!(s.contains("reason=pool_exhausted"));
        assert!(s.contains(" cn4=3 cn4Label=nodeId "), "{s}");
        assert!(s.contains(" outcome=failure"), "{s}");
        assert!(s.contains(&format!(" cs6={LOG_SCHEMA_VERSION} cs6Label=schema")), "{s}");
    }

    #[test]
    fn decimal() {
        for v in [0, 9, 10, 1_793_196_960_123, u64::MAX] {
            let mut o = Vec::new();
            put_u64(&mut o, v);
            assert_eq!(o, v.to_string().as_bytes());
        }
    }

    #[test]
    fn subscriber_table_limit_reason() {
        let ev = Event::Limit { ts_us: 1_000_000, kind: crate::LimitKind::SubscriberTable, sub: 1 << 64, sub_len: 64 };
        let mut v = Vec::new();
        json(&mut v, 1, &node(), &ev);
        assert!(String::from_utf8(v).unwrap().contains("\"event.reason\":\"subscriber_table_limit\""));
        let mut v = Vec::new();
        cef(&mut v, 1, &node(), &ev);
        assert!(String::from_utf8(v).unwrap().contains(" reason=subscriber_table_limit "));
    }

    #[test]
    fn output_health_records() {
        let mut v = Vec::new();
        json(&mut v, 9, &node(), &Event::OutputFailure { ts_us: 0, lost: 12, recovered: false, reason: None });
        let s = String::from_utf8(v).unwrap();
        for want in [
            "\"event.action\":\"audit_output_failure\"",
            "\"event.outcome\":\"failure\"",
            "\"plat.audit.destination\":\"file\"",
            "\"plat.audit.state\":\"degraded\"",
            "\"plat.audit.lost\":12",
        ] {
            assert!(s.contains(want), "{want} in {s}");
        }
        let ev = Event::RemoteLoss { ts_us: 0, ip: "2001:db8::5".parse().unwrap(), port: 6514, lost: 3, reason: None };
        assert_eq!(ev.severity(), 4);
        let mut v = Vec::new();
        json(&mut v, 10, &node(), &ev);
        let s = String::from_utf8(v).unwrap();
        for want in [
            "\"event.action\":\"audit_remote_loss\"",
            "\"destination.ip\":\"2001:db8::5\"",
            "\"destination.port\":6514",
            "\"plat.audit.lost\":3",
        ] {
            assert!(s.contains(want), "{want} in {s}");
        }
        let mut v = Vec::new();
        cef(&mut v, 10, &node(), &ev);
        let s = String::from_utf8(v).unwrap();
        assert!(s.contains("|audit_remote_loss|audit_remote_loss|7|"), "{s}");
        assert!(s.contains(" cs5=[2001:db8::5]:6514 cs5Label=collector cn3=3 cn3Label=lost"), "{s}");
        let mut v = Vec::new();
        cef(&mut v, 11, &node(), &Event::OutputFailure { ts_us: 0, lost: 1, recovered: false, reason: None });
        assert!(String::from_utf8(v).unwrap().contains("|audit_output_failure|audit_output_failure|9|"));
        // SEC-7: a failed cut-back carries its own reason.
        let ev = Event::OutputFailure {
            ts_us: 0,
            lost: 0,
            recovered: false,
            reason: Some(crate::OutputFailureReason::TruncateFailed),
        };
        let mut v = Vec::new();
        json(&mut v, 12, &node(), &ev);
        assert!(String::from_utf8(v).unwrap().contains(",\"plat.reason\":\"truncate_failed\""));
        let mut v = Vec::new();
        cef(&mut v, 12, &node(), &ev);
        assert!(String::from_utf8(v).unwrap().contains(" reason=truncate_failed"));
    }

    /// AU-5(1) storage threshold and AU-9/AU-11 retention records (schema 3).
    #[test]
    fn storage_and_retention_records() {
        let low = Event::StorageThreshold { ts_us: 0, available: 1000, threshold: 4096, state: StorageState::Below };
        assert_eq!((low.severity(), low.outcome()), (4, Some("failure")));
        let mut v = Vec::new();
        json(&mut v, 3, &node(), &low);
        let s = String::from_utf8(v).unwrap();
        for want in [
            "\"event.action\":\"audit_storage_threshold\"",
            "\"plat.audit.state\":\"below_threshold\"",
            "\"plat.audit.available_bytes\":1000",
            "\"plat.audit.min_free_bytes\":4096",
        ] {
            assert!(s.contains(want), "{want} in {s}");
        }
        let ok = Event::StorageThreshold { ts_us: 0, available: 9000, threshold: 4096, state: StorageState::Recovered };
        assert_eq!((ok.severity(), ok.outcome()), (5, Some("success")));
        // SEC-204: free space unknown is a failure, without a byte count.
        let unknown = Event::StorageThreshold { ts_us: 0, available: 0, threshold: 4096, state: StorageState::Unknown };
        assert_eq!((unknown.severity(), unknown.outcome()), (4, Some("failure")));
        let mut v = Vec::new();
        json(&mut v, 3, &node(), &unknown);
        let s = String::from_utf8(v).unwrap();
        assert!(s.contains("\"plat.audit.state\":\"unknown\""), "{s}");
        assert!(!s.contains("available_bytes"), "{s}");
        // NIST-202: the scheduled record does not claim success; the result
        // record carries the real outcome.
        let at = |state| Event::RetentionPrune {
            ts_us: 0,
            rotated_us: 17,
            seq_first: 5,
            seq_last: 9,
            chain_prefix: 0xab,
            state,
        };
        for (st, outcome, name) in [
            (PruneState::Scheduled, "unknown", "scheduled"),
            (PruneState::Deleted, "success", "deleted"),
            (PruneState::Failed, "failure", "failed"),
        ] {
            let mut v = Vec::new();
            json(&mut v, 4, &node(), &at(st));
            let s = String::from_utf8(v).unwrap();
            assert!(s.contains(&format!("\"event.outcome\":\"{outcome}\",\"plat.audit.state\":\"{name}\"")), "{s}");
            let mut v = Vec::new();
            cef(&mut v, 4, &node(), &at(st));
            let s = String::from_utf8(v).unwrap();
            assert!(s.contains(&format!("outcome={outcome}")) && s.contains(&format!("act={name}")), "{s}");
        }
        let prune = at(PruneState::Scheduled);
        let mut v = Vec::new();
        json(&mut v, 4, &node(), &prune);
        let s = String::from_utf8(v).unwrap();
        for want in [
            "\"event.action\":\"audit_retention_prune\"",
            "\"plat.audit.pruned_rotated_us\":17",
            "\"plat.audit.pruned_seq_first\":5",
            "\"plat.audit.pruned_seq_last\":9",
            "\"plat.audit.pruned_chain_prefix\":\"00000000000000ab\"",
        ] {
            assert!(s.contains(want), "{want} in {s}");
        }
        let mut v = Vec::new();
        cef(&mut v, 4, &node(), &prune);
        let s = String::from_utf8(v).unwrap();
        assert!(s.contains("cs5=5-9 cs5Label=prunedSeqRange"), "{s}");
        let mut v = Vec::new();
        cef(&mut v, 5, &node(), &low);
        assert!(String::from_utf8(v).unwrap().contains("cs4=below_threshold"));
    }

    fn json_of(ev: &Event) -> String {
        let mut v = Vec::new();
        json(&mut v, 1, &node(), ev);
        String::from_utf8(v).unwrap()
    }

    fn cef_of(ev: &Event) -> String {
        let mut v = Vec::new();
        cef(&mut v, 1, &node(), ev);
        String::from_utf8(v).unwrap()
    }

    /// Schema 5: FIPS state on service_start, reason on remote loss.
    #[test]
    fn fips_and_remote_loss_reason() {
        use crate::event::{FipsMark, LifecycleKind, RemoteLossReason};
        let ev = Event::Lifecycle {
            ts_us: 0,
            kind: LifecycleKind::Start,
            fips: Some(FipsMark { active: true, provider: "aws-lc-rs-fips" }),
        };
        let s = json_of(&ev);
        assert!(s.contains("\"plat.fips\":true,\"plat.fips_provider\":\"aws-lc-rs-fips\""), "{s}");
        assert!(cef_of(&ev).contains(" cs1=aws-lc-rs-fips cs1Label=fipsProvider cn2=1 cn2Label=fips"));
        let stop = Event::Lifecycle { ts_us: 0, kind: LifecycleKind::Stop, fips: None };
        assert!(!json_of(&stop).contains("plat.fips"));
        let loss = Event::RemoteLoss {
            ts_us: 0,
            ip: "192.0.2.10".parse().unwrap(),
            port: 6514,
            lost: 2,
            reason: Some(RemoteLossReason::TlsVerify),
        };
        assert!(json_of(&loss).contains("\"plat.reason\":\"tls_verify\""));
        assert!(cef_of(&loss).contains(" reason=tls_verify"));
    }

    /// Hostile certificate text cannot break out of JSON or CEF fields.
    #[test]
    fn management_connection_escaping() {
        use crate::event::{AuditText, MgmtConnection, MgmtPath, MgmtReason};
        use std::sync::Arc;
        let subject = AuditText::new("evil\" ,\"x\":1 \\ cs1=pwn\nnext", AuditText::SUBJECT_MAX);
        let ev = Event::ManagementConnection {
            ts_us: 0,
            conn: Arc::new(MgmtConnection {
                ip: "2001:db8::7".parse().unwrap(),
                port: 50_000,
                subject: Some(subject),
                cert_sha256: Some([0xab; 32]),
                reason: MgmtReason::NotAllowlisted,
                path: None,
                allow_entry: None,
                sans: vec![AuditText::new("dns:a\"b.example", AuditText::SUBJECT_MAX), AuditText::new("uri:x=y", 64)],
            }),
        };
        let s = json_of(&ev);
        assert!(s.contains("\"tls.client.subject\":\"evil\\\" ,\\\"x\\\":1 \\\\ cs1=pwn?next\""), "{s}");
        assert!(s.contains("\"plat.mgmt.reason\":\"not_allowlisted\",") && s.contains("\"event.outcome\":\"failure\""));
        assert!(s.contains(&format!("\"tls.client.hash.sha256\":\"{}\"", "ab".repeat(32))), "{s}");
        assert!(!s.contains("url.path"));
        assert!(!s.contains('\n'));
        let c = cef_of(&ev);
        assert!(c.contains(" act=reject c6a2=2001:db8::7 spt=50000 reason=not_allowlisted"), "{c}");
        assert!(c.contains(" suser=evil\" ,\"x\":1 \\\\ cs1\\=pwn?next cs1="), "{c}");
        let ok = Event::ManagementConnection {
            ts_us: 0,
            conn: Arc::new(MgmtConnection {
                ip: "192.0.2.9".parse().unwrap(),
                port: 1,
                subject: None,
                cert_sha256: None,
                reason: MgmtReason::Accepted,
                path: Some(MgmtPath::Metrics),
                allow_entry: Some(AuditText::new("dns:prom.example", AuditText::SUBJECT_MAX)),
                sans: Vec::new(),
            }),
        };
        assert!(json_of(&ok).contains("\"plat.mgmt.allow_entry\":\"dns:prom.example\""));
        assert!(cef_of(&ok).contains(" cs2=dns:prom.example cs2Label=allowEntry"));
        assert!(s.contains("\"tls.client.x509.alternative_names\":[\"dns:a\\\"b.example\",\"uri:x=y\"]"), "{s}");
        assert!(c.contains(" cs3=dns:a\"b.example,uri:x\\=y cs3Label=subjectAltNames"), "{c}");
        assert!(json_of(&ok).contains("\"url.path\":\"/metrics\""));
        assert!(cef_of(&ok).contains(" act=accept src=192.0.2.9 spt=1 reason=accepted request=/metrics"));
        let sup = Event::ManagementSuppressed { ts_us: 0, suppressed: 41, window_secs: 60 };
        assert!(json_of(&sup).contains("\"plat.mgmt.suppressed\":41,\"plat.mgmt.window_secs\":60"));
        assert_eq!(sup.action(), "management_connection_suppressed");
    }

    #[test]
    fn revocation_records() {
        use crate::event::{
            AuditText, RefreshKind, RefreshTransition, RevocationCheck, RevocationRefresh, RevocationSource,
            RevocationStatus, TlsRole,
        };
        use std::sync::Arc;
        let check = RevocationCheck {
            role: TlsRole::SyslogServer,
            cert_sha256: [1; 32],
            serial_hex: AuditText::new("01ab", AuditText::SHORT_MAX),
            issuer_dn: AuditText::new("CN=Intermediate,O=Example", AuditText::DN_MAX),
            chain_index: 1,
            status: RevocationStatus::Revoked,
            source: RevocationSource::CrlFetch,
            ocsp_reason: Some("connect"),
            crl_reason: None,
            revocation_reason: Some("key_compromise"),
            revocation_date_us: Some(1_000_000),
            ocsp_responder: Some(AuditText::new("ocsp.example.net:80", AuditText::SHORT_MAX)),
            crl_source: Some(AuditText::new("crl.example.net:80", AuditText::SHORT_MAX)),
            policy: "hard_fail",
            allowed: false,
        };
        let ev = Event::RevocationCheck { ts_us: 0, check: Arc::new(check) };
        assert_eq!((ev.action(), ev.outcome(), ev.severity()), ("tls_revocation_check", Some("failure"), 4));
        let s = json_of(&ev);
        for want in [
            "\"plat.tls.role\":\"syslog_server\"",
            &format!("\"tls.server.hash.sha256\":\"{}\"", "01".repeat(32)),
            "\"x509.serial_number\":\"01ab\"",
            "\"x509.issuer.distinguished_name\":\"CN=Intermediate,O=Example\"",
            "\"plat.revocation.chain_index\":1",
            "\"plat.revocation.status\":\"revoked\"",
            "\"plat.revocation.source\":\"crl_fetch\"",
            "\"plat.revocation.policy\":\"hard_fail\"",
            "\"plat.ocsp.reason\":\"connect\"",
            "\"plat.revocation.reason\":\"key_compromise\"",
            "\"plat.revocation.date\":\"1970-01-01T00:00:01.000000Z\"",
            "\"plat.ocsp.responder\":\"ocsp.example.net:80\"",
            "\"plat.crl.source\":\"crl.example.net:80\"",
        ] {
            assert!(s.contains(want), "{want} in {s}");
        }
        assert!(!s.contains("plat.crl.reason"));
        let c = cef_of(&ev);
        assert!(c.contains(" act=revoked cs1=syslog_server cs1Label=tlsRole cs2=crl_fetch"), "{c}");
        assert!(c.contains(" cs4=CN\\=Intermediate,O\\=Example cs4Label=issuer"), "{c}");
        assert!(c.contains(" reason=key_compromise msg=ocsp:connect crl:-"), "{c}");
        let r = Event::RevocationRefresh {
            ts_us: 0,
            refresh: Arc::new(RevocationRefresh {
                kind: RefreshKind::Crl,
                source: AuditText::new("crl.example.net:80", AuditText::SHORT_MAX),
                transition: RefreshTransition::StaleDropped,
                reason: Some("timeout"),
            }),
        };
        let s = json_of(&r);
        assert!(s.contains("\"event.outcome\":\"failure\",\"plat.revocation.transition\":\"stale_dropped\""), "{s}");
        assert!(s.contains("\"plat.crl.source\":\"crl.example.net:80\",\"event.reason\":\"timeout\""), "{s}");
        assert!(cef_of(&r).contains(" act=stale_dropped cs1=crl.example.net:80 cs1Label=crlSource reason=timeout"));
    }
}
