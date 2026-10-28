//! Record formatting: JSON lines (ECS-style dotted keys), ArcSight CEF, and
//! the RFC 5424 syslog header.
//!
//! No field is attacker-controlled text: values are IP addresses, numbers,
//! and static strings; the node name is restricted to `[A-Za-z0-9-_.]` at
//! config load. That rules out log injection (CWE-117) without escaping on
//! the hot formatting path.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::LOG_SCHEMA_VERSION;
use crate::event::{Event, StorageState};
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
        Event::Lifecycle { .. } => {
            let _ = write!(out, ",\"event.outcome\":\"success\",\"service.version\":\"{}\"", env!("CARGO_PKG_VERSION"));
        }
        Event::Counter { name, value, .. } => {
            let _ = write!(out, ",\"plat.counter.name\":\"{name}\",\"plat.counter.value\":{value}");
        }
        Event::QueueOverflow { lost, .. } => {
            let _ = write!(out, ",\"event.outcome\":\"failure\",\"plat.audit.lost\":{lost}");
        }
        Event::OutputFailure { lost, recovered, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"failure\",\"plat.audit.destination\":\"file\",\"plat.audit.state\":\"{}\",\
                 \"plat.audit.lost\":{lost}",
                if recovered { "recovered" } else { "degraded" }
            );
        }
        Event::RemoteLoss { ip, port, lost, .. } => {
            let _ = write!(
                out,
                ",\"event.outcome\":\"failure\",\"plat.audit.destination\":\"syslog\",\"destination.ip\":\"{ip}\",\
                 \"destination.port\":{port},\"plat.audit.lost\":{lost}"
            );
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
    }
    out.push(b'}');
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
        Event::OutputFailure { lost, recovered, .. } => {
            let _ = write!(
                out,
                " cs3=file cs3Label=destination cs4={} cs4Label=state cn3={lost} cn3Label=lost",
                if recovered { "recovered" } else { "degraded" }
            );
        }
        Event::RemoteLoss { ip, port, lost, .. } => {
            let _ = write!(
                out,
                " cs3=syslog cs3Label=destination cs5={} cs5Label=collector cn3={lost} cn3Label=lost",
                std::net::SocketAddr::new(ip, port)
            );
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
        Event::Lifecycle { .. } => {}
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
        json(&mut v, 9, &node(), &Event::OutputFailure { ts_us: 0, lost: 12, recovered: false });
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
        let ev = Event::RemoteLoss { ts_us: 0, ip: "2001:db8::5".parse().unwrap(), port: 6514, lost: 3 };
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
        cef(&mut v, 11, &node(), &Event::OutputFailure { ts_us: 0, lost: 1, recovered: false });
        assert!(String::from_utf8(v).unwrap().contains("|audit_output_failure|audit_output_failure|9|"));
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
}
