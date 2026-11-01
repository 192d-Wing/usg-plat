//! QA repro (WU5 checksum note): the fast path's RFC 1624 update is only
//! correct for a *complete* UDP checksum. A `CHECKSUM_PARTIAL` packet (a
//! local or container sender on veth / tap with TX checksum offload on)
//! carries in the UDP checksum field the folded, *uncomplemented*
//! pseudo-header sum `P` (Linux `udp6_hwcsum_outgoing` / `udp4_hwcsum`:
//! `uh->check = ~csum_*_magic(...)`); the egress device or
//! `skb_checksum_help` later adds the L4 sum and complements.
//!
//! `adjust` treats the field as `~sum` and applies `~(~HC + ~m + m')`,
//! which for an uncomplemented `P` moves the sum by `m - m'` instead of
//! `m' - m`. After `XDP_TX` / `XDP_REDIRECT` the skb metadata
//! (`ip_summed`, `csum_start`) is gone, so nothing completes the sum and
//! the frame leaves with a checksum that is neither partial nor correct.
//!
//! These tests pin that behaviour so a fix (pass such packets, verify
//! the full checksum, or require offloads off on attached devices) is a
//! visible change.
//!
//! COMPLIANCE MAPPING:
//! - RFC 1624 eqn. 3, RFC 768, RFC 7915 §4.5 / §5.1 - L4 checksum update
//! - NIST 800-53: SA-11 - developer testing

use plat_xdp_core::abi::{FibParams, SlotRec};
use plat_xdp_core::{HDR4, HDR6, csum, rewrite_v4_to_v6, rewrite_v6_to_v4};

const ETH: usize = 14;
const PAYLOAD: &[u8] = b"partial-checksum-repro-0123456789";

const SRC6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const DST6: [u8; 16] = [0, 0x64, 0xff, 0x9b, 0, 0x01, 0, 0, 0, 0, 0, 0, 198, 51, 100, 2];
const POOL4: [u8; 4] = [192, 0, 2, 7];
const DST4: [u8; 4] = [198, 51, 100, 2];
const SPORT6: u16 = 40000;
const POOL_PORT: u16 = 1234;
const DPORT: u16 = 7;

fn rec() -> SlotRec {
    SlotRec {
        state: plat_xdp_core::abi::SLOT_LIVE,
        src6: SRC6,
        dst6: DST6,
        sport6: SPORT6.to_be_bytes(),
        dport: DPORT.to_be_bytes(),
        pool_port4: POOL_PORT.to_be_bytes(),
        pool4: POOL4,
        dst4: DST4,
        ..SlotRec::default()
    }
}

fn sum(b: &[u8]) -> u64 {
    b.chunks(2).map(|c| u64::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum()
}

fn ulen() -> u16 {
    (8 + PAYLOAD.len()) as u16
}

fn pseudo6(s: &[u8; 16], d: &[u8; 16]) -> u64 {
    sum(s) + sum(d) + u64::from(ulen()) + 17
}

fn pseudo4(s: &[u8; 4], d: &[u8; 4]) -> u64 {
    sum(s) + sum(d) + u64::from(ulen()) + 17
}

/// UDP header (checksum field zero) + payload.
fn l4_sum(sport: u16, dport: u16) -> u64 {
    u64::from(sport) + u64::from(dport) + u64::from(ulen()) + sum(PAYLOAD)
}

/// Full (wire) checksum, RFC 768 zero rule.
fn full(pseudo: u64, sport: u16, dport: u16) -> u16 {
    csum::udp_nonzero(csum::finish(pseudo + l4_sum(sport, dport)))
}

/// What a sender with TX offload puts in the field (CHECKSUM_PARTIAL).
fn partial(pseudo: u64) -> u16 {
    csum::fold(pseudo)
}

/// What `skb_checksum_help` / the NIC would do to a still-partial field:
/// sum from `csum_start` (the field included) to the end, complement.
fn complete(field: u16, sport: u16, dport: u16) -> u16 {
    csum::udp_nonzero(csum::finish(u64::from(field) + l4_sum(sport, dport)))
}

fn v6_block(c: u16) -> [u8; HDR6] {
    let mut h = [0u8; HDR6];
    h[12..14].copy_from_slice(&[0x86, 0xdd]);
    h[ETH] = 0x60;
    h[ETH + 4..ETH + 6].copy_from_slice(&ulen().to_be_bytes());
    h[ETH + 6] = 17;
    h[ETH + 7] = 64;
    h[ETH + 8..ETH + 24].copy_from_slice(&SRC6);
    h[ETH + 24..ETH + 40].copy_from_slice(&DST6);
    let u = ETH + 40;
    h[u..u + 2].copy_from_slice(&SPORT6.to_be_bytes());
    h[u + 2..u + 4].copy_from_slice(&DPORT.to_be_bytes());
    h[u + 4..u + 6].copy_from_slice(&ulen().to_be_bytes());
    h[u + 6..u + 8].copy_from_slice(&c.to_be_bytes());
    h
}

fn v4_block(c: u16) -> [u8; HDR4] {
    let mut h = [0u8; HDR4];
    h[12..14].copy_from_slice(&[0x08, 0x00]);
    h[ETH] = 0x45;
    h[ETH + 2..ETH + 4].copy_from_slice(&(20 + ulen()).to_be_bytes());
    h[ETH + 8] = 64;
    h[ETH + 9] = 17;
    h[ETH + 12..ETH + 16].copy_from_slice(&DST4);
    h[ETH + 16..ETH + 20].copy_from_slice(&POOL4);
    let u = ETH + 20;
    h[u..u + 2].copy_from_slice(&DPORT.to_be_bytes());
    h[u + 2..u + 4].copy_from_slice(&POOL_PORT.to_be_bytes());
    h[u + 4..u + 6].copy_from_slice(&ulen().to_be_bytes());
    h[u + 6..u + 8].copy_from_slice(&c.to_be_bytes());
    h
}

fn out4_csum(c6: u16) -> u16 {
    let mut o = [0u8; HDR4];
    rewrite_v6_to_v4(&v6_block(c6), &mut o, &FibParams::default(), &rec(), 0, 1);
    u16::from_be_bytes([o[ETH + 26], o[ETH + 27]])
}

fn out6_csum(c4: u16) -> u16 {
    let mut o = [0u8; HDR6];
    rewrite_v4_to_v6(&v4_block(c4), &mut o, &FibParams::default(), &rec(), 0);
    u16::from_be_bytes([o[ETH + 46], o[ETH + 47]])
}

/// Control: a complete checksum is translated correctly (v6 -> v4).
#[test]
fn full_checksum_v6_to_v4_is_correct() {
    let c6 = full(pseudo6(&SRC6, &DST6), SPORT6, DPORT);
    assert_eq!(out4_csum(c6), full(pseudo4(&POOL4, &DST4), POOL_PORT, DPORT));
}

/// Control: a complete checksum is translated correctly (v4 -> v6).
#[test]
fn full_checksum_v4_to_v6_is_correct() {
    let c4 = full(pseudo4(&DST4, &POOL4), DPORT, POOL_PORT);
    assert_eq!(out6_csum(c4), full(pseudo6(&DST6, &SRC6), DPORT, SPORT6));
}

/// Repro: a CHECKSUM_PARTIAL v6 packet. The output field is wrong as a
/// full checksum (what the receiver checks after XDP_REDIRECT/TX) and
/// also wrong as a partial one (had anything completed it).
#[test]
fn partial_checksum_v6_to_v4_is_wrong() {
    let got = out4_csum(partial(pseudo6(&SRC6, &DST6)));
    let want = full(pseudo4(&POOL4, &DST4), POOL_PORT, DPORT);
    assert_ne!(got, want, "XDP output as sent on the wire: receiver drops it");
    assert_ne!(complete(got, POOL_PORT, DPORT), want, "even if a later stage completed it");
    // The correct update of a partial field: only the pseudo-header
    // (address) delta, with the opposite sign (`adjust` with old/new
    // swapped); ports are summed when the checksum is completed. Shown
    // for the reviewers' fix choice; it still needs a completion step.
    let fixed = csum::adjust(partial(pseudo6(&SRC6, &DST6)), new4(), old6());
    assert_eq!(complete(fixed, POOL_PORT, DPORT), want);
}

/// Repro: a CHECKSUM_PARTIAL v4 packet (local sender on the upstream side).
#[test]
fn partial_checksum_v4_to_v6_is_wrong() {
    let got = out6_csum(partial(pseudo4(&DST4, &POOL4)));
    let want = full(pseudo6(&DST6, &SRC6), DPORT, SPORT6);
    assert_ne!(got, want);
    assert_ne!(complete(got, DPORT, SPORT6), want);
}

/// The program cannot tell the two cases apart from the bytes alone
/// without summing the payload: a partial field verifies as a full one
/// only by coincidence. Show that a full verification would catch it
/// (the "pass packets whose checksum does not verify" option).
#[test]
fn full_verification_distinguishes_partial() {
    let p = partial(pseudo6(&SRC6, &DST6));
    let verify = |c: u16| csum::fold(pseudo6(&SRC6, &DST6) + l4_sum(SPORT6, DPORT) + u64::from(c)) == 0xffff;
    assert!(verify(full(pseudo6(&SRC6, &DST6), SPORT6, DPORT)));
    assert!(!verify(p));
}

fn old6() -> u64 {
    sum(&SRC6) + sum(&DST6)
}

fn new4() -> u64 {
    sum(&POOL4) + sum(&DST4)
}
