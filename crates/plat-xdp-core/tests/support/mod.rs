//! Level-1 differential harness support (plan §11): a host [`Env`] backed
//! by in-memory tables and a static FIB, and the reference pipeline
//! `kernel_ingress → plat_nat64::Nat64::process → kernel_egress` that the
//! fast path must equal byte for byte (plan §2.4).
//!
//! The `Env` records are built from engine state (`State::lookup6`,
//! `State::has_session`) and the known remote, with the install rules of
//! plan §4.2 I3 (UDP only, no hairpin, no pool remote). WU4 replaces
//! [`Reference::install`] with `plat_nat64::mirror::ModelMirror`.

// Shared by several test crates; each uses a different subset.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use plat_audit::{AuditSink, Event};
use plat_common::{Clock, Config, Counters, Ipv4Cidr};
use plat_nat64::{Nat64, Verdict as EngineVerdict, WorkerCtx};
use plat_packet::checksum as ck;
use plat_xdp_core::abi::{
    AF_INET, AF_INET6, Control, EgressEnt, FIB_RET_FRAG_NEEDED, FIB_RET_FWD_DISABLED, FIB_RET_NO_NEIGH,
    FIB_RET_SUCCESS, FibParams, IfaceEnt, Key4, Key6, ROLE_ACCESS, ROLE_UPSTREAM, SLICE_ACTIVE, SLOT_LIVE, SliceEnt,
    SlotRec, XlatConfig, iface_slot,
};
use plat_xdp_core::decide::{Action, Env, Verdict};
use plat_xdp_core::ident::{self, IdentKey};
use plat_xdp_core::{HDR4, HDR6, PassReason};
use plat_xlat::{HEADROOM, Prefix6052};

pub const ACCESS_IF: u32 = 2;
pub const UPSTREAM_IF: u32 = 3;
pub const TUN_IF: u32 = 100;
/// Locally administered MACs (no real hardware).
pub const ACCESS_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
pub const UPSTREAM_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x03];
/// Permanent neighbour entries of the static FIB.
pub const NH4_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x04, 0x01];
pub const NH6_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x06, 0x01];
/// Source MACs of the client and server side frames.
pub const CLIENT_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x0c, 0x01];
pub const SERVER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x05, 0x01];
pub const GEN: u32 = 7;
pub const NOW_NS: u64 = 1_000_000_000_000;

/// Client prefix of every fixture (RFC 9637 documentation space; outside
/// every NAT64 prefix used here).
pub const CLIENT_NET: u128 = 0x3fff_0100_0000_0000_0000_0000_0000_0000;
pub const CLIENT_BITS: u32 = 40;
/// Pool of every fixture: 198.51.100.0/24 (TEST-NET-2).
pub const POOL_NET: u32 = 0xc633_6400;
/// Remote (server) networks: 192.0.2.0/24 and 203.0.113.0/24.
pub const SERVER_NETS: [u32; 2] = [0xc000_0200, 0xcb00_7100];

/// The RFC 6052 §2.4 example prefixes (/32 … /96) plus the example
/// config's network-specific /96.
pub const PREFIXES: [&str; 7] = [
    "64:ff9b:1::/96",
    "2001:db8::/32",
    "2001:db8:100::/40",
    "2001:db8:122::/48",
    "2001:db8:122:300::/56",
    "2001:db8:122:344::/64",
    "2001:db8:122:344::/96",
];

pub fn ok<T, E: std::fmt::Debug>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{e:?}"),
    }
}

pub fn some<T>(o: Option<T>, what: &str) -> T {
    match o {
        Some(v) => v,
        None => panic!("missing {what}"),
    }
}

/// Translation knobs of a fixture.
#[derive(Debug, Clone)]
pub struct Knobs {
    pub prefix: &'static str,
    pub copy_tos: bool,
    pub mtu4: u16,
    pub mtu6: u16,
    pub lowest6: u16,
}

impl Default for Knobs {
    fn default() -> Self {
        Self { prefix: PREFIXES[0], copy_tos: true, mtu4: 1500, mtu6: 1500, lowest6: 1280 }
    }
}

/// The example config with the fixture's prefix, client prefix, pool and
/// MTUs, and non-global destinations allowed (the servers live in
/// documentation ranges).
pub fn config(k: &Knobs) -> Config {
    let mut t = include_str!("../../../../config/platd.example.toml").to_string();
    for (a, b) in [
        ("nat64_prefix = \"64:ff9b:1::/96\"", format!("nat64_prefix = \"{}\"", k.prefix)),
        ("client_prefixes = [\"2001:db8:100::/40\"]", "client_prefixes = [\"3fff:100::/40\"]".to_string()),
        ("pool = [\"192.0.2.0/24\"]", "pool = [\"198.51.100.0/24\"]".to_string()),
        ("allow_non_global_destinations = false", "allow_non_global_destinations = true".to_string()),
        ("copy_tos = true", format!("copy_tos = {}", k.copy_tos)),
        ("ipv4_mtu = 1500", format!("ipv4_mtu = {}", k.mtu4)),
        ("ipv6_mtu = 1500", format!("ipv6_mtu = {}", k.mtu6)),
        ("lowest_ipv6_mtu = 1280", format!("lowest_ipv6_mtu = {}", k.lowest6)),
    ] {
        assert!(t.contains(a), "fixture key {a}");
        t = t.replacen(a, &b, 1);
    }
    ok(Config::from_toml(&t))
}

/// The host side of the kernel: link MTUs, the TUN MTU, the forwarding
/// sysctl and neighbour state. Shared by the candidate's FIB stub and the
/// reference's `kernel_egress`, so both see the same network.
#[derive(Debug, Clone, Copy)]
pub struct Net {
    pub tun_mtu: u32,
    pub link_mtu4: u32,
    pub link_mtu6: u32,
    pub forwarding: bool,
    pub neigh: bool,
}

impl Default for Net {
    fn default() -> Self {
        Self { tun_mtu: 1500, link_mtu4: 1500, link_mtu6: 1500, forwarding: true, neigh: true }
    }
}

/// Host [`Env`]: maps as hash tables, a static FIB and a fixed clock.
#[derive(Debug)]
pub struct HostEnv {
    pub ifaces: HashMap<u32, IfaceEnt>,
    pub egress: HashMap<u32, EgressEnt>,
    pub control: Control,
    pub config: XlatConfig,
    pub now: u64,
    pub out6: HashMap<Key6, u32>,
    pub in4: HashMap<Key4, u32>,
    pub slots: Vec<SlotRec>,
    pub slices: Vec<SliceEnt>,
    pub net: Net,
    pub ident_key: IdentKey,
    pub ident_table: Vec<u16>,
    pub rng: u64,
    /// Overrides the FIB result's MACs (the spike vectors' addresses).
    pub fib_macs: Option<([u8; 6], [u8; 6])>,
}

impl HostEnv {
    pub fn new(cfg: &Config, net: Net) -> Self {
        let t = &cfg.translation;
        let mut ifaces = HashMap::new();
        let mut egress = HashMap::new();
        for (ifindex, mac, role) in [(ACCESS_IF, ACCESS_MAC, ROLE_ACCESS), (UPSTREAM_IF, UPSTREAM_MAC, ROLE_UPSTREAM)] {
            ifaces.insert(iface_slot(ifindex), IfaceEnt { ifindex, mac, role, pad: 0 });
            egress.insert(iface_slot(ifindex), EgressEnt { ifindex, allowed: 1, pad: [0; 3] });
        }
        Self {
            ifaces,
            egress,
            control: Control {
                enabled: 1,
                tun_ifindex: TUN_IF,
                deadline_ns: NOW_NS + 1_000_000_000,
                tun_mtu: net.tun_mtu,
                pad: 0,
            },
            config: XlatConfig {
                mtu4: t.ipv4_mtu,
                mtu6: t.ipv6_mtu,
                frag6: t.lowest_ipv6_mtu.min(t.ipv6_mtu),
                copy_tos: t.copy_tos,
            },
            now: NOW_NS,
            out6: HashMap::new(),
            in4: HashMap::new(),
            slots: Vec::new(),
            slices: vec![SliceEnt { state: SLICE_ACTIVE, pad: [0; 3], generation: GEN }],
            net,
            ident_key: IdentKey::new(0x0123_4567_89ab_cdef, 0x0fed_cba9_8765_4321),
            ident_table: (0..ident::TABLE).map(|i| (i as u16).wrapping_mul(40_503)).collect(),
            rng: 0x9e37_79b9_7f4a_7c15,
            fib_macs: None,
        }
    }

    /// Installs a record (and both keys) and returns its slot.
    pub fn install(&mut self, rec: SlotRec) -> u32 {
        let slot = self.slots.len() as u32;
        self.out6.insert(Key6::new(rec.src6, rec.dst6, rec.sport6, rec.dport), slot);
        self.in4.insert(Key4::new(rec.pool4, rec.dst4, rec.pool_port4, rec.dport), slot);
        self.slots.push(rec);
        slot
    }
}

impl Env for HostEnv {
    fn iface(&self, ifindex: u32) -> Option<IfaceEnt> {
        self.ifaces.get(&iface_slot(ifindex)).copied()
    }

    fn control(&self) -> Option<Control> {
        Some(self.control)
    }

    fn config(&self) -> Option<XlatConfig> {
        Some(self.config)
    }

    fn now_ns(&self) -> u64 {
        self.now
    }

    fn out6(&self, key: &Key6) -> Option<u32> {
        self.out6.get(key).copied()
    }

    fn in4(&self, key: &Key4) -> Option<u32> {
        self.in4.get(key).copied()
    }

    fn slot(&self, idx: u32) -> Option<SlotRec> {
        self.slots.get(idx as usize).copied()
    }

    fn slice(&self, idx: u16) -> Option<SliceEnt> {
        self.slices.get(usize::from(idx)).copied()
    }

    /// The kernel's order: forwarding on the ingress device, route, MTU,
    /// neighbour.
    fn fib(&mut self, p: &mut FibParams) -> i64 {
        if p.ifindex != TUN_IF {
            return -22;
        }
        if !self.net.forwarding {
            return FIB_RET_FWD_DISABLED;
        }
        let (out_if, smac, dmac, mtu) = match p.family {
            AF_INET => (UPSTREAM_IF, UPSTREAM_MAC, NH4_MAC, self.net.link_mtu4),
            AF_INET6 => (ACCESS_IF, ACCESS_MAC, NH6_MAC, self.net.link_mtu6),
            _ => return -97,
        };
        if u32::from(p.tot_len) > mtu {
            p.tot_len = mtu as u16;
            return FIB_RET_FRAG_NEEDED;
        }
        if !self.net.neigh {
            return FIB_RET_NO_NEIGH;
        }
        let (smac, dmac) = self.fib_macs.unwrap_or((smac, dmac));
        p.ifindex = out_if;
        p.smac = smac;
        p.dmac = dmac;
        FIB_RET_SUCCESS
    }

    fn egress(&self, ifindex: u32) -> Option<EgressEnt> {
        self.egress.get(&iface_slot(ifindex)).copied()
    }

    fn ident(&mut self, src6: &[u8; 16], dst4: &[u8; 4]) -> u16 {
        let m = self.ident_key.mix(src6, dst4, 17);
        self.rng = ident::xorshift(self.rng);
        let i = ident::index(m) as usize;
        let (c, id) = ident::advance(self.ident_table[i], ident::step(self.rng), m);
        self.ident_table[i] = c;
        id
    }
}

/// What the reference pipeline did with a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefOut {
    /// One translated frame on the wire (the only outcome a fast-path
    /// redirect may correspond to).
    Frame(Vec<u8>),
    /// Anything else: dropped, answered with an ICMP error, fragmented,
    /// held, or not forwarded by the kernel.
    Not(String),
}

/// The reference: the kernel's forwarding steps around the full engine.
pub struct Reference {
    pub nat: Nat64,
    pub ctx: WorkerCtx,
    pub rx: crossbeam_channel::Receiver<Event>,
    pub clock: Clock,
    pub cfg: Config,
    pub prefix: Prefix6052,
    pub pool: Vec<Ipv4Cidr>,
    buf: Vec<u8>,
    /// Packets processed since the fixture was built.
    pub uses: usize,
}

impl Reference {
    pub fn new(k: &Knobs) -> Self {
        let cfg = config(k);
        let clock = Clock::new();
        let (sink, rx) = AuditSink::bounded(1 << 16);
        let p = cfg.nat64.pool[0];
        let owned = (0..p.size() as u32).map(|i| p.network() + i).collect();
        let nat = ok(Nat64::new(&cfg, owned, sink, clock.clone()));
        let ctx = nat.new_worker(Arc::new(Counters::default()), 1);
        let t = &cfg.translation;
        let prefix = some(Prefix6052::new(t.nat64_prefix.network(), t.nat64_prefix.prefix_len()), "prefix");
        let pool = cfg.nat64.pool.clone();
        Self { nat, ctx, rx, clock, cfg, prefix, pool, buf: vec![0u8; HEADROOM + 70_000], uses: 0 }
    }

    pub fn in_pool(&self, a: u32) -> bool {
        self.pool.iter().any(|c| c.contains(a))
    }

    /// One packet through the engine: the single output packet, if any.
    fn engine(&mut self, l3: &[u8]) -> Result<Vec<u8>, String> {
        self.uses += 1;
        let n = l3.len();
        self.buf[HEADROOM..HEADROOM + n].copy_from_slice(l3);
        let v = self.nat.process(&mut self.buf, HEADROOM, n, &mut self.ctx);
        // Audit records are consumed so the bounded queue never refuses.
        for _ in self.rx.try_iter() {}
        match v {
            EngineVerdict::Forward { start, len } => Ok(self.buf[start..start + len].to_vec()),
            other => Err(format!("engine: {other:?}")),
        }
    }

    /// `kernel_egress(engine(kernel_ingress(frame)))` for a frame received
    /// on `ingress`.
    pub fn wire(&mut self, frame: &[u8], ingress: u32, net: &Net) -> RefOut {
        match self.wire_inner(frame, ingress, net) {
            Ok(f) => RefOut::Frame(f),
            Err(e) => RefOut::Not(e),
        }
    }

    fn wire_inner(&mut self, frame: &[u8], ingress: u32, net: &Net) -> Result<Vec<u8>, String> {
        let pkt = kernel_ingress(frame, ingress, net)?;
        let in_v = pkt[0] >> 4;
        let out = self.engine(&pkt)?;
        if out.first().map(|b| b >> 4) == Some(in_v) {
            return Err("engine answered in the same family (local ICMP error or hairpin)".into());
        }
        kernel_egress(out, net)
    }

    /// Installs the session `(src6, sport) ↔ (dst4, dport)` into `env` from
    /// engine state, applying plan §4.2 I3. Returns the slot, or `None`
    /// when the engine has no such session or I3 refuses it.
    pub fn install(&self, env: &mut HostEnv, src6: u128, sport: u16, dst4: u32, dport: u16) -> Option<u32> {
        let k6 = plat_nat64::state::Key6 { proto: 17, addr: src6, port: sport };
        let k4 = self.nat.state().lookup6(k6)?;
        if !self.nat.state().has_session(k4, (dst4, dport)) {
            return None;
        }
        // I3: no own-node or cross-node hairpin, no remote in the pool.
        if self.in_pool(dst4) {
            return None;
        }
        Some(env.install(SlotRec {
            state: SLOT_LIVE,
            slice: 0,
            generation: GEN,
            seen_ns: 0,
            src6: src6.to_be_bytes(),
            dst6: self.prefix.embed(dst4).to_be_bytes(),
            sport6: sport.to_be_bytes(),
            dport: dport.to_be_bytes(),
            pool_port4: k4.port.to_be_bytes(),
            pool4: k4.addr.to_be_bytes(),
            dst4: dst4.to_be_bytes(),
            ..SlotRec::default()
        }))
    }

    /// The engine's IPv4 transport address for `(src6, sport)`.
    pub fn mapping(&self, src6: u128, sport: u16) -> Option<(u32, u16)> {
        let k4 = self.nat.state().lookup6(plat_nat64::state::Key6 { proto: 17, addr: src6, port: sport })?;
        Some((k4.addr, k4.port))
    }
}

fn mac_of(ifindex: u32) -> [u8; 6] {
    if ifindex == ACCESS_IF { ACCESS_MAC } else { UPSTREAM_MAC }
}

/// The receiving kernel: `PACKET_OTHERHOST` drop, `ip6_rcv` / `ip_rcv`
/// validation and trimming, the forwarding hop decrement (RFC 1812 §5.3.1;
/// at TTL ≤ 1 the kernel answers itself) and the TUN MTU (IPv6 never
/// fragments in transit; IPv4 above it is fragmented or refused, so the
/// engine never sees it whole). Role-agnostic: the kernel routes either
/// family from either interface.
pub fn kernel_ingress(frame: &[u8], ingress: u32, net: &Net) -> Result<Vec<u8>, String> {
    if frame.len() < 14 || frame[..6] != mac_of(ingress) {
        return Err("kernel: not for us".into());
    }
    let l3 = &frame[14..];
    let mut pkt = match u16::from_be_bytes([frame[12], frame[13]]) {
        0x86dd => {
            if l3.len() < 40 || l3[0] >> 4 != 6 {
                return Err("kernel: bad ipv6".into());
            }
            let plen = usize::from(u16::from_be_bytes([l3[4], l3[5]]));
            if plen == 0 || 40 + plen > l3.len() {
                return Err("kernel: bad ipv6 length".into());
            }
            let mut p = l3[..40 + plen].to_vec();
            if p[7] <= 1 {
                return Err("kernel: hop limit (time exceeded)".into());
            }
            p[7] -= 1;
            p
        }
        0x0800 => {
            if l3.len() < 20 || l3[0] >> 4 != 4 {
                return Err("kernel: bad ipv4".into());
            }
            let ihl = usize::from(l3[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([l3[2], l3[3]]));
            if ihl < 20 || ihl > l3.len() || ck::fold(ck::sum(&l3[..ihl])) != 0xffff || total < ihl || total > l3.len()
            {
                return Err("kernel: bad ipv4 header".into());
            }
            let mut p = l3[..total].to_vec();
            if p[8] <= 1 {
                return Err("kernel: ttl (time exceeded)".into());
            }
            p[8] -= 1;
            fix_v4_csum(&mut p);
            p
        }
        _ => return Err("kernel: not ip".into()),
    };
    if pkt.len() as u32 > net.tun_mtu {
        return Err("kernel: above the TUN MTU".into());
    }
    if !net.forwarding {
        return Err("kernel: forwarding disabled".into());
    }
    pkt.shrink_to_fit();
    Ok(pkt)
}

/// The kernel forwarding the TUN's output: hop decrement, forwarding,
/// egress link MTU, neighbour, and the Ethernet header from the static FIB.
pub fn kernel_egress(mut pkt: Vec<u8>, net: &Net) -> Result<Vec<u8>, String> {
    if !net.forwarding || !net.neigh {
        return Err("kernel: egress not forwarded".into());
    }
    let (dmac, smac, ety, mtu) = match pkt.first().map(|b| b >> 4) {
        Some(4) => {
            if pkt[8] <= 1 {
                return Err("kernel: egress ttl".into());
            }
            pkt[8] -= 1;
            fix_v4_csum(&mut pkt);
            (NH4_MAC, UPSTREAM_MAC, [0x08, 0x00], net.link_mtu4)
        }
        Some(6) => {
            if pkt[7] <= 1 {
                return Err("kernel: egress hop limit".into());
            }
            pkt[7] -= 1;
            (NH6_MAC, ACCESS_MAC, [0x86, 0xdd], net.link_mtu6)
        }
        _ => return Err("kernel: egress not ip".into()),
    };
    if pkt.len() as u32 > mtu {
        return Err("kernel: egress above link MTU".into());
    }
    Ok(eth(dmac, smac, ety, &pkt))
}

/// Recomputes the IPv4 header checksum over IHL × 4 bytes (options
/// included), clamped to 20 bytes and the buffer for malformed IHLs.
pub fn fix_v4_csum(p: &mut [u8]) {
    let ihl = (usize::from(p[0] & 0x0f) * 4).clamp(20, p.len());
    p[10] = 0;
    p[11] = 0;
    let c = ck::finish(ck::sum(&p[..ihl]));
    p[10..12].copy_from_slice(&c.to_be_bytes());
}

pub fn eth(dst: [u8; 6], src: [u8; 6], ety: [u8; 2], l3: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + l3.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ety);
    f.extend_from_slice(l3);
    f
}

/// Header fields of an IPv6 UDP test packet.
#[derive(Debug, Clone, Copy)]
pub struct U6 {
    pub src: u128,
    pub sport: u16,
    pub dst: u128,
    pub dport: u16,
    pub hop: u8,
    pub tc: u8,
    pub flow: u32,
}

impl U6 {
    pub fn new(src: u128, sport: u16, dst: u128, dport: u16) -> Self {
        Self { src, sport, dst, dport, hop: 64, tc: 0, flow: 0 }
    }
}

/// IPv6 UDP packet with a correct checksum (0 sent as 0xFFFF).
pub fn udp6(h: &U6, payload: &[u8]) -> Vec<u8> {
    let l = 8 + payload.len();
    let mut p = vec![0u8; 40 + l];
    p[0..4].copy_from_slice(&((6u32 << 28) | (u32::from(h.tc) << 20) | (h.flow & 0xf_ffff)).to_be_bytes());
    p[4..6].copy_from_slice(&(l as u16).to_be_bytes());
    p[6] = 17;
    p[7] = h.hop;
    p[8..24].copy_from_slice(&h.src.to_be_bytes());
    p[24..40].copy_from_slice(&h.dst.to_be_bytes());
    p[40..42].copy_from_slice(&h.sport.to_be_bytes());
    p[42..44].copy_from_slice(&h.dport.to_be_bytes());
    p[44..46].copy_from_slice(&(l as u16).to_be_bytes());
    p[48..].copy_from_slice(payload);
    let c = ck::finish(ck::pseudo_v6(h.src, h.dst, 17, l as u32) + ck::sum(&p[40..]));
    p[46..48].copy_from_slice(&ck::udp_nonzero(c).to_be_bytes());
    p
}

/// Header fields of an IPv4 UDP test packet.
#[derive(Debug, Clone, Copy)]
pub struct U4 {
    pub src: u32,
    pub sport: u16,
    pub dst: u32,
    pub dport: u16,
    pub ttl: u8,
    pub tos: u8,
    pub id: u16,
    pub df: bool,
}

impl U4 {
    pub fn new(src: u32, sport: u16, dst: u32, dport: u16) -> Self {
        Self { src, sport, dst, dport, ttl: 64, tos: 0, id: 0x1234, df: true }
    }
}

/// IPv4 UDP packet with correct header and UDP checksums (0 sent as 0xFFFF).
pub fn udp4(h: &U4, payload: &[u8]) -> Vec<u8> {
    let l = 8 + payload.len();
    let total = 20 + l;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[1] = h.tos;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&h.id.to_be_bytes());
    p[6] = if h.df { 0x40 } else { 0 };
    p[8] = h.ttl;
    p[9] = 17;
    p[12..16].copy_from_slice(&h.src.to_be_bytes());
    p[16..20].copy_from_slice(&h.dst.to_be_bytes());
    fix_v4_csum(&mut p);
    p[20..22].copy_from_slice(&h.sport.to_be_bytes());
    p[22..24].copy_from_slice(&h.dport.to_be_bytes());
    p[24..26].copy_from_slice(&(l as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    let c = ck::finish(ck::pseudo_v4(h.src, h.dst, 17, l as u16) + ck::sum(&p[20..]));
    p[26..28].copy_from_slice(&ck::udp_nonzero(c).to_be_bytes());
    p
}

/// Sets payload bytes `word..word + 2` (an even payload offset) so that
/// the one's-complement sum `base + payload` (the payload with that word
/// zeroed, plus `base`) is negative zero: the computed checksum is then 0
/// and transmitted as 0xFFFF (RFC 768). No-op for payloads under 2 bytes.
pub fn force_zero_csum(payload: &mut [u8], base: u64) {
    if payload.len() < 2 {
        return;
    }
    let w = (payload.len() - 2) & !1;
    payload[w] = 0;
    payload[w + 1] = 0;
    let s = ck::fold(base + ck::sum(payload));
    payload[w..w + 2].copy_from_slice(&(!s).to_be_bytes());
}

/// The UDP checksum sum (pseudo-header + header with checksum 0) without
/// the payload, for [`force_zero_csum`]: IPv6 side.
pub fn base_sum6(src: u128, dst: u128, sport: u16, dport: u16, payload_len: usize) -> u64 {
    let l = (8 + payload_len) as u16;
    ck::pseudo_v6(src, dst, 17, u32::from(l)) + u64::from(sport) + u64::from(dport) + u64::from(l)
}

/// IPv4 side of [`base_sum6`].
pub fn base_sum4(src: u32, dst: u32, sport: u16, dport: u16, payload_len: usize) -> u64 {
    let l = (8 + payload_len) as u16;
    ck::pseudo_v4(src, dst, 17, l) + u64::from(sport) + u64::from(dport) + u64::from(l)
}

/// The frame a redirect produces: the output header block, then the
/// payload, trimmed to `new_len`. Checks that `new_len` and `trim` account
/// for every input byte.
pub fn apply(frame: &[u8], a: &Action) -> Option<Vec<u8>> {
    let (hdr, in_hdr, new_len, trim): (&[u8], usize, u32, u32) = match a {
        Action::V6ToV4(Verdict::Redirect { hdr, new_len, trim, .. }) => (hdr, HDR6, *new_len, *trim),
        Action::V4ToV6(Verdict::Redirect { hdr, new_len, trim, .. }) => (hdr, HDR4, *new_len, *trim),
        _ => return None,
    };
    let body = new_len as usize - hdr.len();
    assert_eq!(in_hdr + body + trim as usize, frame.len(), "new_len/trim account for the frame");
    let mut o = hdr.to_vec();
    o.extend_from_slice(&frame[in_hdr..in_hdr + body]);
    Some(o)
}

/// Compares a candidate frame with the reference frame, substituting the
/// candidate's IPv4 Identification into the reference (random by design,
/// plan §2.4) and recomputing its header checksum. Also checks ID = 0
/// whenever DF = 1.
pub fn same_frame(cand: &[u8], reference: &[u8]) -> Result<(), String> {
    let mut r = reference.to_vec();
    if cand.len() >= 34 && cand[12..14] == [0x08, 0x00] && r.len() >= 34 {
        if cand[20] & 0x40 != 0 && cand[18..20] != [0, 0] {
            return Err(format!("DF set with ID {:02x}{:02x}", cand[18], cand[19]));
        }
        r[18..20].copy_from_slice(&cand[18..20]);
        fix_v4_csum(&mut r[14..]);
    }
    if cand == r.as_slice() { Ok(()) } else { Err(format!("mismatch:\n cand {}\n ref  {}", hex(cand), hex(&r))) }
}

/// Runs a frame through the candidate and the reference. A redirect must
/// equal the reference's single translated frame (the safety property);
/// returns the candidate's pass reason otherwise.
pub fn differential(
    r: &mut Reference,
    env: &mut HostEnv,
    frame: &[u8],
    ingress: u32,
) -> Result<Option<PassReason>, String> {
    differential_full(r, env, frame, ingress).map(|(p, _)| p)
}

/// [`differential`], also returning what the reference did.
pub fn differential_full(
    r: &mut Reference,
    env: &mut HostEnv,
    frame: &[u8],
    ingress: u32,
) -> Result<(Option<PassReason>, RefOut), String> {
    let a = plat_xdp_core::decide_frame(env, ingress, frame);
    let net = env.net;
    let reference = r.wire(frame, ingress, &net);
    match apply(frame, &a) {
        None => Ok((a.pass_reason(), reference)),
        Some(cand) => match &reference {
            RefOut::Frame(f) => same_frame(&cand, f).map(|()| (None, reference)),
            RefOut::Not(why) => Err(format!("candidate redirected, reference did not ({why}): {}", hex(frame))),
        },
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len()).step_by(2).map(|i| ok(u8::from_str_radix(&s[i..i + 2], 16))).collect()
}

/// A subscriber address inside the client prefix.
pub fn client(host: u128) -> u128 {
    CLIENT_NET | (host & ((1u128 << (128 - CLIENT_BITS)) - 1))
}

/// A server address in one of the documentation networks.
pub fn server(net: u8, host: u8) -> u32 {
    SERVER_NETS[usize::from(net) % 2] | u32::from(host)
}

/// An established outbound session: the creating packet went through the
/// reference and the session was installed into a fresh `env`.
pub struct Session {
    pub src6: u128,
    pub sport: u16,
    pub dst4: u32,
    pub dport: u16,
    pub pool4: u32,
    pub pool_port: u16,
    pub slot: u32,
}

/// Creates the session `(src6, sport) → (dst4, dport)` through the
/// reference and installs it into `env`.
pub fn establish(
    r: &mut Reference,
    env: &mut HostEnv,
    src6: u128,
    sport: u16,
    dst4: u32,
    dport: u16,
) -> Result<Session, String> {
    let dst6 = r.prefix.embed(dst4);
    let create = eth(ACCESS_MAC, CLIENT_MAC, [0x86, 0xdd], &udp6(&U6::new(src6, sport, dst6, dport), b"create"));
    let net = env.net;
    if let RefOut::Not(why) = r.wire(&create, ACCESS_IF, &net) {
        return Err(format!("creating packet not forwarded: {why}"));
    }
    let slot = r.install(env, src6, sport, dst4, dport).ok_or("install refused")?;
    let (pool4, pool_port) = r.mapping(src6, sport).ok_or("no mapping")?;
    Ok(Session { src6, sport, dst4, dport, pool4, pool_port, slot })
}

/// Fixtures are rebuilt after this many packets, so ports and subscribers
/// never run out in long proptest runs.
pub const FIXTURE_USES: usize = 20_000;

/// Number of proptest cases: `PROPTEST_CASES`, default 10 000 (CI sets
/// 1 000 000).
pub fn cases() -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000)
}
