//! Peer wire codec.
//!
//! Frame: `u32 len | u8 type | payload`, where `len` counts the type byte
//! and the payload and is at most the configured `max_frame`. Fixed fields
//! are little-endian; there is no serde and no self-description. Decoding
//! is strict: every length is checked before use, list counts are checked
//! against the bytes left before anything is allocated, enum and bool bytes
//! must be valid, and the payload must be consumed exactly. Unknown types
//! are refused (the caller closes and audits the connection).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10 (Information Input Validation) - strict decoding of
//!   peer frames; SC-5 (Denial-of-Service Protection) - frame size cap and
//!   allocation bounded by the received bytes

use plat_common::Ipv4Cidr;
use std::net::Ipv4Addr;

use crate::digest::PartitionScheme;
use crate::slices::{MemberId, SliceId};
use crate::view::{MAX_MEMBERS, View};

/// Peer protocol version carried in `Hello`.
pub const PROTO_VERSION: u16 = 1;

/// `u32 len` + `u8 type`.
pub const HEADER_LEN: usize = 5;

/// Smallest accepted `max_frame` (fits every control message).
pub const MIN_MAX_FRAME: usize = 1024;

/// Longest node name in `Hello`.
pub const MAX_NAME_LEN: usize = 64;

/// Most owned CIDRs a `Hello` may carry (legacy overlap check).
pub const MAX_OWNED: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("frame length {0} exceeds the limit {1}")]
    TooLarge(usize, usize),
    #[error("empty frame")]
    Empty,
    #[error("unknown message type {0}")]
    UnknownType(u8),
    #[error("truncated payload")]
    Truncated,
    #[error("{0} trailing payload bytes")]
    Trailing(usize),
    #[error("invalid field {0}")]
    Invalid(&'static str),
}

/// Why a peer was refused (`cluster_peer_rejected` `cluster.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    NotAllowed,
    IdMismatch,
    DuplicateId,
    DigestMismatch,
    Version,
    Overlap,
    Handshake,
    /// Malformed or unexpected frame on an established connection.
    Protocol,
    /// Replication input outside the slice, pool or client prefixes.
    InvalidInput,
    /// Connection or pending-handshake limit.
    Capacity,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::NotAllowed => "not_allowed",
            RejectReason::IdMismatch => "id_mismatch",
            RejectReason::DuplicateId => "duplicate_id",
            RejectReason::DigestMismatch => "digest_mismatch",
            RejectReason::Version => "version",
            RejectReason::Overlap => "overlap",
            RejectReason::Handshake => "handshake",
            RejectReason::Protocol => "protocol",
            RejectReason::InvalidInput => "invalid_input",
            RejectReason::Capacity => "capacity",
        }
    }

    fn code(self) -> u8 {
        match self {
            RejectReason::NotAllowed => 1,
            RejectReason::IdMismatch => 2,
            RejectReason::DuplicateId => 3,
            RejectReason::DigestMismatch => 4,
            RejectReason::Version => 5,
            RejectReason::Overlap => 6,
            RejectReason::Handshake => 7,
            RejectReason::Protocol => 8,
            RejectReason::InvalidInput => 9,
            RejectReason::Capacity => 10,
        }
    }

    fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => RejectReason::NotAllowed,
            2 => RejectReason::IdMismatch,
            3 => RejectReason::DuplicateId,
            4 => RejectReason::DigestMismatch,
            5 => RejectReason::Version,
            6 => RejectReason::Overlap,
            7 => RejectReason::Handshake,
            8 => RejectReason::Protocol,
            9 => RejectReason::InvalidInput,
            10 => RejectReason::Capacity,
            _ => return None,
        })
    }
}

/// A port block on the wire: the IPv4 address itself (pool indexes are
/// node-local) and the block number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireBlock {
    pub addr: u32,
    pub block: u16,
}

/// A BIB entry on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireBib {
    pub sub: u128,
    /// IANA protocol: 1 (ICMP), 6 (TCP) or 17 (UDP).
    pub proto: u8,
    pub v6: u128,
    pub port6: u16,
    pub v4: u32,
    pub port4: u16,
    pub created_wall_us: u64,
}

/// One snapshot record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapRecord {
    Block { sub: u128, block: WireBlock, alloc_wall_us: u64 },
    Bib(WireBib),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub proto_version: u16,
    pub node_id: MemberId,
    /// `[A-Za-z0-9._-]`, at most [`MAX_NAME_LEN`] bytes.
    pub name: String,
    pub config_digest: [u8; 32],
    pub epoch: u64,
    pub scheme: PartitionScheme,
    /// Owned CIDRs in contiguous/`owned_pool` mode (overlap check); empty
    /// with slices.
    pub owned: Vec<Ipv4Cidr>,
}

/// Every peer message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Hello(Hello),
    /// `None` = accepted.
    HelloAck(Option<RejectReason>),
    /// `pre`: a pre-vote (Raft §9.6) that changes no voter state, so a
    /// partitioned node cannot inflate the term and depose a healthy leader.
    Vote {
        epoch: u64,
        pre: bool,
    },
    /// `last_view`: the newest view the voter has acked (the new leader
    /// bases its first view on the newest one from its quorum).
    VoteAck {
        epoch: u64,
        pre: bool,
        granted: bool,
        last_view: Option<View>,
    },
    ViewPropose {
        base_epoch: u64,
        view: View,
    },
    ViewAck {
        epoch: u64,
    },
    /// Leader to member. `seq` echoes the newest `HeartbeatAck.seq` the
    /// leader received from this member (lease anchor, see membership).
    /// `epoch` is the leader's current view, `commit` the newest view a
    /// majority acked (members gain slices only under committed views).
    Heartbeat {
        epoch: u64,
        lease_ms: u32,
        seq: u64,
        commit: u64,
    },
    HeartbeatAck {
        epoch: u64,
        seq: u64,
    },
    Reserve {
        slice: SliceId,
        seq: u64,
        blocks: Vec<WireBlock>,
    },
    Ack {
        slice: SliceId,
        seq: u64,
    },
    BlockAlloc {
        slice: SliceId,
        seq: u64,
        sub: u128,
        block: WireBlock,
        wall_us: u64,
    },
    BlockRelease {
        slice: SliceId,
        seq: u64,
        sub: u128,
        block: WireBlock,
    },
    BibCreate {
        slice: SliceId,
        seq: u64,
        bib: WireBib,
    },
    BibDelete {
        slice: SliceId,
        seq: u64,
        proto: u8,
        v4: u32,
        port4: u16,
    },
    SubHome {
        sub: u128,
        slice: SliceId,
    },
    SubGone {
        sub: u128,
    },
    SnapshotBegin {
        slice: SliceId,
        seq: u64,
    },
    SnapshotChunk {
        slice: SliceId,
        seq: u64,
        records: Vec<SnapRecord>,
    },
    SnapshotEnd {
        slice: SliceId,
        seq: u64,
    },
    /// Backup to primary: the backup's copy of `slice` has a gap at
    /// record `seq` (lost or refused input); send a new snapshot.
    Resync {
        slice: SliceId,
        seq: u64,
    },
    HandoverFence {
        slice: SliceId,
        epoch: u64,
        final_seq: u64,
    },
    HandoverDone {
        slice: SliceId,
        epoch: u64,
    },
    /// Member to every voter: whether every slice it backs up in the view
    /// `epoch` is in sync (failback waits for it).
    SyncStatus {
        epoch: u64,
        in_sync: bool,
    },
}

mod ty {
    pub const HELLO: u8 = 1;
    pub const HELLO_ACK: u8 = 2;
    pub const VOTE: u8 = 3;
    pub const VOTE_ACK: u8 = 4;
    pub const VIEW_PROPOSE: u8 = 5;
    pub const VIEW_ACK: u8 = 6;
    pub const HEARTBEAT: u8 = 7;
    pub const HEARTBEAT_ACK: u8 = 8;
    pub const RESERVE: u8 = 16;
    pub const ACK: u8 = 17;
    pub const BLOCK_ALLOC: u8 = 18;
    pub const BLOCK_RELEASE: u8 = 19;
    pub const BIB_CREATE: u8 = 20;
    pub const BIB_DELETE: u8 = 21;
    pub const SUB_HOME: u8 = 22;
    pub const SUB_GONE: u8 = 23;
    pub const SNAPSHOT_BEGIN: u8 = 24;
    pub const SNAPSHOT_CHUNK: u8 = 25;
    pub const SNAPSHOT_END: u8 = 26;
    pub const RESYNC: u8 = 27;
    pub const HANDOVER_FENCE: u8 = 32;
    pub const HANDOVER_DONE: u8 = 33;
    pub const SYNC_STATUS: u8 = 34;
}

impl Msg {
    /// Wire type byte.
    pub fn type_code(&self) -> u8 {
        match self {
            Msg::Hello(_) => ty::HELLO,
            Msg::HelloAck(_) => ty::HELLO_ACK,
            Msg::Vote { .. } => ty::VOTE,
            Msg::VoteAck { .. } => ty::VOTE_ACK,
            Msg::ViewPropose { .. } => ty::VIEW_PROPOSE,
            Msg::ViewAck { .. } => ty::VIEW_ACK,
            Msg::Heartbeat { .. } => ty::HEARTBEAT,
            Msg::HeartbeatAck { .. } => ty::HEARTBEAT_ACK,
            Msg::Reserve { .. } => ty::RESERVE,
            Msg::Ack { .. } => ty::ACK,
            Msg::BlockAlloc { .. } => ty::BLOCK_ALLOC,
            Msg::BlockRelease { .. } => ty::BLOCK_RELEASE,
            Msg::BibCreate { .. } => ty::BIB_CREATE,
            Msg::BibDelete { .. } => ty::BIB_DELETE,
            Msg::SubHome { .. } => ty::SUB_HOME,
            Msg::SubGone { .. } => ty::SUB_GONE,
            Msg::SnapshotBegin { .. } => ty::SNAPSHOT_BEGIN,
            Msg::SnapshotChunk { .. } => ty::SNAPSHOT_CHUNK,
            Msg::SnapshotEnd { .. } => ty::SNAPSHOT_END,
            Msg::HandoverFence { .. } => ty::HANDOVER_FENCE,
            Msg::HandoverDone { .. } => ty::HANDOVER_DONE,
            Msg::Resync { .. } => ty::RESYNC,
            Msg::SyncStatus { .. } => ty::SYNC_STATUS,
        }
    }

    /// Membership traffic, which must be queued ahead of replication data
    /// so a replication backlog cannot cause a false failover.
    pub fn is_control(&self) -> bool {
        matches!(
            self,
            Msg::Hello(_)
                | Msg::HelloAck(_)
                | Msg::Vote { .. }
                | Msg::VoteAck { .. }
                | Msg::ViewPropose { .. }
                | Msg::ViewAck { .. }
                | Msg::Heartbeat { .. }
                | Msg::HeartbeatAck { .. }
                | Msg::HandoverFence { .. }
                | Msg::HandoverDone { .. }
                | Msg::SyncStatus { .. }
        )
    }
}

// ---------------------------------------------------------------- encode

fn put_view(out: &mut Vec<u8>, v: &View) {
    out.extend_from_slice(&v.epoch.to_le_bytes());
    out.extend_from_slice(&v.leader.to_le_bytes());
    for list in [&v.live, &v.standby] {
        out.push(list.len().min(MAX_MEMBERS) as u8);
        for m in list.iter().take(MAX_MEMBERS) {
            out.extend_from_slice(&m.to_le_bytes());
        }
    }
}

fn put_block(out: &mut Vec<u8>, b: &WireBlock) {
    out.extend_from_slice(&b.addr.to_le_bytes());
    out.extend_from_slice(&b.block.to_le_bytes());
}

fn put_bib(out: &mut Vec<u8>, b: &WireBib) {
    out.extend_from_slice(&b.sub.to_le_bytes());
    out.push(b.proto);
    out.extend_from_slice(&b.v6.to_le_bytes());
    out.extend_from_slice(&b.port6.to_le_bytes());
    out.extend_from_slice(&b.v4.to_le_bytes());
    out.extend_from_slice(&b.port4.to_le_bytes());
    out.extend_from_slice(&b.created_wall_us.to_le_bytes());
}

fn put_slice_seq(out: &mut Vec<u8>, slice: SliceId, seq: u64) {
    out.extend_from_slice(&slice.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
}

/// Append one frame for `msg` to `out`. Fails (leaving `out` unchanged)
/// when the frame would exceed `max_frame` or a field is unencodable; the
/// caller must then split the message (snapshot chunks) or drop it.
pub fn encode(msg: &Msg, max_frame: usize, out: &mut Vec<u8>) -> Result<(), CodecError> {
    let start = out.len();
    out.extend_from_slice(&[0; 4]);
    out.push(msg.type_code());
    match msg {
        Msg::Hello(h) => {
            if h.name.len() > MAX_NAME_LEN || !valid_name(h.name.as_bytes()) {
                out.truncate(start);
                return Err(CodecError::Invalid("hello.name"));
            }
            if h.owned.len() > MAX_OWNED {
                out.truncate(start);
                return Err(CodecError::Invalid("hello.owned"));
            }
            out.extend_from_slice(&h.proto_version.to_le_bytes());
            out.extend_from_slice(&h.node_id.to_le_bytes());
            out.push(h.name.len() as u8);
            out.extend_from_slice(h.name.as_bytes());
            out.extend_from_slice(&h.config_digest);
            out.extend_from_slice(&h.epoch.to_le_bytes());
            out.push(h.scheme.code());
            out.extend_from_slice(&(h.owned.len() as u16).to_le_bytes());
            for c in &h.owned {
                out.extend_from_slice(&c.network().to_le_bytes());
                out.push(c.prefix_len());
            }
        }
        Msg::HelloAck(r) => out.push(r.map_or(0, RejectReason::code)),
        Msg::Vote { epoch, pre } => {
            out.extend_from_slice(&epoch.to_le_bytes());
            out.push(u8::from(*pre));
        }
        Msg::ViewAck { epoch } => out.extend_from_slice(&epoch.to_le_bytes()),
        Msg::VoteAck { epoch, pre, granted, last_view } => {
            out.extend_from_slice(&epoch.to_le_bytes());
            out.push(u8::from(*pre));
            out.push(u8::from(*granted));
            match last_view {
                Some(v) => {
                    if v.live.len() > MAX_MEMBERS || v.standby.len() > MAX_MEMBERS {
                        out.truncate(start);
                        return Err(CodecError::Invalid("view.members"));
                    }
                    out.push(1);
                    put_view(out, v);
                }
                None => out.push(0),
            }
        }
        Msg::ViewPropose { base_epoch, view } => {
            if view.live.len() > MAX_MEMBERS || view.standby.len() > MAX_MEMBERS {
                out.truncate(start);
                return Err(CodecError::Invalid("view.members"));
            }
            out.extend_from_slice(&base_epoch.to_le_bytes());
            put_view(out, view);
        }
        Msg::Heartbeat { epoch, lease_ms, seq, commit } => {
            out.extend_from_slice(&epoch.to_le_bytes());
            out.extend_from_slice(&lease_ms.to_le_bytes());
            out.extend_from_slice(&seq.to_le_bytes());
            out.extend_from_slice(&commit.to_le_bytes());
        }
        Msg::HeartbeatAck { epoch, seq } => {
            out.extend_from_slice(&epoch.to_le_bytes());
            out.extend_from_slice(&seq.to_le_bytes());
        }
        Msg::Reserve { slice, seq, blocks } => {
            put_slice_seq(out, *slice, *seq);
            out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
            for b in blocks {
                put_block(out, b);
            }
        }
        Msg::Ack { slice, seq }
        | Msg::SnapshotBegin { slice, seq }
        | Msg::SnapshotEnd { slice, seq }
        | Msg::Resync { slice, seq } => put_slice_seq(out, *slice, *seq),
        Msg::BlockAlloc { slice, seq, sub, block, wall_us } => {
            put_slice_seq(out, *slice, *seq);
            out.extend_from_slice(&sub.to_le_bytes());
            put_block(out, block);
            out.extend_from_slice(&wall_us.to_le_bytes());
        }
        Msg::BlockRelease { slice, seq, sub, block } => {
            put_slice_seq(out, *slice, *seq);
            out.extend_from_slice(&sub.to_le_bytes());
            put_block(out, block);
        }
        Msg::BibCreate { slice, seq, bib } => {
            put_slice_seq(out, *slice, *seq);
            put_bib(out, bib);
        }
        Msg::BibDelete { slice, seq, proto, v4, port4 } => {
            put_slice_seq(out, *slice, *seq);
            out.push(*proto);
            out.extend_from_slice(&v4.to_le_bytes());
            out.extend_from_slice(&port4.to_le_bytes());
        }
        Msg::SubHome { sub, slice } => {
            out.extend_from_slice(&sub.to_le_bytes());
            out.extend_from_slice(&slice.to_le_bytes());
        }
        Msg::SubGone { sub } => out.extend_from_slice(&sub.to_le_bytes()),
        Msg::SnapshotChunk { slice, seq, records } => {
            put_slice_seq(out, *slice, *seq);
            out.extend_from_slice(&(records.len() as u32).to_le_bytes());
            for r in records {
                match r {
                    SnapRecord::Block { sub, block, alloc_wall_us } => {
                        out.push(1);
                        out.extend_from_slice(&sub.to_le_bytes());
                        put_block(out, block);
                        out.extend_from_slice(&alloc_wall_us.to_le_bytes());
                    }
                    SnapRecord::Bib(b) => {
                        out.push(2);
                        put_bib(out, b);
                    }
                }
            }
        }
        Msg::HandoverFence { slice, epoch, final_seq } => {
            out.extend_from_slice(&slice.to_le_bytes());
            out.extend_from_slice(&epoch.to_le_bytes());
            out.extend_from_slice(&final_seq.to_le_bytes());
        }
        Msg::HandoverDone { slice, epoch } => {
            out.extend_from_slice(&slice.to_le_bytes());
            out.extend_from_slice(&epoch.to_le_bytes());
        }
        Msg::SyncStatus { epoch, in_sync } => {
            out.extend_from_slice(&epoch.to_le_bytes());
            out.push(u8::from(*in_sync));
        }
    }
    let len = out.len() - start - 4;
    if len > max_frame || len > u32::MAX as usize {
        out.truncate(start);
        return Err(CodecError::TooLarge(len, max_frame));
    }
    out[start..start + 4].copy_from_slice(&(len as u32).to_le_bytes());
    Ok(())
}

// ---------------------------------------------------------------- decode

fn valid_name(b: &[u8]) -> bool {
    b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn valid_proto(p: u8) -> bool {
    matches!(p, 1 | 6 | 17)
}

/// Bounds-checked cursor over one payload.
struct Rd<'a> {
    b: &'a [u8],
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let (h, t) = self.b.split_at_checked(n).ok_or(CodecError::Truncated)?;
        self.b = t;
        Ok(h)
    }

    fn arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?.try_into().map_err(|_| CodecError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.arr::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.arr()?))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.arr()?))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.arr()?))
    }

    fn u128(&mut self) -> Result<u128, CodecError> {
        Ok(u128::from_le_bytes(self.arr()?))
    }

    fn bool(&mut self, what: &'static str) -> Result<bool, CodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecError::Invalid(what)),
        }
    }

    /// A list count whose elements take at least `min_elem` bytes each;
    /// refused before allocation when the payload cannot hold them.
    fn count(&mut self, n: usize, min_elem: usize) -> Result<usize, CodecError> {
        if n.saturating_mul(min_elem) > self.b.len() { Err(CodecError::Truncated) } else { Ok(n) }
    }

    fn slice_seq(&mut self) -> Result<(SliceId, u64), CodecError> {
        Ok((self.u16()?, self.u64()?))
    }

    fn block(&mut self) -> Result<WireBlock, CodecError> {
        Ok(WireBlock { addr: self.u32()?, block: self.u16()? })
    }

    fn bib(&mut self) -> Result<WireBib, CodecError> {
        let sub = self.u128()?;
        let proto = self.u8()?;
        if !valid_proto(proto) {
            return Err(CodecError::Invalid("bib.proto"));
        }
        Ok(WireBib {
            sub,
            proto,
            v6: self.u128()?,
            port6: self.u16()?,
            v4: self.u32()?,
            port4: self.u16()?,
            created_wall_us: self.u64()?,
        })
    }

    fn members(&mut self) -> Result<Vec<MemberId>, CodecError> {
        let n = usize::from(self.u8()?);
        if n > MAX_MEMBERS {
            return Err(CodecError::Invalid("view.members"));
        }
        let n = self.count(n, 2)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.u16()?);
        }
        if !v.windows(2).all(|w| w[0] < w[1]) {
            return Err(CodecError::Invalid("view.members order"));
        }
        Ok(v)
    }

    fn view(&mut self) -> Result<View, CodecError> {
        let epoch = self.u64()?;
        let leader = self.u16()?;
        let live = self.members()?;
        let standby = self.members()?;
        if standby.iter().any(|m| live.binary_search(m).is_ok()) {
            return Err(CodecError::Invalid("view.standby"));
        }
        Ok(View { epoch, live, standby, leader })
    }
}

/// Decode one frame from the front of `buf`. `Ok(None)` means more bytes
/// are needed; `Ok(Some((msg, used)))` consumed `used` bytes. Any error is
/// fatal for the connection.
pub fn decode(buf: &[u8], max_frame: usize) -> Result<Option<(Msg, usize)>, CodecError> {
    let Some(hdr) = buf.first_chunk::<4>() else { return Ok(None) };
    let len = u32::from_le_bytes(*hdr) as usize;
    if len == 0 {
        return Err(CodecError::Empty);
    }
    if len > max_frame {
        return Err(CodecError::TooLarge(len, max_frame));
    }
    let Some(frame) = buf.get(4..4 + len) else { return Ok(None) };
    let (t, payload) = frame.split_first().ok_or(CodecError::Empty)?;
    let msg = decode_payload(*t, payload)?;
    Ok(Some((msg, 4 + len)))
}

/// Decode a payload of type `t` (without the frame header).
pub fn decode_payload(t: u8, payload: &[u8]) -> Result<Msg, CodecError> {
    let mut r = Rd { b: payload };
    let msg = match t {
        ty::HELLO => {
            let proto_version = r.u16()?;
            let node_id = r.u16()?;
            let n = usize::from(r.u8()?);
            if n > MAX_NAME_LEN {
                return Err(CodecError::Invalid("hello.name"));
            }
            let name = r.take(n)?;
            if !valid_name(name) {
                return Err(CodecError::Invalid("hello.name"));
            }
            let name = String::from_utf8(name.to_vec()).map_err(|_| CodecError::Invalid("hello.name"))?;
            let config_digest = r.arr::<32>()?;
            let epoch = r.u64()?;
            let scheme = PartitionScheme::from_code(r.u8()?).ok_or(CodecError::Invalid("hello.scheme"))?;
            let n = usize::from(r.u16()?);
            if n > MAX_OWNED {
                return Err(CodecError::Invalid("hello.owned"));
            }
            let n = r.count(n, 5)?;
            let mut owned = Vec::with_capacity(n);
            for _ in 0..n {
                let net = r.u32()?;
                let len = r.u8()?;
                owned.push(Ipv4Cidr::new(Ipv4Addr::from(net), len).map_err(|_| CodecError::Invalid("hello.owned"))?);
            }
            Msg::Hello(Hello { proto_version, node_id, name, config_digest, epoch, scheme, owned })
        }
        ty::HELLO_ACK => match r.u8()? {
            0 => Msg::HelloAck(None),
            c => Msg::HelloAck(Some(RejectReason::from_code(c).ok_or(CodecError::Invalid("hello_ack.reason"))?)),
        },
        ty::VOTE => Msg::Vote { epoch: r.u64()?, pre: r.bool("vote.pre")? },
        ty::VOTE_ACK => {
            let epoch = r.u64()?;
            let pre = r.bool("vote_ack.pre")?;
            let granted = r.bool("vote_ack.granted")?;
            let last_view = if r.bool("vote_ack.view")? { Some(r.view()?) } else { None };
            Msg::VoteAck { epoch, pre, granted, last_view }
        }
        ty::VIEW_PROPOSE => {
            let base_epoch = r.u64()?;
            Msg::ViewPropose { base_epoch, view: r.view()? }
        }
        ty::VIEW_ACK => Msg::ViewAck { epoch: r.u64()? },
        ty::HEARTBEAT => Msg::Heartbeat { epoch: r.u64()?, lease_ms: r.u32()?, seq: r.u64()?, commit: r.u64()? },
        ty::HEARTBEAT_ACK => Msg::HeartbeatAck { epoch: r.u64()?, seq: r.u64()? },
        ty::RESERVE => {
            let (slice, seq) = r.slice_seq()?;
            let n = r.u32()? as usize;
            let n = r.count(n, 6)?;
            let mut blocks = Vec::with_capacity(n);
            for _ in 0..n {
                blocks.push(r.block()?);
            }
            Msg::Reserve { slice, seq, blocks }
        }
        ty::ACK => {
            let (slice, seq) = r.slice_seq()?;
            Msg::Ack { slice, seq }
        }
        ty::BLOCK_ALLOC => {
            let (slice, seq) = r.slice_seq()?;
            Msg::BlockAlloc { slice, seq, sub: r.u128()?, block: r.block()?, wall_us: r.u64()? }
        }
        ty::BLOCK_RELEASE => {
            let (slice, seq) = r.slice_seq()?;
            Msg::BlockRelease { slice, seq, sub: r.u128()?, block: r.block()? }
        }
        ty::BIB_CREATE => {
            let (slice, seq) = r.slice_seq()?;
            Msg::BibCreate { slice, seq, bib: r.bib()? }
        }
        ty::BIB_DELETE => {
            let (slice, seq) = r.slice_seq()?;
            let proto = r.u8()?;
            if !valid_proto(proto) {
                return Err(CodecError::Invalid("bib.proto"));
            }
            Msg::BibDelete { slice, seq, proto, v4: r.u32()?, port4: r.u16()? }
        }
        ty::SUB_HOME => Msg::SubHome { sub: r.u128()?, slice: r.u16()? },
        ty::SUB_GONE => Msg::SubGone { sub: r.u128()? },
        ty::SNAPSHOT_BEGIN => {
            let (slice, seq) = r.slice_seq()?;
            Msg::SnapshotBegin { slice, seq }
        }
        ty::SNAPSHOT_CHUNK => {
            let (slice, seq) = r.slice_seq()?;
            let n = r.u32()? as usize;
            // Smallest record: tag + Block (1 + 16 + 6 + 8).
            let n = r.count(n, 31)?;
            let mut records = Vec::with_capacity(n);
            for _ in 0..n {
                records.push(match r.u8()? {
                    1 => SnapRecord::Block { sub: r.u128()?, block: r.block()?, alloc_wall_us: r.u64()? },
                    2 => SnapRecord::Bib(r.bib()?),
                    _ => return Err(CodecError::Invalid("snapshot.record")),
                });
            }
            Msg::SnapshotChunk { slice, seq, records }
        }
        ty::SNAPSHOT_END => {
            let (slice, seq) = r.slice_seq()?;
            Msg::SnapshotEnd { slice, seq }
        }
        ty::RESYNC => {
            let (slice, seq) = r.slice_seq()?;
            Msg::Resync { slice, seq }
        }
        ty::SYNC_STATUS => Msg::SyncStatus {
            epoch: r.u64()?,
            in_sync: match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(CodecError::Invalid("sync_status.in_sync")),
            },
        },
        ty::HANDOVER_FENCE => Msg::HandoverFence { slice: r.u16()?, epoch: r.u64()?, final_seq: r.u64()? },
        ty::HANDOVER_DONE => Msg::HandoverDone { slice: r.u16()?, epoch: r.u64()? },
        other => return Err(CodecError::UnknownType(other)),
    };
    if !r.b.is_empty() {
        return Err(CodecError::Trailing(r.b.len()));
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const MAX: usize = 1 << 20;

    fn rt(m: &Msg) -> Msg {
        let mut out = Vec::new();
        encode(m, MAX, &mut out).unwrap();
        let (d, used) = decode(&out, MAX).unwrap().unwrap();
        assert_eq!(used, out.len());
        // Every strict prefix is incomplete, never an error or a panic.
        for i in 0..out.len() {
            assert!(matches!(decode(&out[..i], MAX), Ok(None)), "prefix {i} of {m:?}");
        }
        d
    }

    fn arb_view() -> impl Strategy<Value = View> {
        (any::<u64>(), any::<u16>(), proptest::collection::btree_set(0u16..200, 0..10)).prop_map(|(e, l, s)| {
            let all: Vec<u16> = s.into_iter().collect();
            let (live, standby) = all.split_at(all.len() / 2);
            View { epoch: e, leader: l, live: live.to_vec(), standby: standby.to_vec() }
        })
    }

    fn arb_block() -> impl Strategy<Value = WireBlock> {
        (any::<u32>(), any::<u16>()).prop_map(|(addr, block)| WireBlock { addr, block })
    }

    fn arb_bib() -> impl Strategy<Value = WireBib> {
        (
            any::<u128>(),
            prop_oneof![Just(1u8), Just(6), Just(17)],
            any::<u128>(),
            any::<u16>(),
            any::<u32>(),
            any::<u16>(),
            any::<u64>(),
        )
            .prop_map(|(sub, proto, v6, port6, v4, port4, created_wall_us)| WireBib {
                sub,
                proto,
                v6,
                port6,
                v4,
                port4,
                created_wall_us,
            })
    }

    fn arb_msg() -> impl Strategy<Value = Msg> {
        let hello = (
            any::<u16>(),
            any::<u16>(),
            "[a-z0-9.-]{0,64}",
            any::<[u8; 32]>(),
            any::<u64>(),
            any::<bool>(),
            proptest::collection::vec((any::<u32>(), 0u8..=32), 0..20),
        )
            .prop_map(|(v, id, name, d, e, s, owned)| {
                Msg::Hello(Hello {
                    proto_version: v,
                    node_id: id,
                    name,
                    config_digest: d,
                    epoch: e,
                    scheme: if s { PartitionScheme::Slices } else { PartitionScheme::Contiguous },
                    owned: owned
                        .into_iter()
                        .map(|(a, l)| {
                            Ipv4Cidr::new(Ipv4Addr::from(a & if l == 0 { 0 } else { u32::MAX << (32 - l) }), l).unwrap()
                        })
                        .collect(),
                })
            });
        let reason = prop_oneof![
            Just(None),
            Just(Some(RejectReason::NotAllowed)),
            Just(Some(RejectReason::IdMismatch)),
            Just(Some(RejectReason::DuplicateId)),
            Just(Some(RejectReason::DigestMismatch)),
            Just(Some(RejectReason::Version)),
            Just(Some(RejectReason::Overlap)),
            Just(Some(RejectReason::Handshake)),
            Just(Some(RejectReason::Protocol)),
            Just(Some(RejectReason::InvalidInput)),
            Just(Some(RejectReason::Capacity)),
        ];
        let rec = prop_oneof![
            (any::<u128>(), arb_block(), any::<u64>()).prop_map(|(sub, block, alloc_wall_us)| SnapRecord::Block {
                sub,
                block,
                alloc_wall_us
            }),
            arb_bib().prop_map(SnapRecord::Bib),
        ];
        prop_oneof![
            hello,
            reason.prop_map(Msg::HelloAck),
            (any::<u64>(), any::<bool>()).prop_map(|(epoch, pre)| Msg::Vote { epoch, pre }),
            (any::<u64>(), any::<bool>(), any::<bool>(), proptest::option::of(arb_view()))
                .prop_map(|(epoch, pre, granted, last_view)| Msg::VoteAck { epoch, pre, granted, last_view }),
            (any::<u64>(), arb_view()).prop_map(|(base_epoch, view)| Msg::ViewPropose { base_epoch, view }),
            any::<u64>().prop_map(|epoch| Msg::ViewAck { epoch }),
            (any::<u64>(), any::<u32>(), any::<u64>(), any::<u64>())
                .prop_map(|(epoch, lease_ms, seq, commit)| Msg::Heartbeat { epoch, lease_ms, seq, commit }),
            (any::<u64>(), any::<u64>()).prop_map(|(epoch, seq)| Msg::HeartbeatAck { epoch, seq }),
            (any::<u16>(), any::<u64>(), proptest::collection::vec(arb_block(), 0..50))
                .prop_map(|(slice, seq, blocks)| Msg::Reserve { slice, seq, blocks }),
            (any::<u16>(), any::<u64>()).prop_map(|(slice, seq)| Msg::Ack { slice, seq }),
            (any::<u16>(), any::<u64>(), any::<u128>(), arb_block(), any::<u64>())
                .prop_map(|(slice, seq, sub, block, wall_us)| Msg::BlockAlloc { slice, seq, sub, block, wall_us }),
            (any::<u16>(), any::<u64>(), any::<u128>(), arb_block())
                .prop_map(|(slice, seq, sub, block)| Msg::BlockRelease { slice, seq, sub, block }),
            (any::<u16>(), any::<u64>(), arb_bib()).prop_map(|(slice, seq, bib)| Msg::BibCreate { slice, seq, bib }),
            (any::<u16>(), any::<u64>(), prop_oneof![Just(1u8), Just(6), Just(17)], any::<u32>(), any::<u16>())
                .prop_map(|(slice, seq, proto, v4, port4)| Msg::BibDelete { slice, seq, proto, v4, port4 }),
            (any::<u128>(), any::<u16>()).prop_map(|(sub, slice)| Msg::SubHome { sub, slice }),
            any::<u128>().prop_map(|sub| Msg::SubGone { sub }),
            (any::<u16>(), any::<u64>()).prop_map(|(slice, seq)| Msg::SnapshotBegin { slice, seq }),
            (any::<u16>(), any::<u64>(), proptest::collection::vec(rec, 0..30))
                .prop_map(|(slice, seq, records)| Msg::SnapshotChunk { slice, seq, records }),
            (any::<u16>(), any::<u64>()).prop_map(|(slice, seq)| Msg::SnapshotEnd { slice, seq }),
            (any::<u16>(), any::<u64>(), any::<u64>()).prop_map(|(slice, epoch, final_seq)| Msg::HandoverFence {
                slice,
                epoch,
                final_seq
            }),
            (any::<u16>(), any::<u64>()).prop_map(|(slice, epoch)| Msg::HandoverDone { slice, epoch }),
            (any::<u16>(), any::<u64>()).prop_map(|(slice, seq)| Msg::Resync { slice, seq }),
            (any::<u64>(), any::<bool>()).prop_map(|(epoch, in_sync)| Msg::SyncStatus { epoch, in_sync }),
        ]
    }

    proptest! {
        #[test]
        fn round_trip(m in arb_msg()) {
            prop_assert_eq!(rt(&m), m);
        }

        #[test]
        fn arbitrary_bytes_never_panic(b in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = decode(&b, MIN_MAX_FRAME);
            if let Some((t, p)) = b.split_first() {
                let _ = decode_payload(*t, p);
            }
        }

        #[test]
        fn flipped_bytes_never_panic(m in arb_msg(), pos in any::<prop::sample::Index>(), v in any::<u8>()) {
            let mut out = Vec::new();
            encode(&m, MAX, &mut out).unwrap();
            let i = pos.index(out.len());
            out[i] = v;
            let _ = decode(&out, MAX);
        }

        #[test]
        fn trailing_bytes_refused(m in arb_msg()) {
            let mut out = Vec::new();
            encode(&m, MAX, &mut out).unwrap();
            let len = u32::from_le_bytes(out[..4].try_into().unwrap()) + 1;
            out[..4].copy_from_slice(&len.to_le_bytes());
            out.push(0);
            prop_assert_eq!(decode(&out, MAX), Err(CodecError::Trailing(1)));
        }
    }

    #[test]
    fn frame_limits() {
        assert_eq!(decode(&[0, 0, 0, 0], MAX), Err(CodecError::Empty));
        assert_eq!(decode(&[0, 0, 0x10, 0, 7], MAX), Ok(None));
        assert_eq!(decode(&[1, 0, 0x10, 0], MAX), Err(CodecError::TooLarge(0x10_0001, MAX)));
        assert_eq!(decode(&[1, 0, 0, 0, 99], MAX), Err(CodecError::UnknownType(99)));
        assert_eq!(decode(&[1, 0, 0, 0, 0], MAX), Err(CodecError::UnknownType(0)));
        assert_eq!(decode(&[1, 0, 0, 0, ty::VOTE], MAX), Err(CodecError::Truncated));
        let big = Msg::Reserve { slice: 0, seq: 0, blocks: vec![WireBlock { addr: 0, block: 0 }; 200] };
        let mut out = vec![9];
        assert!(matches!(encode(&big, MIN_MAX_FRAME, &mut out), Err(CodecError::TooLarge(..))));
        assert_eq!(out, vec![9], "failed encode leaves the buffer unchanged");
    }

    #[test]
    fn huge_counts_refused_before_allocation() {
        let mut p = Vec::new();
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&0u64.to_le_bytes());
        p.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_payload(ty::RESERVE, &p), Err(CodecError::Truncated));
        assert_eq!(decode_payload(ty::SNAPSHOT_CHUNK, &p), Err(CodecError::Truncated));
    }

    #[test]
    fn invalid_fields_refused() {
        let mut out = Vec::new();
        let bad = Msg::Hello(Hello {
            proto_version: 1,
            node_id: 0,
            name: "bad name".into(),
            config_digest: [0; 32],
            epoch: 0,
            scheme: PartitionScheme::Slices,
            owned: vec![],
        });
        assert_eq!(encode(&bad, MAX, &mut out), Err(CodecError::Invalid("hello.name")));
        // Bad bool, bad proto, unsorted view, standby overlapping live.
        let mut p = 0u64.to_le_bytes().to_vec();
        p.extend_from_slice(&[0, 2, 0]);
        assert_eq!(decode_payload(ty::VOTE_ACK, &p), Err(CodecError::Invalid("vote_ack.granted")));
        let mut p = 0u16.to_le_bytes().to_vec();
        p.extend_from_slice(&0u64.to_le_bytes());
        p.push(5);
        p.extend_from_slice(&[0; 4 + 2]);
        assert_eq!(decode_payload(ty::BIB_DELETE, &p), Err(CodecError::Invalid("bib.proto")));
        let mut p = 0u64.to_le_bytes().to_vec();
        p.extend_from_slice(&0u64.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&[2, 1, 0, 0, 0, 0]);
        assert_eq!(decode_payload(ty::VIEW_PROPOSE, &p), Err(CodecError::Invalid("view.members order")));
        let mut p = 0u64.to_le_bytes().to_vec();
        p.extend_from_slice(&0u64.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&[1, 3, 0, 1, 3, 0]);
        assert_eq!(decode_payload(ty::VIEW_PROPOSE, &p), Err(CodecError::Invalid("view.standby")));
    }
}
