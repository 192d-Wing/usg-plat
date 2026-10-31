//! Stateful NAT64 (RFC 6146) for the 464XLAT PLAT role (RFC 6877).
//!
//! # Concurrency model
//!
//! Workers run to completion on their own packets and share the tables
//! below, each split into independently locked shards (power-of-two count,
//! randomly keyed hashing):
//!
//! | Table  | Key                          | Value                       |
//! |--------|------------------------------|-----------------------------|
//! | `bib6` | (proto, IPv6 src, src port)  | IPv4 transport address      |
//! | `bib4` | (proto, pool addr, pool port)| BIB entry + its sessions    |
//! | `subs` | subscriber IPv6 prefix       | port blocks, port bitmaps   |
//!
//! Lock order is `bib6 → subs` (released) `→ bib4`; the sweeper takes
//! `bib6 → bib4`, releases both, then `subs`. No path takes `bib6` or `subs`
//! while holding `bib4`, so there is no cycle. Steady-state packets take at
//! most two uncontended shard locks and never allocate.
//!
//! # Cluster HA (`cluster.partition = "slices"`)
//!
//! The pool is split into slices (`plat-cluster`); each has an atomic
//! ownership state read on every packet ([`pool::SliceState`]). Workers push
//! block/BIB/subscriber changes into their own bounded ring
//! ([`repl::ReplProducer`]); the replicator (platd) drains them. The
//! subscriber [`repl::Directory`] has its own shards and is a leaf after
//! every engine lock.

pub mod engine;
pub mod frag;
pub mod held;
pub mod ident;
pub mod pool;
pub mod repl;
pub mod shard;
pub mod state;
pub mod tcp;

pub use engine::{Nat64, Verdict, WorkerCtx};
pub use held::{HeldSynExpiry, SynMeta};
pub use pool::{AllocFail, SliceState};
pub use repl::{AdoptInput, Directory, Home, ReplHub, ReplProducer, ReplRecord, Shadow, ShadowError};
pub use state::{
    AdoptError, AdoptMeta, AdoptStats, ClusterSetup, ExportCursor, MAX_REPL_RING_BYTES, ReleaseStats, check_ring_memory,
};
