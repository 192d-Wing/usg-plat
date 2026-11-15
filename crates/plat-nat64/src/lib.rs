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
//! every engine lock. A takeover is a resumable [`Adoption`] cursor that
//! the control thread steps under a time budget; the slice stays
//! `Adopting` (unusable) until its last step (POAM-047).

pub mod engine;
pub mod frag;
pub mod held;
pub mod ident;
pub mod mirror;
pub mod pool;
#[cfg(feature = "hold-probe")]
pub mod probe;
pub mod repl;
pub mod shard;
pub mod state;
pub mod tcp;

pub use engine::{Nat64, Verdict, WorkerCtx};
pub use held::{HeldSynExpiry, SynMeta};
#[cfg(any(test, feature = "model"))]
pub use mirror::ModelMirror;
pub use mirror::{Mirror, MirrorEntry, MirrorFail, MirrorKeys, NoMirror};
pub use pool::{AllocFail, SliceState};
pub use repl::{AdoptInput, Detached, Directory, Home, ReplHub, ReplProducer, ReplRecord, Shadow, ShadowError};
pub use state::{
    ADOPT_BATCH, ADOPT_STEP_BUDGET, ADOPT_STEP_MAX_ITEMS, AdoptError, AdoptMeta, AdoptSource, AdoptStats, Adoption,
    ClusterSetup, ExportCursor, MAX_REPL_RING_BYTES, ReleaseStats, Step, check_ring_memory,
};
