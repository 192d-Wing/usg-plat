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

pub mod engine;
pub mod pool;
pub mod shard;
pub mod state;
pub mod tcp;

pub use engine::{Nat64, Verdict, WorkerCtx};
