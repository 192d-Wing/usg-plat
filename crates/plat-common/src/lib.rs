//! Shared types for usg-plat: configuration, prefixes, the coarse clock and
//! data-plane counters.

pub mod clock;
pub mod config;
pub mod counters;
pub mod net;

pub use clock::Clock;
pub use config::{Config, ConfigError};
pub use counters::{Counter, Counters, DropReason};
pub use net::{HttpUrl, Ipv4Cidr, Ipv6Cidr};
