//! IPv4/IPv6 CIDR prefixes, parsed and validated at the configuration boundary.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CidrError {
    #[error("missing '/' prefix length")]
    MissingLen,
    #[error("invalid address")]
    BadAddr,
    #[error("invalid prefix length")]
    BadLen,
    #[error("host bits set beyond prefix length")]
    HostBits,
}

/// An IPv4 prefix with no host bits set.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    addr: u32,
    len: u8,
}

impl Ipv4Cidr {
    pub fn new(addr: Ipv4Addr, len: u8) -> Result<Self, CidrError> {
        if len > 32 {
            return Err(CidrError::BadLen);
        }
        let a = u32::from(addr);
        if a & !Self::mask_of(len) != 0 {
            return Err(CidrError::HostBits);
        }
        Ok(Self { addr: a, len })
    }

    #[inline]
    fn mask_of(len: u8) -> u32 {
        if len == 0 { 0 } else { u32::MAX << (32 - len) }
    }

    #[inline]
    pub fn network(&self) -> u32 {
        self.addr
    }

    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    #[inline]
    pub fn contains(&self, a: u32) -> bool {
        a & Self::mask_of(self.len) == self.addr
    }

    /// Number of addresses in the prefix.
    pub fn size(&self) -> u64 {
        1u64 << (32 - self.len)
    }

    /// Iterates every address in the prefix.
    pub fn addrs(&self) -> impl Iterator<Item = u32> + use<> {
        let base = self.addr as u64;
        (base..base + self.size()).map(|a| a as u32)
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.addr), self.len)
    }
}

impl fmt::Debug for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = CidrError;
    fn from_str(s: &str) -> Result<Self, CidrError> {
        let (a, l) = s.split_once('/').ok_or(CidrError::MissingLen)?;
        let addr = a.parse::<Ipv4Addr>().map_err(|_| CidrError::BadAddr)?;
        let len = l.parse::<u8>().map_err(|_| CidrError::BadLen)?;
        Self::new(addr, len)
    }
}

/// An IPv6 prefix with no host bits set.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Cidr {
    addr: u128,
    len: u8,
}

impl Ipv6Cidr {
    pub fn new(addr: Ipv6Addr, len: u8) -> Result<Self, CidrError> {
        if len > 128 {
            return Err(CidrError::BadLen);
        }
        let a = u128::from(addr);
        if a & !Self::mask_of(len) != 0 {
            return Err(CidrError::HostBits);
        }
        Ok(Self { addr: a, len })
    }

    #[inline]
    pub fn mask_of(len: u8) -> u128 {
        if len == 0 { 0 } else { u128::MAX << (128 - len) }
    }

    #[inline]
    pub fn network(&self) -> u128 {
        self.addr
    }

    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    #[inline]
    pub fn contains(&self, a: u128) -> bool {
        a & Self::mask_of(self.len) == self.addr
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.addr), self.len)
    }
}

impl fmt::Debug for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Ipv6Cidr {
    type Err = CidrError;
    fn from_str(s: &str) -> Result<Self, CidrError> {
        let (a, l) = s.split_once('/').ok_or(CidrError::MissingLen)?;
        let addr = a.parse::<Ipv6Addr>().map_err(|_| CidrError::BadAddr)?;
        let len = l.parse::<u8>().map_err(|_| CidrError::BadLen)?;
        Self::new(addr, len)
    }
}

macro_rules! serde_via_str {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}
serde_via_str!(Ipv4Cidr);
serde_via_str!(Ipv6Cidr);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_contains() {
        let p: Ipv4Cidr = "192.0.2.0/24".parse().unwrap();
        assert!(p.contains(u32::from(Ipv4Addr::new(192, 0, 2, 77))));
        assert!(!p.contains(u32::from(Ipv4Addr::new(192, 0, 3, 1))));
        assert_eq!(p.size(), 256);
        let q: Ipv6Cidr = "64:ff9b::/96".parse().unwrap();
        assert!(q.contains(u128::from("64:ff9b::c000:201".parse::<Ipv6Addr>().unwrap())));
    }

    #[test]
    fn rejects_host_bits_and_bad_len() {
        assert_eq!("192.0.2.1/24".parse::<Ipv4Cidr>(), Err(CidrError::HostBits));
        assert_eq!("192.0.2.0/33".parse::<Ipv4Cidr>(), Err(CidrError::BadLen));
        assert_eq!("2001:db8::1/64".parse::<Ipv6Cidr>(), Err(CidrError::HostBits));
        assert_eq!("2001:db8::".parse::<Ipv6Cidr>(), Err(CidrError::MissingLen));
    }
}
