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

/// Longest accepted `http://` URL (OCSP responder, CRL location).
pub const MAX_URL_LEN: usize = 2048;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UrlError {
    #[error("URL longer than {MAX_URL_LEN} bytes")]
    TooLong,
    #[error("only http:// URLs are supported")]
    Scheme,
    #[error("URL must not contain user information, a fragment, spaces or control characters")]
    Forbidden,
    #[error("invalid host")]
    Host,
    #[error("invalid port")]
    Port,
}

/// A plain `http://host[:port][/path]` URL, as used for OCSP responders
/// (RFC 6960 Appendix A) and CRL distribution points (RFC 5280 §4.2.1.13).
///
/// Deliberately narrow: no userinfo, no fragment, no percent-decoding, no
/// IDNA. `host` is a DNS name, a dotted IPv4 address or a bracketed IPv6
/// literal (stored without brackets); `path` always starts with `/` and
/// keeps any query string verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl HttpUrl {
    pub fn parse(s: &str) -> Result<Self, UrlError> {
        if s.len() > MAX_URL_LEN {
            return Err(UrlError::TooLong);
        }
        let rest = match s.get(..7) {
            Some(p) if p.eq_ignore_ascii_case("http://") => &s[7..],
            _ => return Err(UrlError::Scheme),
        };
        if rest.bytes().any(|b| !(b'!'..=b'~').contains(&b) || b == b'#') {
            return Err(UrlError::Forbidden);
        }
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_owned()),
            Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
            None => (rest, "/".to_owned()),
        };
        if authority.contains('@') {
            return Err(UrlError::Forbidden);
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let end = v6.find(']').ok_or(UrlError::Host)?;
            let host = &v6[..end];
            host.parse::<Ipv6Addr>().map_err(|_| UrlError::Host)?;
            (host, &v6[end + 1..])
        } else {
            match authority.find(':') {
                Some(i) => (&authority[..i], &authority[i..]),
                None => (authority, ""),
            }
        };
        let port = match port {
            "" => 80,
            p => match p.strip_prefix(':').map(str::parse::<u16>) {
                Some(Ok(n)) if n != 0 => n,
                _ => return Err(UrlError::Port),
            },
        };
        if !authority.starts_with('[') && !is_dns_name(host) && host.parse::<Ipv4Addr>().is_err() {
            return Err(UrlError::Host);
        }
        Ok(Self { host: host.to_ascii_lowercase(), port, path })
    }

    /// `host:port` for logs and the HTTP `Host` header (IPv6 bracketed).
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// RFC 1123 host name: 1..=253 bytes, labels 1..=63 of `[A-Za-z0-9-]`, no
/// leading/trailing hyphen. A trailing dot is not accepted.
pub fn is_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

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

    #[test]
    fn http_urls() {
        let u = HttpUrl::parse("http://ocsp.example.net/a/b?x=1").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("ocsp.example.net", 80, "/a/b?x=1"));
        let u = HttpUrl::parse("HTTP://[2001:db8::1]:8080").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("2001:db8::1", 8080, "/"));
        assert_eq!(u.authority(), "[2001:db8::1]:8080");
        assert_eq!(HttpUrl::parse("http://192.0.2.20?q").unwrap().path, "/?q");
        assert_eq!(HttpUrl::parse("https://x.example/"), Err(UrlError::Scheme));
        assert_eq!(HttpUrl::parse("http://u:p@x.example/"), Err(UrlError::Forbidden));
        assert_eq!(HttpUrl::parse("http://x.example/a b"), Err(UrlError::Forbidden));
        assert_eq!(HttpUrl::parse("http://x.example/#f"), Err(UrlError::Forbidden));
        assert_eq!(HttpUrl::parse("http://x.example:0/"), Err(UrlError::Port));
        assert_eq!(HttpUrl::parse("http://x.example:99999/"), Err(UrlError::Port));
        assert_eq!(HttpUrl::parse("http://-bad.example/"), Err(UrlError::Host));
        assert_eq!(HttpUrl::parse("http:///path"), Err(UrlError::Host));
        assert_eq!(HttpUrl::parse("http://[::1/"), Err(UrlError::Host));
        let long = format!("http://x.example/{}", "a".repeat(MAX_URL_LEN));
        assert_eq!(HttpUrl::parse(&long), Err(UrlError::TooLong));
    }
}
