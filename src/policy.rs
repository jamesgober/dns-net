//! The resolve-time address hook: which addresses a lookup may return.
//!
//! A proxy choosing an upstream, or a server sending a webhook to a URL a
//! user gave it, must not be steered to its own loopback, its private
//! network, or a cloud metadata address (server-side request forgery). A name
//! that resolves to a public address once and a private one later (DNS
//! rebinding) is caught the same way, as long as the caller connects to the
//! addresses the lookup returned and does not resolve the name again.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::name::Name;

/// Decides, for each address a lookup found, whether the caller may have it.
///
/// Runs on every address of every lookup, cached or not, so it must be cheap
/// and must not block. Any `Fn(&Name, IpAddr) -> bool` is one.
///
/// ```
/// use std::net::IpAddr;
/// use dns_net::{AddressPolicy, Name};
/// // Only the 192.0.2.0/24 network.
/// let only_lab = |_host: &Name, addr: IpAddr| matches!(addr, IpAddr::V4(v4) if v4.octets()[..3] == [192, 0, 2]);
/// assert!(only_lab.allows(&Name::parse("x")?, "192.0.2.9".parse()?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait AddressPolicy: Send + Sync {
    /// Whether `addr`, found for `host`, may be returned.
    fn allows(&self, host: &Name, addr: IpAddr) -> bool;
}

impl<F> AddressPolicy for F
where
    F: Fn(&Name, IpAddr) -> bool + Send + Sync,
{
    fn allows(&self, host: &Name, addr: IpAddr) -> bool {
        self(host, addr)
    }
}

/// Every address is allowed: the default for a resolver used for anything
/// but outbound connections chosen by others.
///
/// ```
/// use dns_net::{AddressPolicy, AllowAll, Name};
/// assert!(AllowAll.allows(&Name::root(), "127.0.0.1".parse()?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl AddressPolicy for AllowAll {
    fn allows(&self, _host: &Name, _addr: IpAddr) -> bool {
        true
    }
}

/// Only globally reachable unicast addresses ([`is_public`]), with optional
/// exceptions: networks the caller trusts, such as its own service network.
///
/// ```
/// use dns_net::{AddressPolicy, Name, PublicOnly};
/// let host = Name::parse("hook.example")?;
/// let policy = PublicOnly::new();
/// assert!(policy.allows(&host, "93.184.215.14".parse()?));
/// for refused in ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fd00::1", "::ffff:10.0.0.1"] {
///     assert!(!policy.allows(&host, refused.parse()?), "{refused}");
/// }
/// let internal = PublicOnly::new().allow("10.20.0.0".parse()?, 16);
/// assert!(internal.allows(&host, "10.20.1.1".parse()?));
/// assert!(!internal.allows(&host, "10.21.1.1".parse()?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct PublicOnly {
    allowed: Vec<(IpAddr, u8)>,
}

impl PublicOnly {
    /// Public addresses only, no exceptions.
    #[must_use]
    pub fn new() -> PublicOnly {
        PublicOnly::default()
    }

    /// Also allows the network `addr/prefix` (the prefix is clamped to the
    /// address's length). An IPv4 network also covers its IPv4-mapped IPv6 form.
    #[must_use]
    pub fn allow(mut self, addr: IpAddr, prefix: u8) -> PublicOnly {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        self.allowed.push((addr, prefix.min(max)));
        self
    }
}

impl AddressPolicy for PublicOnly {
    fn allows(&self, _host: &Name, addr: IpAddr) -> bool {
        let addr = canonical(addr);
        is_public(addr)
            || self
                .allowed
                .iter()
                .any(|&(net, p)| in_network(addr, net, p))
    }
}

/// An IPv4-mapped IPv6 address as its IPv4 address; anything else unchanged.
fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => addr,
        },
        v4 => v4,
    }
}

fn in_network(addr: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (addr, canonical(net)) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// Whether `addr` is a globally reachable unicast address: not unspecified,
/// loopback, private (RFC 1918, RFC 4193), shared (RFC 6598), link-local,
/// multicast, broadcast, reserved, benchmarking, documentation, discard, or
/// in the IETF protocol block (RFC 6890). Addresses that carry an IPv4
/// address (IPv4-mapped, NAT64 well-known prefix, 6to4) are judged by that
/// IPv4 address; Teredo and IPv4-compatible addresses are refused, since
/// where they lead is not visible in the address.
///
/// ```
/// use dns_net::is_public;
/// assert!(is_public("1.1.1.1".parse()?));
/// assert!(!is_public("100.64.0.1".parse()?));
/// assert!(!is_public("64:ff9b::7f00:1".parse()?)); // NAT64 of 127.0.0.1
/// assert!(is_public("2606:4700:4700::1111".parse()?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub fn is_public(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    let refused = o[0] == 0 // this network
        || o[0] == 10
        || (o[0] == 100 && (o[1] & 0xC0) == 64) // shared, 100.64/10
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (o[1] & 0xF0) == 16)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // TEST-NET-1
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 6to4 relay anycast
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] & 0xFE) == 18) // benchmarking, 198.18/15
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // TEST-NET-3
        || o[0] >= 224; // multicast, reserved, broadcast
    !refused
}

fn public_v6(a: Ipv6Addr) -> bool {
    if let Some(v4) = a.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let s = a.segments();
    let bits = u128::from(a);
    // NAT64, well-known prefix 64:ff9b::/96 (RFC 6052): judge the IPv4 address.
    if bits >> 32 == 0x0064_ff9b_0000_0000_0000_0000 {
        return public_v4(Ipv4Addr::from((bits & 0xFFFF_FFFF) as u32));
    }
    // 6to4, 2002::/16 (RFC 3056): the IPv4 address is in bits 16 to 48.
    if s[0] == 0x2002 {
        return public_v4(Ipv4Addr::from(((bits >> 80) & 0xFFFF_FFFF) as u32));
    }
    let refused = bits >> 32 == 0 // unspecified, loopback, IPv4-compatible (::/96)
        || s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 1 // NAT64 local use, 64:ff9b:1::/48
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // discard, 100::/64
        || (s[0] == 0x2001 && s[1] < 0x0200) // IETF protocol block 2001::/23 (Teredo included)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] & 0xFE00) == 0xFC00 // unique local, fc00::/7
        || (s[0] & 0xFFC0) == 0xFE80 // link-local
        || (s[0] & 0xFFC0) == 0xFEC0 // site-local (deprecated)
        || (s[0] & 0xFF00) == 0xFF00 // multicast
        || (s[0] == 0x3fff && s[1] < 0x1000); // documentation, 3fff::/20 (RFC 9637)
    // Only the global unicast block 2000::/3 is assigned for public use.
    !refused && (s[0] & 0xE000) == 0x2000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_ranges() {
        for refused in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.255",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_public(ip(refused)), "{refused}");
        }
        for allowed in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.169.0.1",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ] {
            assert!(is_public(ip(allowed)), "{allowed}");
        }
    }

    #[test]
    fn v6_ranges() {
        for refused in [
            "::",
            "::1",
            "::7f00:1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:1ff::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "2002:c0a8:101::1",
            "3fff::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "4000::1",
            "e000::1",
        ] {
            assert!(!is_public(ip(refused)), "{refused}");
        }
        for allowed in [
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2001:200::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "3fff:1000::1",
        ] {
            assert!(is_public(ip(allowed)), "{allowed}");
        }
    }

    #[test]
    fn exceptions() {
        let host = Name::root();
        let p = PublicOnly::new()
            .allow(ip("10.0.0.0"), 8)
            .allow(ip("fd00::"), 200);
        assert!(p.allows(&host, ip("10.9.9.9")));
        assert!(p.allows(&host, ip("::ffff:10.9.9.9")));
        assert!(!p.allows(&host, ip("11.0.0.0")) || is_public(ip("11.0.0.0")));
        assert!(p.allows(&host, ip("fd00::")));
        assert!(
            !p.allows(&host, ip("fd00::1")),
            "the prefix was clamped to 128"
        );
        assert!(!p.allows(&host, ip("127.0.0.1")));
        let everything = PublicOnly::new().allow(ip("0.0.0.0"), 0);
        assert!(everything.allows(&host, ip("127.0.0.1")));
        assert!(
            !everything.allows(&host, ip("::1")),
            "an IPv4 network covers IPv4 only"
        );
    }
}
