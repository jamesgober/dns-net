//! The numbered fields of a message: record types, classes, opcodes, and
//! response codes. Each is a plain number with names for the known values, so
//! an unknown value is carried, never refused.

use std::fmt;

/// A record type (RFC 1035 section 3.2.2 and later registrations).
///
/// ```
/// use dns_net::RecordType;
/// assert_eq!(RecordType::AAAA.to_string(), "AAAA");
/// assert_eq!(RecordType(65280).to_string(), "TYPE65280");
/// assert_eq!("mx".parse::<RecordType>(), Ok(RecordType::MX));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordType(pub u16);

impl RecordType {
    /// An IPv4 address.
    pub const A: RecordType = RecordType(1);
    /// An authoritative name server.
    pub const NS: RecordType = RecordType(2);
    /// The canonical name of an alias.
    pub const CNAME: RecordType = RecordType(5);
    /// The start of a zone of authority.
    pub const SOA: RecordType = RecordType(6);
    /// A domain name pointer (reverse lookups).
    pub const PTR: RecordType = RecordType(12);
    /// A mail exchange (RFC 7505 for the null MX).
    pub const MX: RecordType = RecordType(15);
    /// Text strings.
    pub const TXT: RecordType = RecordType(16);
    /// An IPv6 address (RFC 3596).
    pub const AAAA: RecordType = RecordType(28);
    /// A service location (RFC 2782).
    pub const SRV: RecordType = RecordType(33);
    /// The EDNS(0) pseudo-record (RFC 6891).
    pub const OPT: RecordType = RecordType(41);
    /// Any type, in a question only.
    pub const ANY: RecordType = RecordType(255);
    /// Certification authority authorization (RFC 8659).
    pub const CAA: RecordType = RecordType(257);

    const NAMES: [(RecordType, &'static str); 12] = [
        (RecordType::A, "A"),
        (RecordType::NS, "NS"),
        (RecordType::CNAME, "CNAME"),
        (RecordType::SOA, "SOA"),
        (RecordType::PTR, "PTR"),
        (RecordType::MX, "MX"),
        (RecordType::TXT, "TXT"),
        (RecordType::AAAA, "AAAA"),
        (RecordType::SRV, "SRV"),
        (RecordType::OPT, "OPT"),
        (RecordType::ANY, "ANY"),
        (RecordType::CAA, "CAA"),
    ];

    /// Whether names in this type's data may be compressed when written: the
    /// types of RFC 1035 only (RFC 3597 section 4).
    #[must_use]
    pub fn compresses_names(self) -> bool {
        matches!(
            self,
            RecordType::NS | RecordType::CNAME | RecordType::SOA | RecordType::PTR | RecordType::MX
        )
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match RecordType::NAMES.iter().find(|(t, _)| t == self) {
            Some((_, name)) => f.write_str(name),
            None => write!(f, "TYPE{}", self.0),
        }
    }
}

/// The text was not a record type's name or `TYPEnnn`.
///
/// ```
/// assert!("XYZ".parse::<dns_net::RecordType>().is_err());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownType;

impl fmt::Display for UnknownType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a record type")
    }
}

impl std::error::Error for UnknownType {}

impl std::str::FromStr for RecordType {
    type Err = UnknownType;
    fn from_str(s: &str) -> Result<RecordType, UnknownType> {
        if let Some((t, _)) = RecordType::NAMES
            .iter()
            .find(|(_, name)| name.eq_ignore_ascii_case(s))
        {
            return Ok(*t);
        }
        let digits = s
            .get(..4)
            .filter(|p| p.eq_ignore_ascii_case("TYPE"))
            .and_then(|_| s.get(4..))
            .ok_or(UnknownType)?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(UnknownType);
        }
        digits.parse().map(RecordType).map_err(|_| UnknownType)
    }
}

/// A record class. Only `IN` is used on the internet.
///
/// ```
/// assert_eq!(dns_net::Class::IN.to_string(), "IN");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Class(pub u16);

impl Class {
    /// The internet.
    pub const IN: Class = Class(1);
    /// Chaos (used for server identification queries).
    pub const CH: Class = Class(3);
    /// Any class, in a question only.
    pub const ANY: Class = Class(255);
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Class::IN => f.write_str("IN"),
            Class::CH => f.write_str("CH"),
            Class::ANY => f.write_str("ANY"),
            Class(n) => write!(f, "CLASS{n}"),
        }
    }
}

/// The kind of a message (4 bits of the header).
///
/// ```
/// assert_eq!(dns_net::Opcode::default(), dns_net::Opcode::QUERY);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Opcode(pub u8);

impl Opcode {
    /// A standard query.
    pub const QUERY: Opcode = Opcode(0);
    /// A server status request.
    pub const STATUS: Opcode = Opcode(2);
    /// A zone change notification (RFC 1996).
    pub const NOTIFY: Opcode = Opcode(4);
    /// A dynamic update (RFC 2136).
    pub const UPDATE: Opcode = Opcode(5);
}

/// A response code: the 4 bits of the header, extended to 12 by EDNS(0).
///
/// ```
/// assert_eq!(dns_net::Rcode::NXDOMAIN.to_string(), "NXDOMAIN");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rcode(pub u16);

impl Rcode {
    /// No error.
    pub const NOERROR: Rcode = Rcode(0);
    /// The server could not read the query.
    pub const FORMERR: Rcode = Rcode(1);
    /// The server failed.
    pub const SERVFAIL: Rcode = Rcode(2);
    /// The name does not exist.
    pub const NXDOMAIN: Rcode = Rcode(3);
    /// The server does not support the query.
    pub const NOTIMP: Rcode = Rcode(4);
    /// The server refused.
    pub const REFUSED: Rcode = Rcode(5);
    /// The server does not support the EDNS version (RFC 6891).
    pub const BADVERS: Rcode = Rcode(16);
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Rcode::NOERROR => f.write_str("NOERROR"),
            Rcode::FORMERR => f.write_str("FORMERR"),
            Rcode::SERVFAIL => f.write_str("SERVFAIL"),
            Rcode::NXDOMAIN => f.write_str("NXDOMAIN"),
            Rcode::NOTIMP => f.write_str("NOTIMP"),
            Rcode::REFUSED => f.write_str("REFUSED"),
            Rcode::BADVERS => f.write_str("BADVERS"),
            Rcode(n) => write!(f, "RCODE{n}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names_round_trip() {
        for (t, name) in RecordType::NAMES {
            assert_eq!(t.to_string(), name);
            assert_eq!(name.parse::<RecordType>(), Ok(t));
        }
        assert_eq!("TYPE99".parse::<RecordType>(), Ok(RecordType(99)));
        assert_eq!("type65535".parse::<RecordType>(), Ok(RecordType(65535)));
        assert!("TYPE65536".parse::<RecordType>().is_err());
        assert!("TYPE".parse::<RecordType>().is_err());
        assert!("TYPE+1".parse::<RecordType>().is_err());
        assert!("".parse::<RecordType>().is_err());
        assert!("\u{e9}TYPE1".parse::<RecordType>().is_err());
    }

    #[test]
    fn other_names() {
        assert_eq!(Class(42).to_string(), "CLASS42");
        assert_eq!(Rcode(23).to_string(), "RCODE23");
        assert!(RecordType::MX.compresses_names());
        assert!(!RecordType::SRV.compresses_names());
    }
}
