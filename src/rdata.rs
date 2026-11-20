//! Record data for the types the resolver reads: A, AAAA, NS, CNAME, PTR,
//! SOA, MX, TXT, SRV, and CAA. Any other type, and any class but `IN`, is
//! kept as its bytes (RFC 3597).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{DecodeError, EncodeError};
use crate::message::Writer;
use crate::name::{Name, read_name};
use crate::types::{Class, RecordType};

/// The data of one record.
///
/// ```
/// use dns_net::{Name, RData, RecordType};
/// let mx = RData::Mx { preference: 10, exchange: Name::parse("mail.example")? };
/// assert_eq!(mx.rtype(), RecordType::MX);
/// assert_eq!(mx.to_string(), "10 mail.example.");
/// # Ok::<(), dns_net::NameError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// A name server for the owner's zone.
    Ns(Name),
    /// The owner is an alias of this name.
    Cname(Name),
    /// A pointer to a name (reverse lookups).
    Ptr(Name),
    /// The start of a zone.
    Soa {
        /// The primary name server.
        mname: Name,
        /// The responsible person's mailbox, as a name.
        rname: Name,
        /// The zone's serial number.
        serial: u32,
        /// Seconds between secondary refreshes.
        refresh: u32,
        /// Seconds between failed refresh retries.
        retry: u32,
        /// Seconds until a secondary stops answering without a refresh.
        expire: u32,
        /// The TTL of negative answers (RFC 2308).
        minimum: u32,
    },
    /// A mail exchange; lower preferences first. A root exchange with
    /// preference 0 is the null MX: no mail (RFC 7505).
    Mx {
        /// The preference.
        preference: u16,
        /// The host.
        exchange: Name,
    },
    /// One or more character strings, each at most 255 bytes.
    Txt(Vec<Box<[u8]>>),
    /// A service location (RFC 2782).
    Srv {
        /// Lower first.
        priority: u16,
        /// Relative share among equal priorities.
        weight: u16,
        /// The port.
        port: u16,
        /// The host; the root means the service is not offered.
        target: Name,
    },
    /// Certification authority authorization (RFC 8659).
    Caa {
        /// Flags; bit 7 (128) is issuer critical.
        flags: u8,
        /// The property tag, letters and digits (`issue`, `issuewild`, `iodef`).
        tag: Box<str>,
        /// The property value.
        value: Box<[u8]>,
    },
    /// Data of another type or class, as received.
    Unknown {
        /// The record type.
        rtype: RecordType,
        /// The bytes.
        data: Box<[u8]>,
    },
}

impl RData {
    /// The record type this data belongs to.
    #[must_use]
    pub fn rtype(&self) -> RecordType {
        match self {
            RData::A(_) => RecordType::A,
            RData::Aaaa(_) => RecordType::AAAA,
            RData::Ns(_) => RecordType::NS,
            RData::Cname(_) => RecordType::CNAME,
            RData::Ptr(_) => RecordType::PTR,
            RData::Soa { .. } => RecordType::SOA,
            RData::Mx { .. } => RecordType::MX,
            RData::Txt(_) => RecordType::TXT,
            RData::Srv { .. } => RecordType::SRV,
            RData::Caa { .. } => RecordType::CAA,
            RData::Unknown { rtype, .. } => *rtype,
        }
    }

    /// The TXT strings joined, as DKIM and SPF read them (RFC 6376 section 3.6.2.2).
    ///
    /// ```
    /// let txt = dns_net::RData::Txt(vec![b"v=spf1 ".to_vec().into(), b"-all".to_vec().into()]);
    /// assert_eq!(txt.txt_joined().as_deref(), Some(&b"v=spf1 -all"[..]));
    /// ```
    #[must_use]
    pub fn txt_joined(&self) -> Option<Vec<u8>> {
        match self {
            RData::Txt(strings) => Some(strings.concat()),
            _ => None,
        }
    }

    /// Decodes `len` bytes of data at `start` in `msg`.
    pub(crate) fn decode(
        rtype: RecordType,
        class: Class,
        msg: &[u8],
        start: usize,
        len: usize,
    ) -> Result<RData, DecodeError> {
        let end = start + len;
        let data = msg.get(start..end).ok_or(DecodeError::Short)?;
        let bad = DecodeError::BadRdata { rtype: rtype.0 };
        if class != Class::IN {
            return Ok(RData::Unknown {
                rtype,
                data: data.into(),
            });
        }
        let name_at = |pos: &mut usize| -> Result<Name, DecodeError> {
            let name = read_name(msg, pos)?;
            if *pos > end { Err(bad) } else { Ok(name) }
        };
        let u16_at = |p: usize| u16::from_be_bytes([data[p], data[p + 1]]);
        let rdata = match rtype {
            RecordType::A => {
                let b: [u8; 4] = data.try_into().map_err(|_| bad)?;
                RData::A(Ipv4Addr::from(b))
            }
            RecordType::AAAA => {
                let b: [u8; 16] = data.try_into().map_err(|_| bad)?;
                RData::Aaaa(Ipv6Addr::from(b))
            }
            RecordType::NS | RecordType::CNAME | RecordType::PTR => {
                let mut pos = start;
                let name = name_at(&mut pos)?;
                if pos != end {
                    return Err(bad);
                }
                match rtype {
                    RecordType::NS => RData::Ns(name),
                    RecordType::CNAME => RData::Cname(name),
                    _ => RData::Ptr(name),
                }
            }
            RecordType::SOA => {
                let mut pos = start;
                let mname = name_at(&mut pos)?;
                let rname = name_at(&mut pos)?;
                if end - pos != 20 {
                    return Err(bad);
                }
                let n = |i: usize| {
                    let p = pos + i * 4;
                    u32::from_be_bytes([msg[p], msg[p + 1], msg[p + 2], msg[p + 3]])
                };
                RData::Soa {
                    mname,
                    rname,
                    serial: n(0),
                    refresh: n(1),
                    retry: n(2),
                    expire: n(3),
                    minimum: n(4),
                }
            }
            RecordType::MX => {
                if len < 3 {
                    return Err(bad);
                }
                let mut pos = start + 2;
                let exchange = name_at(&mut pos)?;
                if pos != end {
                    return Err(bad);
                }
                RData::Mx {
                    preference: u16_at(0),
                    exchange,
                }
            }
            RecordType::SRV => {
                if len < 7 {
                    return Err(bad);
                }
                // RFC 2782 says the target is not compressed; a pointer is
                // still read, since it has only one meaning (RFC 3597 section 4).
                let mut pos = start + 6;
                let target = name_at(&mut pos)?;
                if pos != end {
                    return Err(bad);
                }
                RData::Srv {
                    priority: u16_at(0),
                    weight: u16_at(2),
                    port: u16_at(4),
                    target,
                }
            }
            RecordType::TXT => {
                if data.is_empty() {
                    return Err(bad);
                }
                let mut strings = Vec::new();
                let mut p = 0;
                while p < data.len() {
                    let l = usize::from(data[p]);
                    let s = data.get(p + 1..p + 1 + l).ok_or(bad)?;
                    strings.push(s.into());
                    p += 1 + l;
                }
                RData::Txt(strings)
            }
            RecordType::CAA => {
                if len < 2 {
                    return Err(bad);
                }
                let tag_len = usize::from(data[1]);
                let tag = data.get(2..2 + tag_len).ok_or(bad)?;
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(bad);
                }
                let tag = std::str::from_utf8(tag).map_err(|_| bad)?;
                RData::Caa {
                    flags: data[0],
                    tag: tag.into(),
                    value: data[2 + tag_len..].into(),
                }
            }
            RecordType::OPT => return Err(DecodeError::BadOpt),
            _ => RData::Unknown {
                rtype,
                data: data.into(),
            },
        };
        Ok(rdata)
    }

    /// Writes the data (without its length, which the caller patches).
    pub(crate) fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        let compress = self.rtype().compresses_names();
        match self {
            RData::A(a) => w.bytes(&a.octets()),
            RData::Aaaa(a) => w.bytes(&a.octets()),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => w.name(n, compress),
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                w.name(mname, compress);
                w.name(rname, compress);
                for v in [serial, refresh, retry, expire, minimum] {
                    w.bytes(&v.to_be_bytes());
                }
            }
            RData::Mx {
                preference,
                exchange,
            } => {
                w.bytes(&preference.to_be_bytes());
                w.name(exchange, compress);
            }
            RData::Txt(strings) => {
                if strings.is_empty() {
                    return Err(EncodeError::FieldTooLong);
                }
                for s in strings {
                    let l = u8::try_from(s.len()).map_err(|_| EncodeError::FieldTooLong)?;
                    w.bytes(&[l]);
                    w.bytes(s);
                }
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                for v in [priority, weight, port] {
                    w.bytes(&v.to_be_bytes());
                }
                w.name(target, false);
            }
            RData::Caa { flags, tag, value } => {
                if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return Err(EncodeError::BadCaaTag);
                }
                let l = u8::try_from(tag.len()).map_err(|_| EncodeError::FieldTooLong)?;
                w.bytes(&[*flags, l]);
                w.bytes(tag.as_bytes());
                w.bytes(value);
            }
            RData::Unknown { data, .. } => w.bytes(data),
        }
        Ok(())
    }
}

impl fmt::Display for RData {
    /// The presentation form (RFC 1035 section 5.1), names with a trailing dot.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fq = |n: &Name| {
            if n.is_root() {
                ".".to_string()
            } else {
                format!("{n}.")
            }
        };
        let quoted = |f: &mut fmt::Formatter<'_>, s: &[u8]| -> fmt::Result {
            f.write_str("\"")?;
            for &b in s {
                match b {
                    b'"' | b'\\' => write!(f, "\\{}", b as char)?,
                    0x20..=0x7E => write!(f, "{}", b as char)?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
            f.write_str("\"")
        };
        match self {
            RData::A(a) => write!(f, "{a}"),
            RData::Aaaa(a) => write!(f, "{a}"),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => f.write_str(&fq(n)),
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => write!(
                f,
                "{} {} {serial} {refresh} {retry} {expire} {minimum}",
                fq(mname),
                fq(rname)
            ),
            RData::Mx {
                preference,
                exchange,
            } => write!(f, "{preference} {}", fq(exchange)),
            RData::Txt(strings) => {
                for (i, s) in strings.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" ")?;
                    }
                    quoted(f, s)?;
                }
                Ok(())
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{priority} {weight} {port} {}", fq(target)),
            RData::Caa { flags, tag, value } => {
                write!(f, "{flags} {tag} ")?;
                quoted(f, value)
            }
            RData::Unknown { data, .. } => {
                // RFC 3597 section 5.
                write!(f, "\\# {}", data.len())?;
                if !data.is_empty() {
                    f.write_str(" ")?;
                }
                for b in data.iter() {
                    write!(f, "{b:02X}")?;
                }
                Ok(())
            }
        }
    }
}
