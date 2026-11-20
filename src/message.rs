//! Messages: the header, the question, the three record sections, and the
//! EDNS(0) OPT record (RFC 1035 section 4, RFC 6891).

use crate::error::{DecodeError, EncodeError};
use crate::name::{Name, read_name};
use crate::rdata::RData;
use crate::types::{Class, Opcode, Rcode, RecordType};

/// The longest message: TCP's two-byte length prefix.
pub const MAX_MESSAGE: usize = 65_535;
/// The most records one message may count across its three sections. A
/// record takes at least 11 bytes, so a full TCP message holds under 6,000;
/// real answers hold a few dozen.
pub const MAX_RECORDS: usize = 4_096;
/// The payload size advertised by default: 1,232 bytes fits an IPv6 path
/// with a 1,280-byte MTU without fragmentation (the 2020 DNS flag day).
pub const DEFAULT_PAYLOAD: u16 = 1_232;
/// The most names one message's compression table tracks when writing.
const COMPRESSION_ENTRIES: usize = 128;

/// The fixed 12-byte header, without its counts (which come from the sections).
///
/// ```
/// let h = dns_net::Header { id: 7, recursion_desired: true, ..Default::default() };
/// assert!(!h.response);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The id a response repeats.
    pub id: u16,
    /// A response (QR).
    pub response: bool,
    /// The kind of message.
    pub opcode: Opcode,
    /// An authoritative answer (AA).
    pub authoritative: bool,
    /// The message was cut to fit (TC).
    pub truncated: bool,
    /// Recursion desired (RD).
    pub recursion_desired: bool,
    /// Recursion available (RA).
    pub recursion_available: bool,
    /// Authentic data (AD, RFC 4035): a validating server checked the answer.
    pub authentic_data: bool,
    /// Checking disabled (CD, RFC 4035).
    pub checking_disabled: bool,
    /// The low 4 bits of the response code; see [`Message::rcode`].
    pub rcode: u8,
}

impl Header {
    fn flags(&self) -> u16 {
        let bit = |b: bool, at: u16| u16::from(b) << at;
        bit(self.response, 15)
            | (u16::from(self.opcode.0 & 0x0F) << 11)
            | bit(self.authoritative, 10)
            | bit(self.truncated, 9)
            | bit(self.recursion_desired, 8)
            | bit(self.recursion_available, 7)
            | bit(self.authentic_data, 5)
            | bit(self.checking_disabled, 4)
            | u16::from(self.rcode & 0x0F)
    }

    fn from_flags(id: u16, f: u16) -> Header {
        let bit = |at: u16| f & (1 << at) != 0;
        Header {
            id,
            response: bit(15),
            opcode: Opcode(((f >> 11) & 0x0F) as u8),
            authoritative: bit(10),
            truncated: bit(9),
            recursion_desired: bit(8),
            recursion_available: bit(7),
            authentic_data: bit(5),
            checking_disabled: bit(4),
            rcode: (f & 0x0F) as u8,
        }
    }
}

/// The question: a name, a type, and a class.
///
/// ```
/// use dns_net::{Class, Name, Question, RecordType};
/// let q = Question::new(Name::parse("example.com")?, RecordType::A);
/// assert_eq!(q.qclass, Class::IN);
/// # Ok::<(), dns_net::NameError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    /// The name asked about.
    pub name: Name,
    /// The type asked for.
    pub qtype: RecordType,
    /// The class, `IN` on the internet.
    pub qclass: Class,
}

impl Question {
    /// A question in class `IN`.
    #[must_use]
    pub fn new(name: Name, qtype: RecordType) -> Question {
        Question {
            name,
            qtype,
            qclass: Class::IN,
        }
    }
}

/// One resource record.
///
/// ```
/// use std::net::Ipv4Addr;
/// use dns_net::{Class, Name, RData, Record};
/// let r = Record::new(Name::parse("example.com")?, 300, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
/// assert_eq!(r.class, Class::IN);
/// assert_eq!(r.to_string(), "example.com. 300 IN A 192.0.2.1");
/// # Ok::<(), dns_net::NameError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The owner.
    pub name: Name,
    /// The class.
    pub class: Class,
    /// Seconds it may be cached. A value with the top bit set is read as 0
    /// (RFC 2181 section 8).
    pub ttl: u32,
    /// The data, which carries the type.
    pub data: RData,
}

impl Record {
    /// A record in class `IN`.
    #[must_use]
    pub fn new(name: Name, ttl: u32, data: RData) -> Record {
        Record {
            name,
            class: Class::IN,
            ttl,
            data,
        }
    }

    /// The record type.
    #[must_use]
    pub fn rtype(&self) -> RecordType {
        self.data.rtype()
    }
}

impl std::fmt::Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let owner = if self.name.is_root() {
            ".".to_string()
        } else {
            format!("{}.", self.name)
        };
        write!(
            f,
            "{owner} {} {} {} {}",
            self.ttl,
            self.class,
            self.rtype(),
            self.data
        )
    }
}

/// One EDNS(0) option, as received (RFC 6891 section 6.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdnsOption {
    /// The option code.
    pub code: u16,
    /// Its data.
    pub data: Box<[u8]>,
}

/// The EDNS(0) pseudo-record (RFC 6891).
///
/// ```
/// let e = dns_net::Edns::new(1232);
/// assert_eq!(e.version, 0);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edns {
    /// The largest UDP payload the sender can receive.
    pub payload: u16,
    /// The upper 8 bits of the response code.
    pub ext_rcode: u8,
    /// The EDNS version (0).
    pub version: u8,
    /// DNSSEC OK (DO): the sender wants DNSSEC records.
    pub dnssec_ok: bool,
    /// The options.
    pub options: Vec<EdnsOption>,
}

impl Edns {
    /// Version 0, no options, DO clear.
    #[must_use]
    pub fn new(payload: u16) -> Edns {
        Edns {
            payload,
            ext_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }
}

/// A whole message.
///
/// ```
/// use dns_net::{Message, Name, Question, RecordType};
/// let q = Message::query(0x1234, Question::new(Name::parse("example.com")?, RecordType::MX));
/// let bytes = q.encode()?;
/// let back = Message::decode(&bytes)?;
/// assert_eq!(back, q);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// The header.
    pub header: Header,
    /// The question (a message has at most one, RFC 9619).
    pub question: Option<Question>,
    /// The answer section.
    pub answers: Vec<Record>,
    /// The authority section.
    pub authority: Vec<Record>,
    /// The additional section, without the OPT record.
    pub additional: Vec<Record>,
    /// The OPT record, when present.
    pub edns: Option<Edns>,
}

impl Message {
    /// A recursive query with EDNS(0) at [`DEFAULT_PAYLOAD`].
    #[must_use]
    pub fn query(id: u16, question: Question) -> Message {
        Message {
            header: Header {
                id,
                recursion_desired: true,
                ..Header::default()
            },
            question: Some(question),
            edns: Some(Edns::new(DEFAULT_PAYLOAD)),
            ..Message::default()
        }
    }

    /// The full response code: the header's 4 bits and, with EDNS, its 8 more.
    #[must_use]
    pub fn rcode(&self) -> Rcode {
        let ext = self.edns.as_ref().map_or(0, |e| u16::from(e.ext_rcode));
        Rcode((ext << 4) | u16::from(self.header.rcode & 0x0F))
    }

    /// Decodes a message.
    ///
    /// Strict: the bytes must be exactly one message (no trailing bytes), at
    /// most one question, at most [`MAX_RECORDS`] records, each record's data
    /// in its type's format and filling its length, and at most one OPT
    /// record, owned by the root, in the additional section. Names are
    /// decompressed under fixed budgets: pointers only point
    /// backwards, at most 127 per name, 255 bytes per name.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] says what was refused.
    pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        if bytes.len() > MAX_MESSAGE {
            return Err(DecodeError::TooLong);
        }
        let header = bytes.get(..12).ok_or(DecodeError::Short)?;
        let u16_at = |p: usize| u16::from_be_bytes([header[p], header[p + 1]]);
        let mut msg = Message {
            header: Header::from_flags(u16_at(0), u16_at(2)),
            ..Message::default()
        };
        let (qd, an, ns, ar) = (
            usize::from(u16_at(4)),
            usize::from(u16_at(6)),
            usize::from(u16_at(8)),
            usize::from(u16_at(10)),
        );
        if qd > 1 {
            return Err(DecodeError::QuestionCount);
        }
        let records = an + ns + ar;
        // A question takes at least 5 bytes and a record at least 11: refuse
        // counts the bytes cannot hold before reserving room for them.
        if records > MAX_RECORDS || qd * 5 + records * 11 > bytes.len() - 12 {
            return Err(DecodeError::TooManyRecords);
        }
        let mut pos = 12;
        if qd == 1 {
            let name = read_name(bytes, &mut pos)?;
            let tail = bytes.get(pos..pos + 4).ok_or(DecodeError::Short)?;
            msg.question = Some(Question {
                name,
                qtype: RecordType(u16::from_be_bytes([tail[0], tail[1]])),
                qclass: Class(u16::from_be_bytes([tail[2], tail[3]])),
            });
            pos += 4;
        }
        msg.answers.reserve_exact(an);
        msg.authority.reserve_exact(ns);
        for i in 0..records {
            let section = if i < an {
                0
            } else if i < an + ns {
                1
            } else {
                2
            };
            let name = read_name(bytes, &mut pos)?;
            let fixed = bytes.get(pos..pos + 10).ok_or(DecodeError::Short)?;
            let rtype = RecordType(u16::from_be_bytes([fixed[0], fixed[1]]));
            let class = u16::from_be_bytes([fixed[2], fixed[3]]);
            let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
            let len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
            pos += 10;
            if bytes.len() - pos < len {
                return Err(DecodeError::Short);
            }
            if rtype == RecordType::OPT {
                if section != 2 || msg.edns.is_some() || !name.is_root() {
                    return Err(DecodeError::BadOpt);
                }
                msg.edns = Some(decode_opt(class, ttl, &bytes[pos..pos + len])?);
                pos += len;
                continue;
            }
            let data = RData::decode(rtype, Class(class), bytes, pos, len)?;
            pos += len;
            let record = Record {
                name,
                class: Class(class),
                ttl: if ttl > 0x7FFF_FFFF { 0 } else { ttl },
                data,
            };
            match section {
                0 => msg.answers.push(record),
                1 => msg.authority.push(record),
                _ => msg.additional.push(record),
            }
        }
        if pos != bytes.len() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(msg)
    }

    /// Encodes the message, compressing names where RFC 3597 allows it.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] when a field or the message is too long.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        self.encode_into(&mut w)?;
        Ok(w.buf)
    }

    pub(crate) fn encode_into(&self, w: &mut Writer) -> Result<(), EncodeError> {
        let count = |n: usize| u16::try_from(n).map_err(|_| EncodeError::TooManyRecords);
        let ar = count(self.additional.len() + usize::from(self.edns.is_some()))?;
        w.bytes(&self.header.id.to_be_bytes());
        // Only the low 4 bits of the response code go in the header; the rest
        // are the OPT record's.
        w.bytes(&self.header.flags().to_be_bytes());
        w.bytes(&u16::from(self.question.is_some()).to_be_bytes());
        w.bytes(&count(self.answers.len())?.to_be_bytes());
        w.bytes(&count(self.authority.len())?.to_be_bytes());
        w.bytes(&ar.to_be_bytes());
        if let Some(q) = &self.question {
            w.name(&q.name, true);
            w.bytes(&q.qtype.0.to_be_bytes());
            w.bytes(&q.qclass.0.to_be_bytes());
        }
        for r in self
            .answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            w.name(&r.name, true);
            w.bytes(&r.rtype().0.to_be_bytes());
            w.bytes(&r.class.0.to_be_bytes());
            w.bytes(&r.ttl.to_be_bytes());
            let at = w.buf.len();
            w.bytes(&[0, 0]);
            r.data.encode(w)?;
            w.patch_len(at)?;
        }
        if let Some(e) = &self.edns {
            w.bytes(&[0]);
            w.bytes(&RecordType::OPT.0.to_be_bytes());
            w.bytes(&e.payload.to_be_bytes());
            let ttl = (u32::from(e.ext_rcode) << 24)
                | (u32::from(e.version) << 16)
                | (u32::from(e.dnssec_ok) << 15);
            w.bytes(&ttl.to_be_bytes());
            let at = w.buf.len();
            w.bytes(&[0, 0]);
            for o in &e.options {
                let l = u16::try_from(o.data.len()).map_err(|_| EncodeError::FieldTooLong)?;
                w.bytes(&o.code.to_be_bytes());
                w.bytes(&l.to_be_bytes());
                w.bytes(&o.data);
            }
            w.patch_len(at)?;
        }
        if w.buf.len() > MAX_MESSAGE {
            return Err(EncodeError::TooLong);
        }
        Ok(())
    }
}

fn decode_opt(class: u16, ttl: u32, data: &[u8]) -> Result<Edns, DecodeError> {
    let mut options = Vec::new();
    let mut p = 0;
    while p < data.len() {
        let head = data.get(p..p + 4).ok_or(DecodeError::BadOpt)?;
        let code = u16::from_be_bytes([head[0], head[1]]);
        let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let value = data.get(p + 4..p + 4 + len).ok_or(DecodeError::BadOpt)?;
        options.push(EdnsOption {
            code,
            data: value.into(),
        });
        p += 4 + len;
    }
    Ok(Edns {
        payload: class,
        ext_rcode: (ttl >> 24) as u8,
        version: (ttl >> 16) as u8,
        dnssec_ok: ttl & 0x8000 != 0,
        options,
    })
}

/// Writes a message, compressing names against those already written.
pub(crate) struct Writer {
    pub(crate) buf: Vec<u8>,
    /// Offsets of names (and their suffixes) already written, below 0x4000,
    /// with their length in wire form.
    names: Vec<(u16, u8)>,
}

impl Writer {
    pub(crate) fn new() -> Writer {
        Writer {
            buf: Vec::with_capacity(512),
            names: Vec::new(),
        }
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Writes `name`, ending in a pointer to an earlier copy of its longest
    /// suffix when `compress` is set. Either way its own labels become
    /// targets for later names.
    pub(crate) fn name(&mut self, name: &Name, compress: bool) {
        let wire = name.wire();
        let mut starts = [0usize; 128];
        let mut count = 0;
        let mut p = 0;
        while wire[p] != 0 {
            starts[count] = p;
            count += 1;
            p += 1 + usize::from(wire[p]);
        }
        let mut cut = count;
        let mut target = None;
        if compress {
            'find: for (i, &s) in starts[..count].iter().enumerate() {
                let suffix = &wire[s..];
                for &(at, len) in &self.names {
                    if usize::from(len) == suffix.len() && self.suffix_at(usize::from(at), suffix) {
                        cut = i;
                        target = Some(at);
                        break 'find;
                    }
                }
            }
        }
        for &s in &starts[..cut] {
            let here = self.buf.len();
            if here < 0x4000 && self.names.len() < COMPRESSION_ENTRIES {
                self.names.push((here as u16, (wire.len() - s) as u8));
            }
            let len = usize::from(wire[s]);
            self.buf.extend_from_slice(&wire[s..=s + len]);
        }
        match target {
            Some(at) => self.buf.extend_from_slice(&(0xC000 | at).to_be_bytes()),
            None => self.buf.push(0),
        }
    }

    /// Whether the name written at `at` (following pointers) is `suffix`, case ignored.
    fn suffix_at(&self, at: usize, suffix: &[u8]) -> bool {
        let mut pos = at;
        read_name(&self.buf, &mut pos).is_ok_and(|n| n.wire().eq_ignore_ascii_case(suffix))
    }

    pub(crate) fn patch_len(&mut self, at: usize) -> Result<(), EncodeError> {
        let len = u16::try_from(self.buf.len() - at - 2).map_err(|_| EncodeError::FieldTooLong)?;
        self.buf[at..at + 2].copy_from_slice(&len.to_be_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn n(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    fn sample() -> Message {
        let owner = n("www.example.com");
        Message {
            header: Header {
                id: 0xBEEF,
                response: true,
                recursion_desired: true,
                recursion_available: true,
                authentic_data: true,
                ..Header::default()
            },
            question: Some(Question::new(owner.clone(), RecordType::A)),
            answers: vec![
                Record::new(owner.clone(), 60, RData::Cname(n("web.example.com"))),
                Record::new(
                    n("web.example.com"),
                    60,
                    RData::A(Ipv4Addr::new(192, 0, 2, 7)),
                ),
                Record::new(n("web.example.com"), 60, RData::Aaaa(Ipv6Addr::LOCALHOST)),
                Record::new(
                    n("example.com"),
                    60,
                    RData::Mx {
                        preference: 5,
                        exchange: n("mx.example.com"),
                    },
                ),
                Record::new(
                    n("_x._tcp.example.com"),
                    60,
                    RData::Srv {
                        priority: 1,
                        weight: 2,
                        port: 443,
                        target: n("web.example.com"),
                    },
                ),
                Record::new(
                    n("example.com"),
                    60,
                    RData::Txt(vec![b"a".to_vec().into(), Vec::new().into()]),
                ),
                Record::new(
                    n("example.com"),
                    60,
                    RData::Caa {
                        flags: 128,
                        tag: "issue".into(),
                        value: b"ca.example".to_vec().into(),
                    },
                ),
                Record::new(
                    n("example.com"),
                    60,
                    RData::Unknown {
                        rtype: RecordType(65280),
                        data: vec![1, 2, 3].into(),
                    },
                ),
            ],
            authority: vec![
                Record::new(n("example.com"), 60, RData::Ns(n("ns1.example.com"))),
                Record::new(
                    n("example.com"),
                    60,
                    RData::Soa {
                        mname: n("ns1.example.com"),
                        rname: n("hostmaster.example.com"),
                        serial: 1,
                        refresh: 2,
                        retry: 3,
                        expire: 4,
                        minimum: 5,
                    },
                ),
            ],
            additional: vec![Record::new(
                n("ns1.example.com"),
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, 53)),
            )],
            edns: Some(Edns {
                payload: 1232,
                ext_rcode: 1,
                version: 0,
                dnssec_ok: true,
                options: vec![EdnsOption {
                    code: 10,
                    data: vec![9; 8].into(),
                }],
            }),
        }
    }

    #[test]
    fn round_trip_with_compression() {
        let m = sample();
        let bytes = m.encode().unwrap();
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.rcode(), Rcode(16));
        // "example.com" is written in full twice: in the question, and in
        // the SRV target, which is never compressed (RFC 2782). Every other
        // copy is a pointer.
        let full = b"\x07example\x03com\x00";
        assert_eq!(bytes.windows(full.len()).filter(|w| w == full).count(), 2);
        // The SRV target is written in full (RFC 2782).
        let srv_target = b"\x03web\x07example\x03com\x00";
        assert!(bytes.windows(srv_target.len()).any(|w| w == srv_target));
    }

    #[test]
    fn query_round_trip_and_size() {
        let q = Message::query(1, Question::new(n("example.com"), RecordType::A));
        let bytes = q.encode().unwrap();
        // Header 12, question 13 + 4, OPT 11.
        assert_eq!(bytes.len(), 40);
        assert_eq!(Message::decode(&bytes).unwrap(), q);
    }

    #[test]
    fn strictness() {
        let bytes = sample().encode().unwrap();
        // Trailing bytes.
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(Message::decode(&long), Err(DecodeError::TrailingBytes));
        // Every truncation fails without panicking.
        for cut in 0..bytes.len() {
            assert!(Message::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        // Two questions.
        let mut two = bytes.clone();
        two[5] = 2;
        assert_eq!(Message::decode(&two), Err(DecodeError::QuestionCount));
        // Counts the bytes cannot hold.
        let mut many = bytes.clone();
        many[6] = 0xFF;
        assert_eq!(Message::decode(&many), Err(DecodeError::TooManyRecords));
        assert_eq!(
            Message::decode(&vec![0; MAX_MESSAGE + 1]),
            Err(DecodeError::TooLong)
        );
    }

    fn one_answer(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut b = vec![0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        b.extend_from_slice(b"\x01a\x00");
        b.extend_from_slice(&rtype.to_be_bytes());
        b.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        b.extend_from_slice(rdata);
        b
    }

    #[test]
    fn rdata_must_fill_its_length() {
        let bad = |rtype: u16, rdata: &[u8]| {
            assert_eq!(
                Message::decode(&one_answer(rtype, rdata)),
                Err(DecodeError::BadRdata { rtype }),
                "type {rtype} {rdata:?}"
            );
        };
        bad(1, &[1, 2, 3]);
        bad(1, &[1, 2, 3, 4, 5]);
        bad(28, &[0; 15]);
        bad(5, b"\x01b\x00\x00");
        bad(15, b"\x00\x01");
        bad(15, b"\x00\x01\x01b\x00\x00");
        bad(33, b"\x00\x01\x00\x01\x00");
        bad(6, b"\x00\x00\x00\x00\x00");
        bad(16, b"");
        bad(16, b"\x05abc");
        bad(257, b"\x00\x00");
        bad(257, b"\x00\x02i-");
        bad(257, b"\x00\x09issue");
        // A name in the data that runs past the data's end.
        let mut m = one_answer(5, b"\x01b");
        m.extend_from_slice(b"\x00");
        // The header counted one record; the extra byte becomes the end of
        // the name, which is past the rdata.
        assert!(Message::decode(&m).is_err());
        // An A record in another class is kept as bytes.
        let mut ch = one_answer(1, &[0, 0, 0]);
        ch[18] = 3;
        let msg = Message::decode(&ch).unwrap();
        assert!(matches!(msg.answers[0].data, RData::Unknown { .. }));
    }

    #[test]
    fn ttl_top_bit_reads_as_zero() {
        let mut b = one_answer(1, &[1, 2, 3, 4]);
        b[19..23].copy_from_slice(&0x8000_0001u32.to_be_bytes());
        assert_eq!(Message::decode(&b).unwrap().answers[0].ttl, 0);
    }

    #[test]
    fn opt_rules() {
        let q = Message::query(1, Question::new(n("a"), RecordType::A));
        let mut bytes = q.encode().unwrap();
        // Two OPT records.
        let opt = bytes[bytes.len() - 11..].to_vec();
        bytes.extend_from_slice(&opt);
        bytes[11] = 2;
        assert_eq!(Message::decode(&bytes), Err(DecodeError::BadOpt));
        // OPT in the answer section.
        assert_eq!(
            Message::decode(&one_answer(41, &[])),
            Err(DecodeError::BadOpt)
        );
        // OPT owned by a name other than the root.
        let mut m = Message::query(1, Question::new(n("a"), RecordType::A))
            .encode()
            .unwrap();
        let at = m.len() - 11;
        m.splice(at..=at, b"\x01x\x00".iter().copied());
        assert_eq!(Message::decode(&m), Err(DecodeError::BadOpt));
        // An option that runs past the OPT data.
        let mut e = Message::query(1, Question::new(n("a"), RecordType::A))
            .encode()
            .unwrap();
        let len_at = e.len() - 2;
        e[len_at + 1] = 3;
        e.extend_from_slice(&[0, 1, 0]);
        assert_eq!(Message::decode(&e), Err(DecodeError::BadOpt));
    }

    #[test]
    fn writer_compresses_case_insensitively() {
        let mut w = Writer::new();
        w.name(&n("Example.COM"), true);
        let before = w.buf.len();
        w.name(&n("www.example.com"), true);
        // "www" and a pointer.
        assert_eq!(w.buf.len() - before, 4 + 2);
        w.name(&n("www.example.com"), false);
        assert_eq!(w.buf.len() - before, 6 + 17);
    }
}
