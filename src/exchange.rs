//! One query and its reply, without I/O: build the query, check that a reply
//! answers it, and take from the reply only the records that answer the
//! question.
//!
//! The checks are the cache-poisoning defences of a stub resolver: the reply
//! repeats the random id, the question exactly as sent (including the random
//! case of each letter, the "0x20" bit), and only records on the chain from
//! the question's name to its answer are kept. Records about other names, the
//! authority section (but for the SOA of a negative answer) and the additional
//! section are never used.

use std::fmt;

use crate::error::{DecodeError, EncodeError};
use crate::message::{Edns, Message, Question, Record};
use crate::name::Name;
use crate::rdata::RData;
use crate::types::{Opcode, Rcode, RecordType};

/// The longest CNAME chain followed for one question, in one reply or across
/// several (RFC 1034 section 3.6.2 leaves the bound to the resolver).
pub const MAX_CHAIN: usize = 8;

/// The EDNS(0) Padding option code (RFC 7830).
const PADDING: u16 = 12;

/// A query on its way to a server, and the checks its reply must pass.
///
/// ```
/// use dns_net::{Exchange, Message, Name, Question, RecordType};
/// let q = Question::new(Name::parse("example.com")?, RecordType::A);
/// // The id and the case bits come from a random source in the resolver.
/// let ex = Exchange::new(&q, 0x5A5A, &[0b1010_1010], Some(1232))?;
/// assert_eq!(ex.question().name.to_string(), "eXaMpLe.CoM");
///
/// let mut reply = Message::decode(ex.bytes())?;
/// reply.header.response = true;
/// assert!(ex.check(&reply.encode()?).is_ok());
///
/// // The same reply with the name in lower case is refused.
/// reply.question = Some(q.clone());
/// assert!(ex.check(&reply.encode()?).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Exchange {
    id: u16,
    question: Question,
    edns: bool,
    bytes: Vec<u8>,
}

impl Exchange {
    /// A recursive query for `question` with `id`, the letters of the name
    /// cased by `case_bits` (one bit per letter; empty leaves the case
    /// alone), and EDNS(0) advertising `payload` (or no OPT record). The AD
    /// bit is set, asking a validating server to report it (RFC 6840 section
    /// 5.7).
    ///
    /// # Errors
    ///
    /// [`EncodeError`] cannot happen for a valid question; it is passed on.
    pub fn new(
        question: &Question,
        id: u16,
        case_bits: &[u8],
        payload: Option<u16>,
    ) -> Result<Exchange, EncodeError> {
        Exchange::padded(question, id, case_bits, payload, 0)
    }

    /// As [`Exchange::new`], with the query padded to a multiple of `block`
    /// bytes by an EDNS(0) Padding option (RFC 7830), so its length does not
    /// tell an observer of an encrypted transport which name was asked for.
    /// RFC 8467 recommends 128 for queries. A `block` of 0, or no `payload`
    /// (no OPT record to carry the option), pads nothing.
    ///
    /// ```
    /// use dns_net::{Exchange, Name, Question, RecordType};
    /// let q = Question::new(Name::parse("example.com")?, RecordType::A);
    /// let ex = Exchange::padded(&q, 1, &[], Some(1232), 128)?;
    /// assert_eq!(ex.bytes().len() % 128, 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`Exchange::new`].
    pub fn padded(
        question: &Question,
        id: u16,
        case_bits: &[u8],
        payload: Option<u16>,
        block: usize,
    ) -> Result<Exchange, EncodeError> {
        let sent = Question {
            name: question.name.with_case(case_bits),
            qtype: question.qtype,
            qclass: question.qclass,
        };
        let mut msg = Message::query(id, sent.clone());
        msg.header.authentic_data = true;
        msg.edns = payload.map(Edns::new);
        let mut bytes = msg.encode()?;
        if let (Some(edns), true) = (msg.edns.as_mut(), block > 0) {
            // The option itself takes 4 bytes before its zeros.
            let pad = (block - (bytes.len() + 4) % block) % block;
            edns.options.push(crate::message::EdnsOption {
                code: PADDING,
                data: vec![0; pad].into(),
            });
            bytes = msg.encode()?;
        }
        Ok(Exchange {
            id,
            question: sent,
            edns: payload.is_some(),
            bytes,
        })
    }

    /// The id.
    #[must_use]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// The question as sent, with its randomized case.
    #[must_use]
    pub fn question(&self) -> &Question {
        &self.question
    }

    /// Whether the query carries an OPT record.
    #[must_use]
    pub fn has_edns(&self) -> bool {
        self.edns
    }

    /// The query, ready for a UDP datagram.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The query with TCP's two-byte length in front (RFC 1035 section 4.2.2).
    #[must_use]
    pub fn tcp_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.bytes.len() + 2);
        out.extend_from_slice(&(self.bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Checks that `reply` is the answer to this query: a response, the same
    /// id, a standard query, and the question exactly as sent. A reply without
    /// a question is accepted only with an error code, which some servers send
    /// for a query they cannot read.
    ///
    /// The id is compared before anything is decoded, so a flood of forged
    /// replies costs two byte comparisons each.
    ///
    /// # Errors
    ///
    /// [`Mismatch`] says why the reply is not this query's; the caller drops
    /// it and keeps waiting.
    pub fn check(&self, reply: &[u8]) -> Result<Message, Mismatch> {
        if reply.len() < 12 || reply[..2] != self.id.to_be_bytes() {
            return Err(Mismatch::Id);
        }
        let msg = Message::decode(reply).map_err(Mismatch::Undecodable)?;
        if !msg.header.response {
            return Err(Mismatch::NotResponse);
        }
        if msg.header.opcode != Opcode::QUERY {
            return Err(Mismatch::Opcode);
        }
        match &msg.question {
            Some(q) => {
                if q.qtype != self.question.qtype
                    || q.qclass != self.question.qclass
                    || q.name != self.question.name
                {
                    return Err(Mismatch::Question);
                }
                if !q.name.eq_exact(&self.question.name) {
                    return Err(Mismatch::Case);
                }
            }
            None => {
                let rcode = msg.rcode();
                if rcode == Rcode::NOERROR || rcode == Rcode::NXDOMAIN {
                    return Err(Mismatch::Question);
                }
            }
        }
        Ok(msg)
    }
}

/// Why a reply was not taken as the answer to a query.
///
/// ```
/// assert_eq!(dns_net::Mismatch::Case.to_string(), "the reply changed the case of the name");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// Another id, or too short to hold one.
    Id,
    /// The bytes are not a well-formed message.
    Undecodable(DecodeError),
    /// A query, not a response.
    NotResponse,
    /// Not a standard query.
    Opcode,
    /// Another question, or none with a success code.
    Question,
    /// The question's name with its case changed: the case randomization did
    /// not survive, which a forged reply would not know to repeat.
    Case,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mismatch::Id => f.write_str("the reply has another id"),
            Mismatch::Undecodable(e) => write!(f, "the reply is malformed: {e}"),
            Mismatch::NotResponse => f.write_str("the reply is not a response"),
            Mismatch::Opcode => f.write_str("the reply is not a standard query"),
            Mismatch::Question => f.write_str("the reply answers another question"),
            Mismatch::Case => f.write_str("the reply changed the case of the name"),
        }
    }
}

impl std::error::Error for Mismatch {}

/// What a lookup found.
///
/// ```
/// assert_ne!(dns_net::Status::Found, dns_net::Status::NxDomain);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// Records of the type asked for.
    Found,
    /// The name exists, but has no records of that type (NODATA).
    NoData,
    /// The name does not exist (NXDOMAIN).
    NxDomain,
}

/// The part of a reply that answers the question.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// What was found.
    pub status: Status,
    /// The records of the type asked for, owned by the last name of the chain.
    pub records: Vec<Record>,
    /// The CNAME records from the question's name to that name, in order.
    pub chain: Vec<Record>,
    /// How long the answer may be cached: the smallest TTL of its records,
    /// or for a negative answer the SOA's (RFC 2308 section 5). `None` when
    /// a negative answer has no SOA, and must not be cached.
    pub ttl: Option<u32>,
    /// The reply had the AD bit set: the server says it validated the
    /// answer with DNSSEC. Worth only as much as the path to that server.
    pub authentic: bool,
}

impl Answer {
    /// The name the records belong to: the end of the CNAME chain.
    #[must_use]
    pub fn canonical_name<'a>(&'a self, question: &'a Name) -> &'a Name {
        match self.chain.last().map(|r| &r.data) {
            Some(RData::Cname(target)) => target,
            _ => question,
        }
    }
}

/// What a reply means for the question.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// An answer, positive or negative.
    Answer(Answer),
    /// The reply was cut to fit: ask again over TCP.
    Truncated,
    /// The chain ends in a CNAME whose target the reply does not answer: ask
    /// again for the target, keeping the chain.
    Follow {
        /// The name to ask about next.
        target: Name,
        /// The CNAME records so far.
        chain: Vec<Record>,
    },
    /// The server reported an error (SERVFAIL, REFUSED, FORMERR, NOTIMP, ...).
    ServerError(Rcode),
    /// The reply contradicts itself: two CNAMEs for one name, a CNAME loop,
    /// a chain over [`MAX_CHAIN`], or NXDOMAIN with records for the name.
    Bogus,
}

impl Outcome {
    /// Reads `reply` (already accepted by [`Exchange::check`]) as an answer to
    /// `question`. Names are compared without case.
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use dns_net::{Message, Name, Outcome, Question, RData, Record, RecordType, Status};
    /// let q = Question::new(Name::parse("www.example")?, RecordType::A);
    /// let mut reply = Message::query(1, q.clone());
    /// reply.header.response = true;
    /// reply.answers.push(Record::new(Name::parse("www.example")?, 300, RData::A(Ipv4Addr::new(192, 0, 2, 1))));
    /// // A record about another name is ignored, never cached.
    /// reply.answers.push(Record::new(Name::parse("bank.example")?, 300, RData::A(Ipv4Addr::new(192, 0, 2, 66))));
    /// let Outcome::Answer(answer) = Outcome::read(&q, &reply) else { panic!() };
    /// assert_eq!(answer.status, Status::Found);
    /// assert_eq!(answer.records.len(), 1);
    /// # Ok::<(), dns_net::NameError>(())
    /// ```
    #[must_use]
    pub fn read(question: &Question, reply: &Message) -> Outcome {
        Outcome::read_chain(question, reply, &question.name, &[])
    }

    /// As [`Outcome::read`], continuing a chain from an earlier reply: `name`
    /// is the target being asked about, `chain` the CNAMEs that led to it.
    #[must_use]
    pub fn read_chain(
        question: &Question,
        reply: &Message,
        name: &Name,
        chain: &[Record],
    ) -> Outcome {
        if reply.header.truncated {
            return Outcome::Truncated;
        }
        let rcode = reply.rcode();
        if rcode != Rcode::NOERROR && rcode != Rcode::NXDOMAIN {
            return Outcome::ServerError(rcode);
        }
        let mut chain = chain.to_vec();
        let mut current = name.clone();
        let mut records = Vec::new();
        loop {
            let owned = || {
                reply
                    .answers
                    .iter()
                    .filter(|r| r.class == question.qclass && r.name == current)
            };
            records.extend(
                owned()
                    .filter(|r| r.rtype() == question.qtype || question.qtype == RecordType::ANY)
                    .cloned(),
            );
            if question.qtype == RecordType::CNAME {
                break;
            }
            let mut cnames = owned().filter(|r| r.rtype() == RecordType::CNAME);
            let Some(cname) = cnames.next() else { break };
            // A CNAME and other data at one name cannot both be true (RFC
            // 1034 section 3.6.2), and readers would pick differently.
            if !records.is_empty() {
                return Outcome::Bogus;
            }
            if cnames.next().is_some() {
                return Outcome::Bogus;
            }
            let RData::Cname(target) = &cname.data else {
                return Outcome::Bogus;
            };
            if *target == current
                || *target == question.name
                || chain.iter().any(|r| r.name == *target)
            {
                return Outcome::Bogus;
            }
            if chain.len() >= MAX_CHAIN {
                return Outcome::Bogus;
            }
            let target = target.clone();
            chain.push(cname.clone());
            current = target;
        }
        let chain_ttl = chain.iter().map(|r| r.ttl).min();
        if !records.is_empty() {
            if rcode == Rcode::NXDOMAIN {
                return Outcome::Bogus;
            }
            let ttl = records.iter().map(|r| r.ttl).chain(chain_ttl).min();
            return Outcome::Answer(Answer {
                status: Status::Found,
                records,
                chain,
                ttl,
                authentic: reply.header.authentic_data,
            });
        }
        // A negative answer's TTL: the SOA of a zone the name is in.
        let soa_ttl = reply.authority.iter().find_map(|r| match &r.data {
            RData::Soa { minimum, .. }
                if r.class == question.qclass && current.is_within(&r.name) =>
            {
                Some(r.ttl.min(*minimum))
            }
            _ => None,
        });
        if rcode == Rcode::NOERROR && soa_ttl.is_none() && !chain.is_empty() {
            return Outcome::Follow {
                target: current,
                chain,
            };
        }
        Outcome::Answer(Answer {
            status: if rcode == Rcode::NXDOMAIN {
                Status::NxDomain
            } else {
                Status::NoData
            },
            records,
            ttl: soa_ttl.map(|t| chain_ttl.map_or(t, |c| c.min(t))),
            chain,
            authentic: reply.header.authentic_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::message::Header;

    fn n(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    fn q(name: &str, t: RecordType) -> Question {
        Question::new(n(name), t)
    }

    fn reply_to(ex: &Exchange) -> Message {
        let mut m = Message::decode(ex.bytes()).unwrap();
        m.header.response = true;
        m.header.recursion_available = true;
        m
    }

    fn a(name: &str, ttl: u32, last: u8) -> Record {
        Record::new(n(name), ttl, RData::A(Ipv4Addr::new(192, 0, 2, last)))
    }

    fn cname(name: &str, ttl: u32, target: &str) -> Record {
        Record::new(n(name), ttl, RData::Cname(n(target)))
    }

    fn soa(zone: &str, ttl: u32, minimum: u32) -> Record {
        Record::new(
            n(zone),
            ttl,
            RData::Soa {
                mname: n("ns.example"),
                rname: n("admin.example"),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum,
            },
        )
    }

    #[test]
    fn check_refuses_every_mismatch() {
        let question = q("www.example.com", RecordType::A);
        let ex = Exchange::new(&question, 0x1234, &[0x5A, 0xA5], Some(1232)).unwrap();
        let good = reply_to(&ex);
        assert!(ex.check(&good.encode().unwrap()).is_ok());

        let mut m = good.clone();
        m.header.id ^= 1;
        assert_eq!(ex.check(&m.encode().unwrap()), Err(Mismatch::Id));
        let mut m = good.clone();
        m.header.response = false;
        assert_eq!(ex.check(&m.encode().unwrap()), Err(Mismatch::NotResponse));
        let mut m = good.clone();
        m.header.opcode = Opcode::NOTIFY;
        assert_eq!(ex.check(&m.encode().unwrap()), Err(Mismatch::Opcode));
        let mut m = good.clone();
        m.question = Some(q("www.example.org", RecordType::A));
        assert_eq!(ex.check(&m.encode().unwrap()), Err(Mismatch::Question));
        let mut m = good.clone();
        m.question = Some(q("www.example.com", RecordType::AAAA));
        assert_eq!(ex.check(&m.encode().unwrap()), Err(Mismatch::Question));
        let mut m = good.clone();
        m.question = Some(question.clone());
        assert_eq!(ex.check(&m.encode().unwrap()), Err(Mismatch::Case));
        let mut m = good.clone();
        m.question = None;
        assert_eq!(ex.check(&m.encode().unwrap()), Err(Mismatch::Question));
        m.header.rcode = 1;
        assert!(
            ex.check(&m.encode().unwrap()).is_ok(),
            "FORMERR without a question"
        );
        assert_eq!(ex.check(&[0x12, 0x34]), Err(Mismatch::Id));
        assert!(matches!(
            ex.check(&[0x12, 0x34, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
            Err(Mismatch::Undecodable(_))
        ));
    }

    #[test]
    fn case_randomization_changes_letters_only() {
        let question = q("a1-b.example", RecordType::A);
        let ex = Exchange::new(&question, 1, &[0xFF], None).unwrap();
        assert_eq!(ex.question().name.to_string(), "A1-B.EXAMPLE");
        assert!(!ex.has_edns());
        assert_eq!(Message::decode(ex.bytes()).unwrap().edns, None);
        let tcp = ex.tcp_bytes();
        assert_eq!(
            usize::from(u16::from_be_bytes([tcp[0], tcp[1]])),
            ex.bytes().len()
        );
    }

    #[test]
    fn found_through_a_chain() {
        let question = q("www.example", RecordType::A);
        let mut m = Message {
            header: Header {
                response: true,
                ..Header::default()
            },
            question: Some(question.clone()),
            ..Message::default()
        };
        m.answers = vec![
            cname("WWW.example", 300, "edge.cdn.example"),
            cname("edge.cdn.example", 60, "e1.cdn.example"),
            a("e1.cdn.example", 120, 1),
            a("e1.cdn.example", 120, 2),
            // Not on the chain: dropped.
            a("www.example", 9, 9),
            a("other.example", 9, 9),
        ];
        // "www.example" has a CNAME and an A record, which cannot both be
        // true: the reply is refused.
        assert_eq!(Outcome::read(&question, &m), Outcome::Bogus);

        m.answers
            .retain(|r| r.name != n("www.example") || r.rtype() == RecordType::CNAME);
        m.answers.retain(|r| r.name != n("other.example"));
        let Outcome::Answer(ans) = Outcome::read(&question, &m) else {
            panic!()
        };
        assert_eq!(ans.records.len(), 2);
        assert_eq!(ans.chain.len(), 2);
        assert_eq!(ans.ttl, Some(60));
        assert_eq!(ans.canonical_name(&question.name), &n("e1.cdn.example"));
    }

    #[test]
    fn bogus_chains() {
        let question = q("a.example", RecordType::A);
        let mut m = Message {
            header: Header {
                response: true,
                ..Header::default()
            },
            question: Some(question.clone()),
            ..Message::default()
        };
        m.answers = vec![
            cname("a.example", 1, "b.example"),
            cname("b.example", 1, "a.example"),
        ];
        assert_eq!(Outcome::read(&question, &m), Outcome::Bogus);
        m.answers = vec![cname("a.example", 1, "a.example")];
        assert_eq!(Outcome::read(&question, &m), Outcome::Bogus);
        m.answers = vec![
            cname("a.example", 1, "b.example"),
            cname("a.example", 1, "c.example"),
        ];
        assert_eq!(Outcome::read(&question, &m), Outcome::Bogus);
        m.answers = (0..=MAX_CHAIN)
            .map(|i| {
                let from = if i == 0 {
                    "a.example".to_string()
                } else {
                    format!("c{i}.example")
                };
                cname(&from, 1, &format!("c{}.example", i + 1))
            })
            .collect();
        assert_eq!(Outcome::read(&question, &m), Outcome::Bogus);
        m.answers = vec![a("a.example", 1, 1)];
        m.header.rcode = 3;
        assert_eq!(Outcome::read(&question, &m), Outcome::Bogus);
    }

    #[test]
    fn negative_answers() {
        let question = q("nope.example", RecordType::A);
        let mut m = Message {
            header: Header {
                response: true,
                rcode: 3,
                ..Header::default()
            },
            question: Some(question.clone()),
            ..Message::default()
        };
        m.authority = vec![soa("example", 900, 60)];
        let Outcome::Answer(ans) = Outcome::read(&question, &m) else {
            panic!()
        };
        assert_eq!(ans.status, Status::NxDomain);
        assert_eq!(ans.ttl, Some(60));

        // An SOA of a zone the name is not in gives no TTL.
        m.authority = vec![soa("other.example", 900, 60)];
        let Outcome::Answer(ans) = Outcome::read(&question, &m) else {
            panic!()
        };
        assert_eq!(ans.ttl, None);

        // NODATA.
        m.header.rcode = 0;
        m.authority = vec![soa("example", 30, 600)];
        let Outcome::Answer(ans) = Outcome::read(&question, &m) else {
            panic!()
        };
        assert_eq!(ans.status, Status::NoData);
        assert_eq!(ans.ttl, Some(30));
    }

    #[test]
    fn chain_without_an_answer_is_followed() {
        let question = q("a.example", RecordType::A);
        let mut m = Message {
            header: Header {
                response: true,
                ..Header::default()
            },
            question: Some(question.clone()),
            ..Message::default()
        };
        m.answers = vec![cname("a.example", 1, "b.other")];
        let Outcome::Follow { target, chain } = Outcome::read(&question, &m) else {
            panic!()
        };
        assert_eq!(target, n("b.other"));
        // The second reply answers the target; the chain carries over.
        let mut second = Message {
            header: Header {
                response: true,
                ..Header::default()
            },
            question: Some(Question::new(target.clone(), RecordType::A)),
            ..Message::default()
        };
        second.answers = vec![a("b.other", 50, 3)];
        let Outcome::Answer(ans) = Outcome::read_chain(&question, &second, &target, &chain) else {
            panic!()
        };
        assert_eq!(ans.records.len(), 1);
        assert_eq!(ans.ttl, Some(1));
    }

    #[test]
    fn server_errors_and_truncation() {
        let question = q("a.example", RecordType::A);
        let mut m = Message {
            header: Header {
                response: true,
                rcode: 2,
                ..Header::default()
            },
            question: Some(question.clone()),
            ..Message::default()
        };
        assert_eq!(
            Outcome::read(&question, &m),
            Outcome::ServerError(Rcode::SERVFAIL)
        );
        m.header.truncated = true;
        assert_eq!(Outcome::read(&question, &m), Outcome::Truncated);
    }
}
