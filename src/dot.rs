//! DNS over TLS (RFC 7858): one connection per TLS upstream, opened when a
//! query needs it, kept while queries are in flight and for a short idle
//! time after, carrying any number of queries at once matched by id (RFC 7766
//! section 6.2.1.1: replies may come in any order).
//!
//! The TCP connect and the TLS handshake run on a short-lived thread with
//! blocking reads, as the TCP fallback does. The established session then
//! moves to the resolver's thread, which registers the socket with its driver
//! and drives the session without I/O: ciphertext from each receive goes in,
//! plaintext comes out, and queries are sealed and written as they are sent.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Instant;

use net_io::Token;
use tls_net::{
    ClientSession, DnsName, Event, MAX_RECORD_PAYLOAD, MIN_OUTPUT_BUFFER, ServerIdentity,
    SessionState, TlsClient, TlsError,
};

use crate::config::TlsTarget;
use crate::resolver::Error;

/// The most ciphertext held without the session consuming it: a record is at
/// most about 16 KiB and the session takes each one whole, so more than this
/// waiting means the peer is not speaking TLS.
const MAX_HELD_INPUT: usize = 256 * 1024;

/// The most plaintext held while a reply is incomplete: one message of
/// 65,535 bytes and its length, and the start of the next.
const MAX_HELD_PLAIN: usize = 2 * 65_537;

/// The session, without a transport.
pub(crate) struct Session {
    session: ClientSession,
    input: Vec<u8>,
    filled: usize,
    output: Vec<u8>,
    peer_closed: bool,
    broken: bool,
}

impl Session {
    fn new(session: ClientSession) -> Session {
        Session {
            input: vec![0; session.input_capacity_required()],
            session,
            filled: 0,
            output: vec![0; MIN_OUTPUT_BUFFER],
            peer_closed: false,
            broken: false,
        }
    }

    /// Appends ciphertext after what the session has not consumed yet.
    fn push(&mut self, cipher: &[u8]) -> io::Result<()> {
        let want = (self.filled + cipher.len()).max(self.session.input_capacity_required());
        if want > MAX_HELD_INPUT {
            self.broken = true;
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if self.input.len() < want {
            self.input.resize(want, 0);
        }
        self.input[self.filled..self.filled + cipher.len()].copy_from_slice(cipher);
        self.filled += cipher.len();
        Ok(())
    }

    /// Steps the session until it needs more input, writing what it seals to
    /// `wire` and appending plaintext to `plain`. True when anything moved.
    fn run(&mut self, wire: &mut impl Write, plain: &mut Vec<u8>) -> io::Result<bool> {
        if self.broken {
            return Err(invalid(TlsError::WrongState));
        }
        let mut moved = false;
        loop {
            let p = match self
                .session
                .step(&mut self.input[..self.filled], &mut self.output)
            {
                Ok(p) => p,
                Err(e) => {
                    self.broken = true;
                    return Err(invalid(e));
                }
            };
            let (consumed, written) = (p.consumed, p.written);
            let mut stop = false;
            match p.event {
                Event::Data(d) => {
                    if plain.len() + d.len() > MAX_HELD_PLAIN {
                        self.broken = true;
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    plain.extend_from_slice(d);
                    moved = true;
                }
                Event::NeedInput => stop = consumed == 0 && written == 0,
                Event::PeerClosed | Event::Closed => {
                    self.peer_closed = true;
                    stop = true;
                }
                Event::OutputFull if written == 0 => {
                    self.broken = true;
                    return Err(invalid(TlsError::OutputFull {
                        required: MIN_OUTPUT_BUFFER,
                    }));
                }
                _ => {}
            }
            if written > 0 {
                if let Err(e) = wire.write_all(&self.output[..written]) {
                    self.broken = true;
                    return Err(e);
                }
            }
            self.input.copy_within(consumed..self.filled, 0);
            self.filled -= consumed;
            moved |= consumed > 0 || written > 0;
            if stop {
                return Ok(moved);
            }
        }
    }

    /// Seals `bytes` and writes the records.
    fn send(
        &mut self,
        mut bytes: &[u8],
        wire: &mut impl Write,
        plain: &mut Vec<u8>,
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.broken {
                return Err(invalid(TlsError::WrongState));
            }
            let part = &bytes[..bytes.len().min(MAX_RECORD_PAYLOAD)];
            match self.session.encrypt(part, &mut self.output) {
                Ok(n) => {
                    if let Err(e) = wire.write_all(&self.output[..n]) {
                        self.broken = true;
                        return Err(e);
                    }
                    bytes = &bytes[part.len()..];
                }
                // Records the session queued (a key update's reply) go out
                // through `step` first.
                Err(TlsError::WrongState)
                    if matches!(
                        self.session.state(),
                        SessionState::Established | SessionState::HalfClosed
                    ) =>
                {
                    if !self.run(wire, plain)? {
                        self.broken = true;
                        return Err(invalid(TlsError::WrongState));
                    }
                }
                Err(e) => {
                    self.broken = true;
                    return Err(invalid(e));
                }
            }
        }
        Ok(())
    }

    /// Sends `close_notify`.
    fn close(&mut self, wire: &mut impl Write) {
        if !self.broken {
            if let Ok(n) = self.session.close(&mut self.output) {
                let _ = wire.write_all(&self.output[..n]);
            }
        }
    }
}

fn invalid(e: TlsError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Connects to `addr`, runs the handshake for `target`, and returns the
/// socket and the established session, within `deadline`. Runs on a helper
/// thread.
pub(crate) fn connect(
    client: &TlsClient,
    addr: SocketAddr,
    target: &TlsTarget,
    deadline: Instant,
) -> Result<(TcpStream, Session), Error> {
    let identity = if target.pins.is_empty() {
        ServerIdentity::parse(&target.name).map_err(|_| Error::Tls)?
    } else {
        ServerIdentity::Pinned {
            name: DnsName::new(&target.name).map_err(|_| Error::Tls)?,
            spki_sha256: target.pins.clone(),
            require_chain: false,
        }
    };
    let session = client.connect_to(&identity).map_err(|_| Error::Tls)?;
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Error::Timeout);
    }
    let stream = TcpStream::connect_timeout(&addr, left).map_err(|e| match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Error::Timeout,
        k => Error::Io(k),
    })?;
    let _ = stream.set_nodelay(true);
    let mut session = Session::new(session);
    let mut chunk = [0u8; 4096];
    let mut early = Vec::new();
    loop {
        session
            .run(&mut &stream, &mut early)
            .map_err(|_| Error::Tls)?;
        if session.session.info().is_some() {
            break;
        }
        if session.peer_closed {
            return Err(Error::Tls);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Timeout);
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(|e| Error::Io(e.kind()))?;
        let n = match (&stream).read(&mut chunk) {
            Ok(0) => return Err(Error::Tls),
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(Error::Timeout);
            }
            Err(e) => return Err(Error::Io(e.kind())),
        };
        session.push(&chunk[..n]).map_err(|_| Error::Tls)?;
    }
    // A server does not speak before it is asked.
    if !early.is_empty() {
        return Err(Error::Bogus);
    }
    stream
        .set_read_timeout(None)
        .map_err(|e| Error::Io(e.kind()))?;
    Ok((stream, session))
}

/// An open connection on the resolver's thread.
pub(crate) struct Conn {
    pub(crate) stream: Arc<TcpStream>,
    pub(crate) token: Token,
    session: Session,
    /// Plaintext of replies not yet complete.
    plain: Vec<u8>,
    /// When the last query in flight ended (for the idle close).
    pub(crate) idle_since: Instant,
}

impl Conn {
    pub(crate) fn new(stream: TcpStream, session: Session, token: Token) -> Conn {
        Conn {
            stream: Arc::new(stream),
            token,
            session,
            plain: Vec::new(),
            idle_since: Instant::now(),
        }
    }

    /// Sends one query with its two-byte length (RFC 1035 section 4.2.2).
    pub(crate) fn send(&mut self, framed: &[u8]) -> io::Result<()> {
        let mut wire = &*self.stream;
        let mut plain = std::mem::take(&mut self.plain);
        let r = self.session.send(framed, &mut wire, &mut plain);
        self.plain = plain;
        r
    }

    /// Takes ciphertext from the socket; returns the complete replies it
    /// finished, and whether the peer closed.
    pub(crate) fn absorb(&mut self, cipher: &[u8]) -> io::Result<(Vec<Vec<u8>>, bool)> {
        self.session.push(cipher)?;
        let mut wire = &*self.stream;
        let mut plain = std::mem::take(&mut self.plain);
        let r = self.session.run(&mut wire, &mut plain);
        self.plain = plain;
        r?;
        let replies = split_messages(&mut self.plain)?;
        Ok((replies, self.session.peer_closed))
    }

    /// Sends `close_notify`.
    pub(crate) fn close(&mut self) {
        let mut wire = &*self.stream;
        self.session.close(&mut wire);
    }
}

/// Takes the whole length-prefixed messages (RFC 1035 section 4.2.2) from the
/// front of `plain`, leaving an incomplete one there.
///
/// # Errors
///
/// `InvalidData` for a length shorter than a DNS header.
pub(crate) fn split_messages(plain: &mut Vec<u8>) -> io::Result<Vec<Vec<u8>>> {
    let mut messages = Vec::new();
    let mut at = 0;
    while let Some(len) = plain
        .get(at..at + 2)
        .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    {
        if len < 12 {
            // Shorter than a header: not DNS.
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let Some(message) = plain.get(at + 2..at + 2 + len) else {
            break;
        };
        messages.push(message.to_vec());
        at += 2 + len;
    }
    plain.drain(..at);
    Ok(messages)
}

/// What the resolver keeps per TLS upstream.
#[derive(Default)]
pub(crate) struct Slot {
    pub(crate) conn: Option<Conn>,
    pub(crate) connecting: bool,
    /// Queries on this upstream (sent or waiting): id to (flight, generation).
    pub(crate) ids: HashMap<u16, (usize, u32)>,
    /// Ids waiting for the connection, in order.
    pub(crate) queued: Vec<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(len: usize, fill: u8) -> Vec<u8> {
        let mut v = (len as u16).to_be_bytes().to_vec();
        v.extend(std::iter::repeat_n(fill, len));
        v
    }

    #[test]
    fn messages_split_at_every_byte() {
        let mut stream = framed(12, 1);
        stream.extend(framed(300, 2));
        stream.extend(framed(12, 3));
        // Fed in two pieces, cut at every place.
        for cut in 0..=stream.len() {
            let mut plain = stream[..cut].to_vec();
            let mut got = split_messages(&mut plain).unwrap();
            plain.extend_from_slice(&stream[cut..]);
            got.extend(split_messages(&mut plain).unwrap());
            assert!(plain.is_empty(), "cut {cut}");
            let lens: Vec<usize> = got.iter().map(Vec::len).collect();
            assert_eq!(lens, vec![12, 300, 12], "cut {cut}");
        }
    }

    #[test]
    fn short_lengths_are_refused() {
        let mut plain = framed(11, 0);
        assert!(split_messages(&mut plain).is_err());
        let mut empty = Vec::new();
        assert!(split_messages(&mut empty).unwrap().is_empty());
    }
}
