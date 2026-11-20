//! A fake upstream: a UDP socket and a TCP listener on one loopback port,
//! answering with whatever the test's handler decides.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use dns_net::{
    Header, Message, Name, Question, RData, Record, RecordType, ResolverConfig, Upstream,
};

/// What the handler asks the fake server to do with one query.
pub enum Reply {
    /// Send these messages (each as its own datagram) back.
    Messages(Vec<Message>),
    /// Send these raw datagrams back.
    Raw(Vec<Vec<u8>>),
    /// Send nothing.
    Nothing,
}

/// One query the fake server received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub from: SocketAddr,
    pub tcp: bool,
    pub query: Message,
}

type Handler = dyn Fn(&Message, bool, SocketAddr) -> Reply + Send + Sync;

pub struct Fake {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Fake {
    /// Starts a server; `handler(query, over_tcp)` decides each reply.
    pub fn start<H>(handler: H) -> Fake
    where
        H: Fn(&Message, bool) -> Reply + Send + Sync + 'static,
    {
        Fake::start_from(move |q, tcp, _| handler(q, tcp))
    }

    /// As [`Fake::start`], the handler also given the query's source address.
    pub fn start_from<H>(handler: H) -> Fake
    where
        H: Fn(&Message, bool, SocketAddr) -> Reply + Send + Sync + 'static,
    {
        let handler: Arc<Handler> = Arc::new(handler);
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        tcp.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        {
            let (seen, stop, handler) = (seen.clone(), stop.clone(), handler.clone());
            threads.push(std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, from)) = udp.recv_from(&mut buf) else {
                        continue;
                    };
                    let Ok(query) = Message::decode(&buf[..n]) else {
                        continue;
                    };
                    seen.lock().unwrap().push(Seen {
                        from,
                        tcp: false,
                        query: query.clone(),
                    });
                    for bytes in render(handler(&query, false, from)) {
                        let _ = udp.send_to(&bytes, from);
                    }
                }
            }));
        }
        {
            let (seen, stop, handler) = (seen.clone(), stop.clone(), handler.clone());
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let Ok((mut s, from)) = tcp.accept() else {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    s.set_nonblocking(false).unwrap();
                    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).is_err() {
                        continue;
                    }
                    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if s.read_exact(&mut q).is_err() {
                        continue;
                    }
                    let Ok(query) = Message::decode(&q) else {
                        continue;
                    };
                    seen.lock().unwrap().push(Seen {
                        from,
                        tcp: true,
                        query: query.clone(),
                    });
                    for bytes in render(handler(&query, true, from)) {
                        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&bytes);
                        let _ = s.write_all(&framed);
                    }
                }
            }));
        }
        Fake {
            addr,
            seen,
            stop,
            threads,
        }
    }

    /// A server that never answers.
    pub fn silent() -> Fake {
        Fake::start(|_, _| Reply::Nothing)
    }

    pub fn upstream(&self) -> Upstream {
        Upstream::new(self.addr)
    }

    pub fn queries(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn render(reply: Reply) -> Vec<Vec<u8>> {
    match reply {
        Reply::Messages(ms) => ms.iter().map(|m| m.encode().unwrap()).collect(),
        Reply::Raw(r) => r,
        Reply::Nothing => Vec::new(),
    }
}

/// A config for tests: one upstream, short timeouts.
pub fn config(upstreams: &[&Fake]) -> ResolverConfig {
    let mut c = ResolverConfig::new()
        .timeout(Duration::from_millis(300))
        .deadline(Duration::from_secs(5));
    for f in upstreams {
        c = c.upstream(f.upstream());
    }
    c
}

pub fn n(s: &str) -> Name {
    Name::parse(s).unwrap()
}

/// The response skeleton for `query`: same id and question (case kept),
/// QR and RA set, no records.
pub fn respond(query: &Message) -> Message {
    Message {
        header: Header {
            id: query.header.id,
            response: true,
            recursion_desired: query.header.recursion_desired,
            recursion_available: true,
            ..Header::default()
        },
        question: query.question.clone(),
        edns: query.edns.clone(),
        ..Message::default()
    }
}

pub fn question(query: &Message) -> Question {
    query.question.clone().unwrap()
}

/// An A record for the query's name (in its case).
pub fn a_for(query: &Message, ttl: u32, ip: [u8; 4]) -> Record {
    Record::new(question(query).name, ttl, RData::A(ip.into()))
}

pub fn soa(zone: &str, ttl: u32, minimum: u32) -> Record {
    Record::new(
        n(zone),
        ttl,
        RData::Soa {
            mname: n("ns.test"),
            rname: n("admin.test"),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum,
        },
    )
}

/// Answers A queries with `ip`, AAAA with nothing (NODATA, SOA of "test").
pub fn answer_a(ip: [u8; 4]) -> impl Fn(&Message, bool) -> Reply + Send + Sync + 'static {
    move |q, _| {
        let mut r = respond(q);
        if question(q).qtype == RecordType::A {
            r.answers.push(a_for(q, 300, ip));
        } else {
            r.authority.push(soa("test", 60, 60));
        }
        Reply::Messages(vec![r])
    }
}
