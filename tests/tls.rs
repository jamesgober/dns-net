//! DNS over TLS against a fake upstream built on tls-net, with the test CA in
//! `tests/data` (valid until 2126).

#![cfg(feature = "tls")]

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use dns_net::{Error, Message, RecordType, Resolver, ResolverConfig, Upstream};
use support::{a_for, n, respond};

const CA: &[u8] = include_bytes!("data/ca.pem");
const CERT: &[u8] = include_bytes!("data/dns.pem");
const KEY: &[u8] = include_bytes!("data/dns.key");
const PINNED_CERT: &[u8] = include_bytes!("data/pinned.pem");
const PINNED_KEY: &[u8] = include_bytes!("data/pinned.key");

/// How the fake answers the queries of one connection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Each query as it comes.
    Each,
    /// Waits for `n` queries, then answers them in reverse order.
    Reverse(usize),
    /// Closes the connection after the first query, without answering.
    CloseFirst,
    /// Answers with the TC bit set.
    Truncated,
    /// Answers with the AD bit set.
    Authentic,
}

struct TlsFake {
    addr: SocketAddr,
    /// Connections accepted (handshakes completed).
    connections: Arc<AtomicUsize>,
    /// Connections that ended (the client closed or reset them).
    ended: Arc<AtomicUsize>,
    /// The length of every query received.
    sizes: Arc<Mutex<Vec<usize>>>,
    stop: Arc<AtomicBool>,
}

impl TlsFake {
    fn start(cert: &'static [u8], key: &'static [u8], mode: Mode) -> TlsFake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tls_net::server_from_pem(cert, key).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let ended = Arc::new(AtomicUsize::new(0));
        let sizes = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (c2, e2, s2, stop2) = (
            connections.clone(),
            ended.clone(),
            sizes.clone(),
            stop.clone(),
        );
        let first_done = Arc::new(AtomicBool::new(false));
        std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                let Ok((tcp, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                tcp.set_nonblocking(false).unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let server = server.clone();
                let (c3, e3, s3, first) = (c2.clone(), e2.clone(), s2.clone(), first_done.clone());
                std::thread::spawn(move || {
                    let Ok(mut tls) = server.accept_stream(tcp) else {
                        return;
                    };
                    c3.fetch_add(1, Ordering::SeqCst);
                    serve(&mut tls, mode, &s3, &first);
                    e3.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        TlsFake {
            addr,
            connections,
            ended,
            sizes,
            stop,
        }
    }
}

impl Drop for TlsFake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn read_query(tls: &mut impl Read) -> Option<Message> {
    let mut len = [0u8; 2];
    tls.read_exact(&mut len).ok()?;
    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
    tls.read_exact(&mut q).ok()?;
    Message::decode(&q).ok()
}

fn write_reply(tls: &mut impl Write, m: &Message) -> bool {
    let bytes = m.encode().unwrap();
    let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&bytes);
    tls.write_all(&framed).is_ok() && tls.flush().is_ok()
}

fn answer(q: &Message) -> Message {
    let mut r = respond(q);
    r.answers.push(a_for(q, 60, [192, 0, 2, 53]));
    r
}

fn serve<S: Read + Write>(
    tls: &mut tls_net::TlsStream<S>,
    mode: Mode,
    sizes: &Mutex<Vec<usize>>,
    first: &AtomicBool,
) {
    let mut held = Vec::new();
    loop {
        let Some(q) = read_query(tls) else {
            return;
        };
        sizes.lock().unwrap().push(q.encode().unwrap().len());
        match mode {
            Mode::Each => {
                if !write_reply(tls, &answer(&q)) {
                    return;
                }
            }
            Mode::Reverse(n) => {
                held.push(q);
                if held.len() == n {
                    for q in held.drain(..).rev() {
                        if !write_reply(tls, &answer(&q)) {
                            return;
                        }
                    }
                }
            }
            Mode::CloseFirst => {
                if !first.swap(true, Ordering::SeqCst) {
                    let _ = tls.close();
                    return;
                }
                if !write_reply(tls, &answer(&q)) {
                    return;
                }
            }
            Mode::Truncated => {
                let mut r = respond(&q);
                r.header.truncated = true;
                if !write_reply(tls, &r) {
                    return;
                }
            }
            Mode::Authentic => {
                let mut r = answer(&q);
                r.header.authentic_data = true;
                if !write_reply(tls, &r) {
                    return;
                }
            }
        }
    }
}

fn config(fake: &TlsFake, name: &str) -> ResolverConfig {
    ResolverConfig::new()
        .upstream(Upstream::tls(fake.addr, name).unwrap())
        .tls_client(tls_net::client_with_ca_pem(CA).unwrap())
        .timeout(Duration::from_secs(2))
        .deadline(Duration::from_secs(10))
}

#[test]
fn answers_over_tls_with_padded_queries() {
    let fake = TlsFake::start(CERT, KEY, Mode::Each);
    let r = Resolver::new(config(&fake, "dns.test")).unwrap();
    let found = r.lookup(&n("www.example"), RecordType::A).unwrap();
    assert_eq!(found.ips().count(), 1);
    // Padded to a multiple of 128 bytes (RFC 8467), names of any length.
    r.lookup(
        &n("a-much-longer-name-than-the-first.example"),
        RecordType::A,
    )
    .unwrap();
    let sizes = fake.sizes.lock().unwrap().clone();
    assert_eq!(sizes.len(), 2);
    assert!(sizes.iter().all(|s| s % 128 == 0), "{sizes:?}");
    assert_eq!(r.stats().tls_connections, 1);
    // An IP literal as the identity: the certificate carries 127.0.0.1.
    let by_ip = Resolver::new(config(&fake, "127.0.0.1")).unwrap();
    assert!(by_ip.lookup(&n("ip.example"), RecordType::A).is_ok());
}

#[test]
fn one_connection_carries_many_queries_answered_in_any_order() {
    let fake = TlsFake::start(CERT, KEY, Mode::Reverse(8));
    let r = Resolver::new(config(&fake, "dns.test")).unwrap();
    let (tx, rx) = mpsc::channel();
    for i in 0..8 {
        let tx = tx.clone();
        r.submit(&n(&format!("q{i}.example")), RecordType::A, move |res| {
            tx.send(res.map(|l| l.name().to_string())).unwrap();
        })
        .unwrap();
    }
    let mut names: Vec<String> = (0..8)
        .map(|_| rx.recv_timeout(Duration::from_secs(10)).unwrap().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 8);
    assert_eq!(fake.connections.load(Ordering::SeqCst), 1);
    assert_eq!(r.stats().tls_connections, 1);
}

#[test]
fn a_certificate_for_another_name_is_refused_without_fallback() {
    let fake = TlsFake::start(CERT, KEY, Mode::Each);
    let r = Resolver::new(config(&fake, "other.test").attempts(1)).unwrap();
    assert_eq!(
        r.lookup(&n("x.example"), RecordType::A).err(),
        Some(Error::Tls)
    );
    assert!(fake.sizes.lock().unwrap().is_empty(), "no query was sent");
    // A CA the client does not trust.
    let untrusting = ResolverConfig::new()
        .upstream(Upstream::tls(fake.addr, "dns.test").unwrap())
        .tls_client(tls_net::client_with_ca_pem(PINNED_CERT).unwrap())
        .attempts(1);
    let r = Resolver::new(untrusting).unwrap();
    assert_eq!(
        r.lookup(&n("x.example"), RecordType::A).err(),
        Some(Error::Tls)
    );
}

#[test]
fn a_pinned_key_is_accepted_and_another_refused() {
    let fake = TlsFake::start(PINNED_CERT, PINNED_KEY, Mode::Each);
    let der = tls_net::certificate_der_from_pem(PINNED_CERT).unwrap();
    let pin = tls_net::spki_sha256(&der[0]).unwrap();
    let pinned = ResolverConfig::new()
        .upstream(Upstream::tls_pinned(fake.addr, "pinned.test", &[pin]).unwrap())
        .tls_client(tls_net::client_with_ca_pem(CA).unwrap());
    let r = Resolver::new(pinned).unwrap();
    assert!(r.lookup(&n("x.example"), RecordType::A).is_ok());
    let mut wrong = pin;
    wrong[0] ^= 1;
    let mismatched = ResolverConfig::new()
        .upstream(Upstream::tls_pinned(fake.addr, "pinned.test", &[wrong]).unwrap())
        .tls_client(tls_net::client_with_ca_pem(CA).unwrap())
        .attempts(1);
    let r = Resolver::new(mismatched).unwrap();
    assert_eq!(
        r.lookup(&n("y.example"), RecordType::A).err(),
        Some(Error::Tls)
    );
}

#[test]
fn an_idle_connection_closes_and_the_next_query_opens_one() {
    let fake = TlsFake::start(CERT, KEY, Mode::Each);
    let r = Resolver::new(config(&fake, "dns.test").tls_idle(Duration::from_secs(1))).unwrap();
    r.lookup(&n("one.example"), RecordType::A).unwrap();
    let t = Instant::now();
    while fake.ended.load(Ordering::SeqCst) == 0 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(fake.ended.load(Ordering::SeqCst), 1, "closed when idle");
    assert!(
        t.elapsed() >= Duration::from_millis(700),
        "{:?}",
        t.elapsed()
    );
    r.lookup(&n("two.example"), RecordType::A).unwrap();
    assert_eq!(r.stats().tls_connections, 2);
}

#[test]
fn a_connection_the_server_closes_moves_its_queries_on() {
    let fake = TlsFake::start(CERT, KEY, Mode::CloseFirst);
    let r = Resolver::new(config(&fake, "dns.test")).unwrap();
    let found = r.lookup(&n("retry.example"), RecordType::A);
    let found = found.unwrap_or_else(|e| {
        panic!(
            "{e:?} {:?} connections {} ended {}",
            r.stats(),
            fake.connections.load(Ordering::SeqCst),
            fake.ended.load(Ordering::SeqCst)
        )
    });
    assert_eq!(found.ips().count(), 1);
    assert_eq!(fake.connections.load(Ordering::SeqCst), 2);
}

#[test]
fn a_truncated_reply_over_tls_is_bogus() {
    let fake = TlsFake::start(CERT, KEY, Mode::Truncated);
    let r = Resolver::new(config(&fake, "dns.test").attempts(1)).unwrap();
    assert_eq!(
        r.lookup(&n("tc.example"), RecordType::A).err(),
        Some(Error::Bogus)
    );
    assert_eq!(r.stats().tcp_queries, 0, "never over plain TCP");
}

#[test]
fn the_ad_bit_is_reported_from_a_tls_upstream() {
    let fake = TlsFake::start(CERT, KEY, Mode::Authentic);
    let r = Resolver::new(config(&fake, "dns.test")).unwrap();
    assert!(
        r.lookup(&n("signed.example"), RecordType::A)
            .unwrap()
            .authenticated()
    );
    // Cached with it.
    assert!(
        r.lookup(&n("signed.example"), RecordType::A)
            .unwrap()
            .authenticated()
    );
    let plain = TlsFake::start(CERT, KEY, Mode::Each);
    let r = Resolver::new(config(&plain, "dns.test")).unwrap();
    assert!(
        !r.lookup(&n("unsigned.example"), RecordType::A)
            .unwrap()
            .authenticated()
    );
}

#[test]
fn a_plain_tcp_connection_is_not_tls() {
    // A server that accepts TCP but does not speak TLS.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"\x00\x05hello");
            std::thread::sleep(Duration::from_millis(200));
            drop(s);
        }
    });
    let config = ResolverConfig::new()
        .upstream(Upstream::tls(addr, "dns.test").unwrap())
        .tls_client(tls_net::client_with_ca_pem(CA).unwrap())
        .attempts(1);
    let r = Resolver::new(config).unwrap();
    assert_eq!(
        r.lookup(&n("x.example"), RecordType::A).err(),
        Some(Error::Tls)
    );
    let _ = TcpStream::connect(addr);
}
