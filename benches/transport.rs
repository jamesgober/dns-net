//! What a lookup costs on each transport, on loopback: UDP, TLS on a reused
//! connection, and TLS with a new connection (handshake included). Every
//! lookup asks a new name, so none is answered from the cache.
//!
//! `cargo bench --bench transport --features tls`

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::time::{Duration, Instant};

use dns_net::{Message, Name, RData, Record, RecordType, Resolver, ResolverConfig, Upstream};

const CA: &[u8] = include_bytes!("../tests/data/ca.pem");
const CERT: &[u8] = include_bytes!("../tests/data/dns.pem");
const KEY: &[u8] = include_bytes!("../tests/data/dns.key");

fn answer(query: &[u8]) -> Option<Vec<u8>> {
    let q = Message::decode(query).ok()?;
    let mut r = q.clone();
    r.header.response = true;
    let name = q.question.as_ref()?.name.clone();
    r.answers
        .push(Record::new(name, 60, RData::A(Ipv4Addr::new(192, 0, 2, 1))));
    r.encode().ok()
}

fn udp_server() -> std::net::SocketAddr {
    let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = s.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = s.recv_from(&mut buf) {
            if let Some(r) = answer(&buf[..n]) {
                let _ = s.send_to(&r, from);
            }
        }
    });
    addr
}

fn tls_server() -> std::net::SocketAddr {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = l.local_addr().unwrap();
    let server = tls_net::server_from_pem(CERT, KEY).unwrap();
    std::thread::spawn(move || {
        while let Ok((tcp, _)) = l.accept() {
            let server = server.clone();
            std::thread::spawn(move || {
                let Ok(mut tls) = server.accept_stream(tcp) else {
                    return;
                };
                let mut len = [0u8; 2];
                while tls.read_exact(&mut len).is_ok() {
                    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if tls.read_exact(&mut q).is_err() {
                        return;
                    }
                    let Some(r) = answer(&q) else { return };
                    let mut framed = (r.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&r);
                    if tls.write_all(&framed).is_err() || tls.flush().is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn measure(label: &str, resolver: &Resolver, n: u32, fresh: impl Fn(&Resolver)) {
    let mut times = Vec::with_capacity(n as usize);
    for i in 0..n {
        fresh(resolver);
        let name = Name::parse(&format!("q{i}.bench.example")).unwrap();
        let t = Instant::now();
        resolver.lookup(&name, RecordType::A).unwrap();
        times.push(t.elapsed());
    }
    times.sort();
    let p = |q: f64| times[((times.len() - 1) as f64 * q) as usize];
    println!(
        "{label:<40} median {:>7.1} us   p99 {:>7.1} us",
        p(0.5).as_secs_f64() * 1e6,
        p(0.99).as_secs_f64() * 1e6
    );
}

fn main() {
    let udp = Resolver::new(
        ResolverConfig::new()
            .upstream(Upstream::new(udp_server()))
            .cache_bytes(0),
    )
    .unwrap();
    let tls_addr = tls_server();
    let config = || {
        ResolverConfig::new()
            .upstream(Upstream::tls(tls_addr, "dns.test").unwrap())
            .tls_client(tls_net::client_with_ca_pem(CA).unwrap())
            .cache_bytes(0)
    };
    let tls = Resolver::new(config()).unwrap();
    // Warm up both, and open the TLS connection.
    for i in 0..200 {
        let name = Name::parse(&format!("warm{i}.example")).unwrap();
        udp.lookup(&name, RecordType::A).unwrap();
        tls.lookup(&name, RecordType::A).unwrap();
    }
    measure("UDP", &udp, 5000, |_| {});
    measure("TLS, connection reused", &tls, 5000, |_| {});
    // A new resolver each time: a new connection and a full handshake (a
    // new client, so no session resumption either).
    let mut times = Vec::new();
    for i in 0..200 {
        let r = Resolver::new(config()).unwrap();
        let name = Name::parse(&format!("h{i}.example")).unwrap();
        let t = Instant::now();
        r.lookup(&name, RecordType::A).unwrap();
        times.push(t.elapsed());
    }
    times.sort();
    println!(
        "{:<40} median {:>7.1} us   p99 {:>7.1} us",
        "TLS, new connection (full handshake)",
        times[100].as_secs_f64() * 1e6,
        times[197].as_secs_f64() * 1e6
    );
    std::thread::sleep(Duration::from_millis(10));
}
