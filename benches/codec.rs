//! Costs of the hot paths, measured with the standard library's clock:
//! building a query, checking and reading a reply, decoding a message, and
//! a lookup answered from the cache.
//!
//! `cargo bench --bench codec`

use std::hint::black_box;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use dns_net::{
    Exchange, IpOrder, Message, Name, Outcome, Question, RData, Record, RecordType, Resolver,
    ResolverConfig, Upstream,
};

fn time<F: FnMut()>(label: &str, mut f: F) {
    // Warm up, then take the best of five runs of a fixed count.
    for _ in 0..10_000 {
        f();
    }
    let n = 200_000u32;
    let best = (0..5)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..n {
                f();
            }
            t.elapsed()
        })
        .min()
        .unwrap_or(Duration::ZERO);
    println!(
        "{label:<44} {:>8.1} ns",
        best.as_nanos() as f64 / f64::from(n)
    );
}

fn reply_for(ex: &Exchange) -> Vec<u8> {
    let mut m = Message::decode(ex.bytes()).unwrap();
    m.header.response = true;
    let q = ex.question().clone();
    m.answers.push(Record::new(
        q.name.clone(),
        300,
        RData::Cname(Name::parse("edge.cdn.example.net").unwrap()),
    ));
    for i in 1..=2 {
        m.answers.push(Record::new(
            Name::parse("edge.cdn.example.net").unwrap(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, i)),
        ));
    }
    m.encode().unwrap()
}

fn main() {
    let question = Question::new(Name::parse("www.example.com").unwrap(), RecordType::A);
    let bits = [0x5A, 0xC3];
    time("build a query (id, 0x20 case, EDNS)", || {
        black_box(Exchange::new(black_box(&question), 7, &bits, Some(1232)).unwrap());
    });
    let ex = Exchange::new(&question, 7, &bits, Some(1232)).unwrap();
    let reply = reply_for(&ex);
    time("decode a reply (CNAME and 2 A, 103 bytes)", || {
        black_box(Message::decode(black_box(&reply)).unwrap());
    });
    time("check a reply against its query", || {
        black_box(ex.check(black_box(&reply)).unwrap());
    });
    let msg = ex.check(&reply).unwrap();
    time("read the answer (chain and records)", || {
        black_box(Outcome::read(black_box(&question), &msg));
    });
    let mut wrong = reply.clone();
    wrong[0] ^= 1;
    time("refuse a reply with another id", || {
        black_box(ex.check(black_box(&wrong)).is_err());
    });

    // A cached lookup: one answer from a responder on loopback, then hits.
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = server.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = server.recv_from(&mut buf) {
            let Ok(q) = Message::decode(&buf[..n]) else {
                continue;
            };
            let mut r = q.clone();
            r.header.response = true;
            if let Some(question) = &q.question {
                r.answers.push(Record::new(
                    question.name.clone(),
                    3600,
                    RData::A(Ipv4Addr::new(192, 0, 2, 9)),
                ));
            }
            let _ = server.send_to(&r.encode().unwrap(), from);
        }
    });
    let resolver = Resolver::new(
        ResolverConfig::new()
            .upstream(Upstream::new(addr))
            .ip_order(IpOrder::Ipv4Only),
    )
    .unwrap();
    let name = Name::parse("cached.example.com").unwrap();
    resolver.lookup(&name, RecordType::A).unwrap();
    time("lookup answered from the cache", || {
        black_box(resolver.lookup(black_box(&name), RecordType::A).unwrap());
    });
    time("lookup_ip answered from the cache (A only)", || {
        black_box(
            resolver
                .lookup_ip_with("cached.example.com", &|_: &Name, _| true)
                .ok(),
        );
    });
}
