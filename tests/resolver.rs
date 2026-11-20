//! The resolver against fake upstreams on loopback.
#![cfg(feature = "resolver")]

mod support;

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use dns_net::{Error, IpOrder, RData, Rcode, Record, RecordType, Resolver, Status};
use support::{Fake, Reply, a_for, answer_a, config, n, question, respond, soa};

#[test]
fn answers_and_caches() {
    let fake = Fake::start(answer_a([192, 0, 2, 10]));
    let r = Resolver::new(config(&[&fake])).unwrap();
    let found = r.lookup(&n("www.test"), RecordType::A).unwrap();
    assert_eq!(found.status(), Status::Found);
    assert_eq!(
        found.ips().collect::<Vec<_>>(),
        vec!["192.0.2.10".parse::<IpAddr>().unwrap()]
    );
    assert!(found.ttl() > 290 && found.ttl() <= 300, "{}", found.ttl());
    // Again, in another case: from the cache.
    let again = r.lookup(&n("WWW.test"), RecordType::A).unwrap();
    assert_eq!(again.records(), found.records());
    assert_eq!(fake.count(), 1);
    let s = r.stats();
    assert_eq!((s.queries, s.cache.hits), (1, 1));
    // The query was recursive, with EDNS(0) at 1,232 bytes.
    let q = &fake.queries()[0].query;
    assert!(q.header.recursion_desired);
    assert_eq!(q.edns.as_ref().map(|e| e.payload), Some(1232));
    r.clear_cache();
    r.lookup(&n("www.test"), RecordType::A).unwrap();
    assert_eq!(fake.count(), 2);
}

#[test]
fn lookup_ip_orders_and_merges() {
    let fake = Fake::start(|q, _| {
        let mut r = respond(q);
        let name = question(q).name;
        match question(q).qtype {
            RecordType::A => r.answers.push(a_for(q, 60, [192, 0, 2, 1])),
            _ => r.answers.push(Record::new(
                name,
                60,
                RData::Aaaa("2001:db8::1".parse().unwrap()),
            )),
        }
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(config(&[&fake])).unwrap();
    let both = r.lookup_ip("dual.test").unwrap();
    assert_eq!(
        both,
        vec![
            "192.0.2.1".parse::<IpAddr>().unwrap(),
            "2001:db8::1".parse().unwrap()
        ]
    );
    let r6 = Resolver::new(config(&[&fake]).ip_order(IpOrder::Ipv6First)).unwrap();
    assert_eq!(
        r6.lookup_ip("dual.test").unwrap()[0],
        "2001:db8::1".parse::<IpAddr>().unwrap()
    );
    let r4 = Resolver::new(config(&[&fake]).ip_order(IpOrder::Ipv4Only)).unwrap();
    assert_eq!(r4.lookup_ip("v4.test").unwrap().len(), 1);
}

#[test]
fn negative_answers_are_cached() {
    let fake = Fake::start(|q, _| {
        let mut r = respond(q);
        r.header.rcode = 3;
        r.authority.push(soa("test", 3600, 120));
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(config(&[&fake])).unwrap();
    let miss = r.lookup(&n("nope.test"), RecordType::A).unwrap();
    assert_eq!(miss.status(), Status::NxDomain);
    assert!(miss.ttl() <= 120 && miss.ttl() > 110);
    assert_eq!(
        r.lookup_ip("nope.test"),
        Err(Error::NotFound(Status::NxDomain))
    );
    // A was cached; AAAA was asked once.
    assert_eq!(fake.count(), 2);
}

#[test]
fn negative_ttl_is_capped() {
    let fake = Fake::start(|q, _| {
        let mut r = respond(q);
        r.header.rcode = 3;
        r.authority.push(soa("test", 86_400, 86_400));
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(config(&[&fake]).max_negative_ttl(30)).unwrap();
    assert!(r.lookup(&n("x.test"), RecordType::A).unwrap().ttl() <= 30);
}

#[test]
fn truncated_replies_are_fetched_over_tcp() {
    let fake = Fake::start(|q, tcp| {
        let mut r = respond(q);
        if tcp {
            for i in 0..40u8 {
                r.answers.push(a_for(q, 60, [192, 0, 2, i]));
            }
        } else {
            r.header.truncated = true;
        }
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(config(&[&fake])).unwrap();
    let found = r.lookup(&n("big.test"), RecordType::A).unwrap();
    assert_eq!(found.records().len(), 40);
    let seen = fake.queries();
    assert_eq!(seen.iter().filter(|s| s.tcp).count(), 1);
    assert_eq!(r.stats().tcp_queries, 1);
    // The TCP query is the same query: same id, same casing.
    assert_eq!(seen[0].query, seen[1].query);
}

#[test]
fn a_silent_upstream_fails_over_and_moves_back() {
    let silent = Fake::silent();
    let good = Fake::start(answer_a([192, 0, 2, 2]));
    let r = Resolver::new(config(&[&silent, &good])).unwrap();
    let t = Instant::now();
    let found = r.lookup(&n("one.test"), RecordType::A).unwrap();
    assert_eq!(found.status(), Status::Found);
    assert!(
        t.elapsed() >= Duration::from_millis(280),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(r.stats().timeouts, 1);
    // The next lookup goes to the upstream that worked.
    let t = Instant::now();
    r.lookup(&n("two.test"), RecordType::A).unwrap();
    assert!(
        t.elapsed() < Duration::from_millis(250),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(silent.count(), 1);
}

#[test]
fn every_upstream_silent_times_out_within_the_deadline() {
    let a = Fake::silent();
    let b = Fake::silent();
    let r = Resolver::new(config(&[&a, &b]).attempts(2)).unwrap();
    let t = Instant::now();
    assert_eq!(
        r.lookup(&n("x.test"), RecordType::A).err(),
        Some(Error::Timeout)
    );
    let took = t.elapsed();
    // 2 rounds over 2 upstreams of 300 ms.
    assert!(
        took >= Duration::from_millis(1150) && took < Duration::from_secs(3),
        "{took:?}"
    );
    assert_eq!(a.count() + b.count(), 4);
}

#[test]
fn server_errors_try_the_next_upstream() {
    let failing = Fake::start(|q, _| {
        let mut r = respond(q);
        r.header.rcode = 2;
        Reply::Messages(vec![r])
    });
    let good = Fake::start(answer_a([192, 0, 2, 3]));
    let r = Resolver::new(config(&[&failing, &good])).unwrap();
    assert_eq!(
        r.lookup(&n("x.test"), RecordType::A).unwrap().status(),
        Status::Found
    );
    assert_eq!(r.stats().server_errors, 1);
    let only_failing = Resolver::new(config(&[&failing]).attempts(1)).unwrap();
    assert_eq!(
        only_failing.lookup(&n("y.test"), RecordType::A).err(),
        Some(Error::Server(Rcode::SERVFAIL))
    );
}

#[test]
fn formerr_retries_without_edns() {
    let fake = Fake::start(|q, _| {
        let mut r = respond(q);
        if q.edns.is_some() {
            r.edns = None;
            r.header.rcode = 1;
            r.question = None;
        } else {
            r.answers.push(a_for(q, 60, [192, 0, 2, 4]));
        }
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(config(&[&fake])).unwrap();
    assert_eq!(
        r.lookup(&n("old.test"), RecordType::A)
            .unwrap()
            .records()
            .len(),
        1
    );
    let seen = fake.queries();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].query.edns.is_some() && seen[1].query.edns.is_none());
}

#[test]
fn cname_chains_are_followed_across_queries() {
    let fake = Fake::start(|q, _| {
        let mut r = respond(q);
        let name = question(q).name;
        if name == n("alias.test") {
            r.answers
                .push(Record::new(name, 600, RData::Cname(n("real.other"))));
        } else if name == n("real.other") {
            r.answers.push(a_for(q, 40, [192, 0, 2, 5]));
        }
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(config(&[&fake])).unwrap();
    let found = r.lookup(&n("alias.test"), RecordType::A).unwrap();
    assert_eq!(found.canonical_name(), &n("real.other"));
    assert_eq!(found.chain().len(), 1);
    assert!(found.ttl() <= 40);
    assert_eq!(fake.count(), 2);
}

#[test]
fn cname_loops_fail() {
    let fake = Fake::start(|q, _| {
        let mut r = respond(q);
        let name = question(q).name;
        let next = if name == n("a.test") {
            "b.test"
        } else {
            "a.test"
        };
        r.answers.push(Record::new(name, 60, RData::Cname(n(next))));
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(config(&[&fake])).unwrap();
    assert_eq!(
        r.lookup(&n("a.test"), RecordType::A).err(),
        Some(Error::Bogus)
    );
}

#[test]
fn identical_questions_share_one_query() {
    let fake = Fake::start(|q, _| {
        std::thread::sleep(Duration::from_millis(150));
        let mut r = respond(q);
        r.answers.push(a_for(q, 60, [192, 0, 2, 6]));
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(config(&[&fake])).unwrap();
    let (tx, rx) = mpsc::channel();
    for _ in 0..20 {
        let tx = tx.clone();
        r.submit(&n("hot.test"), RecordType::A, move |res| {
            tx.send(res.map(|l| l.records().len())).unwrap();
        })
        .unwrap();
    }
    for _ in 0..20 {
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(1));
    }
    assert_eq!(fake.count(), 1);
    assert_eq!(r.stats().coalesced, 19);
}

#[test]
fn many_lookups_at_once() {
    let fake = Fake::start(answer_a([192, 0, 2, 7]));
    let r = Resolver::new(config(&[&fake]).max_in_flight(16)).unwrap();
    let (tx, rx) = mpsc::channel();
    for i in 0..300 {
        let tx = tx.clone();
        r.submit(&n(&format!("h{i}.test")), RecordType::A, move |res| {
            tx.send(res.err()).unwrap();
        })
        .unwrap();
    }
    let errors: Vec<Error> = (0..300)
        .filter_map(|_| rx.recv_timeout(Duration::from_secs(10)).unwrap())
        .collect();
    assert!(
        errors.is_empty(),
        "{} failed: {:?}",
        errors.len(),
        &errors[..errors.len().min(5)]
    );
    assert_eq!(fake.count(), 300, "{:?}", r.stats());
}

#[test]
fn too_many_waiting_is_busy() {
    let fake = Fake::start(|q, _| {
        std::thread::sleep(Duration::from_millis(300));
        let mut r = respond(q);
        r.answers.push(a_for(q, 60, [192, 0, 2, 8]));
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(
        config(&[&fake])
            .max_in_flight(1)
            .max_waiting(1)
            .timeout(Duration::from_secs(2)),
    )
    .unwrap();
    let ok = Arc::new(AtomicUsize::new(0));
    for i in 0..2 {
        let ok = ok.clone();
        r.submit(&n(&format!("b{i}.test")), RecordType::A, move |res| {
            if res.is_ok() {
                ok.fetch_add(1, Ordering::SeqCst);
            }
        })
        .unwrap();
    }
    assert_eq!(
        r.submit(&n("b2.test"), RecordType::A, |_| {}).err(),
        Some(Error::Busy)
    );
    let t = Instant::now();
    while ok.load(Ordering::SeqCst) < 2 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(ok.load(Ordering::SeqCst), 2);
    // Room again.
    assert!(r.lookup(&n("b3.test"), RecordType::A).is_ok());
}

#[test]
fn dropping_the_resolver_fails_pending_lookups() {
    let silent = Fake::silent();
    let r = Resolver::new(
        config(&[&silent])
            .timeout(Duration::from_secs(5))
            .deadline(Duration::from_secs(10)),
    )
    .unwrap();
    let (tx, rx) = mpsc::channel();
    r.submit(&n("x.test"), RecordType::A, move |res| {
        tx.send(res.err()).unwrap()
    })
    .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let t = Instant::now();
    drop(r);
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        Some(Error::Stopped)
    );
    assert!(t.elapsed() < Duration::from_secs(1));
}

#[test]
fn local_names_never_reach_the_upstream() {
    let fake = Fake::start(answer_a([192, 0, 2, 9]));
    let r = Resolver::new(config(&[&fake])).unwrap();
    assert_eq!(
        r.lookup_ip("localhost").unwrap(),
        vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "::1".parse().unwrap()
        ]
    );
    assert_eq!(r.lookup_ip("api.localhost").unwrap().len(), 2);
    assert_eq!(
        r.lookup(&n("hidden.onion"), RecordType::A)
            .unwrap()
            .status(),
        Status::NxDomain
    );
    assert_eq!(
        r.lookup_ip("x.invalid"),
        Err(Error::NotFound(Status::NxDomain))
    );
    assert_eq!(fake.count(), 0);
    assert_eq!(r.stats().local, 7);
}

#[test]
fn txt_mx_srv_caa_lookups() {
    let fake = Fake::start(|q, _| {
        let mut r = respond(q);
        let name = question(q).name;
        let data = match question(q).qtype {
            RecordType::TXT => {
                RData::Txt(vec![b"v=spf1 ".to_vec().into(), b"-all".to_vec().into()])
            }
            RecordType::MX => RData::Mx {
                preference: 10,
                exchange: n("mx.test"),
            },
            RecordType::SRV => RData::Srv {
                priority: 1,
                weight: 5,
                port: 5060,
                target: n("sip.test"),
            },
            RecordType::CAA => RData::Caa {
                flags: 0,
                tag: "issue".into(),
                value: b"ca.test".to_vec().into(),
            },
            RecordType::NS => RData::Ns(n("ns1.test")),
            _ => return Reply::Messages(vec![r]),
        };
        r.answers.push(Record::new(name, 60, data));
        Reply::Messages(vec![r])
    });
    let r = Resolver::new(config(&[&fake])).unwrap();
    let txt = r.lookup(&n("test"), RecordType::TXT).unwrap();
    assert_eq!(txt.records()[0].data.txt_joined().unwrap(), b"v=spf1 -all");
    for t in [
        RecordType::MX,
        RecordType::SRV,
        RecordType::CAA,
        RecordType::NS,
    ] {
        let l = r.lookup(&n("_svc._tcp.test"), t).unwrap();
        assert_eq!(l.records()[0].rtype(), t);
    }
    // A type with nothing: NODATA without an SOA is not cached.
    let none = r.lookup(&n("test"), RecordType::PTR).unwrap();
    assert_eq!(none.status(), Status::NoData);
    assert_eq!(none.ttl(), 0);
}

#[test]
fn bad_configuration_is_refused() {
    use dns_net::{ConfigError, ResolverConfig};
    assert_eq!(
        Resolver::new(ResolverConfig::new()).err(),
        Some(Error::Config(ConfigError::NoUpstreams))
    );
}
