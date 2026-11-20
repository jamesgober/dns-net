//! One test per threat in `dev/PLAN.md` section 5: each attack must fail.
#![cfg(feature = "resolver")]

mod support;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dns_net::{Error, Message, Name, PublicOnly, Question, RData, Record, RecordType, Resolver};
use support::{Fake, Reply, a_for, answer_a, config, n, question, respond};

const EVIL: [u8; 4] = [203, 0, 113, 66];
const REAL: [u8; 4] = [192, 0, 2, 80];

fn ip(o: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(o))
}

/// A forged reply goes out first, then the real one.
fn forge_then_answer<F>(forge: F) -> Fake
where
    F: Fn(&Message) -> Vec<u8> + Send + Sync + 'static,
{
    Fake::start(move |q, _| {
        let mut real = respond(q);
        real.answers.push(a_for(q, 60, REAL));
        Reply::Raw(vec![forge(q), real.encode().unwrap()])
    })
}

fn evil_reply(q: &Message) -> Message {
    let mut m = respond(q);
    m.answers.push(a_for(q, 86_400, EVIL));
    m
}

fn only_real(fake: &Fake) -> Resolver {
    let r = Resolver::new(config(&[fake])).unwrap();
    let found = r.lookup(&n("bank.test"), RecordType::A).unwrap();
    assert_eq!(found.ips().collect::<Vec<_>>(), vec![ip(REAL)]);
    r
}

#[test]
fn poisoning_with_the_wrong_id_fails() {
    let fake = forge_then_answer(|q| {
        let mut m = evil_reply(q);
        m.header.id ^= 0x0101;
        m.encode().unwrap()
    });
    let r = only_real(&fake);
    assert_eq!(r.stats().ignored, 1);
}

#[test]
fn poisoning_without_the_random_case_fails() {
    // An off-path forger that guessed the id and port still has to guess the
    // case of every letter. This one gets every letter wrong (a forger that
    // sends lower case is right 1 time in 2^8 for "bank.test").
    let fake = forge_then_answer(|q| {
        let mut m = evil_reply(q);
        let flipped: String = question(q)
            .name
            .to_string()
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();
        let name = Name::parse(&flipped).unwrap();
        m.question = Some(Question::new(name.clone(), RecordType::A));
        m.answers = vec![Record::new(name, 86_400, RData::A(EVIL.into()))];
        m.encode().unwrap()
    });
    let r = only_real(&fake);
    assert_eq!(r.stats().ignored, 1);
}

#[test]
fn poisoning_with_another_question_fails() {
    let fake = forge_then_answer(|q| {
        let mut m = evil_reply(q);
        m.question = Some(Question::new(n("other.test"), RecordType::A));
        m.encode().unwrap()
    });
    only_real(&fake);
}

#[test]
fn poisoning_from_another_address_never_arrives() {
    // The exact reply (right id, right case) from another port: the socket
    // is connected to the upstream, so the kernel drops it.
    let forger = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap());
    let f2 = forger.clone();
    let fake = Fake::start_from(move |q, _, from| {
        let _ = f2.send_to(&evil_reply(q).encode().unwrap(), from);
        std::thread::sleep(Duration::from_millis(50));
        let mut real = respond(q);
        real.answers.push(a_for(q, 60, REAL));
        Reply::Messages(vec![real])
    });
    let r = only_real(&fake);
    assert_eq!(
        r.stats().ignored,
        0,
        "the forgery never reached the resolver"
    );
}

#[test]
fn records_about_other_names_are_never_cached() {
    let fake = Fake::start(|q, _| {
        let name = question(q).name;
        let mut m = respond(q);
        if name == n("www.test") {
            m.answers.push(a_for(q, 60, REAL));
            // Riders: an answer and an additional record for another name.
            m.answers
                .push(Record::new(n("bank.test"), 86_400, RData::A(EVIL.into())));
            m.additional
                .push(Record::new(n("bank.test"), 86_400, RData::A(EVIL.into())));
        } else {
            m.answers.push(a_for(q, 60, REAL));
        }
        Reply::Messages(vec![m])
    });
    let r = Resolver::new(config(&[&fake])).unwrap();
    assert_eq!(r.lookup_ip("www.test").unwrap(), vec![ip(REAL)]);
    let before = fake.count();
    assert_eq!(r.lookup_ip("bank.test").unwrap(), vec![ip(REAL)]);
    assert!(
        fake.count() > before,
        "bank.test was asked, not taken from the riders"
    );
}

#[test]
fn ids_ports_and_case_are_random() {
    let fake = Fake::start(answer_a(REAL));
    let r = Resolver::new(config(&[&fake]).ip_order(dns_net::IpOrder::Ipv4Only)).unwrap();
    for i in 0..64 {
        r.lookup_ip(&format!("host{i}.example.test")).unwrap();
    }
    let seen = fake.queries();
    let ports: HashSet<u16> = seen.iter().map(|s| s.from.port()).collect();
    let ids: HashSet<u16> = seen.iter().map(|s| s.query.header.id).collect();
    assert!(ports.len() >= 60, "{} distinct ports of 64", ports.len());
    assert!(ids.len() >= 60, "{} distinct ids of 64", ids.len());
    assert!(seen.iter().all(|s| s.from.port() >= 1024));
    // The same name, asked 16 times: its 18 letters come out in many cases.
    for _ in 0..16 {
        r.clear_cache();
        r.lookup_ip("abcdefghijklmnop.qr").unwrap();
    }
    let casings: HashSet<String> = fake.queries()[64..]
        .iter()
        .map(|s| question(&s.query).name.to_string())
        .collect();
    assert!(casings.len() >= 14, "{} casings of 16", casings.len());
}

#[test]
fn source_ports_stay_in_the_configured_range() {
    let fake = Fake::start(answer_a(REAL));
    let r = Resolver::new(config(&[&fake]).source_ports(40_000, 40_999)).unwrap();
    for i in 0..20 {
        r.lookup(&n(&format!("p{i}.test")), RecordType::A).unwrap();
    }
    assert!(
        fake.queries()
            .iter()
            .all(|s| (40_000..=40_999).contains(&s.from.port()))
    );
}

#[test]
fn compression_loops_and_huge_counts_are_dropped() {
    let fake = forge_then_answer(|q| {
        let mut b = q.encode().unwrap();
        b[2] |= 0x80; // a response
        // One answer whose name is a pointer to itself.
        b[7] = 1;
        let at = b.len() - 11; // drop the OPT record
        b.truncate(at);
        b[11] = 0;
        let here = b.len() as u16;
        b.extend_from_slice(&(0xC000 | here).to_be_bytes());
        b.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 66]);
        b
    });
    let r = only_real(&fake);
    assert_eq!(r.stats().ignored, 1);

    let fake = forge_then_answer(|q| {
        let mut b = evil_reply(q).encode().unwrap();
        b[6] = 0xFF;
        b[7] = 0xFF;
        b
    });
    let r = only_real(&fake);
    assert_eq!(r.stats().ignored, 1);
}

#[test]
fn the_resolver_never_answers_queries() {
    // Amplification: a query sent to the resolver's source port from the
    // upstream's own address, with the right id, is dropped, and nothing is
    // sent back.
    let fake = Fake::start(|q, _| {
        let mut probe = q.clone();
        probe.header.response = false;
        let mut real = respond(q);
        real.answers.push(a_for(q, 60, REAL));
        Reply::Raw(vec![probe.encode().unwrap(), real.encode().unwrap()])
    });
    let r = only_real(&fake);
    assert_eq!(r.stats().ignored, 1);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(fake.count(), 1, "the resolver sent nothing back");
}

#[test]
fn ssrf_private_and_loopback_addresses_are_refused() {
    let answers: Arc<Mutex<Vec<[u8; 4]>>> = Arc::new(Mutex::new(Vec::new()));
    let a2 = answers.clone();
    let fake = Fake::start(move |q, _| {
        let mut m = respond(q);
        if question(q).qtype == RecordType::A {
            for o in a2.lock().unwrap().iter() {
                m.answers.push(a_for(q, 0, *o));
            }
        }
        Reply::Messages(vec![m])
    });
    let r = Resolver::new(config(&[&fake]).policy(PublicOnly::new())).unwrap();
    let set = |v: Vec<[u8; 4]>| *answers.lock().unwrap() = v;
    for private in [
        [127, 0, 0, 1],
        [10, 0, 0, 1],
        [169, 254, 169, 254],
        [192, 168, 1, 1],
        [0, 0, 0, 0],
    ] {
        set(vec![private]);
        assert_eq!(r.lookup_ip("hook.test"), Err(Error::Refused), "{private:?}");
    }
    set(vec![[10, 0, 0, 1], [93, 184, 215, 14]]);
    assert_eq!(
        r.lookup_ip("hook.test").unwrap(),
        vec![ip([93, 184, 215, 14])]
    );
    for literal in [
        "127.0.0.1",
        "[::1]",
        "::ffff:127.0.0.1",
        "169.254.169.254",
        "[fd00::1]",
        "0.0.0.0",
    ] {
        assert_eq!(r.lookup_ip(literal), Err(Error::Refused), "{literal}");
    }
    assert_eq!(r.lookup_ip("localhost"), Err(Error::Refused));
    for ambiguous in ["127.1", "0x7f000001", "2130706433", "10.0x1"] {
        assert_eq!(
            r.lookup_ip(ambiguous),
            Err(Error::AmbiguousHost),
            "{ambiguous}"
        );
    }
    for bad in ["a/b", "evil.test\\.", "x y", "a%2e.test"] {
        assert!(matches!(r.lookup_ip(bad), Err(Error::Name(_))), "{bad}");
    }
    // The default policy of this resolver allows everything else.
    assert_eq!(
        r.lookup_ip_with("localhost", &dns_net::AllowAll).unwrap()[0],
        ip([127, 0, 0, 1])
    );
}

#[test]
fn dns_rebinding_is_caught_on_every_lookup() {
    // Public the first time, loopback the second, with TTL 0 so nothing is
    // cached in between.
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = calls.clone();
    let fake = Fake::start(move |q, _| {
        let mut m = respond(q);
        if question(q).qtype == RecordType::A {
            let first = c2.fetch_add(1, Ordering::SeqCst) == 0;
            let o = if first {
                [93, 184, 215, 14]
            } else {
                [127, 0, 0, 1]
            };
            m.answers.push(a_for(q, 0, o));
        }
        Reply::Messages(vec![m])
    });
    let r = Resolver::new(config(&[&fake]).ip_order(dns_net::IpOrder::Ipv4Only)).unwrap();
    let policy = PublicOnly::new();
    assert_eq!(
        r.lookup_ip_with("rebind.test", &policy).unwrap(),
        vec![ip([93, 184, 215, 14])]
    );
    assert_eq!(
        r.lookup_ip_with("rebind.test", &policy),
        Err(Error::Refused)
    );
}

#[test]
fn names_that_are_not_host_names_are_refused_for_addresses() {
    let fake = Fake::start(answer_a(REAL));
    let r = Resolver::new(config(&[&fake])).unwrap();
    // A name with a NUL byte can be asked for with `lookup`, which takes a
    // parsed name, but never through the host-name path.
    let odd = Name::parse("a\\000b.test").unwrap();
    assert!(r.lookup(&odd, RecordType::A).is_ok());
    assert!(matches!(r.lookup_ip("a\\000b.test"), Err(Error::Name(_))));
}
