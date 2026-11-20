//! Lookups from sessions on net-io's reactor workers: the session parks, the
//! resolver posts to the worker's completion queue, and the worker is never
//! blocked while the query is out.
#![cfg(feature = "resolver")]

mod support;

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dns_net::{AddressPolicy, AllowAll, Resolver, Ticket};
use net_io::{
    ConnectionInfo, DriverKind, Input, ListenerSpec, Server, ServerBuilder, Session,
    SessionContext, Step,
};
use support::{Fake, Reply, a_for, config, respond};

/// Reads a host name per line and writes back its addresses.
struct Lookup {
    resolver: Resolver,
    policy: Arc<dyn AddressPolicy>,
    ticket: Option<Ticket<Vec<IpAddr>>>,
}

impl Lookup {
    fn reply(&mut self, cx: &mut SessionContext<'_>) -> Step {
        let line = match self.ticket.take().and_then(|t| t.take()) {
            Some(Ok(addrs)) => {
                let list: Vec<String> = addrs.iter().map(ToString::to_string).collect();
                format!("ok {}\n", list.join(","))
            }
            Some(Err(e)) => format!("err {e}\n"),
            None => "err pending\n".to_string(),
        };
        let _ = cx.output().push(line.as_bytes());
        Step::Write
    }
}

impl Session for Lookup {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let bytes = input.bytes();
        let Some(end) = bytes.iter().position(|&b| b == b'\n') else {
            return Step::Read;
        };
        let host = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
        input.consume(end + 1);
        let started = self.resolver.park_ip(
            &host,
            Arc::clone(&self.policy),
            &cx.completer(),
            cx.info().id,
            7,
        );
        match started {
            Ok(ticket) => {
                let ready = ticket.is_ready();
                self.ticket = Some(ticket);
                if ready {
                    self.reply(cx)
                } else {
                    Step::Park {
                        until: Some(Instant::now() + Duration::from_secs(10)),
                    }
                }
            }
            Err(e) => {
                let _ = cx.output().push(format!("err {e}\n").as_bytes());
                Step::Write
            }
        }
    }

    fn on_wake(&mut self, cx: &mut SessionContext<'_>, token: u32, _value: u64) -> Step {
        assert_eq!(token, 7);
        self.reply(cx)
    }

    fn on_writable(&mut self, _cx: &mut SessionContext<'_>) -> Step {
        Step::Read
    }
}

fn server(resolver: Resolver, workers: u16) -> (Server, SocketAddr) {
    let policy: Arc<dyn AddressPolicy> = Arc::new(AllowAll);
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Reactor)
        .workers(workers)
        .sessions(move |_: &ConnectionInfo| Lookup {
            resolver: resolver.clone(),
            policy: Arc::clone(&policy),
            ticket: None,
        })
        .gate(net_io::AllowAll)
        .build()
        .unwrap();
    server.open_door().unwrap();
    let addr = server.listeners()[0].local.socket_addr().unwrap();
    (server, addr)
}

fn ask(conn: &mut BufReader<TcpStream>, host: &str) -> String {
    conn.get_mut()
        .write_all(format!("{host}\n").as_bytes())
        .unwrap();
    let mut line = String::new();
    conn.read_line(&mut line).unwrap();
    line.trim_end().to_string()
}

fn connect(addr: SocketAddr) -> BufReader<TcpStream> {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    BufReader::new(s)
}

#[test]
fn a_parked_session_gets_its_answer() {
    let fake = Fake::start(|q, _| {
        // Slow enough that the session parks.
        std::thread::sleep(Duration::from_millis(100));
        let mut m = respond(q);
        if q.question.as_ref().unwrap().qtype == dns_net::RecordType::A {
            m.answers.push(a_for(q, 60, [192, 0, 2, 20]));
        }
        Reply::Messages(vec![m])
    });
    let resolver = Resolver::new(config(&[&fake]).ip_order(dns_net::IpOrder::Ipv4Only)).unwrap();
    let (server, addr) = server(resolver, 1);
    let mut conn = connect(addr);
    assert_eq!(ask(&mut conn, "slow.test"), "ok 192.0.2.20");
    // From the cache now: the ticket is ready at once and nothing parks.
    assert_eq!(ask(&mut conn, "slow.test"), "ok 192.0.2.20");
    assert_eq!(fake.count(), 1);
    // A literal and a bad host answer at once too.
    assert_eq!(ask(&mut conn, "192.0.2.99"), "ok 192.0.2.99");
    assert!(ask(&mut conn, "127.1").starts_with("err"));
    let _ = server.shutdown(Instant::now() + Duration::from_secs(2));
}

#[test]
fn one_worker_serves_others_while_a_lookup_is_out() {
    // The worker has one thread; a lookup that takes 600 ms must not hold up
    // a second connection's lookup of a cached name.
    let fake = Fake::start(|q, _| {
        let name = q
            .question
            .as_ref()
            .unwrap()
            .name
            .to_string()
            .to_ascii_lowercase();
        if name.starts_with("slow") {
            std::thread::sleep(Duration::from_millis(600));
        }
        let mut m = respond(q);
        m.answers.push(a_for(q, 60, [192, 0, 2, 21]));
        Reply::Messages(vec![m])
    });
    let resolver = Resolver::new(
        config(&[&fake])
            .ip_order(dns_net::IpOrder::Ipv4Only)
            .timeout(Duration::from_secs(2)),
    )
    .unwrap();
    resolver.lookup_ip("fast.test").unwrap();
    let (server, addr) = server(resolver, 1);
    let mut slow = connect(addr);
    slow.get_mut().write_all(b"slow.test\n").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let mut fast = connect(addr);
    let t = Instant::now();
    assert_eq!(ask(&mut fast, "fast.test"), "ok 192.0.2.21");
    assert!(
        t.elapsed() < Duration::from_millis(400),
        "{:?}",
        t.elapsed()
    );
    let mut line = String::new();
    slow.read_line(&mut line).unwrap();
    assert_eq!(line.trim_end(), "ok 192.0.2.21");
    let _ = server.shutdown(Instant::now() + Duration::from_secs(2));
}
