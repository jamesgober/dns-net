//! The resolver: one thread that multiplexes every query on net-io's reactor
//! driver, a cache in front of it that callers read on their own thread, and
//! three ways in: blocking calls, callbacks, and tickets that wake a parked
//! net-io connection.
//!
//! Each attempt is a new UDP socket on a random source port, connected to the
//! upstream (so the kernel drops datagrams from any other address), carrying a
//! random id and a randomly cased name. Replies that fail any check are
//! dropped and the attempt keeps waiting; a truncated reply is fetched again
//! over TCP on a short-lived thread. Identical questions in flight share one
//! query, so a forger cannot multiply its chances by asking many times.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use net_io::{
    BufferPool, Completer, Completion, Completions, ConnectOptions, ConnectionId, Driver, NetError,
    Operation, OperationKind, Phase, SharedSocket, SizeClass, TcpConnection, Token,
};

use crate::cache::{Cache, CacheStats, Entry};
use crate::config::{ConfigError, ResolverConfig};
use crate::error::NameError;
use crate::exchange::{Exchange, MAX_CHAIN, Outcome, Status};
use crate::message::{Question, Record};
use crate::name::Name;
use crate::policy::AddressPolicy;
use crate::random::Random;
use crate::rdata::RData;
use crate::types::{Class, Rcode, RecordType};

/// Why a lookup failed.
///
/// ```
/// assert_eq!(dns_net::Error::Timeout.to_string(), "no upstream answered in time");
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The name is not a valid name (or host name, for address lookups).
    Name(NameError),
    /// The host name ends in a number, which URL parsers read as an IPv4
    /// address (`127.1`, `0x7f000001`): it is refused rather than sent to DNS.
    AmbiguousHost,
    /// The configuration was refused.
    Config(ConfigError),
    /// No upstream answered in time.
    Timeout,
    /// Every upstream answered with an error code (the last one is given).
    Server(Rcode),
    /// The replies contradicted themselves (a CNAME loop or conflict, or a
    /// chain over the limit).
    Bogus,
    /// An address lookup found no addresses: the name does not exist, or has
    /// none of the families asked for.
    NotFound(Status),
    /// The address policy refused every address found.
    Refused,
    /// Too many lookups are waiting.
    Busy,
    /// The resolver has stopped.
    Stopped,
    /// The operating system's random source failed; nothing was sent.
    Random,
    /// A socket operation failed.
    Io(io::ErrorKind),
    /// A TLS upstream's handshake failed: its certificate or key did not
    /// match, or it did not speak TLS.
    Tls,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Name(e) => write!(f, "bad name: {e}"),
            Error::AmbiguousHost => f.write_str("the host name ends in a number"),
            Error::Config(e) => write!(f, "bad configuration: {e}"),
            Error::Timeout => f.write_str("no upstream answered in time"),
            Error::Server(r) => write!(f, "the upstreams answered {r}"),
            Error::Bogus => f.write_str("the replies contradicted themselves"),
            Error::NotFound(Status::NxDomain) => f.write_str("the name does not exist"),
            Error::NotFound(_) => f.write_str("the name has no addresses"),
            Error::Refused => f.write_str("the address policy refused every address"),
            Error::Busy => f.write_str("too many lookups are waiting"),
            Error::Stopped => f.write_str("the resolver has stopped"),
            Error::Random => f.write_str("the system's random source failed"),
            Error::Io(kind) => write!(f, "socket error: {kind}"),
            Error::Tls => f.write_str("the TLS handshake with the upstream failed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<NameError> for Error {
    fn from(e: NameError) -> Error {
        Error::Name(e)
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Error {
        Error::Config(e)
    }
}

/// Which address families an address lookup asks for, in what order.
///
/// ```
/// assert_eq!(dns_net::IpOrder::default(), dns_net::IpOrder::Ipv4First);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IpOrder {
    /// A and AAAA, IPv4 addresses first.
    #[default]
    Ipv4First,
    /// AAAA and A, IPv6 addresses first.
    Ipv6First,
    /// A only.
    Ipv4Only,
    /// AAAA only.
    Ipv6Only,
}

impl IpOrder {
    fn types(self) -> &'static [RecordType] {
        match self {
            IpOrder::Ipv4First => &[RecordType::A, RecordType::AAAA],
            IpOrder::Ipv6First => &[RecordType::AAAA, RecordType::A],
            IpOrder::Ipv4Only => &[RecordType::A],
            IpOrder::Ipv6Only => &[RecordType::AAAA],
        }
    }
}

/// The answer to one lookup, shared with the cache (cloning it is cheap).
///
/// ```no_run
/// use dns_net::{Name, RecordType, Resolver, ResolverConfig};
/// let resolver = Resolver::new(ResolverConfig::system()?)?;
/// let mx = resolver.lookup(&Name::parse("example.com")?, RecordType::MX)?;
/// for record in mx.records() {
///     println!("{}", record.data);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Lookup {
    name: Name,
    rtype: RecordType,
    entry: Arc<Entry>,
    expires: Option<Instant>,
}

impl Lookup {
    /// The name asked about.
    #[must_use]
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// The type asked for.
    #[must_use]
    pub fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// Found, NODATA, or NXDOMAIN.
    #[must_use]
    pub fn status(&self) -> Status {
        self.entry.status
    }

    /// The records of the type asked for (empty for a negative answer). Their
    /// `ttl` fields are as received; [`Lookup::ttl`] is what is left.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        &self.entry.records
    }

    /// The CNAME records that led from the name to the records, in order.
    #[must_use]
    pub fn chain(&self) -> &[Record] {
        &self.entry.chain
    }

    /// The name the records belong to: the end of the CNAME chain.
    #[must_use]
    pub fn canonical_name(&self) -> &Name {
        match self.entry.chain.last().map(|r| &r.data) {
            Some(RData::Cname(target)) => target,
            _ => &self.name,
        }
    }

    /// Seconds the answer stays valid (0 when it was not cached).
    #[must_use]
    pub fn ttl(&self) -> u32 {
        self.expires.map_or(0, |e| {
            u32::try_from(e.saturating_duration_since(Instant::now()).as_secs()).unwrap_or(u32::MAX)
        })
    }

    /// Whether the answer is DNSSEC-validated by the upstream: every reply
    /// behind it had the AD bit set, and came over a path an attacker cannot
    /// write to (a TLS upstream, or one on loopback). An AD bit from a plain
    /// upstream across a network is never reported, since anyone on the path
    /// could set it (RFC 6698 section 1.3, RFC 7672).
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.entry.authentic
    }

    /// The A and AAAA addresses among the records.
    pub fn ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.entry.records.iter().filter_map(|r| match r.data {
            RData::A(a) => Some(IpAddr::V4(a)),
            RData::Aaaa(a) => Some(IpAddr::V6(a)),
            _ => None,
        })
    }
}

/// A result that arrives later, for a session parked on a net-io worker; see
/// [`Resolver::park`].
pub struct Ticket<T> {
    slot: Arc<TicketSlot<T>>,
}

struct TicketSlot<T> {
    value: Mutex<Option<Result<T, Error>>>,
    /// 0: neither side done; 1: the caller has its ticket; 2: the result
    /// arrived first (no wake is posted then: the caller sees it at once).
    state: AtomicU8,
}

impl<T> Ticket<T> {
    /// The result, once; `None` while it is pending.
    pub fn take(&self) -> Option<Result<T, Error>> {
        lock(&self.slot.value).take()
    }

    /// Whether the result is there.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        lock(&self.slot.value).is_some()
    }
}

impl<T> fmt::Debug for Ticket<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ticket")
            .field("ready", &self.is_ready())
            .finish()
    }
}

/// Counters of a resolver since it started.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolverStats {
    /// UDP queries sent.
    pub queries: u64,
    /// Queries sent again over TCP after a truncated reply.
    pub tcp_queries: u64,
    /// Replies dropped because they did not match their query (another id,
    /// another question, the case changed, malformed): forgeries, or late
    /// replies to earlier attempts.
    pub ignored: u64,
    /// Attempts that timed out.
    pub timeouts: u64,
    /// Replies with an error code, or that contradicted themselves.
    pub server_errors: u64,
    /// Lookups that joined a query already in flight for the same question.
    pub coalesced: u64,
    /// Lookups answered without a query: `localhost`, `.invalid`, `.onion`.
    pub local: u64,
    /// TLS connections opened to upstreams (handshakes completed).
    pub tls_connections: u64,
    /// The cache's counters.
    pub cache: CacheStats,
}

type Done = Box<dyn FnOnce(Result<Lookup, Error>) + Send>;
type IpDone = Box<dyn FnOnce(Result<Vec<IpAddr>, Error>) + Send>;

struct Job {
    question: Question,
    done: Done,
}

#[derive(Default)]
struct Counters {
    queries: AtomicU64,
    tcp: AtomicU64,
    ignored: AtomicU64,
    timeouts: AtomicU64,
    server_errors: AtomicU64,
    coalesced: AtomicU64,
    local: AtomicU64,
    tls: AtomicU64,
}

struct Shared {
    config: ResolverConfig,
    cache: Mutex<Cache>,
    queue: Mutex<VecDeque<Job>>,
    waker: net_io::DriverWaker,
    stop: AtomicBool,
    outstanding: AtomicUsize,
    counters: Counters,
}

struct Owner {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.waker.wake();
        if let Some(t) = lock(&self.thread).take() {
            // The last handle can be dropped inside a callback, on the
            // resolver's own thread, which must not wait for itself.
            if t.thread().id() != std::thread::current().id() {
                let _ = t.join();
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A callback that panicked cannot leave these structures half-changed:
    // every lock is held only around plain field updates.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A caching stub resolver. Cloning it is cheap; the thread stops when the
/// last clone is dropped, failing lookups still pending with
/// [`Error::Stopped`].
///
/// ```no_run
/// use dns_net::{Resolver, ResolverConfig};
/// let resolver = Resolver::new(ResolverConfig::system()?)?;
/// let addrs = resolver.lookup_ip("example.com")?;
/// # let _ = addrs;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct Resolver {
    shared: Arc<Shared>,
    _owner: Arc<Owner>,
}

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver")
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

impl Resolver {
    /// Starts a resolver and its thread.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for a configuration out of range or without
    /// upstreams; [`Error::Io`] when the driver or the thread cannot start.
    pub fn new(config: ResolverConfig) -> Result<Resolver, Error> {
        config.validate()?;
        let driver = net_io::new_reactor_driver(64).map_err(net_error)?;
        let shared = Arc::new(Shared {
            cache: Mutex::new(Cache::new(
                config.cache_bytes,
                config.max_ttl,
                config.max_negative_ttl,
            )),
            queue: Mutex::new(VecDeque::new()),
            waker: driver.waker(),
            stop: AtomicBool::new(false),
            outstanding: AtomicUsize::new(0),
            counters: Counters::default(),
            config,
        });
        #[cfg(feature = "tls")]
        let tls = if shared.config.upstreams.iter().any(crate::Upstream::is_tls) {
            match shared.config.tls_client.clone() {
                Some(c) => Some(c),
                None => Some(tls_net::client().map_err(|_| Error::Tls)?),
            }
        } else {
            None
        };
        #[cfg(feature = "tls")]
        let engine = Engine::new(Arc::clone(&shared), driver, tls);
        #[cfg(not(feature = "tls"))]
        let engine = Engine::new(Arc::clone(&shared), driver);
        let thread = std::thread::Builder::new()
            .name("dns-net".into())
            .spawn(move || engine.run())
            .map_err(|e| Error::Io(e.kind()))?;
        Ok(Resolver {
            _owner: Arc::new(Owner {
                shared: Arc::clone(&shared),
                thread: Mutex::new(Some(thread)),
            }),
            shared,
        })
    }

    /// Looks up `rtype` records of `name`, waiting for the answer (at most
    /// the configured deadline). A negative answer is `Ok`, with
    /// [`Lookup::status`] saying which.
    ///
    /// Never call it from a callback given to [`Resolver::submit`]: that
    /// runs on the resolver's thread, which would wait for itself.
    ///
    /// # Errors
    ///
    /// [`Error`]: no upstream answered, every upstream failed, and the rest.
    pub fn lookup(&self, name: &Name, rtype: RecordType) -> Result<Lookup, Error> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.submit(name, rtype, move |r| {
            let _ = tx.send(r);
        })?;
        rx.recv().unwrap_or(Err(Error::Stopped))
    }

    /// Starts a lookup and calls `done` with its result. An answer from the
    /// cache (or for a local name) calls `done` at once, on this thread;
    /// otherwise `done` runs on the resolver's thread, so it must be quick
    /// and must not block.
    ///
    /// # Errors
    ///
    /// [`Error::Busy`] when too many lookups wait, [`Error::Stopped`];
    /// `done` is not called then.
    pub fn submit<F>(&self, name: &Name, rtype: RecordType, done: F) -> Result<(), Error>
    where
        F: FnOnce(Result<Lookup, Error>) + Send + 'static,
    {
        let question = Question::new(name.clone(), rtype);
        if let Some(found) = self.answer_now(&question) {
            done(Ok(found));
            return Ok(());
        }
        self.enqueue(Job {
            question,
            done: Box::new(done),
        })
    }

    /// Starts a lookup for a session on a net-io worker, which returns
    /// `Step::Park` and gets the result in `on_wake`: when it arrives,
    /// `(connection, token, 0)` is posted to `completer`. If the ticket is
    /// ready when this returns (a cached answer), nothing is posted, and the
    /// session must not park.
    ///
    /// The park deadline should be later than the resolver's deadline. If
    /// the worker's completion queue is full the post is lost, and the
    /// session finds the result when its park deadline wakes it.
    ///
    /// ```no_run
    /// use dns_net::{Name, RecordType, Resolver, Ticket, Lookup};
    /// use net_io::{Input, Session, SessionContext, Step};
    ///
    /// struct Mx { resolver: Resolver, ticket: Option<Ticket<Lookup>> }
    /// impl Session for Mx {
    ///     fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
    ///         let n = input.bytes().len();
    ///         input.consume(n);
    ///         let name = Name::parse("example.com").unwrap();
    ///         let ticket = self.resolver
    ///             .park(&name, RecordType::MX, &cx.completer(), cx.info().id, 1)
    ///             .unwrap();
    ///         let ready = ticket.is_ready();
    ///         self.ticket = Some(ticket);
    ///         if ready { self.reply(cx) } else { Step::Park { until: None } }
    ///     }
    ///     fn on_wake(&mut self, cx: &mut SessionContext<'_>, _token: u32, _value: u64) -> Step {
    ///         self.reply(cx)
    ///     }
    /// }
    /// impl Mx {
    ///     fn reply(&mut self, cx: &mut SessionContext<'_>) -> Step {
    ///         if let Some(Ok(found)) = self.ticket.take().and_then(|t| t.take()) {
    ///             let _ = cx.output().push(format!("{} records\n", found.records().len()).as_bytes());
    ///         }
    ///         Step::Write
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`Resolver::submit`].
    pub fn park(
        &self,
        name: &Name,
        rtype: RecordType,
        completer: &Completer,
        connection: ConnectionId,
        token: u32,
    ) -> Result<Ticket<Lookup>, Error> {
        park_with(completer, connection, token, |done| {
            self.submit(name, rtype, done)
        })
    }

    /// Looks up the addresses of `host` (a host name, or an IP literal, with
    /// or without brackets) in the configured [`IpOrder`], and returns those
    /// the configured policy allows.
    ///
    /// `localhost` and names under it are loopback without a query; names
    /// under `.invalid` and `.onion` do not exist (RFC 6761, RFC 7686).
    ///
    /// # Errors
    ///
    /// [`Error::Name`] or [`Error::AmbiguousHost`] for a host that is not a
    /// plain host name; [`Error::NotFound`] when there are no addresses;
    /// [`Error::Refused`] when the policy refused all of them; as
    /// [`Resolver::lookup`].
    pub fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        let policy = Arc::clone(&self.shared.config.policy);
        self.lookup_ip_with(host, &*policy)
    }

    /// As [`Resolver::lookup_ip`], with `policy` instead of the configured one.
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_ip`].
    pub fn lookup_ip_with(
        &self,
        host: &str,
        policy: &dyn AddressPolicy,
    ) -> Result<Vec<IpAddr>, Error> {
        let (name, plan) = plan_ip(host, self.shared.config.ip_order)?;
        let types = match plan {
            IpPlan::Literal(ip) => return filter(&name, vec![ip], policy, None),
            IpPlan::Lookup(types) => types,
        };
        let (tx, rx) = mpsc::sync_channel(types.len());
        for (i, &t) in types.iter().enumerate() {
            let tx = tx.clone();
            self.submit(&name, t, move |r| {
                let _ = tx.send((i, r));
            })?;
        }
        drop(tx);
        let mut results: Vec<Option<Result<Lookup, Error>>> = vec![None; types.len()];
        for (i, r) in rx {
            results[i] = Some(r);
        }
        combine(&name, results, policy)
    }

    /// Starts an address lookup and calls `done` with the allowed addresses;
    /// as [`Resolver::submit`] for where `done` runs.
    ///
    /// # Errors
    ///
    /// As [`Resolver::submit`]; [`Error::Name`] or [`Error::AmbiguousHost`]
    /// for a bad host.
    pub fn submit_ip<F>(
        &self,
        host: &str,
        policy: Arc<dyn AddressPolicy>,
        done: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(Result<Vec<IpAddr>, Error>) + Send + 'static,
    {
        let (name, plan) = plan_ip(host, self.shared.config.ip_order)?;
        let types = match plan {
            IpPlan::Literal(ip) => {
                done(filter(&name, vec![ip], &*policy, None));
                return Ok(());
            }
            IpPlan::Lookup(types) => types,
        };
        struct Gather {
            results: Vec<Option<Result<Lookup, Error>>>,
            left: usize,
            done: Option<IpDone>,
        }
        let gather = Arc::new(Mutex::new(Gather {
            results: vec![None; types.len()],
            left: types.len(),
            done: Some(Box::new(done)),
        }));
        for (i, &t) in types.iter().enumerate() {
            let theirs = Arc::clone(&gather);
            let policy = Arc::clone(&policy);
            let name2 = name.clone();
            let started = self.submit(&name, t, move |r| {
                let mut g = lock(&theirs);
                g.results[i] = Some(r);
                g.left -= 1;
                if g.left == 0 {
                    let results = std::mem::take(&mut g.results);
                    let done = g.done.take();
                    drop(g);
                    if let Some(done) = done {
                        done(combine(&name2, results, &*policy));
                    }
                }
            });
            if let Err(e) = started {
                // The lookups already started still finish; their results
                // are dropped, and `done` is never called.
                lock(&gather).done = None;
                return Err(e);
            }
        }
        Ok(())
    }

    /// [`Resolver::submit_ip`] for a session parked on a net-io worker, as
    /// [`Resolver::park`] describes.
    ///
    /// # Errors
    ///
    /// As [`Resolver::submit_ip`].
    pub fn park_ip(
        &self,
        host: &str,
        policy: Arc<dyn AddressPolicy>,
        completer: &Completer,
        connection: ConnectionId,
        token: u32,
    ) -> Result<Ticket<Vec<IpAddr>>, Error> {
        park_with(completer, connection, token, |done| {
            self.submit_ip(host, policy, done)
        })
    }

    /// Counters since the resolver started.
    #[must_use]
    pub fn stats(&self) -> ResolverStats {
        let c = &self.shared.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        ResolverStats {
            queries: get(&c.queries),
            tcp_queries: get(&c.tcp),
            ignored: get(&c.ignored),
            timeouts: get(&c.timeouts),
            server_errors: get(&c.server_errors),
            coalesced: get(&c.coalesced),
            local: get(&c.local),
            tls_connections: get(&c.tls),
            cache: lock(&self.shared.cache).stats(),
        }
    }

    /// Empties the cache.
    pub fn clear_cache(&self) {
        lock(&self.shared.cache).clear();
    }

    /// A local answer, or a live cached one.
    fn answer_now(&self, q: &Question) -> Option<Lookup> {
        if let Some(entry) = local_answer(q) {
            self.shared.counters.local.fetch_add(1, Ordering::Relaxed);
            return Some(Lookup {
                name: q.name.clone(),
                rtype: q.qtype,
                entry: Arc::new(entry),
                expires: None,
            });
        }
        cached(&self.shared, q)
    }

    fn enqueue(&self, job: Job) -> Result<(), Error> {
        if self.shared.stop.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }
        let limit = self.shared.config.max_in_flight + self.shared.config.max_waiting;
        if self.shared.outstanding.fetch_add(1, Ordering::AcqRel) >= limit {
            self.shared.outstanding.fetch_sub(1, Ordering::AcqRel);
            return Err(Error::Busy);
        }
        lock(&self.shared.queue).push_back(job);
        self.shared.waker.wake();
        Ok(())
    }
}

fn cached(shared: &Shared, q: &Question) -> Option<Lookup> {
    let (entry, expires) = lock(&shared.cache).get(&q.name, q.qtype, Instant::now())?;
    Some(Lookup {
        name: q.name.clone(),
        rtype: q.qtype,
        entry,
        expires: Some(expires),
    })
}

fn park_with<T, S>(
    completer: &Completer,
    connection: ConnectionId,
    token: u32,
    start: S,
) -> Result<Ticket<T>, Error>
where
    T: Send + 'static,
    S: FnOnce(Box<dyn FnOnce(Result<T, Error>) + Send>) -> Result<(), Error>,
{
    let slot = Arc::new(TicketSlot {
        value: Mutex::new(None),
        state: AtomicU8::new(0),
    });
    let theirs = Arc::clone(&slot);
    let completer = completer.clone();
    start(Box::new(move |r| {
        *lock(&theirs.value) = Some(r);
        if theirs.state.swap(2, Ordering::AcqRel) == 1 {
            let _ = completer.post(connection, token, 0);
        }
    }))?;
    // If the result came first (state 2), the caller sees it on the ticket.
    let _ = slot
        .state
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    Ok(Ticket { slot })
}

enum IpPlan {
    Literal(IpAddr),
    Lookup(&'static [RecordType]),
}

fn plan_ip(host: &str, order: IpOrder) -> Result<(Name, IpPlan), Error> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        let name = Name::parse(bare).unwrap_or_else(|_| Name::root());
        return Ok((name, IpPlan::Literal(ip)));
    }
    let name = Name::parse_hostname(host)?;
    if ends_in_number(&name) {
        return Err(Error::AmbiguousHost);
    }
    Ok((name, IpPlan::Lookup(order.types())))
}

/// Whether an AD bit from `up` can be believed: it came over TLS, or from
/// this machine. A plain upstream across a network is a path anyone on it can
/// write to.
fn path_is_trusted(up: &crate::Upstream) -> bool {
    up.is_tls() || up.addr().ip().is_loopback()
}

/// The URL standard's "ends in a number" rule: a last label of digits only,
/// or `0x` and hex digits, makes a URL parser read the host as IPv4.
fn ends_in_number(name: &Name) -> bool {
    let Some(last) = name.labels().last() else {
        return false;
    };
    if last.iter().all(u8::is_ascii_digit) {
        return true;
    }
    match last {
        [b'0', b'x' | b'X', rest @ ..] => rest.iter().all(u8::is_ascii_hexdigit),
        _ => false,
    }
}

fn combine(
    name: &Name,
    results: Vec<Option<Result<Lookup, Error>>>,
    policy: &dyn AddressPolicy,
) -> Result<Vec<IpAddr>, Error> {
    let mut addrs = Vec::new();
    let mut first_error = None;
    let mut nxdomain = false;
    for r in results.into_iter().flatten() {
        match r {
            Ok(l) => {
                nxdomain |= l.status() == Status::NxDomain;
                addrs.extend(l.ips());
            }
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    if addrs.is_empty() {
        if let Some(e) = first_error {
            return Err(e);
        }
    }
    let status = if nxdomain {
        Status::NxDomain
    } else {
        Status::NoData
    };
    filter(name, addrs, policy, Some(status))
}

fn filter(
    name: &Name,
    found: Vec<IpAddr>,
    policy: &dyn AddressPolicy,
    status: Option<Status>,
) -> Result<Vec<IpAddr>, Error> {
    if found.is_empty() {
        return Err(Error::NotFound(status.unwrap_or(Status::NoData)));
    }
    let mut out = Vec::with_capacity(found.len());
    for ip in found {
        if policy.allows(name, ip) && !out.contains(&ip) {
            out.push(ip);
        }
    }
    if out.is_empty() {
        return Err(Error::Refused);
    }
    Ok(out)
}

/// Answers for names that must never reach an upstream.
fn local_answer(q: &Question) -> Option<Entry> {
    let last = q.name.labels().last()?;
    let is = |s: &[u8]| last.eq_ignore_ascii_case(s);
    if is(b"localhost") {
        let data = match q.qtype {
            RecordType::A => Some(RData::A(Ipv4Addr::LOCALHOST)),
            RecordType::AAAA => Some(RData::Aaaa(Ipv6Addr::LOCALHOST)),
            _ => None,
        };
        return Some(Entry {
            status: if data.is_some() {
                Status::Found
            } else {
                Status::NoData
            },
            records: data
                .map(|d| Record::new(q.name.clone(), 0, d))
                .into_iter()
                .collect(),
            chain: Vec::new(),
            authentic: false,
        });
    }
    if is(b"invalid") || is(b"onion") {
        return Some(Entry {
            status: Status::NxDomain,
            records: Vec::new(),
            chain: Vec::new(),
            authentic: false,
        });
    }
    None
}

fn net_error(e: NetError) -> Error {
    match e {
        NetError::Os { source, .. } => Error::Io(source.kind()),
        NetError::ConnectTimeout { .. } | NetError::TimedOut { .. } => Error::Timeout,
        NetError::ConnectionRefused { .. } => Error::Io(io::ErrorKind::ConnectionRefused),
        NetError::ConnectionReset => Error::Io(io::ErrorKind::ConnectionReset),
        NetError::Closed => Error::Io(io::ErrorKind::UnexpectedEof),
        _ => Error::Io(io::ErrorKind::Other),
    }
}

// The resolver's thread.

struct Flight {
    question: Question,
    current: Name,
    chain: Vec<Record>,
    waiters: Vec<Done>,
    order: Vec<usize>,
    tries: usize,
    deadline: Instant,
    edns: bool,
    error: Error,
    attempt: Option<Attempt>,
    /// Every reply so far had the AD bit and came over a trusted path.
    authentic: bool,
}

struct Attempt {
    exchange: Exchange,
    upstream: usize,
    generation: u32,
    expires: Instant,
    transport: Transport,
}

enum Transport {
    Udp {
        token: Token,
        socket: Arc<UdpSocket>,
    },
    Tcp,
    /// On the upstream's TLS connection, under this id.
    #[cfg(feature = "tls")]
    Tls {
        id: u16,
    },
}

/// The result of a TLS connect on its helper thread: the upstream, and the
/// socket and session.
#[cfg(feature = "tls")]
type TlsReady = (
    usize,
    Result<(std::net::TcpStream, crate::dot::Session), Error>,
);

struct TcpDone {
    flight: usize,
    generation: u32,
    result: Result<Vec<u8>, Error>,
}

/// The most replies read for one attempt in one turn before it is given up
/// as flooded.
const DRAIN_MAX: usize = 256;

enum Verdict {
    /// The reply was not this attempt's; keep waiting.
    Keep,
    /// The attempt is over (answered, failed, or moved to TCP).
    Over,
}

struct Engine {
    shared: Arc<Shared>,
    driver: Box<dyn Driver>,
    completions: Completions,
    batch: Vec<Completion>,
    pool: BufferPool,
    random: Random,
    flights: Vec<Option<Flight>>,
    free: Vec<usize>,
    index: HashMap<(Name, RecordType), usize>,
    waiting: VecDeque<Job>,
    failures: Vec<u32>,
    tcp_tx: mpsc::Sender<TcpDone>,
    tcp_rx: mpsc::Receiver<TcpDone>,
    tcp_active: usize,
    tcp_queue: VecDeque<(usize, u32)>,
    generation: u32,
    /// Flight tokens start here; below are the TLS connections' (one per
    /// upstream).
    base: usize,
    #[cfg(feature = "tls")]
    tls: Option<tls_net::TlsClient>,
    #[cfg(feature = "tls")]
    dot: Vec<crate::dot::Slot>,
    #[cfg(feature = "tls")]
    dot_tx: mpsc::Sender<TlsReady>,
    #[cfg(feature = "tls")]
    dot_rx: mpsc::Receiver<TlsReady>,
}

impl Engine {
    fn new(
        shared: Arc<Shared>,
        driver: Box<dyn Driver>,
        #[cfg(feature = "tls")] tls: Option<tls_net::TlsClient>,
    ) -> Engine {
        let (tcp_tx, tcp_rx) = mpsc::channel();
        #[cfg(feature = "tls")]
        let (dot_tx, dot_rx) = mpsc::channel();
        let upstreams = shared.config.upstreams.len();
        Engine {
            base: upstreams,
            #[cfg(feature = "tls")]
            tls,
            #[cfg(feature = "tls")]
            dot: (0..upstreams)
                .map(|_| crate::dot::Slot::default())
                .collect(),
            #[cfg(feature = "tls")]
            dot_tx,
            #[cfg(feature = "tls")]
            dot_rx,
            shared,
            driver,
            completions: Completions::new(),
            batch: Vec::new(),
            // Buffers are dropped with their socket when an attempt ends, so
            // the pool's budget is only bookkeeping; memory is bounded by the
            // flights in flight.
            pool: BufferPool::standalone(u64::MAX / 2),
            random: Random::new(),
            flights: Vec::new(),
            free: Vec::new(),
            index: HashMap::new(),
            waiting: VecDeque::new(),
            failures: vec![0; upstreams],
            tcp_tx,
            tcp_rx,
            tcp_active: 0,
            tcp_queue: VecDeque::new(),
            generation: 0,
        }
    }

    fn run(mut self) {
        loop {
            if self.shared.stop.load(Ordering::Acquire) {
                self.shutdown();
                return;
            }
            let timeout = self
                .next_expiry()
                .map(|t| t.saturating_duration_since(Instant::now()));
            if self.driver.wait(&mut self.completions, timeout).is_err() {
                std::thread::sleep(Duration::from_millis(1));
            }
            let mut batch = std::mem::take(&mut self.batch);
            batch.extend(self.completions.drain());
            for c in batch.drain(..) {
                self.on_completion(c);
            }
            self.batch = batch;
            while let Ok(t) = self.tcp_rx.try_recv() {
                self.on_tcp(t);
            }
            #[cfg(feature = "tls")]
            while let Ok((u, r)) = self.dot_rx.try_recv() {
                self.on_tls_ready(u, r);
            }
            let jobs = std::mem::take(&mut *lock(&self.shared.queue));
            self.waiting.extend(jobs);
            self.admit();
            self.expire(Instant::now());
        }
    }

    fn next_generation(&mut self) -> u32 {
        self.generation = self.generation.wrapping_add(1);
        self.generation
    }

    fn next_expiry(&self) -> Option<Instant> {
        let attempts = self
            .flights
            .iter()
            .flatten()
            .filter_map(|f| f.attempt.as_ref().map(|a| a.expires))
            .min();
        #[cfg(feature = "tls")]
        let attempts = {
            let idle = self.shared.config.tls_idle;
            let closes = self
                .dot
                .iter()
                .filter(|s| s.ids.is_empty())
                .filter_map(|s| s.conn.as_ref().map(|c| c.idle_since + idle))
                .min();
            attempts.into_iter().chain(closes).min()
        };
        attempts
    }

    fn admit(&mut self) {
        while self.index.len() < self.shared.config.max_in_flight {
            let Some(job) = self.waiting.pop_front() else {
                break;
            };
            self.start(job);
        }
    }

    fn start(&mut self, job: Job) {
        let key = (job.question.name.clone(), job.question.qtype);
        if let Some(&i) = self.index.get(&key) {
            if let Some(f) = self.flights[i].as_mut() {
                f.waiters.push(job.done);
                self.shared
                    .counters
                    .coalesced
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Answered while it waited.
        if let Some(found) = cached(&self.shared, &job.question) {
            self.deliver(vec![job.done], &Ok(found));
            return;
        }
        let config = &self.shared.config;
        let n = config.upstreams.len();
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&u| self.failures[u]);
        let flight = Flight {
            current: job.question.name.clone(),
            question: job.question,
            chain: Vec::new(),
            waiters: vec![job.done],
            order,
            tries: 0,
            deadline: Instant::now() + config.deadline,
            edns: config.payload.is_some(),
            error: Error::Timeout,
            attempt: None,
            authentic: true,
        };
        let i = match self.free.pop() {
            Some(i) => {
                self.flights[i] = Some(flight);
                i
            }
            None => {
                self.flights.push(Some(flight));
                self.flights.len() - 1
            }
        };
        self.index.insert(key, i);
        self.attempt(i);
    }

    /// Sends the next attempt, or finishes the flight when none is left.
    fn attempt(&mut self, i: usize) {
        loop {
            let now = Instant::now();
            let config = &self.shared.config;
            let total = usize::from(config.attempts) * config.upstreams.len();
            let Some(f) = self.flights[i].as_mut() else {
                return;
            };
            if f.tries >= total || now >= f.deadline {
                let e = f.error.clone();
                self.finish(i, Err(e));
                return;
            }
            let upstream = f.order[f.tries % f.order.len()];
            f.tries += 1;
            match self.send(i, upstream, now) {
                Ok(()) => return,
                Err(e) => {
                    if let Some(f) = self.flights[i].as_mut() {
                        f.error = e;
                    }
                }
            }
        }
    }

    fn send(&mut self, i: usize, upstream: usize, now: Instant) -> Result<(), Error> {
        #[cfg(feature = "tls")]
        if self.shared.config.upstreams[upstream].is_tls() {
            return self.send_tls(i, upstream, now);
        }
        self.send_udp(i, upstream, now)
    }

    fn send_udp(&mut self, i: usize, upstream: usize, now: Instant) -> Result<(), Error> {
        let config = &self.shared.config;
        let addr = config.upstreams[upstream].addr();
        let timeout = config.timeout;
        let payload = config.payload;
        let case = config.case_randomization;
        let class = match payload {
            Some(p) if p > 4096 => SizeClass::LARGE,
            _ => SizeClass::SMALL,
        };
        let (question, deadline, edns) = {
            let f = self.flights[i].as_ref().ok_or(Error::Stopped)?;
            (
                Question {
                    name: f.current.clone(),
                    qtype: f.question.qtype,
                    qclass: Class::IN,
                },
                f.deadline,
                f.edns,
            )
        };
        let id = self.random.u16().map_err(|_| Error::Random)?;
        let mut bits = [0u8; 32];
        let need = if case {
            question.name.letter_count().div_ceil(8).min(32)
        } else {
            0
        };
        self.random
            .fill(&mut bits[..need])
            .map_err(|_| Error::Random)?;
        let exchange = Exchange::new(&question, id, &bits[..need], payload.filter(|_| edns))
            .map_err(|_| Error::Bogus)?;
        let socket = Arc::new(self.bind(addr)?);
        socket.connect(addr).map_err(|e| Error::Io(e.kind()))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| Error::Io(e.kind()))?;
        let generation = self.next_generation();
        let token = Token((u64::from(generation) << 32) | (self.base + i) as u64);
        let shared: SharedSocket = socket.clone();
        self.driver.register(shared, token).map_err(net_error)?;
        let sent = socket.send(exchange.bytes());
        let buffer = self.pool.take(class);
        let submitted = match (sent, buffer) {
            (Ok(_), Some(buffer)) => self
                .driver
                .submit(Operation::Receive { token, buffer })
                .map_err(|_| Error::Io(io::ErrorKind::Other)),
            (Err(e), _) => Err(Error::Io(e.kind())),
            (_, None) => Err(Error::Io(io::ErrorKind::OutOfMemory)),
        };
        if let Err(e) = submitted {
            let _ = self.driver.deregister(token);
            return Err(e);
        }
        self.shared.counters.queries.fetch_add(1, Ordering::Relaxed);
        if let Some(f) = self.flights[i].as_mut() {
            f.attempt = Some(Attempt {
                exchange,
                upstream,
                generation,
                expires: (now + timeout).min(deadline),
                transport: Transport::Udp { token, socket },
            });
        }
        Ok(())
    }

    /// A UDP socket on a random port of the configured range. Ports in use
    /// (or reserved, which Windows reports as access denied) are skipped; after
    /// 8 tries the system picks, which current systems also randomize.
    ///
    /// The port is bound through net-io, which binds exclusively on Windows
    /// (`SO_EXCLUSIVEADDRUSE`). Without it Windows lets a wildcard bind share a
    /// port another socket holds on a specific address, and datagrams to that
    /// address go to the other socket: replies would be lost to, or forged by,
    /// any local process on that port (D-020).
    fn bind(&mut self, peer: SocketAddr) -> Result<UdpSocket, Error> {
        let any: IpAddr = if peer.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        let (low, high) = self.shared.config.ports;
        let span = u32::from(high - low) + 1;
        for _ in 0..8 {
            let port = low + self.random.below(span).map_err(|_| Error::Random)? as u16;
            match bind_exclusive(SocketAddr::new(any, port)) {
                Ok(s) => return Ok(s),
                Err(Error::Io(io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied)) => {}
                Err(e) => return Err(e),
            }
        }
        bind_exclusive(SocketAddr::new(any, 0))
    }

    fn on_completion(&mut self, c: Completion) {
        let index = (c.token.0 & 0xFFFF_FFFF) as usize;
        if index < self.base {
            #[cfg(feature = "tls")]
            self.on_tls_completion(index, c);
            return;
        }
        let i = index - self.base;
        let generation = (c.token.0 >> 32) as u32;
        let current = self
            .flights
            .get(i)
            .and_then(Option::as_ref)
            .and_then(|f| f.attempt.as_ref())
            .is_some_and(|a| a.generation == generation);
        if !current || c.kind != OperationKind::Receive {
            return;
        }
        match (c.result, c.buffer) {
            (Ok(_), Some(mut buffer)) => {
                let mut verdict = self.on_reply(i, buffer.as_slice(), false);
                // Read what else is queued until the socket would block, then
                // wait again. The driver may take a short read to mean the
                // socket is empty, which is not so for datagrams, so the
                // socket is drained here. More than DRAIN_MAX replies that
                // are not this query's is a flood: the attempt moves on to
                // a fresh socket.
                let mut drained = 0;
                while matches!(verdict, Verdict::Keep) {
                    let Some(socket) = self.udp_socket(i) else {
                        return;
                    };
                    drained += 1;
                    if drained > DRAIN_MAX {
                        self.fail(i, Error::Timeout);
                        return;
                    }
                    buffer.clear();
                    match socket.recv(buffer.spare()) {
                        Ok(n) => {
                            buffer.set_len(n);
                            verdict = self.on_reply(i, buffer.as_slice(), false);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            buffer.clear();
                            let op = Operation::Receive {
                                token: c.token,
                                buffer,
                            };
                            if self.driver.submit(op).is_err() {
                                self.fail(i, Error::Io(io::ErrorKind::Other));
                            }
                            return;
                        }
                        Err(_) => {
                            self.fail(i, Error::Io(io::ErrorKind::ConnectionRefused));
                            return;
                        }
                    }
                }
            }
            // A refusal from the upstream's host (ICMP), or a socket error:
            // try the next upstream now rather than wait out the timeout.
            _ => self.fail(i, Error::Io(io::ErrorKind::ConnectionRefused)),
        }
    }

    fn udp_socket(&self, i: usize) -> Option<Arc<UdpSocket>> {
        match &self.flights.get(i)?.as_ref()?.attempt.as_ref()?.transport {
            Transport::Udp { socket, .. } => Some(Arc::clone(socket)),
            _ => None,
        }
    }

    fn on_tcp(&mut self, t: TcpDone) {
        self.tcp_active -= 1;
        while self.tcp_active < self.shared.config.tcp_connections {
            let Some((i, generation)) = self.tcp_queue.pop_front() else {
                break;
            };
            if self.is_current_tcp(i, generation) {
                self.spawn_tcp(i);
            }
        }
        if !self.is_current_tcp(t.flight, t.generation) {
            return;
        }
        match t.result {
            Ok(bytes) => {
                if matches!(self.on_reply(t.flight, &bytes, true), Verdict::Keep) {
                    self.fail(t.flight, Error::Bogus);
                }
            }
            Err(e) => self.fail(t.flight, e),
        }
    }

    fn is_current_tcp(&self, i: usize, generation: u32) -> bool {
        self.flights
            .get(i)
            .and_then(Option::as_ref)
            .and_then(|f| f.attempt.as_ref())
            .is_some_and(|a| a.generation == generation && matches!(a.transport, Transport::Tcp))
    }

    /// Reads a reply to the current attempt of flight `i`.
    fn on_reply(&mut self, i: usize, bytes: &[u8], over_tcp: bool) -> Verdict {
        let Some(f) = self.flights[i].as_mut() else {
            return Verdict::Over;
        };
        let Some(a) = f.attempt.as_ref() else {
            return Verdict::Over;
        };
        let msg = match a.exchange.check(bytes) {
            Ok(msg) => msg,
            Err(_) => {
                self.shared.counters.ignored.fetch_add(1, Ordering::Relaxed);
                return Verdict::Keep;
            }
        };
        let upstream = a.upstream;
        let had_edns = a.exchange.has_edns();
        let trusted = path_is_trusted(&self.shared.config.upstreams[upstream]);
        let authentic = f.authentic && trusted && msg.header.authentic_data;
        match Outcome::read_chain(&f.question, &msg, &f.current, &f.chain) {
            Outcome::Answer(mut answer) => {
                self.failures[upstream] = 0;
                answer.authentic = authentic;
                self.finish(i, Ok(answer));
            }
            Outcome::Truncated if !over_tcp => self.start_tcp(i),
            Outcome::Follow { target, chain } => {
                self.failures[upstream] = 0;
                self.close(i);
                if chain.len() >= MAX_CHAIN {
                    self.finish(i, Err(Error::Bogus));
                } else {
                    if let Some(f) = self.flights[i].as_mut() {
                        f.current = target;
                        f.chain = chain;
                        f.tries = 0;
                        f.authentic = authentic;
                    }
                    self.attempt(i);
                }
            }
            Outcome::ServerError(Rcode::FORMERR) if had_edns => {
                // An old server that cannot read the OPT record (RFC 6891
                // section 7): once, the same upstream again without it.
                self.close(i);
                if let Some(f) = self.flights[i].as_mut() {
                    f.edns = false;
                    f.tries -= 1;
                }
                self.attempt(i);
            }
            Outcome::ServerError(rcode) => {
                self.shared
                    .counters
                    .server_errors
                    .fetch_add(1, Ordering::Relaxed);
                self.fail(i, Error::Server(rcode));
            }
            // Bogus, a truncated reply over TCP, and anything later added.
            _ => {
                self.shared
                    .counters
                    .server_errors
                    .fetch_add(1, Ordering::Relaxed);
                self.fail(i, Error::Bogus);
            }
        }
        Verdict::Over
    }

    /// Ends the current attempt as failed and starts the next.
    fn fail(&mut self, i: usize, e: Error) {
        let upstream = self.flights[i]
            .as_ref()
            .and_then(|f| f.attempt.as_ref())
            .map(|a| a.upstream);
        if let Some(u) = upstream {
            self.failures[u] = self.failures[u].saturating_add(1);
        }
        self.close(i);
        if let Some(f) = self.flights[i].as_mut() {
            f.error = e;
        }
        self.attempt(i);
    }

    fn close(&mut self, i: usize) {
        let attempt = self.flights[i].as_mut().and_then(|f| f.attempt.take());
        match attempt {
            Some(Attempt {
                transport: Transport::Udp { token, .. },
                ..
            }) => {
                let _ = self.driver.deregister(token);
            }
            #[cfg(feature = "tls")]
            Some(Attempt {
                transport: Transport::Tls { id },
                upstream,
                ..
            }) => {
                let slot = &mut self.dot[upstream];
                slot.ids.remove(&id);
                slot.queued.retain(|&q| q != id);
                if slot.ids.is_empty() {
                    if let Some(c) = slot.conn.as_mut() {
                        c.idle_since = Instant::now();
                    }
                }
            }
            _ => {}
        }
    }

    fn start_tcp(&mut self, i: usize) {
        let generation = self.next_generation();
        let timeout = self.shared.config.timeout;
        let old = match self.flights[i].as_mut().and_then(|f| {
            let deadline = f.deadline;
            f.attempt.as_mut().map(|a| (a, deadline))
        }) {
            Some((a, deadline)) => {
                let old = std::mem::replace(&mut a.transport, Transport::Tcp);
                a.generation = generation;
                a.expires = (Instant::now() + timeout).min(deadline);
                old
            }
            None => return,
        };
        if let Transport::Udp { token, .. } = old {
            let _ = self.driver.deregister(token);
        }
        self.shared.counters.tcp.fetch_add(1, Ordering::Relaxed);
        if self.tcp_active < self.shared.config.tcp_connections {
            self.spawn_tcp(i);
        } else {
            self.tcp_queue.push_back((i, generation));
        }
    }

    fn spawn_tcp(&mut self, i: usize) {
        let Some(a) = self.flights[i].as_ref().and_then(|f| f.attempt.as_ref()) else {
            return;
        };
        let addr = self.shared.config.upstreams[a.upstream].addr();
        let bytes = a.exchange.tcp_bytes();
        let deadline = a.expires;
        let generation = a.generation;
        let tx = self.tcp_tx.clone();
        let waker = self.shared.waker.clone();
        self.tcp_active += 1;
        let spawned = std::thread::Builder::new()
            .name("dns-net-tcp".into())
            .spawn(move || {
                let result = tcp_exchange(addr, &bytes, deadline);
                let _ = tx.send(TcpDone {
                    flight: i,
                    generation,
                    result,
                });
                waker.wake();
            });
        if let Err(e) = spawned {
            self.tcp_active -= 1;
            self.fail(i, Error::Io(e.kind()));
        }
    }

    fn expire(&mut self, now: Instant) {
        for i in 0..self.flights.len() {
            let late = self.flights[i]
                .as_ref()
                .and_then(|f| f.attempt.as_ref())
                .is_some_and(|a| a.expires <= now);
            if late {
                self.shared
                    .counters
                    .timeouts
                    .fetch_add(1, Ordering::Relaxed);
                self.fail(i, Error::Timeout);
            }
        }
        #[cfg(feature = "tls")]
        {
            let idle = self.shared.config.tls_idle;
            for u in 0..self.dot.len() {
                let slot = &mut self.dot[u];
                let quiet = slot.ids.is_empty()
                    && slot
                        .conn
                        .as_ref()
                        .is_some_and(|c| c.idle_since + idle <= now);
                if quiet {
                    if let Some(mut c) = slot.conn.take() {
                        c.close();
                        let _ = self.driver.deregister(c.token);
                    }
                }
            }
        }
    }

    fn finish(&mut self, i: usize, result: Result<crate::exchange::Answer, Error>) {
        self.close(i);
        let Some(f) = self.flights[i].take() else {
            return;
        };
        self.free.push(i);
        self.index
            .remove(&(f.question.name.clone(), f.question.qtype));
        let result = result.map(|answer| {
            let entry = Arc::new(Entry {
                status: answer.status,
                records: answer.records,
                chain: answer.chain,
                authentic: answer.authentic,
            });
            let expires = lock(&self.shared.cache).insert(
                &f.question.name,
                f.question.qtype,
                Arc::clone(&entry),
                answer.ttl,
                Instant::now(),
            );
            Lookup {
                name: f.question.name.clone(),
                rtype: f.question.qtype,
                entry,
                expires,
            }
        });
        self.deliver(f.waiters, &result);
    }

    fn deliver(&self, waiters: Vec<Done>, result: &Result<Lookup, Error>) {
        for done in waiters {
            self.shared.outstanding.fetch_sub(1, Ordering::AcqRel);
            let r = result.clone();
            // A panicking callback must not take the resolver down with it.
            let _ = catch_unwind(AssertUnwindSafe(move || done(r)));
        }
    }

    fn shutdown(&mut self) {
        for i in 0..self.flights.len() {
            if self.flights[i].is_some() {
                self.finish(i, Err(Error::Stopped));
            }
        }
        #[cfg(feature = "tls")]
        for slot in &mut self.dot {
            if let Some(mut c) = slot.conn.take() {
                c.close();
                let _ = self.driver.deregister(c.token);
            }
        }
        let mut jobs: Vec<Job> = self.waiting.drain(..).collect();
        jobs.extend(lock(&self.shared.queue).drain(..));
        let waiters = jobs.into_iter().map(|j| j.done).collect();
        self.deliver(waiters, &Err(Error::Stopped));
    }
}

/// What a query is padded to on a TLS connection (RFC 8467 section 4.1).
#[cfg(feature = "tls")]
const QUERY_BLOCK: usize = 128;

#[cfg(feature = "tls")]
impl Engine {
    /// Sends attempt `i` on the upstream's TLS connection, or queues it for a
    /// connection being opened (and opens one when none is).
    fn send_tls(&mut self, i: usize, upstream: usize, now: Instant) -> Result<(), Error> {
        let config = &self.shared.config;
        let (timeout, handshake, payload, case) = (
            config.timeout,
            config.tls_handshake,
            config.payload,
            config.case_randomization,
        );
        let (question, deadline, edns) = {
            let f = self.flights[i].as_ref().ok_or(Error::Stopped)?;
            (
                Question {
                    name: f.current.clone(),
                    qtype: f.question.qtype,
                    qclass: Class::IN,
                },
                f.deadline,
                f.edns,
            )
        };
        // Ids are unique among the queries on one connection: they are how
        // replies, which may come in any order, find their query.
        let id = loop {
            let id = self.random.u16().map_err(|_| Error::Random)?;
            if !self.dot[upstream].ids.contains_key(&id) {
                break id;
            }
        };
        let mut bits = [0u8; 32];
        let need = if case {
            question.name.letter_count().div_ceil(8).min(32)
        } else {
            0
        };
        self.random
            .fill(&mut bits[..need])
            .map_err(|_| Error::Random)?;
        let exchange = Exchange::padded(
            &question,
            id,
            &bits[..need],
            payload.filter(|_| edns),
            QUERY_BLOCK,
        )
        .map_err(|_| Error::Bogus)?;
        let generation = self.next_generation();
        let slot = &mut self.dot[upstream];
        let ready = slot.conn.is_some();
        if let Some(conn) = slot.conn.as_mut() {
            if conn.send(&exchange.tcp_bytes()).is_err() {
                self.break_conn(upstream, Error::Io(io::ErrorKind::ConnectionReset));
                return Err(Error::Io(io::ErrorKind::ConnectionReset));
            }
        } else {
            slot.queued.push(id);
        }
        let slot = &mut self.dot[upstream];
        slot.ids.insert(id, (i, generation));
        let connect = !ready && !slot.connecting;
        self.shared.counters.queries.fetch_add(1, Ordering::Relaxed);
        let extra = if ready { Duration::ZERO } else { handshake };
        if let Some(f) = self.flights[i].as_mut() {
            f.attempt = Some(Attempt {
                exchange,
                upstream,
                generation,
                expires: (now + timeout + extra).min(deadline),
                transport: Transport::Tls { id },
            });
        }
        if connect {
            self.connect_tls(upstream);
        }
        Ok(())
    }

    /// Opens a connection to `upstream` on a helper thread.
    fn connect_tls(&mut self, upstream: usize) {
        let up = &self.shared.config.upstreams[upstream];
        let (Some(client), Some(target)) = (self.tls.clone(), up.tls_target()) else {
            self.break_conn(upstream, Error::Tls);
            return;
        };
        let addr = up.addr();
        let deadline = Instant::now() + self.shared.config.tls_handshake;
        let tx = self.dot_tx.clone();
        let waker = self.shared.waker.clone();
        self.dot[upstream].connecting = true;
        let spawned = std::thread::Builder::new()
            .name("dns-net-tls".into())
            .spawn(move || {
                let r = crate::dot::connect(&client, addr, &target, deadline);
                let _ = tx.send((upstream, r));
                waker.wake();
            });
        if let Err(e) = spawned {
            self.dot[upstream].connecting = false;
            self.break_conn(upstream, Error::Io(e.kind()));
        }
    }

    /// A connect finished: register the socket and send what waited, or
    /// fail every query that waited for it.
    fn on_tls_ready(
        &mut self,
        upstream: usize,
        result: Result<(std::net::TcpStream, crate::dot::Session), Error>,
    ) {
        self.dot[upstream].connecting = false;
        let (stream, session) = match result {
            Ok(ok) => ok,
            Err(e) => {
                self.failures[upstream] = self.failures[upstream].saturating_add(1);
                self.break_conn(upstream, e);
                return;
            }
        };
        if stream.set_nonblocking(true).is_err() {
            self.break_conn(upstream, Error::Io(io::ErrorKind::Other));
            return;
        }
        let generation = self.next_generation();
        let token = Token((u64::from(generation) << 32) | upstream as u64);
        let mut conn = crate::dot::Conn::new(stream, session, token);
        let shared: SharedSocket = conn.stream.clone();
        let registered = self.driver.register(shared, token).is_ok();
        let receiving = registered
            && self.pool.take(SizeClass::MEDIUM).is_some_and(|buffer| {
                self.driver
                    .submit(Operation::Receive { token, buffer })
                    .is_ok()
            });
        if !receiving {
            if registered {
                let _ = self.driver.deregister(token);
            }
            self.break_conn(upstream, Error::Io(io::ErrorKind::Other));
            return;
        }
        self.shared.counters.tls.fetch_add(1, Ordering::Relaxed);
        // Send what waited, in order.
        let queued = std::mem::take(&mut self.dot[upstream].queued);
        for id in queued {
            let Some(&(i, generation)) = self.dot[upstream].ids.get(&id) else {
                continue;
            };
            let framed = self.flights[i]
                .as_ref()
                .and_then(|f| f.attempt.as_ref())
                .filter(|a| a.generation == generation)
                .map(|a| a.exchange.tcp_bytes());
            if let Some(framed) = framed {
                if conn.send(&framed).is_err() {
                    self.dot[upstream].conn = Some(conn);
                    self.break_conn(upstream, Error::Io(io::ErrorKind::ConnectionReset));
                    return;
                }
            }
        }
        self.dot[upstream].conn = Some(conn);
    }

    fn on_tls_completion(&mut self, upstream: usize, c: Completion) {
        let current = self.dot[upstream]
            .conn
            .as_ref()
            .is_some_and(|conn| conn.token == c.token);
        if !current || c.kind != OperationKind::Receive {
            return;
        }
        let (Ok(n), Some(mut buffer)) = (c.result, c.buffer) else {
            self.break_conn(upstream, Error::Io(io::ErrorKind::ConnectionReset));
            return;
        };
        if n == 0 {
            // The server closed the connection (an idle timeout of its own,
            // RFC 7766 section 6.2.3): queries in flight move on.
            self.break_conn(upstream, Error::Io(io::ErrorKind::ConnectionReset));
            return;
        }
        let absorbed = match self.dot[upstream].conn.as_mut() {
            Some(conn) => conn.absorb(buffer.as_slice()),
            None => return,
        };
        let (replies, closed) = match absorbed {
            Ok(r) => r,
            Err(_) => {
                self.break_conn(upstream, Error::Tls);
                return;
            }
        };
        for reply in replies {
            self.dispatch_tls(upstream, &reply);
        }
        if closed {
            self.break_conn(upstream, Error::Io(io::ErrorKind::ConnectionReset));
            return;
        }
        let Some(token) = self.dot[upstream].conn.as_ref().map(|c| c.token) else {
            return;
        };
        buffer.clear();
        if self
            .driver
            .submit(Operation::Receive { token, buffer })
            .is_err()
        {
            self.break_conn(upstream, Error::Io(io::ErrorKind::Other));
        }
    }

    /// A whole reply from a TLS connection, to the query with its id.
    fn dispatch_tls(&mut self, upstream: usize, reply: &[u8]) {
        let id = u16::from_be_bytes([reply[0], reply[1]]);
        let Some(&(i, generation)) = self.dot[upstream].ids.get(&id) else {
            // An id with no query: one that timed out, or a confused server.
            self.shared.counters.ignored.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let current = self.flights[i]
            .as_ref()
            .and_then(|f| f.attempt.as_ref())
            .is_some_and(|a| a.generation == generation);
        if current && matches!(self.on_reply(i, reply, true), Verdict::Keep) {
            // On a connection only this query has the id: a reply that does
            // not match it is the server's error, not a forgery to wait out.
            self.fail(i, Error::Bogus);
        }
    }

    /// Drops the upstream's connection and fails every query on it, each of
    /// which moves to its next attempt.
    fn break_conn(&mut self, upstream: usize, e: Error) {
        if let Some(conn) = self.dot[upstream].conn.take() {
            let _ = self.driver.deregister(conn.token);
        }
        // Taken out before any query fails: a failed query's next attempt
        // may land on this same upstream, and must not be swept away with
        // the old ones.
        self.dot[upstream].queued.clear();
        let on = std::mem::take(&mut self.dot[upstream].ids);
        for (_, (i, generation)) in on {
            let current = self.flights[i]
                .as_ref()
                .and_then(|f| f.attempt.as_ref())
                .is_some_and(|a| a.generation == generation);
            if current {
                self.fail(i, e.clone());
            }
        }
    }
}

/// Binds `addr` through net-io (exclusively on Windows) and returns a
/// standard socket for the same binding, which the driver registers.
fn bind_exclusive(addr: SocketAddr) -> Result<UdpSocket, Error> {
    let bound = net_io::UdpSocket::bind(addr).map_err(|e| match e {
        NetError::AddrInUse { .. } => Error::Io(io::ErrorKind::AddrInUse),
        NetError::PermissionDenied { .. } => Error::Io(io::ErrorKind::PermissionDenied),
        other => net_error(other),
    })?;
    #[cfg(unix)]
    let owned = std::os::fd::AsFd::as_fd(&bound).try_clone_to_owned();
    #[cfg(windows)]
    let owned = std::os::windows::io::AsSocket::as_socket(&bound).try_clone_to_owned();
    // The clone refers to the same socket; net-io's handle closes when
    // `bound` drops at the end of this function.
    owned.map(UdpSocket::from).map_err(|e| Error::Io(e.kind()))
}

/// One query over TCP, within `deadline`.
fn tcp_exchange(addr: SocketAddr, query: &[u8], deadline: Instant) -> Result<Vec<u8>, Error> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Error::Timeout);
    }
    let mut conn = TcpConnection::connect_with(addr, ConnectOptions::new().timeout(left))
        .map_err(net_error)?;
    conn.set_exchange_deadline(Some(deadline));
    conn.set_phase(Phase::Sending);
    conn.send_all(query).map_err(net_error)?;
    conn.set_phase(Phase::Receiving);
    let mut len = [0u8; 2];
    conn.recv_exact(&mut len).map_err(net_error)?;
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
    conn.recv_exact(&mut reply).map_err(net_error)?;
    let _ = conn.close();
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_at_the_end_are_ambiguous() {
        for host in [
            "127.1",
            "0x7f000001",
            "a.0x",
            "a.0X1f",
            "1.2.3.4.5",
            "2130706433",
        ] {
            assert_eq!(
                plan_ip(host, IpOrder::Ipv4First).err(),
                Some(Error::AmbiguousHost),
                "{host}"
            );
        }
        for host in ["a.b1", "1.a", "a.0xg", "x0.example"] {
            assert!(plan_ip(host, IpOrder::Ipv4First).is_ok(), "{host}");
        }
    }

    #[test]
    fn literals_and_bad_hosts() {
        let (_, plan) = plan_ip("[2001:db8::1]", IpOrder::Ipv4First).unwrap();
        assert!(matches!(plan, IpPlan::Literal(IpAddr::V6(_))));
        let (_, plan) = plan_ip("192.0.2.1", IpOrder::Ipv4First).unwrap();
        assert!(matches!(plan, IpPlan::Literal(IpAddr::V4(_))));
        assert_eq!(
            plan_ip("a b", IpOrder::Ipv4First).err(),
            Some(Error::Name(NameError::NotHostname))
        );
        assert!(plan_ip("fe80::1%eth0", IpOrder::Ipv4First).is_err());
    }

    #[test]
    fn only_tls_or_loopback_paths_carry_the_ad_bit() {
        let plain = |s: &str| crate::Upstream::new(s.parse().unwrap());
        assert!(path_is_trusted(&plain("127.0.0.1:53")));
        assert!(path_is_trusted(&plain("[::1]:53")));
        assert!(!path_is_trusted(&plain("192.0.2.53:53")));
        assert!(!path_is_trusted(&plain("[2001:db8::53]:53")));
        #[cfg(feature = "tls")]
        assert!(path_is_trusted(
            &crate::Upstream::tls("192.0.2.53:853".parse().unwrap(), "dns.example").unwrap()
        ));
    }

    #[test]
    fn local_names() {
        let q = |s: &str, t| Question::new(Name::parse(s).unwrap(), t);
        let e = local_answer(&q("LocalHost", RecordType::A)).unwrap();
        assert_eq!(e.records[0].data, RData::A(Ipv4Addr::LOCALHOST));
        let e = local_answer(&q("app.localhost", RecordType::AAAA)).unwrap();
        assert_eq!(e.records[0].data, RData::Aaaa(Ipv6Addr::LOCALHOST));
        assert_eq!(
            local_answer(&q("localhost", RecordType::MX))
                .unwrap()
                .status,
            Status::NoData
        );
        assert_eq!(
            local_answer(&q("x.onion", RecordType::A)).unwrap().status,
            Status::NxDomain
        );
        assert_eq!(
            local_answer(&q("x.invalid", RecordType::A)).unwrap().status,
            Status::NxDomain
        );
        assert!(local_answer(&q("localhost.example", RecordType::A)).is_none());
    }
}
