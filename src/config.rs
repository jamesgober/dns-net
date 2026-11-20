//! The resolver's configuration: its upstream servers, from the operating
//! system or given, and its timeouts, budgets, and defences.

use std::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use crate::policy::{AddressPolicy, AllowAll};
use crate::resolver::IpOrder;

/// The most upstreams taken from resolv.conf, as the C library does (`MAXNS`).
#[cfg_attr(windows, allow(dead_code))]
const MAX_SYSTEM_UPSTREAMS: usize = 3;
/// The most bytes of resolv.conf or `reg` output read.
const MAX_CONFIG_TEXT: usize = 1 << 20;

/// One upstream server: a recursive resolver reached over UDP (and over TCP
/// when a reply is truncated), or with the `tls` feature over TLS only
/// (RFC 7858).
///
/// ```
/// let u = dns_net::Upstream::new("192.0.2.53:53".parse()?);
/// assert_eq!(u.addr().port(), 53);
/// assert!(!u.is_tls());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Upstream {
    addr: SocketAddr,
    tls: Option<Arc<TlsTarget>>,
}

/// Who a TLS upstream must prove to be.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct TlsTarget {
    /// The name the certificate must carry (and SNI), or an IP literal.
    pub(crate) name: Box<str>,
    /// SHA-256 of acceptable SubjectPublicKeyInfos; empty for a chain check.
    pub(crate) pins: Vec<[u8; 32]>,
}

impl Upstream {
    /// The server at `addr`, over UDP and TCP.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Upstream {
        Upstream { addr, tls: None }
    }

    /// The server at `addr` over TLS, authenticated by `server_name` (a host
    /// name, sent as SNI, or an IP address the certificate must carry)
    /// against the resolver's trust anchors: RFC 8310's strict privacy
    /// profile. Port 853 is DNS over TLS's (RFC 7858).
    ///
    /// ```
    /// # #[cfg(feature = "tls")] {
    /// let quad9 = dns_net::Upstream::tls("9.9.9.9:853".parse()?, "dns.quad9.net")?;
    /// assert!(quad9.is_tls());
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] for a name that is not a host name or an IP address.
    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    pub fn tls(addr: SocketAddr, server_name: &str) -> Result<Upstream, ConfigError> {
        Upstream::tls_with(addr, server_name, Vec::new())
    }

    /// The server at `addr` over TLS, authenticated by the SHA-256 of its
    /// public key (SubjectPublicKeyInfo) matching one of `pins`: RFC 7858's
    /// key-pinned profile, for a server with a certificate no public CA
    /// signed. `server_name` is sent as SNI; the certificate's names are not
    /// checked, its signature over the handshake and its validity are.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] for no pins, or a name that is not a host name.
    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    pub fn tls_pinned(
        addr: SocketAddr,
        server_name: &str,
        pins: &[[u8; 32]],
    ) -> Result<Upstream, ConfigError> {
        if pins.is_empty() {
            return Err(ConfigError::Invalid {
                field: "pins",
                expected: "at least one SHA-256 pin",
            });
        }
        if server_name.parse::<std::net::IpAddr>().is_ok() {
            return Err(ConfigError::Invalid {
                field: "server_name",
                expected: "a host name (a pinned identity sends it as SNI)",
            });
        }
        Upstream::tls_with(addr, server_name, pins.to_vec())
    }

    #[cfg(feature = "tls")]
    fn tls_with(
        addr: SocketAddr,
        server_name: &str,
        pins: Vec<[u8; 32]>,
    ) -> Result<Upstream, ConfigError> {
        let name = server_name.strip_suffix('.').unwrap_or(server_name);
        let valid = name.parse::<std::net::IpAddr>().is_ok()
            || crate::name::Name::parse_hostname(name).is_ok_and(|n| n.label_count() >= 1);
        if !valid {
            return Err(ConfigError::Invalid {
                field: "server_name",
                expected: "a host name or an IP address",
            });
        }
        Ok(Upstream {
            addr,
            tls: Some(Arc::new(TlsTarget {
                name: name.into(),
                pins,
            })),
        })
    }

    /// Its address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Whether it is reached over TLS.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// The name a TLS upstream is checked against.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        self.tls.as_deref().map(|t| &*t.name)
    }

    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn tls_target(&self) -> Option<Arc<TlsTarget>> {
        self.tls.clone()
    }
}

/// Why the configuration could not be built or read.
///
/// ```
/// let e = dns_net::ConfigError::NoUpstreams;
/// assert_eq!(e.to_string(), "no upstream servers are configured");
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// No upstream server was given or found.
    NoUpstreams,
    /// The system's configuration could not be read.
    Read {
        /// What was being read.
        what: &'static str,
        /// The I/O error's kind.
        kind: std::io::ErrorKind,
    },
    /// A value out of range.
    Invalid {
        /// The setting.
        field: &'static str,
        /// What it must be.
        expected: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NoUpstreams => f.write_str("no upstream servers are configured"),
            ConfigError::Read { what, kind } => write!(f, "could not read {what}: {kind}"),
            ConfigError::Invalid { field, expected } => write!(f, "{field} must be {expected}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The resolver's settings. Every default is the safe choice; see each method.
///
/// ```
/// use std::time::Duration;
/// use dns_net::{PublicOnly, ResolverConfig, Upstream};
/// let config = ResolverConfig::new()
///     .upstream(Upstream::new("192.0.2.53:53".parse()?))
///     .timeout(Duration::from_millis(1500))
///     .cache_bytes(16 << 20)
///     .policy(PublicOnly::new());
/// assert_eq!(config.upstreams().len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
#[derive(Clone)]
pub struct ResolverConfig {
    pub(crate) upstreams: Vec<Upstream>,
    pub(crate) timeout: Duration,
    pub(crate) attempts: u8,
    pub(crate) deadline: Duration,
    pub(crate) cache_bytes: usize,
    pub(crate) max_ttl: u32,
    pub(crate) max_negative_ttl: u32,
    pub(crate) case_randomization: bool,
    pub(crate) payload: Option<u16>,
    pub(crate) ports: (u16, u16),
    pub(crate) max_in_flight: usize,
    pub(crate) max_waiting: usize,
    pub(crate) tcp_connections: usize,
    pub(crate) ip_order: IpOrder,
    pub(crate) policy: Arc<dyn AddressPolicy>,
    pub(crate) tls_idle: Duration,
    pub(crate) tls_handshake: Duration,
    #[cfg(feature = "tls")]
    pub(crate) tls_client: Option<tls_net::TlsClient>,
}

impl fmt::Debug for ResolverConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverConfig")
            .field("upstreams", &self.upstreams)
            .field("timeout", &self.timeout)
            .field("attempts", &self.attempts)
            .field("deadline", &self.deadline)
            .field("cache_bytes", &self.cache_bytes)
            .field("max_ttl", &self.max_ttl)
            .field("max_negative_ttl", &self.max_negative_ttl)
            .field("case_randomization", &self.case_randomization)
            .field("payload", &self.payload)
            .field("ports", &self.ports)
            .field("max_in_flight", &self.max_in_flight)
            .field("max_waiting", &self.max_waiting)
            .field("tcp_connections", &self.tcp_connections)
            .field("ip_order", &self.ip_order)
            .field("tls_idle", &self.tls_idle)
            .field("tls_handshake", &self.tls_handshake)
            .finish_non_exhaustive()
    }
}

impl Default for ResolverConfig {
    fn default() -> ResolverConfig {
        ResolverConfig::new()
    }
}

impl ResolverConfig {
    /// No upstreams yet; a 2 s timeout per attempt, 2 rounds over the
    /// upstreams, 10 s per lookup at most; a 4 MiB cache, TTLs capped at a
    /// day (positive) and 15 minutes (negative); case randomization on;
    /// EDNS(0) at 1,232 bytes; source ports from 1024 to 65535; 256 queries
    /// in flight, 4,096 lookups waiting, 8 TCP connections at once;
    /// addresses IPv4 first; every address allowed.
    pub fn new() -> ResolverConfig {
        ResolverConfig {
            upstreams: Vec::new(),
            timeout: Duration::from_secs(2),
            attempts: 2,
            deadline: Duration::from_secs(10),
            cache_bytes: 4 << 20,
            max_ttl: 86_400,
            max_negative_ttl: 900,
            case_randomization: true,
            payload: Some(crate::message::DEFAULT_PAYLOAD),
            ports: (1024, 65535),
            max_in_flight: 256,
            max_waiting: 4096,
            tcp_connections: 8,
            ip_order: IpOrder::Ipv4First,
            policy: Arc::new(AllowAll),
            tls_idle: Duration::from_secs(10),
            tls_handshake: Duration::from_secs(5),
            #[cfg(feature = "tls")]
            tls_client: None,
        }
    }

    /// The operating system's upstream servers, with the defaults of
    /// [`ResolverConfig::new`] for everything else: `/etc/resolv.conf` on
    /// Unix (its first three `nameserver` lines, and `timeout` and
    /// `attempts` from `options`), the DNS servers of the network
    /// adapters on Windows (read from the registry with `reg.exe`, once).
    ///
    /// Search domains are not used: every name is looked up as given.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Read`] when the configuration cannot be read,
    /// [`ConfigError::NoUpstreams`] when it names no server.
    pub fn system() -> Result<ResolverConfig, ConfigError> {
        let mut config = ResolverConfig::new();
        #[cfg(windows)]
        {
            for addr in windows_servers()? {
                config.upstreams.push(Upstream::new(addr));
            }
        }
        #[cfg(not(windows))]
        {
            let text = read_limited("/etc/resolv.conf")?;
            let parsed = parse_resolv_conf(&text);
            config.upstreams = parsed.servers.into_iter().map(Upstream::new).collect();
            if let Some(t) = parsed.timeout {
                config.timeout = Duration::from_secs(u64::from(t));
            }
            if let Some(a) = parsed.attempts {
                config.attempts = a;
            }
        }
        if config.upstreams.is_empty() {
            return Err(ConfigError::NoUpstreams);
        }
        Ok(config)
    }

    /// Adds an upstream; they are tried in order, the ones that have been
    /// failing last.
    pub fn upstream(mut self, upstream: Upstream) -> ResolverConfig {
        self.upstreams.push(upstream);
        self
    }

    /// The upstreams.
    #[must_use]
    pub fn upstreams(&self) -> &[Upstream] {
        &self.upstreams
    }

    /// How long one attempt waits for its reply (2 s; 50 ms to 30 s).
    pub fn timeout(mut self, timeout: Duration) -> ResolverConfig {
        self.timeout = timeout;
        self
    }

    /// Rounds over the upstreams before giving up (2; 1 to 5).
    pub fn attempts(mut self, attempts: u8) -> ResolverConfig {
        self.attempts = attempts;
        self
    }

    /// The most one lookup may take, CNAME follow-ups included (10 s; at
    /// least the timeout, at most 60 s).
    pub fn deadline(mut self, deadline: Duration) -> ResolverConfig {
        self.deadline = deadline;
        self
    }

    /// The cache's budget in bytes (4 MiB; 0 turns the cache off).
    pub fn cache_bytes(mut self, bytes: usize) -> ResolverConfig {
        self.cache_bytes = bytes;
        self
    }

    /// The longest a positive answer is cached, whatever its TTL (1 day).
    pub fn max_ttl(mut self, seconds: u32) -> ResolverConfig {
        self.max_ttl = seconds;
        self
    }

    /// The longest a negative answer is cached (15 minutes; RFC 2308 section
    /// 5 suggests at most a few hours). A name created after a miss is seen
    /// at most this long after.
    pub fn max_negative_ttl(mut self, seconds: u32) -> ResolverConfig {
        self.max_negative_ttl = seconds;
        self
    }

    /// Randomizes the case of each letter of every query's name and requires
    /// the reply to repeat it (on by default; about one bit of entropy per
    /// letter on top of the 16-bit id and the random source port). Turn it
    /// off only for an upstream that does not preserve case.
    pub fn case_randomization(mut self, on: bool) -> ResolverConfig {
        self.case_randomization = on;
        self
    }

    /// The UDP payload advertised with EDNS(0) (1,232; `None` sends no OPT
    /// record; 512 to 4,096). Larger replies come back truncated and are
    /// fetched over TCP.
    pub fn edns_payload(mut self, payload: Option<u16>) -> ResolverConfig {
        self.payload = payload;
        self
    }

    /// The range source ports are drawn from, inclusive (1024 to 65535). A
    /// smaller range gives an off-path attacker fewer ports to guess.
    pub fn source_ports(mut self, low: u16, high: u16) -> ResolverConfig {
        self.ports = (low, high);
        self
    }

    /// Queries sent and not yet answered, at most (256). Lookups past it wait.
    pub fn max_in_flight(mut self, n: usize) -> ResolverConfig {
        self.max_in_flight = n;
        self
    }

    /// Lookups waiting for a slot, at most (4,096); past it a lookup fails
    /// with [`crate::Error::Busy`] at once.
    pub fn max_waiting(mut self, n: usize) -> ResolverConfig {
        self.max_waiting = n;
        self
    }

    /// TCP connections at once, for truncated replies (8; each is a thread
    /// while it lasts).
    pub fn tcp_connections(mut self, n: usize) -> ResolverConfig {
        self.tcp_connections = n;
        self
    }

    /// Which address families [`crate::Resolver::lookup_ip`] asks for and in
    /// what order (IPv4 first).
    pub fn ip_order(mut self, order: IpOrder) -> ResolverConfig {
        self.ip_order = order;
        self
    }

    /// The policy [`crate::Resolver::lookup_ip`] applies (every address
    /// allowed by default; [`crate::PublicOnly`] for outbound connections to
    /// addresses others choose).
    pub fn policy<P: AddressPolicy + 'static>(mut self, policy: P) -> ResolverConfig {
        self.policy = Arc::new(policy);
        self
    }

    /// How long a TLS connection with nothing in flight stays open for the
    /// next query (10 s; 1 s to 5 minutes). RFC 7858 asks clients to reuse
    /// connections; a server may close earlier, and the next query opens a
    /// new one.
    pub fn tls_idle(mut self, idle: Duration) -> ResolverConfig {
        self.tls_idle = idle;
        self
    }

    /// The most a TLS connection may take to connect and finish its
    /// handshake (5 s; 100 ms to 30 s). Queries waiting for it have this on
    /// top of their timeout.
    pub fn tls_handshake_timeout(mut self, timeout: Duration) -> ResolverConfig {
        self.tls_handshake = timeout;
        self
    }

    /// The TLS client for TLS upstreams: its trust anchors, policy, and
    /// resumption store (by default `tls_net::client()`: the Mozilla roots).
    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    pub fn tls_client(mut self, client: tls_net::TlsClient) -> ResolverConfig {
        self.tls_client = Some(client);
        self
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |field, expected| Err(ConfigError::Invalid { field, expected });
        if self.upstreams.is_empty() {
            return Err(ConfigError::NoUpstreams);
        }
        // RFC 8310's strict profile: a resolver that asks over TLS never
        // falls back to plaintext, so TLS and plain upstreams do not mix.
        let tls = self.upstreams.iter().filter(|u| u.is_tls()).count();
        if tls != 0 && tls != self.upstreams.len() {
            return invalid("upstreams", "all over TLS or none");
        }
        if self.tls_idle < Duration::from_secs(1) || self.tls_idle > Duration::from_secs(300) {
            return invalid("tls_idle", "from 1 s to 5 minutes");
        }
        if self.tls_handshake < Duration::from_millis(100)
            || self.tls_handshake > Duration::from_secs(30)
        {
            return invalid("tls_handshake_timeout", "from 100 ms to 30 s");
        }
        if self.timeout < Duration::from_millis(50) || self.timeout > Duration::from_secs(30) {
            return invalid("timeout", "from 50 ms to 30 s");
        }
        if !(1..=5).contains(&self.attempts) {
            return invalid("attempts", "from 1 to 5");
        }
        if self.deadline < self.timeout || self.deadline > Duration::from_secs(60) {
            return invalid("deadline", "at least the timeout and at most 60 s");
        }
        if let Some(p) = self.payload {
            if !(512..=4096).contains(&p) {
                return invalid("edns_payload", "from 512 to 4096");
            }
        }
        if self.ports.0 == 0 || self.ports.0 > self.ports.1 {
            return invalid("source_ports", "a range from 1 up");
        }
        if self.max_in_flight == 0 || self.max_in_flight > 65_536 {
            return invalid("max_in_flight", "from 1 to 65536");
        }
        if self.tcp_connections == 0 || self.tcp_connections > 256 {
            return invalid("tcp_connections", "from 1 to 256");
        }
        Ok(())
    }
}

/// What resolv.conf says, as far as the resolver uses it.
#[cfg_attr(windows, allow(dead_code))]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ResolvConf {
    pub(crate) servers: Vec<SocketAddr>,
    pub(crate) timeout: Option<u32>,
    pub(crate) attempts: Option<u8>,
}

/// Reads resolv.conf (resolv.conf(5)): `nameserver` lines (an IP address,
/// an IPv6 one with a numeric scope as `fe80::1%2`) and `options timeout:n
/// attempts:n`. Anything else is ignored, malformed lines included, as the
/// C library does.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn parse_resolv_conf(text: &str) -> ResolvConf {
    let mut out = ResolvConf::default();
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut words = line.split_ascii_whitespace();
        match words.next() {
            Some("nameserver") => {
                if out.servers.len() >= MAX_SYSTEM_UPSTREAMS {
                    continue;
                }
                if let Some(addr) = words.next().and_then(server_addr) {
                    if !out.servers.contains(&addr) {
                        out.servers.push(addr);
                    }
                }
            }
            Some("options") => {
                for w in words {
                    if let Some(v) = w.strip_prefix("timeout:") {
                        if let Ok(v) = v.parse::<u32>() {
                            out.timeout = Some(v.clamp(1, 30));
                        }
                    } else if let Some(v) = w.strip_prefix("attempts:") {
                        if let Ok(v) = v.parse::<u32>() {
                            out.attempts = Some(v.clamp(1, 5) as u8);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// A server's address on port 53, or `None` for one the resolver cannot use.
fn server_addr(text: &str) -> Option<SocketAddr> {
    let (ip, scope) = match text.split_once('%') {
        Some((ip, scope)) => (ip, Some(scope.parse::<u32>().ok()?)),
        None => (text, None),
    };
    let ip: IpAddr = ip.parse().ok()?;
    if ip.is_unspecified() || is_windows_placeholder(ip) {
        return None;
    }
    Some(match (ip, scope) {
        (IpAddr::V6(v6), Some(s)) => SocketAddr::V6(SocketAddrV6::new(v6, 53, 0, s)),
        (_, Some(_)) => return None,
        (ip, None) => SocketAddr::new(ip, 53),
    })
}

/// `fec0:0:0:ffff::1` to `::3`: the site-local addresses Windows lists for an
/// adapter with no IPv6 DNS server of its own. Nothing answers there.
fn is_windows_placeholder(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[..7] == [0xfec0, 0, 0, 0xffff, 0, 0, 0] && (1..=3).contains(&s[7])
        }
        IpAddr::V4(_) => false,
    }
}

/// Reads the output of `reg query <interfaces key> /s`: for each adapter
/// key, its `NameServer` value (set by hand) or else its `DhcpNameServer`
/// (from DHCP), each a list separated by spaces or commas.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_registry(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut fixed: Vec<SocketAddr> = Vec::new();
    let mut dhcp: Vec<SocketAddr> = Vec::new();
    let flush =
        |out: &mut Vec<SocketAddr>, fixed: &mut Vec<SocketAddr>, dhcp: &mut Vec<SocketAddr>| {
            let chosen = if fixed.is_empty() {
                &mut *dhcp
            } else {
                &mut *fixed
            };
            for a in chosen.drain(..) {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
            fixed.clear();
            dhcp.clear();
        };
    for line in text.lines() {
        if line.starts_with("HKEY_") {
            flush(&mut out, &mut fixed, &mut dhcp);
            continue;
        }
        let mut words = line.split_ascii_whitespace();
        let (Some(name), Some("REG_SZ")) = (words.next(), words.next()) else {
            continue;
        };
        let target = match name {
            "NameServer" => &mut fixed,
            "DhcpNameServer" => &mut dhcp,
            _ => continue,
        };
        for value in words.flat_map(|w| w.split(',')) {
            if let Some(addr) = server_addr(value) {
                target.push(addr);
            }
        }
    }
    flush(&mut out, &mut fixed, &mut dhcp);
    out
}

#[cfg(not(windows))]
fn read_limited(path: &'static str) -> Result<String, ConfigError> {
    use std::io::Read;
    let err = |e: std::io::Error| ConfigError::Read {
        what: path,
        kind: e.kind(),
    };
    let file = std::fs::File::open(path).map_err(err)?;
    let mut text = String::new();
    file.take(MAX_CONFIG_TEXT as u64)
        .read_to_string(&mut text)
        .map_err(err)?;
    Ok(text)
}

/// The DNS servers of the network adapters, IPv4 first.
#[cfg(windows)]
fn windows_servers() -> Result<Vec<SocketAddr>, ConfigError> {
    let mut out = Vec::new();
    for key in [
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces",
    ] {
        for a in parse_registry(&run_reg(key)?) {
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    Ok(out)
}

/// Runs `reg query <key> /s` from the system directory (never from `PATH`),
/// without a console window, for at most 5 s.
#[cfg(windows)]
fn run_reg(key: &str) -> Result<String, ConfigError> {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let err = |kind| ConfigError::Read {
        what: "the adapters' DNS servers (reg.exe)",
        kind,
    };
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let root = std::path::PathBuf::from(root);
    if !root.is_absolute() {
        return Err(err(std::io::ErrorKind::InvalidInput));
    }
    let mut child = Command::new(root.join("System32").join("reg.exe"))
        .args(["query", key, "/s"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| err(e.kind()))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or(err(std::io::ErrorKind::BrokenPipe))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = (&mut stdout)
            .take(MAX_CONFIG_TEXT as u64)
            .read_to_end(&mut bytes);
        bytes
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < Duration::from_secs(5) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err(std::io::ErrorKind::TimedOut));
            }
        }
    }
    let bytes = reader.join().map_err(|_| err(std::io::ErrorKind::Other))?;
    // `reg` writes in the console code page; the values read are ASCII.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn resolv_conf() {
        let text = "# generated\n\
            search corp.example\n\
            nameserver 192.0.2.1\n\
            nameserver   2001:db8::53   # comment\n\
            nameserver 192.0.2.1\n\
            nameserver fe80::1%2\n\
            nameserver fe80::1%eth0\n\
            nameserver 0.0.0.0\n\
            nameserver not-an-ip\n\
            nameserver 192.0.2.9\n\
            options ndots:2 timeout:9 attempts:7 rotate\n\
            ; nameserver 192.0.2.77\n";
        let c = parse_resolv_conf(text);
        assert_eq!(
            c.servers,
            vec![
                sa("192.0.2.1:53"),
                sa("[2001:db8::53]:53"),
                sa("[fe80::1%2]:53")
            ]
        );
        assert_eq!(c.timeout, Some(9));
        assert_eq!(c.attempts, Some(5));
        assert_eq!(
            parse_resolv_conf("options timeout:0"),
            ResolvConf {
                timeout: Some(1),
                ..ResolvConf::default()
            }
        );
        assert_eq!(parse_resolv_conf(""), ResolvConf::default());
    }

    #[test]
    fn registry() {
        let text = "\r\n\
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{a}\r\n\
    EnableDHCP    REG_DWORD    0x1\r\n\
    NameServer    REG_SZ    \r\n\
    DhcpNameServer    REG_SZ    192.168.1.254\r\n\
\r\n\
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{b}\r\n\
    NameServer    REG_SZ    8.8.8.8,8.8.4.4\r\n\
    DhcpNameServer    REG_SZ    10.0.0.1\r\n\
\r\n\
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{c}\r\n\
    DhcpNameServer    REG_SZ    192.168.1.254 fec0:0:0:ffff::1\r\n\
End of search: 4 match(es) found.\r\n";
        assert_eq!(
            parse_registry(text),
            vec![sa("192.168.1.254:53"), sa("8.8.8.8:53"), sa("8.8.4.4:53")]
        );
        assert!(parse_registry("").is_empty());
    }

    #[test]
    fn validation() {
        let up = Upstream::new(sa("192.0.2.1:53"));
        assert_eq!(
            ResolverConfig::new().validate(),
            Err(ConfigError::NoUpstreams)
        );
        assert!(
            ResolverConfig::new()
                .upstream(up.clone())
                .validate()
                .is_ok()
        );
        let c = || ResolverConfig::new().upstream(up.clone());
        let bad = [
            c().timeout(Duration::from_millis(10)),
            c().attempts(0),
            c().deadline(Duration::from_millis(100)),
            c().edns_payload(Some(100)),
            c().source_ports(0, 10),
            c().source_ports(2000, 1000),
            c().max_in_flight(0),
            c().tcp_connections(0),
            c().tls_idle(Duration::from_millis(10)),
            c().tls_handshake_timeout(Duration::from_secs(60)),
        ];
        for c in bad {
            assert!(
                matches!(c.validate(), Err(ConfigError::Invalid { .. })),
                "{c:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn this_machine_has_servers() {
        // Every Windows machine CI runs on has at least one adapter with DNS.
        let c = ResolverConfig::system().unwrap();
        assert!(!c.upstreams().is_empty());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_upstreams() {
        let a = sa("192.0.2.53:853");
        assert!(Upstream::tls(a, "dns.example").is_ok());
        assert!(Upstream::tls(a, "dns.example.").is_ok());
        assert!(Upstream::tls(a, "192.0.2.53").is_ok());
        assert!(Upstream::tls(a, "bad name").is_err());
        assert!(Upstream::tls(a, "").is_err());
        assert!(Upstream::tls_pinned(a, "dns.example", &[]).is_err());
        assert!(Upstream::tls_pinned(a, "192.0.2.53", &[[0; 32]]).is_err());
        let pinned = Upstream::tls_pinned(a, "dns.example", &[[7; 32]]).unwrap();
        assert_eq!(pinned.server_name(), Some("dns.example"));
        // No mixing with plaintext upstreams (RFC 8310 strict profile).
        let mixed = ResolverConfig::new()
            .upstream(pinned.clone())
            .upstream(Upstream::new(sa("192.0.2.1:53")));
        assert!(matches!(
            mixed.validate(),
            Err(ConfigError::Invalid {
                field: "upstreams",
                ..
            })
        ));
        assert!(ResolverConfig::new().upstream(pinned).validate().is_ok());
    }
}
