# dns-net - Project Plan

> The design, strategy, and decision record for `dns-net`. A living document: every design decision, idea, or open question about dns-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** `0.2.0` (2026-11-20, tagged on GitHub): the codec, the resolver, the cache, the poisoning defences, and the address policy. Next: `0.3.0`, DNS over TLS and the AD bit.

---

## 1. Purpose

A DNS resolver that does not block on the operating system's resolver, keeps its own cache, resolves record types beyond addresses, and lets the caller refuse addresses it must not connect to.

## 2. Why now

| Trigger | Needs |
|---|---|
| the reactor driver (net-io 0.5) | lookups that do not block a worker |
| proxy-net upstreams and webhook senders | a resolve-time check against private and loopback addresses (SSRF, DNS rebinding) |
| smtp-net delivering directly instead of through a relay | MX records |
| DKIM and domain verification checks | TXT records |
| service discovery in a cluster | SRV records |

## 3. Scope

- Sans-IO message codec (RFC 1035 and successors): header, questions, answers, name compression with loop and length budgets, EDNS(0).
- Records: A, AAAA, CNAME, MX, TXT, SRV, NS, SOA, CAA, PTR; any other type kept as bytes (RFC 3597).
- Resolver: upstreams from the OS configuration or given, UDP with TCP fallback on truncation, retries and timeouts, a TTL-respecting cache with negative caching and a size budget, on net-io's reactor driver.
- A resolve-time address policy: the hook that refuses private, loopback, and other non-public addresses.
- DNSSEC awareness: report the AD bit from a validating upstream; full local validation is a later decision.
- Encrypted transports (DNS over TLS through tls-net, DNS over HTTPS) as later options.
- Out of scope: a DNS server, search lists, the hosts file (see D-011).

## 4. Design

### 4.1 Layers

| Layer | Module | Does I/O | Dependencies |
|---|---|---|---|
| names | `name` | no | none |
| messages and records | `message`, `rdata`, `types` | no | none |
| one query and its reply | `exchange` | no | none |
| cache | `cache` | no | none (feature `resolver`) |
| address policy | `policy` | no | none (feature `resolver`) |
| system configuration | `config` | reads resolv.conf, runs `reg.exe` once | none |
| resolver | `resolver` | sockets, one thread | net-io, mod-rand |

Without the `resolver` feature the crate is the codec alone, with no dependency at all.

### 4.2 The resolver's thread

One thread per resolver owns a net-io reactor driver (epoll, kqueue, or IOCP). Each attempt is a fresh UDP socket bound to a random port, connected to the upstream, registered with the driver. The thread waits for completions, replies from TCP helper threads, new lookups, and the earliest attempt deadline, all through the driver's wait and waker. A truncated reply is fetched again over TCP on a short-lived thread (8 at once by default); TCP is rare enough that a thread costs less than a second I/O model.

Callers reach it three ways: blocking calls (`lookup`, `lookup_ip`), callbacks (`submit`, `submit_ip`), and tickets for a session parked on a net-io worker (`park`, `park_ip`), which post to the worker's completion queue when the answer arrives. A cache hit never touches the thread: the caller reads the cache under its lock and returns.

### 4.3 What a reply must do to be used

1. Arrive on the attempt's socket, which is connected to the upstream: the kernel drops datagrams from any other address and port.
2. Repeat the 16-bit random id (compared before anything is decoded).
3. Decode under the codec's budgets.
4. Be a response to a standard query.
5. Repeat the question exactly as sent, including the random case of every letter.
6. Contain no contradiction: two CNAMEs for one name, a CNAME and other data at one name, a CNAME loop, a chain over 8, NXDOMAIN with records for the name.

Only the records on the chain from the question's name to its answer are used. Records about other names, the additional section, and the authority section (except the SOA that gives a negative answer its TTL, and only when the name is inside that SOA's zone) are dropped. A reply that fails a step is dropped and the attempt keeps waiting, so a forger cannot make a lookup fail early by sending junk.

### 4.4 Costs

Measured with `benches/codec.rs` on Linux (WSL 2, Rust 1.99, release build) at a load average of about 10 from unrelated work, so these are upper bounds:

| Path | Cost |
|---|---|
| build a query (random id and case, EDNS) | 68 ns |
| decode a reply (CNAME and two A records, 103 bytes) | 140 ns |
| check a reply against its query | 158 ns |
| read the answer from it | 86 ns |
| refuse a reply with another id | 1 ns |
| a lookup answered from the cache | 189 ns |
| `lookup_ip` answered from the cache (A only, policy applied) | 281 ns |

Per attempt, outside the benchmark: one socket, one `bind` (two or more when a random port is taken), `connect`, register, `send`, and the close; on the order of 10 to 20 microseconds of system calls (an estimate, not measured). The random source is read 256 bytes at a time, one system call per about seven queries. Memory: a 4 KiB receive buffer per attempt in flight, the cache's budget (4 MiB by default), and about 200 bytes per waiting lookup.

## 5. Threats

| Threat | Defence | Cost |
|---|---|---|
| cache poisoning by an off-path forger | random 16-bit ids and random source ports (1024 to 65535, about 16 bits), case randomization (one bit per letter: 13 for `www.example.com`), a socket connected to the upstream, the question echoed exactly; together about 45 bits for a typical name instead of 16 | 68 ns to build, 158 ns to check, a socket per attempt (estimated 10 to 20 microseconds of system calls) |
| poisoning by records riding along with a real answer | only the chain from the question to its answer is used; only whole answers to questions asked are cached | none measurable (part of reading the answer, 86 ns) |
| a local process on the same port catching or forging replies (Windows lets a wildcard bind share a port held on a specific address) | each attempt's port is bound exclusively through net-io (D-020); a port in use is skipped | one more system call per attempt (estimate: under 2 microseconds) |
| birthday attacks (many identical queries in flight) | one query per question in flight; later lookups join it | one hash lookup per new lookup |
| compression loops, oversized messages | pointers must point strictly backwards; at most 127 pointers and 255 bytes per name; record counts checked against the bytes before anything is reserved; at most 4,096 records | a few hundred steps per name at worst; decoding stays linear in the message |
| a flood of forged replies at one attempt | ids are compared before decoding; after 256 non-matching replies in one turn the attempt moves to a fresh socket | 1 ns per forged datagram with a wrong id |
| server-side request forgery and DNS rebinding | the address policy (`PublicOnly`) runs on every address of every lookup, cached or not; IP literals and `localhost` go through it too; host names that end in a number (`127.1`, `0x7f000001`) are refused, since URL parsers read them as IPv4; the caller connects to the addresses returned | a few nanoseconds per address |
| leaking local names to the network | `localhost` and names under it answer loopback locally; `.invalid` and `.onion` names do not exist (RFC 6761, RFC 7686) | none |
| amplification abuse | client only: no socket listens; a query arriving on a client socket is dropped | none |
| resource exhaustion through lookups | at most 256 queries in flight and 4,096 waiting by default (then `Busy`); a deadline per lookup; 8 TCP connections at once; a byte budget on the cache with CLOCK eviction | bounded memory, given above |
| a slow or dead upstream | an attempt timeout (2 s), rounds over the upstreams (2), upstreams that fail are tried last, an ICMP refusal moves on at once | one timeout per dead upstream at most per lookup |

### 5.1 An experiment: answer agreement for sensitive lookups

- **Hypothesis.** For a lookup whose answer decides where secrets go (a webhook target, an MX for outbound mail), asking two upstreams and requiring the same set of addresses raises the bar for poisoning from one path to two independent paths, at the cost of a second query.
- **Method.** An option on a lookup that sends the question to two upstreams at once (different sockets, ids, casings) and accepts only when both answer with the same record set; measure how often two public resolvers disagree for CDN names (which return different addresses by location) and whether comparing by network instead of address keeps the false-alarm rate low.
- **Expected cost.** Twice the queries, latency of the slower upstream (estimate: +5 to 20 ms against public resolvers), and false refusals for CDN names unless compared loosely. Not built in 0.2.

## 6. Prerequisites

net-io (UDP sockets through its reactor driver, TCP connections), mod-rand (the OS random source), tls-net for DNS over TLS later.

### 6.1 Found in net-io 0.8.1 while building 0.2, fixed in net-io 0.8.2

1. **The Windows driver refused UDP sockets.** `Driver::register` checked `SO_ACCEPTCONN` before `SO_TYPE`, and Windows answers `WSAENOPROTOOPT` for a datagram socket. net-io 0.8.2 checks the type first; dns-net requires it (D-019).
2. **The ready driver lost queued datagrams.** After any short read it marked the socket drained, which holds for a stream but not for datagrams. net-io 0.8.2 waits for `WouldBlock` on sockets that are not streams. dns-net still drains its socket itself (D-012).
3. **`reactor` did not build without `proxy`.** Fixed in net-io 0.8.2; dns-net takes `reactor` alone.

## 7. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Scheduled after the first site; started 2026-11-20 | `std` lookups sufficed until the reactor, direct mail, or discovery needed more; on 2026-11-20 proxy-net upstreams and webhook senders needed a resolve-time address check and lookups that do not block a reactor worker |
| D-002 | 2026-11-20 | 0.2.0 is the first working milestone (codec, records, resolver, cache, defences, address policy); the API is designed with the code instead of in a separate design-lock release | the API is small and its shape follows from net-io's park and completion model, which is easier to prove with code and tests than on paper |
| D-003 | 2026-11-20 | Names kept in wire form, compared without case; `eq_exact` for the case check | one representation for decoding, encoding, and comparison; case randomization needs the exact bytes |
| D-004 | 2026-11-20 | Compression pointers must point strictly before the name they end, at most 127 per name | the walk always moves backwards, so loops cannot exist, and the work per name is bounded without a visited set |
| D-005 | 2026-11-20 | Strict decoding: no trailing bytes, rdata exactly filling its length, one question at most, one OPT in the additional section owned by the root, typed rdata only for class IN | input two readers could interpret differently is refused (DIRECTIVES section 2) |
| D-006 | 2026-11-20 | A compressed SRV target is read, never written | RFC 2782 forbids writing it; a pointer has only one meaning, so reading one is not ambiguous (RFC 3597 section 4) |
| D-007 | 2026-11-20 | A TTL with the top bit set reads as 0 | RFC 2181 section 8 |
| D-008 | 2026-11-20 | Only the chain from the question to its answer is used; a CNAME and other data at one name is bogus | the anti-poisoning rule of 4.3; the conflict cannot be true and readers would pick differently |
| D-009 | 2026-11-20 | One thread per resolver on net-io's reactor driver, a socket per attempt; TCP on short-lived threads | multiplexes any number of queries without blocking callers; a fresh socket per attempt gives a fresh random port; TCP is rare |
| D-010 | 2026-11-20 | Random source ports drawn by the resolver from 1024 to 65535 (configurable), 8 tries, then the system's choice | does not depend on the OS randomizing ports; ports in use or reserved (Windows reports access denied) are skipped |
| D-011 | 2026-11-20 | No search list, no hosts file; `localhost`, `.invalid` and `.onion` answered locally | a name means what it says (no surprise lookups of `name.corp.example`); local names never leave the machine |
| D-012 | 2026-11-20 | After each datagram the attempt's socket is read until `WouldBlock` before the next wait; more than 256 non-matching replies in one turn gives the attempt up | correct whatever the driver assumes about short reads (6.1, item 2, fixed in net-io 0.8.2; the drain stays as a second safeguard), and bounds the work a flood can cause. Cost: one `recv` that returns `WouldBlock` per reply |
| D-013 | 2026-11-20 | The address policy is a trait with `AllowAll` (the default) and `PublicOnly` (RFC 6890 special-purpose blocks refused, embedded IPv4 judged, exceptions by network) | proxies and webhook senders need the check at resolve time; a pluggable trait lets a deployment trust its own networks |
| D-014 | 2026-11-20 | Host names ending in a number are refused by `lookup_ip` | WHATWG URL parsers read `127.1` and `0x7f000001` as IPv4; refusing them closes a gap between what a URL means and what DNS is asked |
| D-015 | 2026-11-20 | Windows upstreams read from the registry through `%SystemRoot%\System32\reg.exe`, once, with a 5 s limit | `GetAdaptersAddresses` needs `unsafe`, which this crate forbids; the registry values match the adapters' DNS servers; the `fec0:0:0:ffff::1-3` placeholders are skipped. To move to a net-io API when it has one |
| D-016 | 2026-11-20 | Cache: whole answers keyed by question, CLOCK eviction, byte budget (4 MiB), positive TTL capped at a day, negative at 15 minutes, no entry over an eighth of the budget | bounded memory; one bit per hit instead of reordering; a created name is seen within 15 minutes of a miss |
| D-017 | 2026-11-20 | FORMERR to a query with EDNS: once more without it, same upstream | RFC 6891 section 7; a forged FORMERR needs the same id, port and case as any forgery |
| D-018 | 2026-11-20 | Randomness from mod-rand's OS tier, 256 bytes per read, no fallback | a predictable id or port defeats the defences; a failing source fails the lookup (fail closed) |
| D-019 | 2026-11-20 | net-io 0.8.2 with `reactor` alone | 0.8.2 registers UDP sockets with the IOCP driver, delivers every queued datagram on epoll and kqueue, and builds without `proxy` (6.1) |
| D-020 | 2026-11-20 | Each attempt's port is bound through net-io's UDP bind, which is exclusive on Windows (`SO_EXCLUSIVEADDRUSE`); the driver gets a standard handle to the same socket | Windows lets a wildcard bind take a port another socket holds on a specific address, and datagrams to that address go to the other socket. On a machine with 552 UDP ports bound to 127.0.0.1, 4 of 300 lookups lost their reply that way; worse, a local process on that port receives the replies and could answer in their place. An exclusive bind fails instead, and the next random port is tried. Linux and macOS already refuse such a bind. Cost: one more system call per attempt (the handle clone), estimated under 2 microseconds |
