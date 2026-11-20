# dns-net - API Reference

> Every public item of `dns-net` `0.2.0`, grouped by layer, with an example for each. The rustdoc on docs.rs has the full signatures.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Features](#features)
- [Names](#names): `Name`, `Labels`, `MAX_NAME`, `MAX_LABEL`, `MAX_POINTERS`, `NameError`
- [Messages](#messages): `Message`, `Header`, `Question`, `Record`, `RData`, `Edns`, `EdnsOption`, `RecordType`, `Class`, `Opcode`, `Rcode`, `UnknownType`, `MAX_MESSAGE`, `MAX_RECORDS`, `DEFAULT_PAYLOAD`, `DecodeError`, `EncodeError`
- [One query](#one-query): `Exchange`, `Mismatch`, `Outcome`, `Answer`, `Status`, `MAX_CHAIN`
- [Resolver](#resolver): `Resolver`, `Lookup`, `Ticket`, `IpOrder`, `ResolverStats`, `CacheStats`, `Error`
- [Configuration](#configuration): `ResolverConfig`, `Upstream`, `ConfigError`
- [Address policy](#address-policy): `AddressPolicy`, `AllowAll`, `PublicOnly`, `is_public`
- [`VERSION`](#version)

## Features

| Feature | Default | Adds |
|---|---|---|
| `resolver` | on | the resolver, cache, configuration readers, and address policy; depends on net-io and mod-rand |

Without `resolver` the crate is the codec: names, messages, and `Exchange`, with no dependencies.

## Names

`Name` is a domain name in wire form. Equality and hashing ignore ASCII case; `eq_exact` compares bytes.

| Item | Purpose |
|---|---|
| `Name::parse(&str)` | text form, with `\.`, `\\` and `\DDD` escapes; printable ASCII only |
| `Name::parse_hostname(&str)` | letters, digits, `-`, `_`, dots only; no escapes |
| `Name::from_wire(&[u8])` | exactly one uncompressed name |
| `Name::root()`, `is_root`, `wire`, `wire_len`, `labels`, `label_count` | inspection |
| `eq_exact`, `is_within(zone)`, `to_lowercase`, `join(suffix)` | comparison and building |
| `with_case(bits)`, `letter_count` | case randomization |

```rust
use dns_net::Name;
let host = Name::parse("API.example.com")?;
assert!(host.is_within(&Name::parse("example.COM")?));
assert_eq!(host.to_lowercase().to_string(), "api.example.com");
# Ok::<(), dns_net::NameError>(())
```

Decompression rules: a pointer must point strictly before the run of labels it ends, at most `MAX_POINTERS` (127) per name, at most `MAX_NAME` (255) bytes once decompressed.

## Messages

`Message { header, question, answers, authority, additional, edns }`, with `Message::decode`, `Message::encode`, `Message::query(id, question)`, and `Message::rcode()` (12 bits with EDNS).

Decoding is strict: no trailing bytes, at most one question, at most `MAX_RECORDS` (4,096) records and no more than the bytes can hold, record data in its type's format filling its length, one OPT record owned by the root in the additional section. A TTL with the top bit set reads as 0. Encoding compresses owner names and the names in NS, CNAME, SOA, PTR, and MX data, never in SRV.

`RData` variants: `A`, `Aaaa`, `Ns`, `Cname`, `Ptr`, `Soa { .. }`, `Mx { preference, exchange }`, `Txt(Vec<Box<[u8]>>)`, `Srv { priority, weight, port, target }`, `Caa { flags, tag, value }`, `Unknown { rtype, data }`. `RData::txt_joined` joins TXT strings as SPF and DKIM read them. Records of any class but `IN` are kept as `Unknown`.

```rust
use std::net::Ipv4Addr;
use dns_net::{Message, Name, Question, RData, Record, RecordType};
let mut reply = Message::query(1, Question::new(Name::parse("example.com")?, RecordType::A));
reply.header.response = true;
reply.answers.push(Record::new(Name::parse("example.com")?, 300, RData::A(Ipv4Addr::new(192, 0, 2, 1))));
let bytes = reply.encode()?;
assert_eq!(Message::decode(&bytes)?.answers[0].to_string(), "example.com. 300 IN A 192.0.2.1");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## One query

`Exchange::new(question, id, case_bits, payload)` builds a query with the given id, case bits, and EDNS payload (or none). `bytes()` is the UDP payload, `tcp_bytes()` has the length prefix. `check(reply)` returns the decoded reply only if it is a response to a standard query with the same id and the question exactly as sent, case included; otherwise a `Mismatch` (`Id`, `Undecodable`, `NotResponse`, `Opcode`, `Question`, `Case`).

`Outcome::read(question, reply)` (or `read_chain` to continue from an earlier CNAME) gives:

| Outcome | Meaning |
|---|---|
| `Answer(Answer)` | `status` (`Found`, `NoData`, `NxDomain`), `records` owned by the end of the chain, `chain` of CNAMEs, `ttl` (`None`: do not cache) |
| `Truncated` | ask again over TCP |
| `Follow { target, chain }` | the chain ends in a CNAME the reply does not answer |
| `ServerError(rcode)` | SERVFAIL, REFUSED, FORMERR, NOTIMP, ... |
| `Bogus` | two CNAMEs for a name, a CNAME and other data, a loop, a chain over `MAX_CHAIN` (8), NXDOMAIN with records |

Records not on the chain, the additional section, and the authority section (except the SOA of a negative answer whose zone holds the name) are never used.

## Resolver

```rust,no_run
use dns_net::{Name, RecordType, Resolver, ResolverConfig};
let resolver = Resolver::new(ResolverConfig::system()?)?;
let addrs = resolver.lookup_ip("example.com")?;
let txt = resolver.lookup(&Name::parse("example.com")?, RecordType::TXT)?;
# let _ = (addrs, txt);
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Method | Returns | Notes |
|---|---|---|
| `Resolver::new(config)` | `Resolver` | starts the resolver's thread; clones share it; the last drop stops it |
| `lookup(&Name, RecordType)` | `Lookup` | blocks; a negative answer is `Ok` with its status |
| `submit(&Name, RecordType, done)` | `()` | `done` runs at once on a cache hit, else on the resolver's thread |
| `park(&Name, RecordType, &Completer, ConnectionId, token)` | `Ticket<Lookup>` | for a net-io session: posts `(connection, token, 0)` when the answer arrives; nothing is posted if the ticket is ready at once |
| `lookup_ip(host)` | `Vec<IpAddr>` | the configured order and policy; IP literals with or without brackets |
| `lookup_ip_with(host, &dyn AddressPolicy)` | `Vec<IpAddr>` | another policy |
| `submit_ip(host, Arc<dyn AddressPolicy>, done)` | `()` | callback form |
| `park_ip(host, policy, &Completer, ConnectionId, token)` | `Ticket<Vec<IpAddr>>` | parked form |
| `stats()` | `ResolverStats` | queries, TCP queries, ignored replies, timeouts, server errors, coalesced, local, and `CacheStats` |
| `clear_cache()` | `()` | |

`Lookup`: `name`, `rtype`, `status`, `records`, `chain`, `canonical_name`, `ttl` (seconds left, 0 when not cached), `ips`.

`Ticket<T>`: `take()` once the result is there, `is_ready()`.

`IpOrder`: `Ipv4First` (default), `Ipv6First`, `Ipv4Only`, `Ipv6Only`.

`localhost` and its subdomains answer loopback; `.invalid` and `.onion` names do not exist; neither reaches an upstream. Host names that end in a number (`127.1`, `0x7f000001`) are refused by the address lookups with `Error::AmbiguousHost`.

`Error`: `Name`, `AmbiguousHost`, `Config`, `Timeout`, `Server(Rcode)`, `Bogus`, `NotFound(Status)`, `Refused`, `Busy`, `Stopped`, `Random`, `Io(ErrorKind)`.

## Configuration

`ResolverConfig::system()` reads `/etc/resolv.conf` (first three `nameserver` lines, `options timeout: attempts:`) or, on Windows, each adapter's DNS servers from the registry. `ResolverConfig::new()` starts empty. Builder methods, with their defaults:

| Method | Default | Range |
|---|---|---|
| `upstream(Upstream)` | none | at least one |
| `timeout` | 2 s per attempt | 50 ms to 30 s |
| `attempts` | 2 rounds over the upstreams | 1 to 5 |
| `deadline` | 10 s per lookup | timeout to 60 s |
| `cache_bytes` | 4 MiB | 0 turns the cache off |
| `max_ttl` | 86,400 s | |
| `max_negative_ttl` | 900 s | |
| `case_randomization` | on | |
| `edns_payload` | `Some(1232)` | 512 to 4,096, or `None` |
| `source_ports(low, high)` | 1024 to 65535 | low at least 1 |
| `max_in_flight` | 256 | 1 to 65,536 |
| `max_waiting` | 4,096 | |
| `tcp_connections` | 8 | 1 to 256 |
| `ip_order` | `Ipv4First` | |
| `policy` | `AllowAll` | any `AddressPolicy` |

## Address policy

`AddressPolicy::allows(&self, host: &Name, addr: IpAddr) -> bool`, implemented for any `Fn(&Name, IpAddr) -> bool + Send + Sync`.

- `AllowAll`: every address.
- `PublicOnly::new().allow(network, prefix)`: only addresses `is_public` accepts, plus the networks allowed. An IPv4-mapped address is judged as IPv4.
- `is_public(addr)`: refuses unspecified, loopback, private (RFC 1918, RFC 4193), shared (100.64/10), link-local, multicast, broadcast, reserved, benchmarking, documentation, discard, the IETF protocol blocks (Teredo included), site-local, and IPv4-compatible addresses; NAT64 (64:ff9b::/96), 6to4, and IPv4-mapped addresses are judged by their IPv4 address; only 2000::/3 is public for IPv6.

```rust
use dns_net::{AddressPolicy, Name, PublicOnly};
let policy = PublicOnly::new().allow("10.8.0.0".parse()?, 16);
let host = Name::parse("svc.internal")?;
assert!(policy.allows(&host, "10.8.3.4".parse()?));
assert!(!policy.allows(&host, "169.254.169.254".parse()?));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## `VERSION`

```rust
println!("dns-net {}", dns_net::VERSION);
```
