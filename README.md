<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>dns-net</b>
    <br>
    <sub><sup>DNS RESOLVER</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/dns-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/dns-net"></a>
    <a href="https://crates.io/crates/dns-net"><img alt="Downloads" src="https://img.shields.io/crates/d/dns-net?color=%230099ff"></a>
    <a href="https://docs.rs/dns-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/dns-net"></a>
    <a href="https://github.com/jamesgober/dns-net/actions"><img alt="CI" src="https://github.com/jamesgober/dns-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>dns-net</strong> is a DNS client for Rust: a strict, sans-IO message codec, and a caching stub resolver on net-io's reactor driver that never blocks a server worker.
    </p>
    <p>
        Every query goes out on a fresh socket with a random source port, a random id, and the name in random case, and a reply must repeat all three. Only the records that answer the question are used or cached. An address policy runs on every address a lookup returns, so a proxy or a webhook sender can refuse loopback, private, and metadata addresses at resolve time.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>. No third-party dependencies: net-io and mod-rand with the <code>resolver</code> feature (on by default), nothing at all without it.
    </p>
    <blockquote>
        <strong>Status: <code>0.3.0</code>.</strong> The codec and the resolver on Linux, macOS, and Windows, with DNS over TLS behind the <code>tls</code> feature. DNS over HTTPS comes next (<a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>).
    </blockquote>
</div>

<hr>
<br>

## Look up addresses

```rust
use dns_net::{PublicOnly, Resolver, ResolverConfig};

let resolver = Resolver::new(ResolverConfig::system()?)?;
let addrs = resolver.lookup_ip("example.com")?;

// For a URL someone else gave you: loopback, private, link-local and the
// other non-public addresses are refused.
let webhook = resolver.lookup_ip_with("hooks.example.net", &PublicOnly::new())?;
```

## Other records

```rust
use dns_net::{Name, RData, RecordType, Resolver, ResolverConfig};

let resolver = Resolver::new(ResolverConfig::system()?)?;
let mx = resolver.lookup(&Name::parse("example.com")?, RecordType::MX)?;
for record in mx.records() {
    if let RData::Mx { preference, exchange } = &record.data {
        println!("{preference} {exchange}");
    }
}
```

## From a net-io session

`Resolver::park` and `Resolver::park_ip` return a ticket and post to the worker's completion queue when the answer arrives; the session returns `Step::Park` and reads the ticket in `on_wake`. A cached answer is ready at once and nothing parks. See the [`Resolver::park`](https://docs.rs/dns-net/latest/dns_net/struct.Resolver.html#method.park) example.

## Over TLS

With the `tls` feature, upstreams can be reached over TLS only (RFC 7858), checked by certificate name or by a pinned key. Queries share one connection per upstream and are padded so their length gives nothing away; nothing ever falls back to plaintext.

```rust
use dns_net::{Resolver, ResolverConfig, Upstream};

let config = ResolverConfig::new()
    .upstream(Upstream::tls("9.9.9.9:853".parse()?, "dns.quad9.net")?)
    .upstream(Upstream::tls("149.112.112.112:853".parse()?, "dns.quad9.net")?);
let resolver = Resolver::new(config)?;
let lookup = resolver.lookup(&"example.com".parse()?, dns_net::RecordType::A)?;
// The upstream validated it with DNSSEC, over a path nobody could alter.
let validated = lookup.authenticated();
```

## The codec alone

```rust
use dns_net::{Message, Name, Question, RecordType};

let query = Message::query(7, Question::new(Name::parse("example.com")?, RecordType::TXT));
let bytes = query.encode()?;
assert_eq!(Message::decode(&bytes)?, query);
```

With `default-features = false` the crate is the codec with no dependencies.

## Scope

Message encoding and decoding with name compression and budgets; A, AAAA, CNAME, NS, PTR, SOA, MX, TXT, SRV, and CAA records; a TTL-respecting cache with negative caching and a byte budget; UDP with TCP fallback, retries, timeouts, and failover; DNS over TLS; the AD bit from a validating upstream on a trusted path; upstreams from `/etc/resolv.conf` or the Windows adapter settings. DNS over HTTPS comes later. A DNS server is out of scope.

The design, the threats and what each defence costs, and the decision log are in [`dev/PLAN.md`](./dev/PLAN.md); the full API is in [`docs/API.md`](./docs/API.md).

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b>: <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
