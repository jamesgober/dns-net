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
        <strong>dns-net</strong> turns names into addresses without the blocking resolver of the operating system. The message codec is sans-IO and strict; the resolver adds caching, retries, and transport over net-io.
    </p>
    <p>
        It is planned for later: the standard library covers lookups until the stack needs non-blocking resolution, its own cache, or record types beyond addresses (MX for smtp-net, TXT for DKIM and domain verification).
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>.
    </p>
    <blockquote>
        <strong>Status: scaffold (<code>0.1.0</code>).</strong> No functional code yet. The design is written down in <a href="./dev/PLAN.md"><code>dev/PLAN.md</code></a> and the schedule in <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>; the public API is locked in <code>0.2.0</code>.
    </blockquote>
</div>

<hr>
<br>

## Scope

Message encoding and decoding with name compression and budgets, A, AAAA, CNAME, MX, TXT, SRV, and NS records, a TTL-respecting cache, UDP with TCP fallback, retries and timeouts, and DNSSEC awareness. A DNS server is out of scope.

See [`dev/PLAN.md`](./dev/PLAN.md) for the full scope, what is deliberately left to other crates, and the decision log.

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> &mdash; <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> &mdash; <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
