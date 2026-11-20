<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>dns-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.2.0] - unreleased

The codec and the resolver.

### Added

- `Name`: domain names in wire form, compared without case; text parsing
  with escapes, a strict host-name parser, and decompression that only
  follows pointers backwards (at most 127 per name, 255 bytes).
- `Message`: strict decoding and encoding of the header, the question, the
  three sections, and EDNS(0), with name compression. Typed data for A, AAAA,
  NS, CNAME, PTR, SOA, MX, TXT, SRV, and CAA; other types kept as bytes.
- `Exchange` and `Outcome`: one query without I/O. A reply is used only if it
  repeats the random id and the question exactly as sent, case included, and
  only the records on the chain from the question to its answer are kept.
- `Resolver`: one thread on net-io's reactor driver, a fresh socket on a
  random port per attempt, TCP when a reply is truncated, retries and
  failover, identical questions sharing one query, ports bound exclusively
  so no other local socket can share them, and blocking, callback,
  and parked-session entry points (`park` posts to a net-io worker's
  completion queue).
- A cache of positive and negative answers with TTL caps and a byte budget.
- `AddressPolicy`, `AllowAll`, `PublicOnly`, and `is_public`: the addresses a
  lookup may return, checked on every lookup, against server-side request
  forgery and DNS rebinding.
- `ResolverConfig::system`: upstreams from `/etc/resolv.conf`, or from the
  network adapters' settings on Windows.
- Attack tests for every threat in the plan, fuzz targets for the codec, the
  reply checks, names, and the configuration readers, and a benchmark.

---

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, architecture, threats, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/dns-net/compare/v0.1.0...HEAD
[0.2.0]: https://github.com/jamesgober/dns-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/dns-net/releases/tag/v0.1.0
