# dns-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Resolver (DONE, 2026-11-20; tagged on GitHub, the first crates.io publish waits on James)

The former 0.2 (design lock) and 0.3 (codec and resolver) in one release (PLAN D-002).

- [x] Sans-IO codec: header, question, records, name compression with loop and length budgets, EDNS(0).
- [x] Records: A, AAAA, CNAME, NS, PTR, SOA, MX, TXT, SRV, CAA; other types as bytes.
- [x] Resolver on net-io's reactor driver: upstreams from resolv.conf, the Windows registry, or given; UDP with TCP fallback on truncation; retries, timeouts, failover; blocking, callback, and parked-session entry points.
- [x] Cache: positive and negative answers, TTL caps, byte budget.
- [x] Poisoning defences: random ids and source ports, case randomization, connected sockets, answers checked against the question, coalescing.
- [x] Address policy hook (`AllowAll`, `PublicOnly`) for SSRF and DNS rebinding.
- [x] An attack test for every threat in PLAN section 5; fuzz targets for the codec, the reply checks, names, and the configuration readers.
- [x] Windows: net-io 0.8.2 registers UDP sockets with its IOCP driver (PLAN 6.1, D-019); every test passes there.

## v0.3.0 - DNS over TLS and the AD bit (DONE, 2026-11-20; tagged on GitHub)
- [x] DNS over TLS through tls-net (feature `tls`): strict and pinned profiles, one pipelined connection per upstream, padding, idle close, no plaintext fallback (PLAN 4.5, D-021 to D-025).
- [x] The AD bit reported on each lookup, from trusted paths only (PLAN 4.6, D-026).
- [x] Tests for every TLS path (names, IP identities, pins, untrusted CAs, a server that does not speak TLS, out-of-order replies, idle close, a server that closes, truncation); a fuzz target for the reply framing; transport costs measured.
- Moved to 0.4.0: the answer-agreement experiment of PLAN 5.1. It needs measurements against public resolvers from more than one network, which neither CI nor the development machine gives; it changes no API, so it does not block 0.3.
- Moved to 0.4.0: Windows upstreams from a net-io adapter API instead of `reg.exe` (PLAN D-015). net-io has no such API yet; this waits on a net-io release.

## v0.4.0 - DNS over HTTPS
- [ ] DNS over HTTPS (RFC 8484) on http-net.
- [ ] The answer-agreement experiment of PLAN 5.1, measured.
- [ ] Windows upstreams from a net-io adapter API, once net-io has one.

## v1.0.0 - Stable
- [ ] The full audit in `DIRECTIVES.md` section 3, after proxy-net or smtp-net has used the API end to end.
