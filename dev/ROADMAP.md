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

## v0.3.0 - Encrypted transports and DNSSEC awareness
- [ ] DNS over TLS through tls-net.
- [ ] The AD bit from a validating upstream reported on each lookup.
- [ ] The answer-agreement experiment of PLAN 5.1, measured.
- [ ] Windows upstreams from a net-io adapter API instead of `reg.exe`, if net-io gains one (PLAN D-015).

## v0.4.0 - DNS over HTTPS
- [ ] DNS over HTTPS (RFC 8484) on http-net.

## v1.0.0 - Stable
- [ ] The full audit in `DIRECTIVES.md` section 3, after proxy-net or smtp-net has used the API end to end.
