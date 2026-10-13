# dns-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Scheduled later** in the stack build order (`_strategy/WEB-STACK-DELIVERABLES.md`). Work starts when its trigger in PLAN.md is reached.
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
- [ ] Codec, resolver, and cache APIs.

## v0.3.0 - Codec and resolver
- [ ] Message codec with budgets; UDP and TCP resolver; cache; poisoning defences.

## v0.4.0 - Encrypted transports and DNSSEC awareness
- [ ] DNS over TLS; AD-bit reporting.

## v1.0.0 - Stable
