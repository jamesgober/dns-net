# dns-net - Project Plan

> The design, strategy, and decision record for `dns-net`. A living document: every design decision, idea, or open question about dns-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** scaffold, `0.1.0`. **Scheduled later** (see `_strategy/WEB-STACK-DELIVERABLES.md`): `std` covers address lookups until the stack needs more.

---

## 1. Purpose

A DNS resolver that does not block on the operating system's resolver, keeps its own cache, and resolves record types beyond addresses.

## 2. Why later, and what triggers it

| Trigger | Needs |
|---|---|
| the reactor driver (net-io 0.5) | lookups that do not block a worker |
| smtp-net delivering directly instead of through a relay | MX records |
| DKIM and domain verification checks | TXT records |
| service discovery in a cluster | SRV records |

## 3. Scope

- Sans-IO message codec (RFC 1035 and successors): header, questions, answers, name compression with loop and length budgets, EDNS(0).
- Records: A, AAAA, CNAME, MX, TXT, SRV, NS, SOA, CAA.
- Resolver: configured upstreams (from the OS configuration or explicit), UDP with TCP fallback on truncation, retries and timeouts, a TTL-respecting cache with negative caching and a size budget.
- DNSSEC awareness: report the AD bit from a validating upstream; full local validation is a later decision.
- Encrypted transports (DNS over TLS through tls-net, DNS over HTTPS) as later options.
- Out of scope: a DNS server.

## 4. Threats

| Threat | Defence |
|---|---|
| cache poisoning | random query ids and source ports, case randomization (0x20), answers checked against the question |
| compression loops, oversized messages | budgets in the codec |
| amplification abuse | client only; never answers queries |

## 5. Prerequisites

net-io (UDP and TCP), tls-net for DNS over TLS.

## 6. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Scheduled after the first site | `std` lookups suffice until the reactor, direct mail, or discovery need more |
