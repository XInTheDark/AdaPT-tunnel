```
# Phase 4 V2 Public-Session Stealth Rewrite Plan

## Purpose

`PLAN.md` is the repository's canonical living implementation plan for current non-trivial work. It should stay forward-looking and track only:

- the current milestone and status
- active/pending implementation chunks
- next tasks in expected execution order
- explicit assumptions and non-goals
- expected latency / bandwidth / CPU impact notes per chunk

## Current milestone

- **Milestone:** Phase 4 v2 public-session stealth rewrite
- **Status:** design reset started; the repository now treats the v1 outer transport model as technically functional but not strong enough to justify aggressive stealth claims
- **Canonical design docs:**
  - `SPEC_v2.md`
  - `docs/ARCHITECTURE_V2.md`
  - `docs/V2_ROADMAP.md`
- **Primary remaining goal:** replace transport-centric camouflage with a public-session stealth architecture that keeps the secure inner core but makes the outer session behave like a real public service
- **Implementation ordering:**
  - Stage 1: hardening + honesty baseline
  - Stage 2A: first public-session carrier baseline
  - Stage 2B: second public-session carrier baseline
  - Stage 3: cover compiler, masked fallback tickets, and indistinguishability-budget control
- **Performance intent:**
  - low-stealth / permissive operation should remain within the same practical order of magnitude as the corresponding public session baseline
  - higher-stealth modes may reduce throughput and increase latency, but must do so through explicit bounded budgets rather than accidental regressions
  - no phase should ship a new carrier with worse probe handling than the honest public service it is borrowing

## Latest shipped chunk impact note

- **Chunk:** v2 design reset docs
- **Latency impact:** none yet; design-only
- **Bandwidth impact:** none yet; design-only
- **CPU impact:** none yet; design-only
- **Notes:** the repository now has a concrete staged plan for replacing the current carrier model with public-session stealth carriers and retiring fake-decoy behaviour

## Core v2 design rules

- No visible AdaPT-specific admission handshake may appear on the public wire in v2 stealth carriers.
- No fake decoy pages or toy probe strings. The public surface must be a real service with real semantics.
- `D1` remains supported only as a low-stealth opaque fallback and must not be treated as the flagship stealth path.
- `S1` and `D2` are redefined in v2 as public-session carrier families, not as thin wrappers around inner tunnel packets.
- Fast lanes and datagram lanes are subordinate to an already-established public session and must never become the default first visible behaviour on hostile paths.
- Any future stealth claim must be backed by the empirical harness, not only by reasoning from the code.

## Assumptions and non-goals

- Break-vNext is allowed for `D2`/`S1` wire behaviour, bundle/config schema, and public transport semantics.
- `H1` remains deferred until the public-session baseline exists and the harness shows the first two families are credible.
- Hybrid PQ remains deferred and continues to be rejected in the live runtime until separately planned.
- AdaPT v2 is not an anonymity system.
- AdaPT v2 is not expected to defeat a global adversary doing perfect long-window end-to-end correlation.
- Self-contained same-host lab deployments may exist for convenience, but they must be documented as weaker camouflage than origin-backed deployments.
- The current v1 outer carriers may be retained temporarily behind explicit legacy flags only when needed for migration/testing.

## Active / pending workstreams

| Chunk | Status | Scope | Expected impact |
|---|---|---|---|
| Planning/docs maintenance | active | Keep `PLAN.md`, `SPEC_v2.md`, and `docs/ARCHITECTURE_V2.md` aligned with live code and shipped scope | No runtime impact |
| Stage 1 hardening | active | Disable legacy `S1` defaults, demote `D1`, remove toy decoys, add pre-auth deadlines/caps, and make transport availability explicit | Reduced attack surface; minor configuration churn |
| Empirical harness | active | Add passive capture, active probe, retry-pattern, and timing/burst regression jobs for AdaPT and browser H2/H3 baselines | Validation-only cost; essential gate |
| Runtime/module split | pending | Break oversized runtime/edge transport code into surface-focused modules before landing public-session carriers | No intentional runtime impact; reduces maintenance risk |
| Hidden-upgrade core | pending | Refactor `apt-admission` so it owns logical hidden-upgrade capsules/tickets rather than a public-wire handshake format | Moderate implementation risk; core enabler |
| First public-session carrier | pending | Ship the first honest public-session stealth carrier, recommended initial target: H2 API-sync carrier | Main v2 milestone; practical stealth uplift |
| Second public-session carrier | pending | Ship the H3 public-session sibling carrier after the first baseline is stable | Major feature; higher protocol complexity |
| Cover compiler and budget controller | pending | Add trace-compiled cover profiles, secret-seeded cover plans, masked fallback tickets, and indistinguishability budgets | High novelty; bounded runtime overhead |

## Next tasks

1. Update the runtime/config surface so legacy `S1` is no longer implicitly advertised, bundled, or selected by default.
2. Add explicit pre-auth read/lifetime deadlines, connection caps, and low-cost validation ordering for every exposed transport path.
3. Land the first version of the empirical harness covering passive wire image, retry ladders, active probes, and timing/burst regression against browser H2/H3 captures.
4. Split the existing transport/runtime modules into surface-oriented components so v2 work does not grow existing oversized files.
5. Choose the first public-session family to implement end-to-end. Recommended default: H2/TLS API-sync baseline before H3.
6. Draft and then implement the hidden-upgrade capsule API and the structured v2 transport blocks for bundles/config.

## Detailed implementation requirements for the first upcoming chunks

### Stage 1 hardening acceptance

- Server does not advertise, start, or bundle legacy `S1` unless a legacy compatibility flag is explicitly enabled.
- Client default selection is `auto`, not hardcoded `D1`.
- Normal attempt order is: explicit operator pin if set, then remembered network preference, then the first configured public-session family, then `D1` only as remembered-safe or explicit fallback.
- No shipped runtime path emits hardcoded fake HTTP decoy strings.
- Every exposed pre-auth path has deadlines and bounded resource allocation.

### Empirical harness acceptance

- The harness captures and stores browser H2 and H3 baseline traces.
- The harness captures current AdaPT `D1` and any remaining legacy carriers as a "known weaker baseline" for improvement tracking.
- The harness exercises active probes and records whether the response matches honest public-service behaviour, silence, or a distinctive protocol failure.
- No future stealth-facing phase is considered complete without a harness delta report.

### First public-session carrier acceptance

- A strict end-to-end hidden upgrade succeeds inside a real public-service session.
- An unauthenticated client can still use the public service normally.
- Invalid or probing clients see ordinary public-service semantics rather than AdaPT-specific failures.
- No AdaPT-specific header, length prefix, or explicit carrier negotiation is exposed on the public wire.
- The client and server derive the same cover plan without negotiating that plan explicitly on the wire.
```
