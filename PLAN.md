# Phase 4 V2 Public-Session Stealth Rewrite Plan

## Purpose

`PLAN.md` is the repository's canonical living implementation plan for current non-trivial work. It should stay forward-looking and track only:

- the current milestone and status
- active/pending implementation chunks
- next tasks in expected execution order
- explicit assumptions and non-goals
- expected latency / bandwidth / CPU impact notes per chunk

## Current milestone

- **Milestone:** Phase D runtime bridge — `apt-runtime` now owns API-sync H2 surface orchestration helpers, real session wiring next
- **Status:** Phase A hardening is complete; early Phase B/C/D prep is now in place with the live `D1` + optional `D2` baseline, manifest-driven harness fixtures, draft v2 structured transport config types, transport-agnostic `UG1`/`UG2`/`UG3`/`UG4` capsule types, masked fallback ticket issuance/opening bound to coarse network context, enriched `apt-origin` starter profiles, config-resolved v2 surface plans, envelope-level admission APIs, and an `apt-runtime` H2 bridge module that prepares/responds to API-sync hidden-upgrade request/response bodies in front of `apt-surface-h2`
- **Canonical design docs:**
  - `SPEC_v2.md`
  - `docs/ARCHITECTURE_V2.md`
  - `docs/V2_ROADMAP.md`
- **Primary remaining goal:** replace the remaining transport-owned outer model with transport-agnostic hidden-upgrade logic plus real public-session surfaces
- **Implementation ordering:**
  - Phase B: runtime/config/model refactor prep
  - Phase C: hidden-upgrade core
  - Phase D: first public-session carrier (`S1`/H2 API-sync)
  - Phase E: second public-session carrier (`D2`/H3 object/origin)
  - Phase F/G/H: cover compiler, budgets, remembered-safe fallbacks, harness closure
- **Performance intent:**
  - default operation should stay within the same practical order of magnitude as `D1`/`D2` today while the public-session carriers come online
  - throughput reductions in later stealth modes must come from explicit budget policy, not accidental regressions
  - no future carrier should regress probe handling below the currently-shipped hardened baseline

## Latest shipped chunk impact note

- **Chunk:** H2 surface module split after the runtime bridge landing
- **Latency impact:** none
- **Bandwidth impact:** none
- **CPU impact:** none
- **Notes:** after the runtime bridge landed, `apt-surface-h2` was split into focused API-sync surface, transport, and test modules so the H2 reference path can continue growing without violating the repository size/ownership rules

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
- The current `D1`/`D2` runtime remains the temporary migration/testing baseline until the first public-session family lands.

## Active / pending workstreams

| Chunk | Status | Scope | Expected impact |
|---|---|---|---|
| Planning/docs maintenance | active | Keep `PLAN.md`, `SPEC_v2.md`, and `docs/ARCHITECTURE_V2.md` aligned with live code and shipped scope; keep near-threshold H2 modules split by responsibility as they grow | No runtime impact |
| Runtime/module split | active | Finish separating remaining transport-owned runtime/helpers into surface-ready modules and remove remaining coupling between the live runtime baseline and future public-session families | No intentional runtime impact; lowers maintenance risk |
| Empirical harness | active | Extend `apt-harness` beyond the initial passive/probe/retry report helpers into baseline corpora ingestion and runtime comparison fixtures; sample fixture manifests are the current sub-step | Offline-only analysis cost |
| Hidden-upgrade core | active | `apt-admission` now has transport-agnostic `UG1`/`UG2`/`UG3`/`UG4` capsule types, slot bindings, masked fallback tickets, and direct envelope APIs that avoid `AdmissionPacket` / `ServerConfirmationPacket` in the tested H2 path; next step is deleting or quarantining remaining legacy wrapper-only flow where practical | Moderate implementation risk; core enabler |
| Structured v2 transport config | active | Draft v2 public-session transport blocks and deployment metadata now resolve into `apt-origin` starter surface plans; next step is feeding those plans into future bundle/origin/surface orchestration without changing the live runtime path yet | Minor config churn |
| Origin family definitions | active | `apt-origin` now carries API-sync and object/origin starter profiles with request graphs, legal upgrade slots, concurrency/timing envelopes, idle rules, and shadow-lane hints; `apt-surface-h2` is the first consumer | No runtime impact yet |
| First public-session carrier | active | `apt-surface-h2` now provides the API-sync surface/body/slot scaffold, and `apt-runtime` owns thin bridge helpers for preparing/responding to hidden-upgrade messages; next step is wiring those helpers into real H2 client/server orchestration | Main v2 milestone |
| Second public-session carrier | pending | Ship the H3 public-session sibling after H2 is stable | Major feature; higher protocol complexity |
| Cover compiler + budget controller | pending | Add machine-readable cover profiles, session plans, and bounded indistinguishability budgets | Bounded CPU/latency overhead |

## Next tasks

1. Split any remaining mixed transport/runtime code into surface-oriented modules before new v2 crates land.
2. Wire the new `apt-runtime` H2 bridge helpers into real H2 client/server orchestration so API-sync sessions are more than in-memory/test flows.
3. Delete or isolate the remaining legacy `AdmissionPacket` / `ServerConfirmationPacket` wrapper assumptions after the new envelope-level path.
4. Split any near-threshold surface/runtime files before the next H2 slice lands, especially `apt-surface-h2` helpers that are approaching the repo size limits.
5. Grow `apt-harness` from manifest-driven samples into richer baseline corpora ingestion and browser/AdaPT comparison fixtures.
6. Follow with the H3 sibling surface and later cover compiler/budget work once the H2 reference path is stable.

## Detailed implementation requirements for the next upcoming chunks

### Phase B acceptance

- No touched runtime transport/config file grows into a new god file.
- Shared runtime helpers stop assuming a live legacy `S1` datapath exists.
- Public-session crates can be added without pushing more transport-specific logic back into `apt-runtime`.
- Structured v2 transport draft types exist behind a clearly versioned schema boundary.

### Phase C acceptance

- Hidden-upgrade logic can be exercised in tests without any dependency on a public-wire `AdmissionPacket`.
- The same hidden-upgrade core can be embedded in both H2 and H3 surfaces.
- Slot/context binding is explicit in the cryptographic helpers and replay model.
- Masked fallback tickets are issued/opened independently of the old resumption-ticket wire envelope.

### Phase D acceptance

- A strict end-to-end hidden upgrade succeeds inside a real public-service H2 API-sync session.
- An unauthenticated client can still use the public service normally.
- Invalid or probing clients see ordinary public-service semantics rather than AdaPT-specific failures.
- No AdaPT-specific header, length prefix, or explicit carrier negotiation is exposed on the public wire.
- The client and server derive the same cover plan without negotiating that plan explicitly on the wire.
