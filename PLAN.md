# Phase 4 V2 Public-Session Stealth Rewrite Plan

## Purpose

`PLAN.md` is the repository's canonical living implementation plan for current non-trivial work. It should stay forward-looking and track only:

- the current milestone and status
- active/pending implementation chunks
- next tasks in expected execution order
- explicit assumptions and non-goals
- expected latency / bandwidth / CPU impact notes per chunk

## Current milestone

- **Milestone:** Phase B/C bridge — runtime/model refactor prep with hidden-upgrade core landing next
- **Status:** Phase A hardening is complete; early Phase B/D prep is now in place with the live `D1` + optional `D2` baseline, manifest-driven harness fixtures, draft v2 structured transport config types, and an initial `apt-origin` family-definition crate as Phase C hidden-upgrade work becomes the next major focus
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

- **Chunk:** Early Phase B prep — harness fixtures + draft structured transport blocks
- **Latency impact:** none on the live datapath; changes are schema/test/offline-analysis only
- **Bandwidth impact:** none at runtime; fixture corpora only affect offline harness assets
- **CPU impact:** negligible at runtime; tiny offline JSON fixture evaluation cost inside harness tests and future reports
- **Notes:** `apt-harness` now supports manifest-driven sample fixture evaluation, and `apt-runtime` now exposes separate draft v2 client/server transport block types (`preferred_family`, structured `s1`/`d2`, `d1_policy`, deployment strength) without changing the live runtime schema yet

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
| Planning/docs maintenance | active | Keep `PLAN.md`, `SPEC_v2.md`, and `docs/ARCHITECTURE_V2.md` aligned with live code and shipped scope | No runtime impact |
| Runtime/module split | active | Finish separating remaining transport-owned runtime/helpers into surface-ready modules and remove remaining coupling between the live runtime baseline and future public-session families | No intentional runtime impact; lowers maintenance risk |
| Empirical harness | active | Extend `apt-harness` beyond the initial passive/probe/retry report helpers into baseline corpora ingestion and runtime comparison fixtures; sample fixture manifests are the current sub-step | Offline-only analysis cost |
| Hidden-upgrade core | pending | Refactor `apt-admission` so it owns logical hidden-upgrade capsules/tickets rather than a public-wire packet envelope | Moderate implementation risk; core enabler |
| Structured v2 transport config | active | Draft v2 public-session transport blocks and deployment metadata now exist behind a separate schema boundary; next step is wiring them into bundle/origin/surface planning without changing the live runtime path yet | Minor config churn |
| Origin family definitions | active | `apt-origin` now carries initial API-sync and object/origin family skeletons plus legal request/response slot classes; next step is enriching them with cover-profile/runtime integration | No runtime impact yet |
| First public-session carrier | pending | Ship the H2 API-sync family end-to-end with honest unauthenticated semantics and hidden-upgrade slots | Main v2 milestone |
| Second public-session carrier | pending | Ship the H3 public-session sibling after H2 is stable | Major feature; higher protocol complexity |
| Cover compiler + budget controller | pending | Add machine-readable cover profiles, session plans, and bounded indistinguishability budgets | Bounded CPU/latency overhead |

## Next tasks

1. Split any remaining mixed transport/runtime code into surface-oriented modules before new v2 crates land.
2. Extend the draft v2 transport/config types into bundle/origin-facing planning structures without changing the live runtime schema yet.
3. Grow `apt-harness` from manifest-driven samples into richer baseline corpora ingestion and browser/AdaPT comparison fixtures.
4. Rework `apt-admission` around transport-agnostic hidden-upgrade capsules (`UG1`/`UG2`/`UG3`/`UG4`) and masked fallback tickets.
5. Enrich `apt-origin` with cover-profile/runtime-facing metadata, then add `apt-surface-h2` for the H2 API-sync reference path.
6. Follow with the H3 sibling, then cover compiler/budget work once both public-session baselines exist.

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
