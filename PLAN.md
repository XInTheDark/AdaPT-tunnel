# Phase 4 V2 Public-Session Stealth Rewrite Plan

## Purpose

`PLAN.md` is the repository's canonical living implementation plan for current non-trivial work. It should stay forward-looking and track only:

- the current milestone and status
- active/pending implementation chunks
- next tasks in expected execution order
- explicit assumptions and non-goals
- expected latency / bandwidth / CPU impact notes per chunk

## Current milestone

- **Milestone:** Phase D H2 implementation complete and testing-ready — the API-sync path is slot/context-bound, runtime-owned, empirically fixture-backed, exercised over real H2/TLS, carries post-upgrade tunnel packets inside legal API-sync messages, and the live runtime no longer depends on admission packet wrappers in its migration-baseline client/server handshake loops
- **Status:** Phase A hardening is complete; early Phase B/C/D prep is now in place with the live `D1` + optional `D2` baseline, richer harness fixture corpora (including backend-level H2 traces), draft v2 structured transport config types, transport-agnostic `UG1`/`UG2`/`UG3`/`UG4` capsule types, masked fallback ticket issuance/opening bound to coarse network context, enriched `apt-origin` starter profiles, config-resolved v2 surface plans, envelope-level admission APIs, explicit public-session slot/context binding for the tested API-sync H2 path, runtime-owned API-sync client/request-handler abstractions, concrete Hyper-backed H2 adapters, rustls-backed H2 surface-plan wiring that uses v2 authority/trust metadata while keeping HTTP encoding inside `apt-surface-h2`, full removal of the remaining `apt-admission` wrapper packet compatibility layer, and connection-local post-upgrade tunnel packet carriage over both cleartext H2 (`h2c`) and rustls/TLS H2 backends
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

- **Chunk:** H2 API-sync tunnel-data completion + wrapper-free admission core
- **Latency impact:** one extra request/response pair still exists for the hidden-upgrade bootstrap; post-upgrade tunnel packets reuse the same request/response cadence as the public API-sync surface with no additional out-of-band round trips
- **Bandwidth impact:** slight increase vs handshake-only H2 because legal API-sync request/response bodies now also carry base64-wrapped tunnel packets in the established session path
- **CPU impact:** modest additional tunnel encode/decode work on the H2 path; no intentional change to the D1/D2 migration baseline
- **Notes:** `apt-admission` no longer exposes or compiles the old `AdmissionPacket` / `ServerConfirmationPacket` wrapper API layer. The H2 runtime path now keeps connection-local established-session state, builds `TunnelSession` objects after `UG4`, and can exchange encrypted tunnel packets inside legal API-sync JSON slots over both Hyper `h2c` and rustls/TLS H2 backends. This is the first repo state that satisfies the Phase D baseline of hidden upgrade plus tunnel data transfer inside real H2 public-service messages.

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
| Runtime/module split | active | Continue separating remaining transport-owned runtime/helpers into surface-ready modules and explicit compatibility layers; the handshake path now uses runtime-local wire wrappers, the admission crate no longer compiles wrapper compatibility at all, and the next step is keeping the H2/H3 session drivers split cleanly as richer carrier families land | No intentional runtime impact; lowers maintenance risk |
| Empirical harness | active | `apt-harness` now supports both coarse passive summaries and richer H2 backend-trace corpora with manifest-driven evaluation; next step is feeding it more realistic captured/session-derived fixtures and additional comparison axes beyond the current authority/path/header/status heuristics | Offline-only analysis cost |
| Hidden-upgrade core | active | `apt-admission` now has transport-agnostic `UG1`/`UG2`/`UG3`/`UG4` capsule types, slot bindings, masked fallback tickets, and direct envelope APIs throughout the crate; the old packet-wrapper compatibility layer has been deleted, and the next step is keeping future H3 work on the same wrapper-free surface | Moderate implementation risk; core enabler |
| Structured v2 transport config | active | Draft v2 public-session transport blocks and deployment metadata now resolve into `apt-origin` starter surface plans; next step is feeding those plans into future bundle/origin/surface orchestration without changing the live runtime path yet | Minor config churn |
| Origin family definitions | active | `apt-origin` now carries API-sync and object/origin starter profiles with request graphs, legal upgrade slots, concurrency/timing envelopes, idle rules, and shadow-lane hints; `apt-surface-h2` is the first consumer | No runtime impact yet |
| First public-session carrier | active | `apt-surface-h2` now provides the API-sync surface/body/slot scaffold, modeled request authority, surface-derived public-session context, HTTP request/response codecs, and established-session tunnel-packet slot helpers; `apt-runtime` owns bridge helpers plus client/request-handler orchestration, connection-local H2 session state, concrete Hyper H2 backends for both `h2c` and rustls/TLS, and plan-driven client trust wiring. The immediate next step is user testing and origin-backed deployment polish before Phase E H3 work expands the same pattern; the shipped apps/docs/bundles now assume H2 directly and no longer expose legacy carrier toggles | Main v2 milestone; ready for user testing |
| Second public-session carrier | pending | Ship the H3 public-session sibling after H2 is stable | Major feature; higher protocol complexity |
| Cover compiler + budget controller | pending | Add machine-readable cover profiles, session plans, and bounded indistinguishability budgets | Bounded CPU/latency overhead |

## Next tasks

1. Hand the H2 API-sync baseline to interactive user testing now that the products, bundles, and operator/client docs all speak the H2-first flow directly.
2. Feed `apt-harness` with more realistic captured/session-derived H2 corpora now that the repo can ingest backend-trace fixtures and compare TLS-backed vs cleartext lab sessions explicitly.
3. Extend the H2 surface-plan wiring from self-signed lab TLS into richer origin-backed deployment behavior (for example stronger trust-source handling and backend/origin routing semantics) without moving HTTP encoding into runtime code.
4. Remove or quarantine the remaining dead D1/D2 migration-baseline runtime code now that product surfaces no longer expose those paths.
5. Split any near-threshold surface/runtime files before the H3 slice lands; the backend/test modules, admission client path, and runtime handshake path were pre-split in recent slices and should stay that way.
6. Start the H3 sibling surface using the same wrapper-free hidden-upgrade core and the H2 API-sync session driver as the reference shape.

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
- After `UG4`, encrypted tunnel packets can flow inside legal H2 API-sync request/response messages on the same public session.
- Invalid or probing clients see ordinary public-service semantics rather than AdaPT-specific failures.
- No AdaPT-specific header, length prefix, or explicit carrier negotiation is exposed on the public wire.
- The client and server derive the same cover plan without negotiating that plan explicitly on the wire.
