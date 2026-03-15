# Phase 4 V2 Public-Session Stealth Rewrite Plan

## Purpose

`PLAN.md` is the repository's canonical living implementation plan for current non-trivial work. It should stay forward-looking and track only:

- the current milestone and status
- active/pending implementation chunks
- next tasks in expected execution order
- explicit assumptions and non-goals
- expected latency / bandwidth / CPU impact notes per chunk

## Current milestone

- **Milestone:** Phase D bootstrap — API-sync H2 surface scaffold is in place, runtime integration next
- **Status:** Phase A hardening is complete; early Phase B/C/D prep is now in place with the live `D1` + optional `D2` baseline, manifest-driven harness fixtures, draft v2 structured transport config types, transport-agnostic `UG1`/`UG2`/`UG3`/`UG4` capsule types, masked fallback ticket issuance/opening bound to coarse network context, enriched `apt-origin` starter profiles, config-resolved v2 surface plans, and a new `apt-surface-h2` crate that models honest API-sync request/response bodies plus legal JSON slot embedding/extraction for hidden-upgrade capsules
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

- **Chunk:** Phase D API-sync H2 surface scaffold
- **Latency impact:** none on the live datapath yet; this slice adds surface-model helpers rather than live runtime wiring
- **Bandwidth impact:** none yet; the helpers only define legal JSON slot placement for future H2 traffic
- **CPU impact:** negligible; slot insertion/extraction is small JSON/base64 work that happens only when the future surface crate is exercised
- **Notes:** `apt-surface-h2` now exists with honest API-sync request/response models and legal JSON slot embedding/extraction that can carry `UG1`/`UG2`-style capsules without depending on the old public-wire packet wrappers

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
| Hidden-upgrade core | active | `apt-admission` now has transport-agnostic `UG1`/`UG2`/`UG3`/`UG4` capsule types, slot bindings, and masked fallback tickets bound to network context; next step is reducing the remaining `AdmissionPacket` / `ServerConfirmationPacket` wrapper assumptions | Moderate implementation risk; core enabler |
| Structured v2 transport config | active | Draft v2 public-session transport blocks and deployment metadata now resolve into `apt-origin` starter surface plans; next step is feeding those plans into future bundle/origin/surface orchestration without changing the live runtime path yet | Minor config churn |
| Origin family definitions | active | `apt-origin` now carries API-sync and object/origin starter profiles with request graphs, legal upgrade slots, concurrency/timing envelopes, idle rules, and shadow-lane hints; `apt-surface-h2` is the first consumer | No runtime impact yet |
| First public-session carrier | active | `apt-surface-h2` now provides the initial API-sync surface/body/slot scaffold; next step is wiring it into runtime/admission flow so real H2 sessions can carry hidden-upgrade traffic | Main v2 milestone |
| Second public-session carrier | pending | Ship the H3 public-session sibling after H2 is stable | Major feature; higher protocol complexity |
| Cover compiler + budget controller | pending | Add machine-readable cover profiles, session plans, and bounded indistinguishability budgets | Bounded CPU/latency overhead |

## Next tasks

1. Split any remaining mixed transport/runtime code into surface-oriented modules before new v2 crates land.
2. Wire `apt-surface-h2` into a runtime-facing admission/session path so real H2 API-sync messages can carry `UG1`/`UG2`/`UG3`/`UG4`.
3. Reduce the remaining `apt-admission` dependence on legacy public-wire wrapper types after the `UG1`/`UG2`/`UG3`/`UG4` + masked-fallback rewrite.
4. Grow `apt-harness` from manifest-driven samples into richer baseline corpora ingestion and browser/AdaPT comparison fixtures.
5. Follow with the H3 sibling surface once the H2 reference path is stable.
6. Then add cover compiler/budget work once both public-session baselines exist.

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
