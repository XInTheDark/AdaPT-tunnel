# AdaPT v2 architecture map

This document maps the `SPEC_v2.md` design onto a concrete repository/workspace structure. It is intentionally implementation-oriented.

The central architectural rule is:

**the outer problem is no longer owned by thin packet carriers. It is owned by public service surfaces plus a hidden-upgrade core.**

## 1. Design principles

- Keep the secure inner tunnel and crypto conservative.
- Move public-wire behaviour into honest H2/H3 service surfaces.
- Keep hidden-upgrade logic transport-agnostic and slot-based.
- Compile cover behaviour into data artefacts where possible instead of hardcoding more heuristics.
- Make the runtime controller enforce explicit stealth budgets rather than implicit folklore.
- Keep binaries thin and split runtime logic by responsibility.

## 2. What to keep from v1

These components are worth preserving with limited semantic change:

- `apt-crypto`
  - key derivation
  - cookies/tickets
  - Noise integration
  - tunnel/session key material
- `apt-tunnel`
  - encrypted inner tunnel packets
  - rekeying
  - replay protection
- parts of `apt-admission`
  - logical credential validation
  - ticket logic
  - replay checks
  - but not the assumption that admission owns a public-wire packet format
- parts of `apt-policy` and `apt-persona`
  - local network memory
  - bounded adaptation
  - but they must be repurposed toward cover-plan selection and budget control

## 3. What must change or shrink

- `apt-carriers` must stop being the conceptual owner of the visible stealth story.
- `apt-runtime` must stop directly encoding the public wire as custom datagrams/length-prefixed streams.
- legacy `S1` runtime code should be deleted or quarantined behind explicit legacy flags.
- current `D2` QUIC-datagram code should be treated as a temporary low-level primitive, not as the final H3-facing public surface.

## 4. Recommended workspace layout

The existing workspace can evolve toward the following responsibilities.

### Keep / repurpose existing crates

#### `crates/apt-crypto`

Keep as the home for:

- Noise session establishment
- ticket and cookie sealing
- runtime key derivation
- any slot-binding AEAD helpers used by hidden-upgrade capsules

#### `crates/apt-admission`

Repurpose into the **hidden-upgrade core**.

New responsibilities:

- logical `UG1` / `UG2` / `UG3` / `UG4` definitions
- credential validation ordering
- replay logic
- stateless-until-validated flow
- fallback ticket issuance/opening

Remove responsibility for:

- the public-wire packet envelope as a first-class protocol format

#### `crates/apt-tunnel`

Keep as the encrypted inner tunnel core.

#### `crates/apt-policy`

Refocus toward:

- remembered network context
- masked fallback ticket policy
- indistinguishability budget state machine
- shadow-lane policy

#### `crates/apt-persona`

Either repurpose or split.

Recommended direction:

- narrow `apt-persona` into per-session seeded plan variation helpers
- move anything cover-grammar-specific into a new dedicated crate

#### `crates/apt-bundle`

Extend for:

- structured `S1` / `D2` transport blocks
- trust material
- cover-family/profile identifiers
- deployment strength metadata

### Add new crates

#### `crates/apt-cover`

New crate owning cover profiles and the compiler/runtime view.

Responsibilities:

- cover profile data model
- trace-compiled graph artefacts
- upgrade slot definitions
- size/timing/concurrency envelope structures
- session cover-plan derivation helpers

#### `crates/apt-surface-h2`

New crate for the `S1` v2 public-session family.

Responsibilities:

- TLS/H2-facing public session integration
- legal request/response slot insertion/extraction
- convergence into honest public-service behaviour
- optional subordinate stream modes if the family supports them

#### `crates/apt-surface-h3`

New crate for the `D2` v2 public-session family.

Responsibilities:

- QUIC/H3-facing public session integration
- graph-aware H3 request/response orchestration
- optional H3 datagram/WebTransport lane hooks behind policy gates

#### `crates/apt-origin`

New crate describing public-service families.

Responsibilities:

- API-sync family
- object/origin family
- later, optional realtime family
- legal graph definitions and family-specific semantics

#### `crates/apt-harness`

New crate or tools package for empirical validation.

Responsibilities:

- passive capture orchestration
- qlog/pcap parsing
- active probe runners
- retry ladder analysis
- burst/timing regression
- browser-baseline comparison jobs

#### `crates/apt-lanes`

Optional new crate for subordinate shadow lanes.

Responsibilities:

- D1 fallback lane
- optional H3/WebTransport lane primitives
- generic side-lane policy boundary

This crate must **not** own the main public surface.

## 5. Runtime orchestration boundaries

`apt-runtime` should remain an orchestration layer only.

Recommended top-level runtime responsibilities:

- client bootstrap and remembered-network lookup
- selecting the public-session family
- deriving the session cover plan
- driving the chosen surface crate
- invoking hidden-upgrade logic
- passing inner tunnel packets between the tunnel core and surface/lane adapters
- maintaining the indistinguishability budget

`apt-runtime` should **not** manually encode the public wire for the main H2/H3 families.

## 6. Recommended runtime modules

Inside `apt-runtime`, the recommended split is roughly:

- `runtime/client_bootstrap.rs`
- `runtime/network_memory.rs`
- `runtime/cover_plan.rs`
- `runtime/upgrade.rs`
- `runtime/budget.rs`
- `runtime/convergence.rs`
- `runtime/session.rs`
- `runtime/shadow_lanes.rs`
- `runtime/surface_h2.rs` thin wrapper around `apt-surface-h2`
- `runtime/surface_h3.rs` thin wrapper around `apt-surface-h3`

The previous pattern of very large mixed-responsibility transport files should not survive the rewrite.

## 7. Public-session data flow

The intended end-to-end flow is:

1. Client chooses a public-session family from explicit pin, remembered ticket, or policy.
2. Client opens a real public session through the corresponding surface crate.
3. Client and server derive the same session cover plan from shared inputs.
4. Hidden-upgrade `UG1` is embedded into a legal upgrade slot.
5. Server validates it through `apt-admission` and replies with `UG2` via a legal server slot.
6. `UG3`/`UG4` complete the hidden upgrade.
7. Inner tunnel packets flow via legal public-session slots.
8. If authorised and safe, subordinate shadow lanes may open.
9. If the budget degrades or ambiguity appears, runtime converges back to public-service semantics.

## 8. Config and bundle architecture

v2 config should expose transport families as structured blocks.

Recommended client-side shape:

- `preferred_family = auto | s1 | d2 | d1`
- `s1 { authority, endpoint, trust, cover_family, profile_version, deployment_strength, ... }`
- `d2 { authority, endpoint, trust, cover_family, profile_version, deployment_strength, ... }`
- `d1_policy { allowed, remembered_safe_only, explicit_pin_only, ... }`

Recommended server-side shape:

- public surface blocks for `s1` and/or `d2`
- origin/backend metadata
- cover profiles served/accepted
- deployment strength declaration
- shadow-lane policy

`enable_s1_fallback`, `stream_server_addr`, `stream_bind`, and `stream_decoy_surface` should not survive as the v2 primary interface.

## 9. Candidate cover families

Recommended implementation order:

### First family: H2 API-sync

Why first:

- simpler semantics than full browser page-load mimicry
- easier to test and converge correctly
- easier to embed legal binary/object request bodies
- easier to keep honest unauthenticated functionality

### Second family: H3 object/origin

Why second:

- gives access to the QUIC/H3 ecosystem
- better long-term performance potential
- more natural place for subordinate datagram-ish lanes
- higher implementation complexity and more moving parts

### Later family: realtime

Examples:

- websocket-like chat
- collaborative sync
- WebTransport

This should come after the first two families are already measured and credible.

## 10. Harness integration

The harness must sit beside the runtime, not as an afterthought.

Required comparisons:

- browser H2 baseline
- browser H3 baseline
- AdaPT v2 `S1`
- AdaPT v2 `D2`
- AdaPT `D1` as opaque fallback baseline

Required probe classes:

- passive flow comparison
- malformed app input
- semi-valid upgrade attempts
- retry ladder observation
- idle/resume behaviour
- shadow-lane activation behaviour

## 11. Migration from v1

Recommended migration order in code:

1. quarantine legacy `S1`
2. split existing runtime transport code
3. rework `apt-admission` into transport-agnostic hidden-upgrade logic
4. add structured v2 config/bundle blocks
5. land the first surface crate and end-to-end hidden upgrade
6. land the harness gates
7. add the second surface crate
8. add compiled cover profiles and budget control
9. reintroduce any subordinate lanes only when empirically justified

## 12. First implementation slice recommendation

The best first slice is:

- Stage 1 hardening
- hidden-upgrade core without legacy packet-envelope assumptions
- one H2 API-sync public-session family
- harness coverage for H2 baseline vs AdaPT H2 family

That slice is small enough to ship, useful enough to validate the architecture, and different enough from v1 to prove the rewrite is real.
