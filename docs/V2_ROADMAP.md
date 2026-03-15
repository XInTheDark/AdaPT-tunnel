# AdaPT v2 phased roadmap

This document is the long-form phased roadmap for the v2 rewrite. `PLAN.md` stays concise and canonical for current work; this file describes the full intended journey.

## 1. Desired end state

The full v2 end state is:

- a conservative inner tunnel core
- hidden-upgrade logic embedded inside real public-service sessions
- at least two public-session families (`S1`/H2 and `D2`/H3)
- compiled cover profiles rather than purely hand-written personas
- secret-seeded per-session cover plans
- indistinguishability-budget control
- masked fallback tickets and network memory
- subordinate fast/shadow lanes only after the public session is established
- empirical gates for every future stealth claim

## 2. High-level phase order

1. Phase A — honesty and hardening baseline
2. Phase B — transport/model refactor prep
3. Phase C — hidden-upgrade core
4. Phase D — first public-session family
5. Phase E — second public-session family
6. Phase F — cover compiler and budget controller
7. Phase G — shadow lanes and remembered-safe fallbacks
8. Phase H — empirical closure and production polish

## 3. Phase A — honesty and hardening baseline

### Goals

- stop overstating current stealth
- shrink the exposed surface
- remove misleading defaults
- establish the harness before the big rewrite

### Deliverables

- legacy `S1` removed from normal default selection and bundle generation
- `D1` explicitly documented and configured as opaque fallback only
- pre-auth deadlines and resource caps across exposed paths
- toy HTTP decoys removed from runtime behaviour
- deterministic retry ladders replaced with remembered selection plus jittered backoff
- first version of the passive/probe harness

### Acceptance criteria

- no default path emits legacy `S1`
- no toy decoy string remains on the main runtime path
- harness can compare AdaPT flows against browser H2/H3 captures
- runtime behaviour is strictly more honest and less fingerprintable than the previous default configuration

### Why this phase matters

Because it prevents the rewrite from being built on top of bad defaults and false confidence.

## 4. Phase B — transport/model refactor prep

### Goals

- split the runtime into surface-ready modules
- stop treating transport wrappers as the owner of stealth
- create room for new crates without growing god files

### Deliverables

- `apt-runtime` transport code split by responsibility
- edge/client bundle/config generation split into focused modules
- structured transport config draft types added behind non-default schema versioning
- legacy `apt-carriers` responsibilities narrowed

### Acceptance criteria

- no touched runtime transport file grows further beyond repository rules
- new surface crates can be added without forcing another monolithic runtime file

## 5. Phase C — hidden-upgrade core

### Goals

- preserve the secure core while severing it from the v1 public-wire packet format
- define `UG1`/`UG2`/`UG3`/`UG4` as logical messages only

### Deliverables

- `apt-admission` rewritten around transport-agnostic hidden-upgrade capsules
- slot/context-bound AEAD helpers
- masked fallback ticket format and issuance/opening
- replay, cookie, and anti-amplification logic adapted to slot-based transport binding

### Acceptance criteria

- hidden-upgrade logic can be exercised in tests without any dependency on a public-wire `AdmissionPacket`
- the same core can be embedded in both H2 and H3 surfaces

### Risks

- keeping too much v1 packet-envelope logic by habit
- letting surface-specific details leak back into the core

## 6. Phase D — first public-session family

### Recommendation

Start with **H2 API-sync**.

### Goals

- prove that AdaPT can exist as a hidden mode inside a real public service
- get active-probe resistance from honest service behaviour rather than fake decoys

### Deliverables

- `apt-origin` API-sync family
- `apt-surface-h2` public-session implementation
- hidden-upgrade slot definitions for the family
- structured client/server transport config for the family
- end-to-end client/server integration

### Acceptance criteria

- unauthenticated users can use the public service normally
- authenticated clients can complete hidden upgrade and tunnel data transfer inside legal service messages
- probes see ordinary H2/TLS service behaviour
- harness shows fewer glaring mismatches vs browser H2 than legacy AdaPT showed vs raw TCP

### Explicit non-goals

- not full browser page-load mimicry yet
- not aggressive low-latency side lanes yet

## 7. Phase E — second public-session family

### Recommendation

Add **H3 object/origin** second.

### Goals

- extend the same architecture into QUIC/H3
- preserve the public-session rule rather than falling back to custom QUIC datagrams

### Deliverables

- `apt-surface-h3`
- H3 cover family definitions in `apt-origin`
- H3 slot definitions and structured config
- harness support for qlog/H3 comparisons

### Acceptance criteria

- hidden upgrade succeeds in a real H3 public session
- probes see honest H3/origin-native behaviour
- the implementation does not reintroduce a datagram-only custom public wire as the main path

### Risks

- drifting back into "custom QUIC + better cosmetics"
- exposing a new stable retry or side-lane pattern

## 8. Phase F — cover compiler and budget controller

### Goals

- move beyond hand-written personas
- make the runtime measure and enforce deviation from real cover behaviour

### Deliverables

- `apt-cover` compiler ingesting real traces into versioned cover profiles
- machine-readable request graphs and upgrade slots
- secret-seeded session cover plans
- indistinguishability-budget controller integrated with `apt-policy`

### Acceptance criteria

- cover profiles are loadable runtime artefacts, not only documentation
- runtime can choose graph branches and upgrade slots from the profile
- budget transitions can be observed in tests and telemetry
- runtime demonstrably reduces hidden-transfer aggressiveness when budget degrades

### Novel contribution

This phase is one of the main candidates for a genuinely new AdaPT contribution: trace-compiled cover grammars plus budget-driven runtime enforcement.

## 9. Phase G — shadow lanes and remembered-safe fallbacks

### Goals

- recover some performance without undoing the public-session stealth model
- avoid deterministic retry ladders

### Deliverables

- masked fallback tickets bound to network context
- remembered-safe family selection
- optional subordinate H3/WebTransport or similar lanes
- explicit `D1` remembered-safe direct fallback policy

### Acceptance criteria

- a new session can jump directly to a likely-good family without an obvious retry ladder
- shadow lanes never appear before the parent public session exists
- operator policy can disable all shadow lanes without breaking the baseline family

### Risks

- reintroducing a new fingerprint via side-lane activation
- allowing `D1` to become the de facto default again

## 10. Phase H — empirical closure and production polish

### Goals

- turn the design into an operationally defensible product
- make release criteria evidence-based

### Deliverables

- browser baseline corpora for H2/H3
- active-probe suites
- retry ladder and idle/resume regression jobs
- deployment guidance for strong/medium/weak modes
- docs cleaned of legacy v1 stealth rhetoric

### Acceptance criteria

- every release candidate can produce a harness report
- docs distinguish clearly between strong origin-backed mode and weaker self-contained mode
- legacy v1 transport compatibility, if retained, is clearly labelled as legacy/testing only

## 11. Recommended first target cover family

The best first v2 family is a narrow **API-sync** public service over H2.

Why:

- easier to host and reason about than full web page-load mimicry
- honest unauthenticated semantics are straightforward
- upgrade slots can live in legal binary/json object bodies
- active-probe handling is much simpler to get right
- easier first stepping stone toward the compiler/profile model

Once that works, extend the same hidden-upgrade core into H3 rather than designing a separate protocol.

## 12. Things to postpone on purpose

These ideas may be worth revisiting later, but should not come before the public-session baseline:

- full browser page-load mimicry with complicated asset graphs
- multi-family simultaneous racing
- aggressive side-lane opening on first session
- H1 request/response family
- exotic protocol-specific decoys
- PQ additions

## 13. Summary recommendation

The roadmap should be understood as:

- **Phase A/B:** clean up the current house
- **Phase C/D/E:** replace the old carrier model with real public-session families
- **Phase F/G/H:** add the parts that make the result genuinely distinctive and robust

If time or scope forces a cut line, stop after a working Phase D or E baseline rather than shipping Phase G features prematurely.
