# Implementation Plan

This plan follows `SPEC_v1.md` (treated as the intended `SPEC.md`, since it is the only spec file currently in the repository).

## 1. Goal for the first buildable version

Deliver a conservative **Milestone 1** implementation of APT/1-core that proves the architecture end to end:

- authenticated admission handshake (`C0` → `S1` → `C2` → `S3`)
- encrypted inner tunnel core
- one datagram carrier (`D1` over UDP)
- one stream carrier (`S1` over an encrypted stream transport abstraction)
- simple persona/shaping engine with bounded jitter, coalescing, and padding
- thin client / edge / tunnel-node binaries that exercise the libraries together

This first version should optimize for:
- correctness of state machines
- clean subsystem boundaries
- observability for debugging
- conservative defaults from the spec

It should **not** try to implement every advanced stealth feature immediately.

---

## 2. Proposed implementation phases

### Phase 0 — Foundations and interfaces

Objective: freeze the codebase layout and core boundaries before protocol logic is written.

Tasks:
1. Finalize module boundaries for `types`, `crypto`, `admission`, `tunnel`, `carriers`, `persona`, `policy`, and `observability`.
2. Define cross-cutting config objects:
   - suite selection
   - policy mode
   - carrier capability bitmap
   - coarse path-class inputs
   - rekey limits
   - logging/telemetry controls
3. Decide what stays library-internal versus public API.
4. Add workspace-wide linting, formatting, and test conventions.
5. Establish a fixture strategy for handshake transcripts and protocol vectors.

Exit criteria:
- workspace structure is stable
- crate ownership boundaries are documented
- public API direction is clear enough to implement without large rewrites

### Phase 1 — Shared types and cryptographic primitives

Objective: implement the foundational types and security primitives needed by all higher layers.

Tasks:
1. In `apt-types`:
   - coarse path classes (`path`, `mtu`, `rtt`, `loss`, `nat`)
   - session IDs, ticket metadata wrappers, key phase markers
   - carrier and suite capability enums/bitmaps
   - control-frame and policy-mode enums
2. In `apt-crypto`:
   - Noise `XXpsk2` wrapper APIs
   - HKDF label helpers for the derived secrets from §12.1
   - XChaCha20-Poly1305 helpers for admission capsules
   - cookie seal/open helpers bound to source address, carrier, nonce, expiry
   - resumption ticket seal/open helpers under `TK`
3. Add unit tests for:
   - key derivation label correctness
   - cookie rejection on address/carrier/expiry mismatch
   - ticket confidentiality / integrity failures

Exit criteria:
- cryptographic helpers are deterministic where expected and fail closed
- no higher-level state machine code needs to know crypto internals

### Phase 2 — Admission plane

Objective: implement the stealth-first logical admission handshake.

Tasks:
1. Define logical messages for `C0`, `S1`, `C2`, `S3` as internal domain types.
2. Implement encode/decode of logical structures independent from any fixed outer wire image.
3. Implement server-side validation ordering exactly as §11 requires:
   1. carrier binding validity
   2. AEAD decrypt
   3. epoch window
   4. replay check
   5. Noise message validity
   6. policy checks
4. Keep the server stateless until `C2` proves return reachability.
5. Implement replay cache retention and cookie lifetime defaults from §25.
6. Define invalid-input outcomes as carrier-driven silence / generic failure rather than APT-specific responses.
7. Add transcript-driven tests for:
   - successful 1.5 RTT establishment
   - replayed `C0`
   - expired cookie in `C2`
   - invalid epoch slot
   - malformed near-miss messages that must not yield a distinctive reply

Exit criteria:
- the admission state machine is correct, deterministic, and quiet on unauthenticated failure
- logical message handling remains carrier-agnostic

### Phase 3 — Inner tunnel core

Objective: implement the encrypted datagram tunnel that carries IP packets and reliable control frames.

Tasks:
1. Define tunnel packet header and frame model from §13.
2. Implement packet number handling and nonce derivation.
3. Implement replay window tracking (minimum 4096 packet window).
4. Implement encryption/decryption for packets containing one or more frames.
5. Implement reliable control-frame retransmission for:
   - `SESSION_UPDATE`
   - `PATH_CHALLENGE`
   - `PATH_RESPONSE`
   - `CLOSE`
6. Implement rekey soft/hard limits from §§14 and 25.
7. Add tests for:
   - replay rejection
   - key-phase transitions
   - mixed frame packing
   - retransmission expiry

Exit criteria:
- two peers can exchange encrypted frames over an abstract transport
- replay and rekey logic behave conservatively and fail closed

### Phase 4 — Carrier layer (Milestone 1 bindings)

Objective: provide two usable outer transports without freezing a global visible APT wire image.

Tasks:
1. Define a carrier trait / abstraction that covers:
   - logical message embedding
   - max record size
   - fragmentation rules
   - invalid-input behaviour
   - anti-amplification behaviour
   - close semantics
   - migration hooks
2. Implement `D1`:
   - opaque datagram over UDP
   - silence on invalid input
   - conservative MTU defaults
3. Implement `S1`:
   - encrypted stream transport abstraction
   - generic standards-compliant failure / decoy-compatible invalid handling
   - framing suitable for logical APT messages without exposing a stable cleartext header
4. Add conformance tests shared across carriers so both pass the same logical admission/tunnel cases.

Exit criteria:
- the same logical admission/tunnel code can run over either `D1` or `S1`
- carrier-specific behaviour remains outside the protocol core

### Phase 5 — Persona engine and scheduler shaping

Objective: implement the first simple, bounded shaping system required by Milestone 1.

Tasks:
1. Define persona inputs from §16.1.
2. Define bounded persona outputs from §16.2.
3. Implement a simple persona generator using:
   - `persona_seed`
   - coarse path classes
   - chosen carrier family
   - policy mode
4. Implement scheduler profile outputs for:
   - pacing family
   - burst size targets
   - packet-size bins
   - padding budget
   - keepalive mode
   - idle-resume behaviour
5. Add enforcement of bounds from §§16.3 and 18:
   - no strictly periodic idle flow
   - no universal fixed size target
   - latency budget takes precedence when queues age out
6. Add tests ensuring:
   - session-to-session variation exists
   - behaviour is coherent inside a session
   - outputs stay inside policy bounds

Exit criteria:
- shaping is simple but spec-aligned
- the first version avoids overfitting or synthetic-looking randomness

### Phase 6 — Policy controller and local-normality bootstrap

Objective: add enough adaptivity to support the intended default mode without overbuilding Milestone 2.

Tasks:
1. Implement policy modes (`stealth-first`, `balanced`, `speed-first`).
2. Implement bootstrap local-normality profiles using only allowed metadata.
3. Support the probation rule from §17.3 before learning aggressively.
4. Implement coarse mode transitions from §20.3.
5. Keep local observations local and coarse.
6. Add tests for poisoning resistance basics:
   - clipped updates
   - robust quantile usage
   - reduced weight for tunnel traffic versus non-tunnel metadata

Exit criteria:
- a new network starts conservatively
- permissive networks can relax toward balanced mode
- interference signals can move the client back toward stealth-first

### Phase 7 — Application wiring

Objective: make the system runnable in development form.

Tasks:
1. `apt-client`
   - load config and credentials
   - maintain local network context
   - initiate admission and manage session lifecycle
   - expose a development packet source/sink before full OS integration
2. `apt-edge`
   - expose carrier listeners
   - validate admission traffic
   - issue cookies and confirm tunnel establishment
   - forward tunnel setup to colocated or remote tunnel node abstraction
3. `apt-tunneld`
   - terminate tunnel sessions
   - process data/control frames
   - surface privacy-aware metrics/logs
4. Add an end-to-end local harness covering:
   - client ↔ edge ↔ tunnel-node startup
   - UDP carrier success path
   - stream carrier fallback success path
   - one rekey event

Exit criteria:
- the scaffold becomes an executable development system
- developers can observe the full session lifecycle locally

### Phase 8 — Milestone 2 features

Objective: expand from the first working system into the richer adaptive design promised by the spec.

Tasks:
1. Resumption tickets
2. Per-network normality profiles
3. Carrier migration
4. Stream decoy surface support
5. More complete policy/fallback behaviour

Exit criteria:
- adaptive behaviour persists across sessions and network contexts
- fallback and migration are usable under degraded paths

### Phase 9 — Milestone 3 features

Objective: add the higher-complexity features only after the core is stable.

Tasks:
1. Optional hybrid PQ mode
2. Standby path health checks
3. Stronger poisoning resistance
4. Operator controls for stealth / balanced / speed tradeoffs

Exit criteria:
- advanced features are added without destabilizing the core

---

## 3. Testing strategy

### Unit tests

Every crate should own its local invariants:
- `apt-crypto`: derivation, sealing, expiry, mismatch rejection
- `apt-admission`: ordering, replay, cookie handling, quiet failure paths
- `apt-tunnel`: replay window, packet numbering, control reliability, rekey triggers
- `apt-persona`: bounded distributions and session coherence
- `apt-policy`: bootstrap and transition logic

### Integration tests

Cross-crate tests should cover:
- full admission transcript over abstract carrier fixtures
- tunnel packet exchange after `S3`
- policy-driven changes to shaping parameters
- carrier fallback and later migration

### Negative / adversarial tests

Must include:
- replay attempts
- malformed near-miss capsules
- invalid tickets and cookies
- amplification pressure
- MTU blackhole simulation
- reset / blackhole / timeout behaviour

### Interop / conformance vectors

As the logical message formats stabilize, add deterministic transcript vectors for:
- handshake success
- failure classes
- rekey transitions
- resumption acceptance/rejection

---

## 4. Operational defaults to freeze early

These values should be codified early so tests and behaviour stay consistent:

- initial policy mode: `stealth-first`
- admission epoch slot: 300 seconds
- replay cache retention: 10 minutes
- cookie lifetime: 20 seconds
- interactive added latency target: 10 ms
- bulk added latency target: 50 ms
- steady-state padding budget: 6%
- probation padding budget: 20%
- unknown NAT keepalive interval: 25 seconds ±35% jitter
- soft rekey: 2 GiB or 20 minutes
- hard rekey: 8 GiB or 60 minutes
- minimum replay window: 4096 packets

---

## 5. Open decisions to confirm before substantive implementation

These are the biggest decisions still worth confirming before coding deeply:

1. **Implementation language**
   - Assumed: Rust workspace
   - Alternative: Go if operational simplicity matters more than type-level modelling

2. **Initial stream carrier shape**
   - Should `S1` target a generic TLS-like encrypted stream abstraction first, or a concrete transport?
   - Recommendation: start abstract, then bind to a concrete transport later.

3. **First end-to-end demo target**
   - Option A: in-memory logical handshake harness only
   - Option B: localhost UDP `D1` first
   - Recommendation: localhost UDP `D1` first, with in-memory fixtures for tests

4. **Edge ↔ tunnel-node topology for v1**
   - Option A: colocated roles only
   - Option B: abstract split-role interface from day one
   - Recommendation: keep binaries separate but allow a colocated local mode first

5. **OS packet integration scope**
   - Option A: defer TUN/TAP and use a development packet source/sink
   - Option B: begin with full OS integration immediately
   - Recommendation: defer full OS integration until the protocol core is stable

---

## 6. Recommended first implementation slice after approval

If implementation starts next, the best first slice is:

1. `apt-types`
2. `apt-crypto`
3. `apt-admission`
4. a minimal transcript test proving `C0`/`S1`/`C2`/`S3`

Why this slice first:
- it establishes the security and trust boundary correctly
- it forces the core message/state abstractions to become concrete
- it keeps carrier serialization and tunnel data-plane work unblocked later

---

## 7. What is intentionally not implemented yet

The current scaffold does **not** yet implement:
- real admission encryption/decryption
- Noise handshake execution
- tunnel packet encryption
- carrier wire formats
- local-normality learning
- migration, resumption, or hybrid PQ
- TUN/TAP integration

That work should begin only after the next implementation slice is explicitly confirmed.
