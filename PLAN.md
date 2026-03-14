# Adaptive Persona Tunnel Implementation Plan

This plan now tracks the repository against the **intended `SPEC_v1.md` end state**, not just the first usable VPN cut.

Assumptions for the current codebase and roadmap:

- **server target:** Linux
- **client targets:** Linux and macOS
- **topology:** combined edge+tunnel daemon first
- **primary live carriers today:** `D1` over UDP with `S1` stream fallback
- **security core today:** implemented
- **remaining gap:** additional carrier families, broader platform/operator hardening, and full spec-completeness work

## 1. Product target

Deliver an AdaPT implementation that is not only a working VPN, but also substantially aligned with the spec's three biggest promises:

1. **no globally stable wire signature**
2. **bounded adaptive persona-driven behavior**
3. **survivability on restrictive or changing networks**

That target is best approached in three phases.

## 2. Priority model

The roadmap is ordered by **practical effectiveness from the current repository state**, not by raw implementation effort.

| Phase | Focus | Estimated effectiveness |
|---|---|---:|
| Phase 1 | Wire-image hardening + adaptive runtime behavior | **90–95%** |
| Phase 2 | Hostile-network survivability and fallback carriers | **72–85%** |
| Phase 3 | Capability depth, operator hardening, and completeness work | **18–65%** |

These percentages are directional impact estimates relative to the current repo baseline. They are not benchmark measurements.

## 3. Progress snapshot

Already present before this phase split:

- protocol/domain types
- cryptographic suite integration and key schedule
- admission handshake (`C0 -> S1 -> C2 -> S3`)
- encrypted tunnel core with replay protection and rekey support
- first production-oriented UDP runtime
- TUN integration and basic route/NAT orchestration
- CLI-driven setup flow
- first-cut persona, policy, and observability crates

Completed in **Phase 1** in this turn:

- added an **opaque D1 runtime wire envelope** for admission and tunnel datagrams, removing raw tunnel packet structure from the live UDP wire path
- derived **runtime-scoped outer keys** from admission/session key material instead of reusing inner keys directly
- integrated **persona-driven runtime behavior** into the live client/server datapath:
  - bounded burst coalescing
  - bounded padding toward persona-selected size bins
  - jittered pacing delays
  - adaptive keepalive scheduling
  - sparse idle cover padding when the persona selects it
- integrated **policy/local-normality feedback** into the live client runtime:
  - persistent per-route network profile state
  - stable-delivery and quiet-impairment policy observations
  - policy-mode transition telemetry
  - remembered carrier/permissiveness hints for later sessions
- added tests for:
  - opaque admission/tunnel wire wrappers
  - adaptive runtime logic
  - config persistence still parsing correctly

Completed in **Phase 2** in this turn:

- promoted `S1` from a framing helper into a live client/server runtime path
- added live `S1` outer-key derivation and opaque admission/confirmation/tunnel wrapping
- integrated stream invalid-input handling with either a generic HTTP failure or decoy-like HTTP surface
- added conservative client carrier ordering, runtime carrier preference, and reconnect/fallback orchestration
- added sparse standby probing and carrier promotion logic
- wired `PATH_CHALLENGE` / `PATH_RESPONSE` into the live runtime for authenticated D1 path revalidation
- added operator-facing stream/fallback/runtime-mode config fields and best-effort config auto-upgrade persistence

## 4. Three-phase roadmap

### Phase 1 — Stealth foundation and adaptive runtime

**Priority:** highest  
**Estimated effectiveness:** **90–95%**  
**Status:** **completed**

#### Objective

Close the biggest gap between "working VPN" and "AdaPT-like behavior" by making the live runtime:

- less trivially fingerprintable
- more adaptive in pacing/size/keepalive behavior
- aware of coarse delivery history rather than fully static

#### Deliverables

1. **Wire-image hardening for the live UDP path**
   - wrap live `D1` admission records in an opaque carrier envelope
   - wrap live `D1` tunnel datagrams in an opaque carrier envelope
   - derive separate outer-carrier keys from admission/session secrets
   - stop sending the clear logical tunnel packet structure directly on the UDP wire

2. **Persona/scheduler integration in the runtime datapath**
   - generate a persona from the session's `persona_seed`
   - coalesce multiple TUN packets into bounded bursts
   - add bounded padding toward persona packet-size bins
   - apply small pacing delays within safe latency limits
   - replace fixed periodic keepalives with persona-driven keepalive sampling
   - support sparse idle cover behavior when selected by the persona

3. **Local-normality and policy-controller integration**
   - persist a local network profile on the client
   - record coarse tunnel metadata into the profile
   - infer a coarse path profile from stored observations
   - start from conservative policy defaults and transition when delivery stabilizes
   - surface policy-mode changes into telemetry/logging
   - remember a prior carrier/permissiveness hint for later sessions

4. **Validation**
   - keep the workspace building and tested with `cargo check --workspace` and `cargo test --workspace`
   - add focused unit coverage for new wire and adaptive-runtime helpers

#### Acceptance criteria

Phase 1 is complete when all of the following are true:

- the live UDP runtime no longer places the logical tunnel packet header directly on the wire
- the client/server runtime uses persona output to affect packet timing/size behavior
- the client persists a local-normality profile and uses it on later runs
- policy-mode changes can occur during a session and are logged as coarse events
- all tests pass

#### Implementation notes

This phase intentionally stops short of adding a new carrier family. It strengthens the existing `D1` runtime first so later fallback work has a better base to build on.

---

### Phase 2 — Hostile-network survivability and fallback

**Priority:** high  
**Estimated effectiveness:** **72–85%**  
**Status:** **completed**

#### Objective

Make AdaPT survive networks where the primary UDP path is blocked, degraded, reset, or unstable.

#### Deliverables

1. **Real `S1` encrypted-stream runtime path**
   - promote the existing stream framing helper into a real runtime transport
   - implement client/server session establishment over the stream carrier
   - integrate it with the same admission/tunnel logic used by `D1`

2. **Decoy-capable stream behavior**
   - define how invalid unauthenticated stream input is surfaced
   - add a concrete decoy or generic-failure surface for stream mode
   - ensure near-miss traffic does not reveal protocol state

3. **Fallback orchestration**
   - let the policy controller move between carriers in conservative order
   - feed handshake blackholes / immediate resets / repeated fallback failures into policy
   - keep one active carrier and at most one standby path

4. **Path and carrier migration**
   - wire `PATH_CHALLENGE` / `PATH_RESPONSE` into the runtime
   - support authenticated address migration on path changes
   - support policy-driven carrier migration after repeated impairment

5. **Standby health checks**
   - run sparse health checks on a standby path/carrier
   - do not let health checks create a noisy or periodic fingerprint

#### Acceptance criteria

Phase 2 is complete when all of the following are true:

- `S1` works as a real transport, not just a framing helper
- the runtime can fall back away from blocked or repeatedly blackholed `D1`
- path ownership is revalidated before trusting a migrated path
- stream invalid-input behavior does not reveal APT-specific state

#### Dependencies

- Phase 1 wire/runtime integration must already exist so new carriers can reuse the adaptive path

---

### Phase 3 — Capability depth, operator hardening, and full-spec breadth

**Priority:** medium  
**Estimated effectiveness:** **18–65%** depending on feature  
**Status:** pending

#### Objective

Finish the broader platform and operator story after the biggest stealth/survivability work is already in place.

#### Deliverables

1. **Additional carrier families**
   - validate and harden the live `D2` encrypted datagram carrier
   - implement `H1` only if highly restrictive request/response fallback is still needed after `S1`

2. **Per-user provisioning end-to-end**
   - expose per-user admission flow in CLI/operator tooling
   - issue/revoke per-user credentials cleanly
   - preserve rotating lookup-hint behavior

3. **IPv6 and richer network handling**
   - support IPv6 tunnel traffic end-to-end
   - improve path classification inputs where safely available
   - broaden platform/runtime coverage where justified

4. **DNS automation and operator polish**
   - apply pushed DNS settings automatically where supported
   - improve deployment ergonomics and service management guidance
   - extend validation / manual test guides to cover new adaptive/fallback behavior

5. **Optional hybrid PQ and advanced hardening**
   - only after the practical stealth/fallback gaps are already closed
   - ensure the negotiation/runtime path is complete before advertising it as supported

6. **Performance and stress hardening**
   - benchmark hot paths
   - review buffering/allocation strategy
   - validate under reconnect churn, many sessions, and prolonged uptime

#### Acceptance criteria

Phase 3 is complete when all of the following are true:

- the operator flow covers shared-deployment and per-user models cleanly
- the runtime has credible IPv4/IPv6 and DNS behavior
- optional advanced features are end-to-end real, not type-level placeholders
- docs and validation guidance match the shipped behavior

## 5. Immediate next target

With Phases 1 and 2 complete, the next highest-value work is:

1. **IPv6 and broader deployment polish**
2. **performance/stress hardening for the now-live carrier set (`D1`, `D2`, `S1`)**
3. **additional carrier families only where still justified (`H1` or others)**

That is the fastest route to turning the current AdaPT runtime from “adaptive multi-carrier tunnel” into a broader, more operator-ready platform.
