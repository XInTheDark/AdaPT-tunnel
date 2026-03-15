# Phase 3 Adaptive Runtime Rewrite Plan

## Purpose

`PLAN.md` is the repository's living implementation plan for current and pending non-trivial work. It should stay forward-looking and track only:

- the current milestone and status
- active/pending implementation chunks
- next tasks in expected execution order
- explicit assumptions and non-goals
- estimated latency / bandwidth / CPU impact notes per chunk

## Current milestone

- **Milestone:** Phase 3 adaptive/persona/local-normality rewrite
- **Status:** chunk 1 shipped (`mode`-only operator/control-surface migration); adaptive feature chunks still pending
- **Primary goal:** make the client-side adaptive system spec-credible by:
  - making adaptive keepalive a real runtime path
  - wiring persona outputs into the live scheduler/runtime
  - replacing the single remembered network profile with a bounded multi-profile store
  - replacing placeholder local-normality tracking with a compact statistical model
- **Performance intent:**
  - mode near `0`: no meaningful throughput/latency penalty
  - mode around `50`: mild impact only
  - mode near `100`: full shaping, but still bounded and practical

### Latest shipped chunk impact note

- **Chunk:** numeric `mode` migration across config/CLI/runtime-facing surfaces
- **Latency impact:** negligible
- **Bandwidth impact:** none
- **CPU impact:** negligible
- **Notes:** this chunk is control-surface/state migration only; it does not yet add new shaping or learning cost

## Numeric mode model

Replace the operator-facing `stealth` / `balanced` / `speed` presets with a single numeric control named **`mode`**.

The intended **Phase 3 end state is `mode`-only** across operator-facing config, CLI, runtime state, docs, telemetry, and tests.

- **Range:** `0..=100`
- **Meaning:**
  - lower values = more throughput-oriented, lower-latency, lower-padding behavior
  - higher values = more conservative, stealth-heavy, padding/shaping-friendly behavior
- **Reference anchors for compatibility and tests:**
  - `0` = previous `speed`
  - `50` = previous `balanced`
  - `100` = previous `stealth`
- **Compatibility/migration requirements:**
  - temporary migration support may accept legacy named presets when reading old config/state or explicit migration inputs
  - map legacy values to the numeric anchors above
  - write only numeric `mode` values on the next config/state save
  - remove legacy named presets from the steady-state operator-facing interface by the end of Phase 3
- **Controller requirements:**
  - `mode` changes happen in bounded increments rather than discrete preset jumps
  - operator policy may set floors/ceilings
  - persona/scheduler outputs are derived from `mode` + path profile + persona seed
- **Scalar design requirements:**
  - this must be a true scalar, not a renamed three-state enum
  - major runtime knobs should scale monotonically with `mode`, including pacing delay budget, padding budget, idle-cover eligibility, batching aggressiveness, soft-packing targets, idle-resume ramp, and controller conservatism
  - neighboring `mode` values should produce small bounded behavior changes rather than cliff-edge flips
  - piecewise-linear curves or interpolated lookup tables are acceptable, but the implementation should not primarily switch on three buckets
- **Implementation note:**
  - anchor points like `0`, `50`, and `100` exist for backward compatibility, QA, and tests; they are not the intended long-term behavior model

## Assumptions and non-goals

- `H1` is intentionally deferred and not part of this rewrite.
- Hybrid PQ remains out of scope and continues to be rejected as unsupported.
- Learning remains client-side only.
- No ML model.
- No capture or inspection of unrelated device traffic.
- No true protocol fragmentation or reassembly format; only soft packing / MTU behavior.
- Auto-migration of old client state is required and sufficient; after migration, only the new multi-profile format is written.
- Legacy named runtime presets are migration-only compatibility inputs; the shipped Phase 3 control surface should use `mode` only.

## Active workstreams and expected performance impact

| Chunk | Status | Scope | Estimated impact |
|---|---|---|---|
| Planning/docs maintenance | active | Rewrite `PLAN.md`, update `AGENTS.md`, keep plan current after each shipped chunk | No runtime impact |
| Numeric mode-only migration | completed | Replaced named preset plumbing with numeric `mode` across config/CLI/runtime-facing state, docs/examples/help, status surfaces, and bundle/config migration paths | Shipped with negligible latency/bandwidth/CPU impact; startup/config parsing only |
| Context discovery + multi-profile persistence | pending | Passive context discovery, profile hashing, migration, bounded profile store | Startup-only overhead; ~0 bandwidth impact; negligible CPU |
| Histogram local-normality model | pending | Replace raw sample deque with bounded counters/histograms and poisoning resistance | Negligible latency/bandwidth; target `<1%` steady CPU |
| Adaptive keepalive learning | pending | Persist learned idle interval state and make adaptive keepalive real | No latency impact; bandwidth neutral-to-lower on permissive paths; negligible CPU |
| Persona/scheduler runtime wiring + soft packing | pending | Consume persona outputs live, derive shaping behavior continuously from numeric `mode`, and add soft MTU-aware packing behavior | `mode=0`: `~0` latency / `~0` padding / `~0-1%` CPU; `mode≈50`: `+0-3 ms` interactive / `+0-10 ms` bulk / `+0-2%` bandwidth / `+0-2%` CPU; `mode=100`: `+0-10 ms` interactive / `+0-40 ms` bulk / `+2-8%` steady bandwidth with up to `15-20%` during probation / `+1-5%` CPU |
| Policy/controller follow-up | pending | Richer signals, remembered preferences, and bounded mode increase/decrease rules | Negligible runtime overhead |
| QA/perf validation | pending | Real-traffic checks at `mode=0`, `mode=50`, and `mode=100` plus test coverage | Validation-only cost |

## Next tasks

1. Split adaptive/policy code by responsibility so the rewrite does not grow new god files.
2. Implement canonicalized context hashing, multi-profile persistence, and legacy single-profile state migration.
3. Add passive client-side context discovery on Linux and macOS with graceful fallback behavior.
4. Replace the current local-normality sample deque with the bounded histogram/counter model.
5. Add the dedicated adaptive keepalive learning controller and persist it per network profile.
6. Wire the remaining persona outputs into runtime scheduling, soft packing, and idle-resume behavior.
7. Update the policy/controller to operate on richer signals and bounded numeric `mode` adjustments.
8. Run workspace tests plus mode-replacement QA/performance checks, then update this file with the shipped chunk and impact notes.

## Detailed implementation requirements

### 1) Planning/docs maintenance

- Keep `PLAN.md` as a forward-looking living plan:
  - only active/pending work
  - current milestone/status
  - next tasks
  - explicit assumptions
  - per-feature estimated performance impact notes
- Add to `AGENTS.md` that `PLAN.md` is the canonical living implementation plan for non-trivial work and must be updated whenever scope, assumptions, status, or expected performance impact changes.
- After each shipped chunk, add a short impact note covering latency, bandwidth, and CPU.

### 2) Numeric mode-only migration

Replace the current operator-facing named mode system with numeric `mode`.

- Add a numeric `mode` value on a `0..=100` scale.
- Lower `mode` values should bias toward throughput and minimal shaping.
- Higher `mode` values should bias toward stealth/conservatism.
- Legacy `stealth` / `balanced` / `speed` inputs may be accepted only for migration/import compatibility, then be translated into `100`, `50`, and `0` respectively.
- On the next config/state write, persist only the numeric `mode` form.
- Admission/config/runtime/observability surfaces should converge on the scalar rather than continuing to expose named presets as the interface.
- By the end of Phase 3, config examples, docs, CLI help, status output, telemetry labels, and tests should speak in terms of `mode` only.
- Runtime behavior should derive from continuous or piecewise-continuous functions of `mode`, not from a renamed fixed three-state switch.
- Internal helper ranges are allowed for safety caps and tests, but adjacent `mode` values should still map to bounded incremental behavior changes.
- Add unit coverage for monotonic scaling of the major derived knobs so the scalar stays real over time rather than drifting back into enum semantics.

### 3) Network profile store + state migration

Replace the current single persisted `network_profile` with:

- `network_profiles: BTreeMap<String, PersistedNetworkProfile>`
- `last_active_profile_key: Option<String>`

Profile key = SHA-256 hex of canonicalized `LocalNetworkContext`.

`PersistedNetworkProfile` must store:

- `context`
- compact `LocalNormalityProfile`
- remembered profile
- last `mode` / controller state
- persisted keepalive-learning state
- `last_seen_unix_secs`

Requirements:

- bound the store to 16 profiles and evict least-recently-seen entries
- auto-migrate old state on load:
  - if legacy `network_profile` exists, convert it into one keyed entry
  - write only the new format on the next store
- this remains client-side only

### 4) Network context discovery

Implement passive client-side context discovery with graceful fallback.

#### Linux

- derive route/interface/gateway from existing route lookup helpers
- classify link type from interface/sysfs
- use hashed Wi-Fi SSID when passively available
- otherwise fall back to interface-based local label

#### macOS

- derive default interface/service from existing helpers
- classify Wi-Fi vs wired from network service/device
- use hashed Wi-Fi network name when available
- otherwise fall back to hashed service/device label

#### Fallback on both

- `LinkType::Unknown` when needed
- gateway fingerprint from hashed gateway/device label
- public-route hint from canonicalized configured server endpoint
- do not capture unrelated device traffic
- no packet sniffing, no pcap, no ambient traffic inspection

### 5) Local-normality model rewrite

Replace the current raw sample deque approach with a bounded, compact statistical model.

Rules:

- no ML model
- no learned neural scorer
- use explicit counters/histograms only

Track bounded histograms/counters for:

- packet-size buckets
- inter-send-gap buckets
- burst-length buckets
- upstream/downstream ratio buckets
- RTT class counts
- loss class counts
- MTU class counts
- NAT class counts
- connection longevity counts
- per-carrier success/failure/rebinding/idle-timeout counters

Poisoning resistance must be explicit:

- clipped per-session update amounts
- slower promotion of failure signals than success signals
- profile changes only affect path classification/`mode` after bounded evidence thresholds

Bootstrap rule:

- stay conservative until either 3 successful sessions exist for the active profile or the minimum histogram evidence threshold is met

Derived outputs:

- richer `PathProfile`
- remembered preferred carrier/permissiveness
- learned keepalive interval state
- bounded `mode` floor/ceiling hints for the controller

### 6) Adaptive keepalive: make adaptive real

Implement a dedicated adaptive keepalive controller and persist it per network profile.

Persisted keepalive-learning state must include:

- current target interval
- last idle outcome summary
- bounded confidence/learning counters

Mode semantics must scale with numeric `mode` rather than selecting from a renamed preset enum.

- at `mode=0`: `SuppressWhenActive` only; no cover; no deliberate stretching beyond the configured base interval; suppress explicit keepalives while recent traffic exists
- around `mode=50`: use `Adaptive`; suppress when active, otherwise schedule jittered keepalives from the learned target
- at high `mode` values approaching `100`: use the same learned interval engine as `Adaptive`, but permit `SparseCover` when the active persona/path classification says cover is appropriate
- as `mode` rises, adaptive stretching beyond the base interval, jitter width, and cover eligibility should increase monotonically within the hard caps below
- do not treat `0`, `50`, and `100` as hard-only operating buckets

Exact interval update rules:

- initialize from configured base interval, default 25s
- on successful idle survival at or above the current target, increase target by 10%, clamp to configured max
- on idle-related impairment/rebinding/quiet-timeout, decrease target by 30% or at least 5s, clamp to configured min
- jitter:
  - `Adaptive`: 85%-115%
  - `SparseCover`: 80%-110%
  - `SuppressWhenActive`: configured base interval only
- keepalive learning updates only from idle-related signals, not from busy periods
- `KeepaliveMode::Adaptive` must become a real, used runtime path

### 7) Persona/scheduler rewrite

Keep persona generation deterministic per session, but make all important outputs live in the runtime.

Persona outputs that must be consumed:

- `pacing_family`
- `burst_size_target`
- `packet_size_bins`
- `padding_budget`
- `keepalive_mode`
- `idle_resume_ramp_ms`
- `fallback_order`
- `migration_threshold`
- `prefers_fragmentation`

`prefers_fragmentation` must be implemented as soft packing / MTU behavior only:

- smaller packing targets
- less aggressive batching on constrained/small-MTU paths
- no new tunnel wire fragmentation/reassembly format

#### Continuous mode scaling requirements

Reference anchors for migration/tests, not hard buckets:

- **`mode=0`**
  - no deliberate pacing delay
  - no padding
  - no idle cover
  - no soft-fragmentation behavior
  - `SuppressWhenActive` keepalive only
  - throughput-oriented batching only
- **`mode≈50`**
  - mild shaping only
  - small jitter / mild burst control
  - steady padding cap `0%-2%`
  - no cover by default
  - `Adaptive` keepalive
  - soft-fragmentation behavior only on small/constrained paths
- **`mode=100`**
  - full persona shaping within hard caps
  - `Adaptive` or `SparseCover`
  - steady padding cap `2%-8%`
  - probation padding up to `15%-20%`
  - gentle idle-resume ramp
  - soft-fragmentation behavior may reduce packing size on constrained paths

Scaling rules:

- pacing-delay budget should rise monotonically with `mode`, while staying at `0 ms` at `mode=0`
- steady padding budget should rise monotonically with `mode`, from `0%` at `mode=0` to a maximum steady-state cap of `8%` at `mode=100`
- probation padding headroom should remain near zero at low `mode` values and only grow materially in the upper end of the scale
- batching aggressiveness and packing size targets should decrease monotonically as `mode` rises, especially on constrained or small-MTU paths
- idle-resume ramp length and initial burst gentleness should increase monotonically with `mode`
- idle-cover eligibility/probability should increase with `mode` and path evidence, while remaining fully disabled at `mode=0`
- neighboring `mode` values should not flip multiple scheduler behaviors at once without an explicit safety reason

#### Runtime effects

- `pacing_family`
  - `Smooth`: tiny inter-record delay grows with `mode` within the configured latency caps
  - `Bursty`: short grouped sends within a burst cap that shrinks and spaces out as `mode` rises
  - `Opportunistic`: immediate send path, but its batching/packing aggressiveness should still scale down as `mode` rises
- `idle_resume_ramp_ms`
  - after long idle, temporarily cap first bursts and keep pacing gentle for the ramp window, with the ramp becoming more pronounced as `mode` rises
- `prefers_fragmentation`
  - reduce per-record packing target and disable aggressive batching on constrained/small-MTU paths, with stronger effect at higher `mode` values

#### Hard performance caps

- `mode=0`: `0 ms` deliberate added latency
- `mode≈50`: up to `3 ms` added interactive latency, up to `10 ms` bulk
- `mode=100`: up to `10 ms` interactive, up to `40 ms` bulk
- never exceed the repository's existing global scheduler latency budgets

### 8) Policy/controller follow-up

Keep the controller explicit and rule-based.

Feed it richer signals:

- stable delivery windows
- immediate reset / blackhole
- NAT rebinding
- MTU blackhole
- RTT inflation
- repeated idle-timeout symptoms
- fallback success/failure per carrier

Transition rules:

- unknown/new profile starts conservative at `mode=100` unless operator policy caps it lower
- decrease `mode` only after profile bootstrap + stable delivery evidence
- permit near-`0` performance-oriented `mode` values only if operator policy allows and the active profile shows sustained success
- increase `mode` toward stealth/conservatism on repeated impairment or rebinding
- use bounded `mode` adjustments rather than large jumps

Carrier ordering:

- explicit operator preference
- then active-profile remembered preference
- then persona fallback order
- then conservative binding order
- always filtered by actually enabled carriers

### 9) Module layout / anti-god-file requirement

Do not grow the current adaptive/policy/persona files into new god files.

- split policy code by responsibility:
  - normality/statistics
  - controller
- split runtime adaptive code by responsibility:
  - context discovery
  - keepalive learning
  - shaping/scheduler behavior
  - persistence/profile selection
- split persona generation from persona data structures if needed

### 10) Performance reporting and QA flow

After each shipped chunk, update this file with a short estimated impact note covering latency, bandwidth, and CPU.

Expected reporting envelopes:

- context discovery / multi-profile state
  - startup-only overhead
  - `~0` bandwidth impact
  - negligible CPU
- histogram normality model
  - negligible latency/bandwidth
  - `<1%` steady CPU
- adaptive keepalive
  - no latency impact
  - bandwidth neutral-to-lower on active/permissive paths
  - negligible CPU
- persona/scheduler rewrite
  - `mode=0`: `~0` latency, `~0` padding bandwidth, `~0-1%` CPU
  - `mode≈50`: `+0-3 ms` interactive / `+0-10 ms` bulk, `+0-2%` bandwidth, `+0-2%` CPU
  - `mode=100`: `+0-10 ms` interactive / `+0-40 ms` bulk, `+2-8%` steady bandwidth and up to `15-20%` during probation, `+1-5%` CPU

Also add a lightweight real-traffic QA flow for at least three anchor points:

- ping RTT
- throughput check (`iperf3` / equivalent)
- rough CPU observation
- run `mode=0`, `mode=50`, and `mode=100` passes

## Test plan

### Unit

- `mode` canonicalization/migration from legacy named presets is stable during the transition period
- context canonicalization/hashing is stable
- legacy single-profile state migrates correctly
- LRU eviction works
- histogram updates/clipping behave as specified
- keepalive interval grows/shrinks exactly on success/failure events
- major derived scheduler/keepalive/padding knobs scale monotonically with `mode`
- adjacent `mode` values produce bounded output deltas rather than cliff-edge behavior jumps
- persona outputs stay inside mode-specific bounds

### Integration

- reconnect on the same context reuses the correct profile
- switching contexts selects a different profile and does not pollute the old one
- adaptive keepalive is actually selected/used in mid-to-high `mode` flows
- `mode=0` emits no padding/cover and no deliberate pacing delay
- `mode≈50` remains within mild shaping caps
- `mode=100` uses full shaping but stays inside hard latency limits
- soft-fragmentation behavior changes packing only; no new fragmentation wire format appears

### Validation

- workspace tests remain green
- smoke/perf checks pass for `mode=0`, `mode=50`, and `mode=100`
- operator-facing docs/examples/help are `mode`-only by the end of Phase 3
- `PLAN.md` and `AGENTS.md` updates are included with the implementation
