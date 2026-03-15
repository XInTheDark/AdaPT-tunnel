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
- **Status:** chunk 2 shipped, plus a runtime hot-path CPU hardening checkpoint, plus the bounded histogram local-normality rewrite
- **Primary remaining goal:** finish the spec-credible adaptive runtime by:
  - making adaptive keepalive a real persisted runtime path
  - wiring persona outputs into live scheduler/runtime behavior so numeric `mode` scales continuously rather than behaving like a renamed enum
  - upgrading the controller to consume richer signals and apply bounded `mode` adjustments
- **Performance intent:**
  - mode near `0`: no meaningful throughput/latency penalty
  - mode around `50`: mild impact only
  - mode near `100`: full shaping, but still bounded and practical

## Latest shipped chunk impact note

- **Chunk:** bounded histogram local-normality model rewrite
- **Latency impact:** negligible
- **Bandwidth impact:** none
- **CPU impact:** negligible steady-state cost; still within the `<1%` target envelope for the model itself
- **Notes:** local-normality now uses persisted bounded histograms/counters instead of raw sample deques, applies explicit per-session clipping budgets, tracks per-carrier success/failure/rebinding/idle-timeout evidence, derives richer path/MTU/RTT/loss/NAT/permissiveness summaries, and refreshes remembered carrier/permissiveness hints from learned profile evidence

## Numeric mode model

The Phase 3 end state remains **`mode`-only** across operator-facing config, CLI, runtime state, docs, telemetry, and tests.

- **Range:** `0..=100`
- **Meaning:**
  - lower values = more throughput-oriented, lower-latency, lower-padding behavior
  - higher values = more conservative, stealth-heavy, padding/shaping-friendly behavior
- **Reference anchors for compatibility and QA:**
  - `0` = previous `speed`
  - `50` = previous `balanced`
  - `100` = previous `stealth`
- **Scalar design requirements:**
  - major runtime knobs must scale monotonically with `mode`, including pacing delay budget, padding budget, idle-cover eligibility, batching aggressiveness, soft-packing targets, idle-resume ramp, and controller conservatism
  - neighboring `mode` values should produce small bounded behavior changes rather than cliff-edge flips
  - piecewise-linear curves or interpolated lookup tables are acceptable, but the implementation must not primarily switch on three buckets
- **Compatibility rule:**
  - legacy named presets may still be accepted only for migration/import compatibility and must be rewritten out as numeric `mode` values on the next save

## Assumptions and non-goals

- `H1` is intentionally deferred and not part of this rewrite.
- Hybrid PQ remains out of scope and continues to be rejected as unsupported.
- Learning remains client-side only.
- No ML model.
- No capture or inspection of unrelated device traffic.
- No true protocol fragmentation or reassembly format; only soft packing / MTU behavior.
- After migration, only the keyed multi-profile client state format is written.
- Legacy named runtime presets are migration-only compatibility inputs; steady-state control surfaces should use `mode` only.

## Active / pending workstreams

| Chunk | Status | Scope | Estimated impact |
|---|---|---|---|
| Planning/docs maintenance | active | Keep `PLAN.md` current after each shipped chunk; keep assumptions, scope, status, and expected performance notes aligned with the live code | No runtime impact |
| Adaptive keepalive learning | pending | Persist learned idle interval state and make adaptive keepalive a real runtime path | No latency impact; bandwidth neutral-to-lower on permissive paths; negligible CPU |
| Persona/scheduler runtime wiring + soft packing | pending | Consume persona outputs live, derive shaping behavior continuously from numeric `mode`, and add soft MTU-aware packing behavior | `mode=0`: `~0` latency / `~0` padding / `~0-1%` CPU; `mode≈50`: `+0-3 ms` interactive / `+0-10 ms` bulk / `+0-2%` bandwidth / `+0-2%` CPU; `mode=100`: `+0-10 ms` interactive / `+0-40 ms` bulk / `+2-8%` steady bandwidth with up to `15-20%` during probation / `+1-5%` CPU |
| Policy/controller follow-up | pending | Feed richer signals into the controller, remember per-profile carrier preference/permissiveness, and apply bounded numeric `mode` increases/decreases | Negligible runtime overhead |
| QA/perf validation | pending | Real-traffic checks at `mode=0`, `mode=50`, and `mode=100`, plus workspace/integration coverage for adaptive behavior | Validation-only cost |

## Next tasks

1. Add the dedicated adaptive keepalive learning controller and persist its learned interval/confidence state inside each stored network profile.
2. Rework persona generation and runtime scheduling so pacing, padding, keepalive style, soft packing, and idle-resume behavior scale continuously from numeric `mode` instead of coarse anchor buckets.
3. Expand the controller to consume richer delivery/impairment/rebinding/idle-timeout signals and to adjust `mode` conservatively with remembered per-profile preferences.
4. Run workspace tests plus mode-by-mode smoke/perf checks, with special attention to CPU under `mode=0`, then update this file again with the next shipped chunk and impact note.

## Detailed implementation requirements for remaining chunks

### 1) Adaptive keepalive: make adaptive real

Implement a dedicated adaptive keepalive controller and persist it per network profile.

Persisted keepalive-learning state must include:

- current target interval
- last idle outcome summary
- bounded confidence / learning counters

Mode semantics must scale with numeric `mode` rather than selecting from a renamed preset enum.

- at `mode=0`: `SuppressWhenActive` only; no cover; no deliberate stretching beyond the configured base interval; suppress explicit keepalives while recent traffic exists
- around `mode=50`: use `Adaptive`; suppress when active, otherwise schedule jittered keepalives from the learned target
- at high `mode` values approaching `100`: use the same learned interval engine as `Adaptive`, but permit `SparseCover` when the active persona/path classification says cover is appropriate
- as `mode` rises, adaptive stretching beyond the base interval, jitter width, and cover eligibility should increase monotonically within the hard caps below
- do not treat `0`, `50`, and `100` as hard-only operating buckets

Exact interval update rules:

- initialize from configured base interval, default `25s`
- on successful idle survival at or above the current target, increase target by `10%`, clamped to configured max
- on idle-related impairment/rebinding/quiet-timeout, decrease target by `30%` or at least `5s`, clamped to configured min
- jitter:
  - Adaptive: `85%–115%`
  - SparseCover: `80%–110%`
  - SuppressWhenActive: configured base interval only
- keepalive learning updates only from idle-related signals, never from busy periods

### 2) Persona / scheduler runtime rewrite

Keep persona generation deterministic per session, but make the important outputs live in the runtime.

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

`prefers_fragmentation` must remain soft packing / MTU behavior only:

- smaller packing targets
- less aggressive batching on constrained / small-MTU paths
- no new tunnel wire fragmentation or reassembly format

Runtime effects:

- `pacing_family`
  - Smooth: tiny inter-record delay only in balanced / high-mode paths
  - Bursty: short grouped sends within burst cap
  - Opportunistic: immediate send path
- `idle_resume_ramp_ms`
  - after long idle, temporarily cap first bursts and keep pacing gentle for the ramp window
- `prefers_fragmentation`
  - reduce per-record packing target and disable aggressive batching on constrained / small-MTU paths

Hard performance caps:

- speed end (`mode≈0`): `0 ms` deliberate added latency
- mid-range (`mode≈50`): up to `3 ms` added interactive latency, up to `10 ms` bulk
- stealth end (`mode≈100`): up to `10 ms` interactive, up to `40 ms` bulk
- never exceed the repo's existing global scheduler latency budgets

### 3) Policy / controller follow-up

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

- unknown/new profile starts conservative
- promote toward balanced only after profile bootstrap + stable delivery evidence
- promote toward the speed end only if operator policy allows and the active profile shows sustained success
- demote toward the stealth end on repeated impairment or rebinding

Carrier ordering must be:

1. explicit operator preference
2. active-profile remembered preference
3. persona fallback order
4. conservative binding order
5. always filtered by actually enabled carriers

### 4) QA / perf validation

Run lightweight real-traffic QA for all three anchor points (`mode=0`, `mode=50`, `mode=100`):

- ping RTT
- throughput check (`iperf3` / equivalent)
- rough CPU observation
- speed-end run, mid-range run, stealth-end run

Required validation coverage:

- workspace tests remain green
- reconnect on the same context reuses the correct stored profile
- switching contexts selects a different profile and does not pollute the old one
- adaptive keepalive is actually selected/used in mid-range and high-mode flows
- low-mode runs emit no deliberate pacing delay and no padding/cover
- mid-range runs stay within mild shaping caps
- high-mode runs stay within hard latency limits while using the full bounded shaping path
- no new fragmentation wire format appears
