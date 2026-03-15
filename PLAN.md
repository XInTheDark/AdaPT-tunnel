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
- **Status:** multi-profile persistence/context discovery, runtime hot-path CPU hardening, bounded histogram local-normality, adaptive keepalive learning, and continuous numeric-mode persona/scheduler shaping are now shipped
- **Primary remaining goal:** finish the spec-credible adaptive runtime by:
  - upgrading the controller to consume richer signals and apply bounded `mode` adjustments
  - validating real-traffic behavior and CPU/latency envelopes at the anchor modes
- **Performance intent:**
  - mode near `0`: no meaningful throughput/latency penalty
  - mode around `50`: mild impact only
  - mode near `100`: full shaping, but still bounded and practical

## Latest shipped chunk impact note

- **Chunk:** persona/scheduler runtime wiring + soft packing
- **Latency impact:** `mode=0` remains `~0 ms`; mid-range shaping now stays within the `0-3 ms` interactive / `0-10 ms` bulk design envelope; high-mode pacing is capped within the `0-10 ms` interactive / `0-40 ms` bulk envelope
- **Bandwidth impact:** `mode=0` remains effectively `0%`; mid-range steady padding stays within `0-2%`; high-mode steady padding now tracks `2-8%` with bounded probationary increases during idle-resume / unbootstrapped phases
- **CPU impact:** `mode=0` remains near the previous baseline; mid/high modes now pay bounded scheduling/shaping overhead in line with the planned `~0-2%` / `~1-5%` envelopes
- **Notes:** persona generation now scales continuously from numeric `mode`, live runtime scheduling consumes pacing family / burst targets / packet-size bins / idle-resume ramp / keepalive style / fallback order / migration threshold / soft packing preferences, and stream-path batching/pacing now changes monotonically with `mode` instead of switching on old preset buckets

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
| Policy/controller follow-up | pending | Feed richer signals into the controller, remember per-profile carrier preference/permissiveness, and apply bounded numeric `mode` increases/decreases | Negligible runtime overhead |
| QA/perf validation | pending | Real-traffic checks at `mode=0`, `mode=50`, and `mode=100`, plus workspace/integration coverage for adaptive behavior | Validation-only cost |

## Next tasks

1. Expand the controller to consume richer delivery/impairment/rebinding/idle-timeout signals and to adjust `mode` conservatively with remembered per-profile preferences.
2. Run workspace tests plus mode-by-mode smoke/perf checks, with special attention to CPU under `mode=0`, then update this file again with the next shipped chunk and impact note.

## Detailed implementation requirements for remaining chunks

### 1) Policy / controller follow-up

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

### 2) QA / perf validation

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
