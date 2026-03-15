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
- **Status:** multi-profile persistence/context discovery, runtime hot-path CPU hardening, bounded histogram local-normality, adaptive keepalive learning, continuous numeric-mode persona/scheduler shaping, and the mode-only controller/admission negotiation rewrite are now shipped
- **Primary remaining goal:** finish the spec-credible adaptive runtime by:
  - validating real-traffic behavior and CPU/latency envelopes at the three reference points
- **Performance intent:**
  - mode near `0`: no meaningful throughput/latency penalty
  - mode around `50`: mild impact only
  - mode near `100`: full shaping, but still bounded and practical

## Latest shipped chunk impact note

- **Chunk:** mode-only controller + admission negotiation rewrite
- **Latency impact:** control-plane overhead remains negligible; runtime shaping now follows the controller’s numeric current mode instead of a coarse bucketed state, so new/untrusted profiles may begin slightly more conservative before decaying toward the negotiated baseline
- **Bandwidth impact:** no admission bandwidth change of note; adaptive padding/cover decisions now follow numeric controller output directly instead of legacy preset remapping
- **CPU impact:** negligible steady-state controller overhead; per-tick/controller bookkeeping remains trivial relative to tunnel I/O
- **Notes:** admission `C0/S1/S3` negotiation is now numeric-mode-based end-to-end, `SessionPolicy` no longer carries runtime mode presets, controller transitions are explicit numeric adjustments from richer signals, fallback ordering now layers explicit preference + remembered profile + persona + conservative ordering, and live shaping/keepalive behavior consumes the controller’s numeric mode rather than converting through `speed/balanced/stealth`

## Numeric mode model

The Phase 3 end state remains **`mode`-only** across operator-facing config, CLI, runtime state, docs, telemetry, and tests.

- **Range:** `0..=100`
- **Meaning:**
  - lower values = more throughput-oriented, lower-latency, lower-padding behavior
  - higher values = more conservative, stealth-heavy, padding/shaping-friendly behavior
- **Reference points for compatibility and QA:**
  - `0` = previous `speed`
  - `50` = previous `balanced`
  - `100` = previous `stealth`
- **Scalar design requirements:**
  - major runtime knobs must scale monotonically with `mode`, including pacing delay budget, padding budget, idle-cover eligibility, batching aggressiveness, soft-packing targets, idle-resume ramp, and controller conservatism
  - neighboring `mode` values should produce small bounded behavior changes rather than cliff-edge flips
  - piecewise-linear curves or interpolated lookup tables are acceptable, but the implementation must not primarily switch on three buckets
- **Compatibility rule:**
  - legacy named presets may still be accepted only for migration/import compatibility and must be rewritten out as numeric `mode` values on the next save
  - the live runtime, admission negotiation, controller, and persisted learning state must not convert numeric `mode` values back into legacy preset enums or bucketed negotiation states

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
| QA/perf validation | pending | Real-traffic checks at `mode=0`, `mode=50`, and `mode=100`, plus workspace/integration coverage for adaptive behavior | Validation-only cost |

## Next tasks

1. Run workspace tests plus mode-by-mode smoke/perf checks, with special attention to CPU under `mode=0`, then update this file again with the next shipped chunk and impact note.
2. Record lightweight real-traffic QA results for latency/throughput/CPU at `mode=0`, `mode=50`, and `mode=100`, and confirm that the shipped numeric controller behavior stays within the intended envelopes.

## Detailed implementation requirements for remaining chunks

### QA / perf validation

Run lightweight real-traffic QA for all three reference points (`mode=0`, `mode=50`, `mode=100`):

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
- negotiated session mode is numeric end-to-end and no longer logs/uses legacy preset states
- mid-range runs stay within mild shaping caps
- high-mode runs stay within hard latency limits while using the full bounded shaping path
- no new fragmentation wire format appears
