# Architecture map

This file maps the `APT/1-core` spec (`SPEC_v1.md`) onto the initial Rust workspace scaffold.

## Design principles for the scaffold

- Keep protocol logic in libraries and keep binaries thin.
- Separate cryptographic concerns from wire/message state machines.
- Keep carrier bindings independent from the inner tunnel core.
- Treat persona generation and policy control as first-class subsystems, not ad hoc helpers.
- Avoid over-freezing APIs before the first implementation slice is agreed.

## Spec-to-crate mapping

### `crates/apt-types`

Owns shared enums, coarse path classes, policy mode types, capability bitmaps, session identifiers, and common configuration shapes.

Primary spec coverage:
- Sections 5, 10, 13, 18, 19, 20, 25

### `crates/apt-crypto`

Owns cryptographic suite configuration and helpers:
- Noise `XXpsk2` integration
- HKDF-based key schedule
- admission AEAD helpers
- anti-amplification cookies
- resumption ticket sealing/opening
- future hybrid PQ integration point

Primary spec coverage:
- Sections 6, 7.3, 10, 12, 14, 15

### `crates/apt-admission`

Owns the admission-plane state machine:
- logical message definitions for `C0`, `S1`, `C2`, `S3`
- validation ordering
- replay resistance hooks
- stateless-until-validated server flow

Primary spec coverage:
- Sections 4.1, 8, 9, 10, 11, 15

### `crates/apt-tunnel`

Owns the inner encrypted tunnel:
- tunnel packet model
- encrypted frame definitions
- replay window state
- key-phase transitions / rekey triggers
- path challenge / response plumbing

Primary spec coverage:
- Sections 4.2, 12, 13, 14, 21, 22, 23

### `crates/apt-carriers`

Owns the outer transport abstraction:
- trait(s) for carrier embedding
- datagram binding `D1`
- stream binding `S1`
- invalid-input behaviour and close semantics
- migration hooks shared with policy/tunnel layers

Primary spec coverage:
- Sections 8, 18, 19, 21, 22, 23

### `crates/apt-persona`

Owns the bounded persona generator and shaping-facing configuration:
- persona inputs/outputs
- pacing families, burst targets, padding budgets
- keepalive and idle-resume strategies
- scheduler-facing shaping profile structs

Primary spec coverage:
- Sections 16, 18, 25

### `crates/apt-policy`

Owns adaptive runtime decisions:
- local-normality profiles
- network-context handling
- poisoning-resistant updates
- policy-mode transitions
- carrier migration decisions

Primary spec coverage:
- Sections 17, 18.4, 20, 21, 22, 24, 25

### `crates/apt-observability`

Owns privacy-aware operator signals:
- coarse structured logs
- metrics names / labels
- debug gating rules
- optional event tracing adapters

Primary spec coverage:
- Sections 23, 24

### `apps/apt-client`

Thin binary that wires together:
- local network observation
- policy controller
- admission and tunnel session lifecycle
- TUN/TAP or packet source integration later

### `apps/apt-edge`

Thin binary for the exposed rendezvous role:
- carrier listeners
- admission handling
- cookie issuance / validation
- edge-to-tunnel-node coordination when deployed split-role

### `apps/apt-tunneld`

Thin binary for the tunnel-node role:
- session termination
- packet forwarding
- control-plane actions like rekey/migration support

## Boundary rules to preserve during implementation

1. `apt-carriers` must never become the owner of inner tunnel semantics.
2. `apt-admission` should operate on logical messages; carrier-specific serialization lives outside it.
3. `apt-crypto` should expose explicit APIs for secrets and key derivation without dictating transport logic.
4. `apt-persona` should output bounded behavioural parameters, not direct network I/O.
5. `apt-policy` should decide *when* to adapt or migrate; `apt-carriers` and `apt-tunnel` execute those decisions.
6. `apt-observability` must only emit coarse metadata by default.

## Initial milestone target

The workspace is arranged so the first real implementation slice can focus on **Milestone 1** from the spec:
- admission handshake
- inner tunnel core
- one datagram binding
- one stream binding
- simple bounded persona engine
