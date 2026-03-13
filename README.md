# AdaPT Tunnel

Rust workspace implementing a first-cut prototype of the **Adaptive Persona Tunnel (APT/1-core)** described in `SPEC_v1.md`.

## Current status

This repository is **past scaffolding** and now contains a working protocol-core prototype:

- shared protocol/runtime types
- cryptographic helpers and Noise `XXpsk2` session establishment
- admission handshake (`C0 -> S1 -> C2 -> S3`)
- encrypted inner tunnel packet core with replay protection and rekey support
- carrier helpers for `D1` datagram and `S1` encrypted-stream framing
- first-cut persona, policy, and observability layers
- development/demo CLIs for client, edge, and tunnel-node roles

Current validation:

- `cargo test --workspace` passes
- `cargo run -q -p apt-client -- demo` passes
- `cargo run -q -p apt-edge -- demo` passes
- `cargo run -q -p apt-tunneld -- demo` passes

## What this is right now

The codebase currently provides a **protocol-core prototype**, not yet a finished deployable VPN product.

Implemented:

- APT admission and tunnel state machines
- session secret derivation and ticket/cookie helpers
- encrypted tunnel frame model and reliable control path
- bounded persona and conservative policy logic

Not yet implemented for production use:

- real long-running server/client daemons
- socket-based remote transport runtime
- TUN/TAP integration and OS routing
- packet forwarding / NAT / egress plumbing
- production configuration, provisioning, and persistence
- integration hardening, benchmarking, and deployment packaging

## WireGuard relationship

APT is **not implemented on top of WireGuard** in this repository.

Per `SPEC_v1.md`, the design uses a **WireGuard-like discipline** for the inner encrypted tunnel:

- full IP packets inside encrypted frames
- unreliable data delivery
- explicit replay protection
- key phases and rekeying

But the actual handshake and control design here are APT-specific:

- Noise `XXpsk2` admission handshake
- APT admission cookies, tickets, and policy/persona layers
- APT tunnel/control frames

## Workspace layout

- `crates/apt-types` — shared domain types, configuration primitives, and protocol/runtime enums
- `crates/apt-crypto` — cryptographic suite integration, Noise key schedule, cookies, and tickets
- `crates/apt-admission` — logical admission messages (`C0`, `S1`, `C2`, `S3`) and validation pipeline
- `crates/apt-tunnel` — inner encrypted tunnel packet model, control frames, replay, and rekeying
- `crates/apt-carriers` — carrier abstraction plus concrete helpers such as `D1` and `S1`
- `crates/apt-persona` — persona generation, scheduler knobs, and shaping profiles
- `crates/apt-policy` — local-normality model, policy controller, and migration decisions
- `crates/apt-observability` — privacy-aware logging, metrics, and tracing helpers
- `apps/apt-client` — current development/demo client entrypoint
- `apps/apt-edge` — current development/demo edge entrypoint
- `apps/apt-tunneld` — current development/demo tunnel-node entrypoint
- `docs/ARCHITECTURE.md` — spec-to-module mapping and boundary notes
- `PLAN.md` — phased implementation plan

## Near-term direction

The next major milestone is to evolve this prototype into a **fully usable VPN runtime** by adding:

- real transport listeners/connectors
- daemon modes and config loading
- TUN/TAP integration
- forwarding/NAT
- deployment-oriented testing and hardening
