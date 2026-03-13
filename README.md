# AdaPT Tunnel

Rust workspace implementing the **Adaptive Persona Tunnel (APT/1-core)** described in `SPEC_v1.md`.

## Current status

The repository now contains two major layers:

1. a tested **APT protocol core**
2. an initial **production-style UDP+TUN runtime** for a combined server daemon and client

Implemented today:

- shared protocol/runtime types
- cryptographic helpers and Noise `XXpsk2` session establishment
- admission handshake (`C0 -> S1 -> C2 -> S3`)
- encrypted inner tunnel packet core with replay protection and rekey support
- carrier helpers for `D1` datagram and `S1` encrypted-stream framing
- first-cut persona, policy, and observability layers
- combined server daemon runtime over UDP (`apt-edge serve`)
- client runtime over UDP (`apt-client connect`)
- key generation helpers for server/client material
- TUN interface wiring and basic route/NAT orchestration
- manual deployment/testing guides under `guides/`

## What this repository is building

APT is **not implemented on top of WireGuard** in this repository.

Per `SPEC_v1.md`, the design uses a **WireGuard-like discipline** for the inner encrypted tunnel:

- full IP packets inside encrypted frames
- unreliable data delivery
- explicit replay protection
- rekeying/key phases

But the actual handshake and control design here are APT-specific:

- Noise `XXpsk2` admission handshake
- APT admission cookies and tickets
- APT tunnel/control frames
- APT persona/policy layers

## Production-oriented commands

### Server

Generate keys:

```bash
cargo run --release -p apt-edge -- gen-keys --out-dir /etc/adapt
```

Run the combined server daemon:

```bash
sudo cargo run --release -p apt-edge -- serve --config /etc/adapt/server.toml
```

### Client

Generate a stable client identity:

```bash
cargo run --release -p apt-client -- gen-identity --out-dir ./adapt-client
```

Connect to the server:

```bash
sudo cargo run --release -p apt-client -- connect --config ./adapt-client/client.toml
```

## Guides

- `guides/DEPLOYMENT.md` — step-by-step manual deployment
- `guides/MANUAL-TESTING.md` — manual verification checklist
- `guides/examples/server.toml` — example Linux server config
- `guides/examples/client.toml` — example client config

## Workspace layout

- `crates/apt-types` — shared domain types, configuration primitives, and protocol/runtime enums
- `crates/apt-crypto` — cryptographic suite integration, Noise key schedule, cookies, and tickets
- `crates/apt-admission` — logical admission messages (`C0`, `S1`, `C2`, `S3`) and validation pipeline
- `crates/apt-tunnel` — inner encrypted tunnel packet model, control frames, replay, and rekeying
- `crates/apt-carriers` — carrier abstraction plus concrete helpers such as `D1` and `S1`
- `crates/apt-runtime` — production runtime/config/TUN/route orchestration layer
- `crates/apt-persona` — persona generation, scheduler knobs, and shaping profiles
- `crates/apt-policy` — local-normality model, policy controller, and migration decisions
- `crates/apt-observability` — privacy-aware logging, metrics, and tracing helpers
- `apps/apt-client` — production client entrypoint
- `apps/apt-edge` — combined production server daemon entrypoint
- `apps/apt-tunneld` — compatibility alias for the combined server daemon

## Important current limitations

The current runtime is designed to be **usable** for early manual deployments, but it is still the first production-oriented cut rather than a fully hardened final VPN product.

Notable limitations still being worked on:

- primary runtime path is UDP (`D1`) only
- server runtime target is Linux
- client runtime target is Linux/macOS, but automated runtime tests are still lighter than the final desired state
- DNS automation is not yet applied automatically; route pushing is implemented first
- advanced migration/decoy/fallback behaviors from later spec milestones are not yet complete

## Validation status

The repository currently builds successfully with:

```bash
cargo check --workspace
```

As the runtime continues to harden, the README and `guides/` directory will remain the source of truth for operator-facing setup.
