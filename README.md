# AdaPT Tunnel

Rust implementation of the **Adaptive Persona Tunnel (APT/1-core)** from `SPEC_v1.md`, including a production-oriented UDP/TUN runtime for a first usable VPN release.

## Current status

The repository now contains:

- the APT protocol core
  - Noise `XXpsk2` admission handshake
  - encrypted tunnel packet core
  - replay protection
  - reliable control frames
  - rekey support
- a production-oriented runtime layer
  - combined Linux server daemon
  - Linux/macOS client runtime
  - UDP `D1` transport
  - TUN interface wiring
  - route installation on client
  - Linux forwarding/NAT setup on server
  - shared-key authentication with per-client static Noise identities
- operational CLIs
  - `apt-edge serve`
  - `apt-client connect`
  - key-generation commands for server/client bootstrap

## WireGuard relationship

APT is **not layered on top of WireGuard** in this repository.

It uses a **WireGuard-like encrypted datagram tunnel discipline** for the inner dataplane:

- full IP packets inside encrypted frames
- unreliable delivery for data packets
- replay protection
- rekey/key-phase transitions

But the actual control and handshake layers are APT-specific:

- `C0 -> S1 -> C2 -> S3` admission flow
- APT cookies and resumption tickets
- APT tunnel/control frames
- APT persona/policy layers

## Supported v1 deployment target

- **server:** Linux
- **client:** Linux and macOS
- **carrier:** `D1` over UDP
- **topology:** combined server daemon (`apt-edge serve`)
- **auth:** one shared deployment admission key plus one static client identity per authorized client

## Quick start

### 1. Generate server-side material

```bash
cargo run --release -p apt-edge -- gen-keyset --out-dir /etc/adapt
```

This writes:

- `shared-admission.key`
- `server-static-private.key`
- `server-static-public.key`
- `cookie.key`
- `ticket.key`

### 2. Generate a client identity

```bash
cargo run --release -p apt-client -- gen-identity --out-dir /etc/adapt/peers/laptop
```

This writes:

- `client-static-private.key`
- `client-static-public.key`

### 3. Create configs

Use the included examples:

- `docs/examples/server.example.toml`
- `docs/examples/client.example.toml`

### 4. Start the server

```bash
cargo run --release -p apt-edge -- serve --config /etc/adapt/server.toml
```

### 5. Connect the client

```bash
cargo run --release -p apt-client -- connect --config /etc/adapt/client.toml
```

For a fuller setup walkthrough, see `docs/DEPLOYMENT.md`.

## Workspace layout

- `crates/apt-types` — shared domain types and protocol/runtime enums
- `crates/apt-crypto` — cryptographic suite integration, Noise key schedule, cookies, and tickets
- `crates/apt-admission` — `C0`, `S1`, `C2`, `S3` admission logic
- `crates/apt-tunnel` — encrypted tunnel packet model, replay protection, and rekeying
- `crates/apt-carriers` — carrier helpers (`D1`, `S1`)
- `crates/apt-runtime` — production runtime, config loading, UDP/TUN orchestration, and deployment helpers
- `crates/apt-persona` — persona generation and shaping defaults
- `crates/apt-policy` — policy controller and local-normality support
- `crates/apt-observability` — privacy-aware tracing and telemetry helpers
- `apps/apt-client` — production client CLI
- `apps/apt-edge` — combined production server CLI
- `apps/apt-tunneld` — compatibility alias for the combined server runtime

## Validation

The repository currently validates with:

```bash
cargo check --workspace
cargo test --workspace
```

## Notes

- The runtime is currently **IPv4-focused** for interface assignment and routed traffic.
- Linux server NAT currently uses `iptables`.
- Split-role server deployment and richer multi-carrier migration remain future work on top of the current usable baseline.
