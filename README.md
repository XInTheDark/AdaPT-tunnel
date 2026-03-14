# AdaPT Tunnel

Rust workspace implementing the **Adaptive Persona Tunnel (APT/1-core)** described in `SPEC_v1.md`.

## Current status

The project now has two layers:

1. a tested **APT protocol core**
2. an initial **user-facing VPN runtime and CLI flow** built around a combined server daemon and client

Implemented today:

- shared protocol/runtime types
- cryptographic helpers and Noise `XXpsk2` session establishment
- admission handshake (`C0 -> S1 -> C2 -> S3`)
- encrypted inner tunnel packet core with replay protection and rekey support
- carrier helpers for `D1` datagram and `S1` encrypted-stream framing
- first-cut persona, policy, and observability layers
- combined server daemon runtime over UDP (`apt-edge start`)
- client runtime over UDP (`apt-client up`)
- guided server initialization (`apt-edge init`)
- ready-to-use client bundle generation (`apt-edge add-client`)
- TUN interface wiring and basic route/NAT orchestration

## The main way to use AdaPT going forward

The intended day-to-day workflow is now CLI-driven.

### Server operator flow

#### 1) Create the server setup

```bash
sudo apt-edge init
```

This guided command creates:

- `/etc/adapt/server.toml` by default
- the server key files
- a `bundles/` directory for client packages

#### 2) Create a ready-to-use client bundle

```bash
sudo apt-edge add-client --config /etc/adapt/server.toml --name laptop
```

This command:

- allocates a client tunnel IP
- authorizes the client in `server.toml`
- generates the client static identity
- writes a client bundle directory you can copy to the device

#### 3) Start the server

```bash
sudo apt-edge start
```

### Client flow

Copy the generated client bundle contents into `/etc/adapt` on the client device, then run:

```bash
sudo apt-client up
```

If you prefer not to install the bundle into `/etc/adapt`, you can still run it directly with `--config client.toml`.

## Recommended quickstart

### On the server

```bash
sudo apt-edge init
sudo apt-edge add-client --config /etc/adapt/server.toml --name laptop
sudo apt-edge start
```

### On the client

After copying the generated bundle contents into `/etc/adapt` on the client:

```bash
sudo apt-client up
```

## CLI reference

### `apt-edge`

#### `apt-edge init`
Guided setup for a new server.

Useful options:

- `--out-dir` — where to write the server files
- `--bind` — UDP listen address
- `--public-endpoint` — public host:port clients should use
- `--endpoint-id` — deployment identifier
- `--egress-interface` — Linux egress interface for NAT
- `--tunnel-subnet` — tunnel subnet, for example `10.77.0.0/24`
- `--interface-name` — server TUN name
- `--push-route` — route(s) to push to clients
- `--dns` — DNS server(s) to suggest to clients
- `--yes` — skip prompts and use defaults for omitted values

#### `apt-edge add-client`
Generate a ready-to-use client bundle and authorize it on the server.

Useful options:

- `--config` — server config path
- `--name` — client name
- `--out-dir` — where to write the client bundle
- `--client-ip` — manually choose the client tunnel IP
- `--yes` — skip prompts for missing values

#### `apt-edge start`
Start the combined server daemon.

Useful option:

- `--config` — server config path

### `apt-client`

#### `apt-client up`
Start the VPN using a generated client bundle.

Useful option:

- `--config` — path to `client.toml`

If omitted, the client tries common default locations first.

## GitHub release assets

GitHub Actions now builds downloadable release bundles automatically when a GitHub Release is published.

Each release attaches tarballs for:

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Linux compatibility note:

- the `x86_64-unknown-linux-gnu` bundle is built on an `ubuntu-22.04` baseline instead of `ubuntu-latest`
- this keeps the shipped GNU/Linux binary from unnecessarily depending on the newest glibc available on GitHub-hosted runners

Each bundle includes:

- `apt-edge`
- `apt-client`
- `apt-tunneld`
- the deployment/testing guides
- example config files

That means most operators can download a release bundle directly instead of building from source.

## Guides

### CLI-first setup
- `guides/DEPLOYMENT.md` — step-by-step guided deployment using the user-friendly CLI flow
- `guides/MANUAL-TESTING.md` — how to validate the tunnel manually after setup

### Manual / advanced setup
- `guides/MANUAL-CONFIG-SETUP.md` — raw config-file-oriented setup and manual details
- `guides/examples/server.toml` — example server config
- `guides/examples/client.toml` — example client config

## WireGuard relationship

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

## Important current limitations

This is now much more usable than the earlier prototype, but it is still the first production-oriented cut rather than the final hardened VPN product.

Current limitations include:

- primary runtime path is UDP (`D1`) only
- server runtime target is Linux
- client runtime target is Linux/macOS
- DNS automation is not yet applied automatically; route pushing is implemented first
- advanced migration/decoy/fallback behaviors from later spec milestones are not yet complete

## Validation status

The repository currently validates with:

```bash
cargo check --workspace
cargo test --workspace
```

The README is now CLI-first on purpose; the more manual/raw setup details live under `guides/`.
