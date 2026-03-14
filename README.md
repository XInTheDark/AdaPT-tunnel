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
- carrier helpers and live runtime paths for `D1` datagram and `S1` encrypted-stream transport
- first-cut persona, policy, and observability layers
- combined server daemon runtime over `D1` + `S1` (`apt-edge start`)
- client runtime with conservative `D1 -> S1` fallback (`apt-client up`)
- guided server initialization (`apt-edge init`)
- ready-to-use client bundle generation (`apt-edge add-client`)
- TUN interface wiring and basic route/NAT orchestration
- authenticated path revalidation and sparse standby probing

## The main way to use AdaPT going forward

The intended day-to-day workflow is now CLI-driven.

### Server operator flow

#### 1) Create the server setup

```bash
sudo apt-edge init
```

When `apt-edge init` asks for the client-facing endpoint, use the server's **real reachable address and port**:

- a public IP is fine, for example `203.0.113.10:51820`
- a DNS name is also fine, for example `vpn.example.com:51820`

Do **not** leave an example placeholder there. Whatever you enter is copied into generated client bundles.

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

On macOS, the client should normally let the OS auto-create a `utun` interface instead of hardcoding a custom TUN name.

When the session comes up, the client now logs the assigned tunnel IP, interface, and routes. The server logs when a client session is established.

If you prefer not to install the bundle into `/etc/adapt`, you can still run it directly with `--config client.toml`.

## Recommended quickstart

### Install from the latest GitHub Release

If you want a download-and-install flow instead of manually unpacking a tarball, use the installer script:

```bash
curl -fsSL https://raw.githubusercontent.com/XInTheDark/AdaPT-tunnel/master/scripts/install.sh | sudo bash -s -- install
```

By default, the installer:

- auto-detects the current platform
- prefers the static `x86_64-unknown-linux-musl` asset on `x86_64` Linux
- installs binaries into `/usr/local/bin`
- installs docs/update metadata into `/usr/local/share/adapt`
- installs an updater command named `adapt-install`
- installs an uninstall command named `adapt-uninstall`

To update an existing installation later:

```bash
sudo adapt-install update
```

To remove the installed release binaries/docs later:

```bash
sudo adapt-uninstall
```

To also remove the standard config and state directories:

```bash
sudo adapt-uninstall --purge-all
```

You can point the installer at another GitHub repo or base if needed:

```bash
curl -fsSL https://raw.githubusercontent.com/XInTheDark/AdaPT-tunnel/master/scripts/install.sh | sudo bash -s -- install --repo your-org/AdaPT-tunnel
```

For GitHub Enterprise or other custom endpoints, the same script also supports `--api-base` and `--web-base`.

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
- `--stream-bind` — TCP listen address for the `S1` fallback carrier
- `--stream-public-endpoint` — client-reachable `S1` endpoint, usually `host:443`
- `--stream-decoy-surface` — whether invalid unauthenticated stream input should get a decoy-like HTTP surface
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
- `--mode stealth|balanced|speed` — one-shot runtime mode override

### `apt-client`

#### `apt-client up`
Start the VPN using a generated client bundle.

Useful option:

- `--config` — path to `client.toml`
- `--mode stealth|balanced|speed` — one-shot runtime mode override
- `--carrier auto|d1|s1` — one-shot preferred-carrier override

If omitted, the client tries common default locations first.

## GitHub release assets

GitHub Actions now builds downloadable release bundles automatically when a GitHub Release is published.

Each release attaches tarballs for:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Linux compatibility note:

- the `x86_64-unknown-linux-musl` bundle is a static Linux build and is the safest default choice when you are deploying onto an unknown or older Linux distribution
- the `x86_64-unknown-linux-gnu` bundle is built on an `ubuntu-22.04` baseline instead of `ubuntu-latest`
- this keeps the shipped GNU/Linux binary from unnecessarily depending on the newest glibc available on GitHub-hosted runners

Each bundle includes:

- `apt-edge`
- `apt-client`
- `apt-tunneld`
- `install.sh`
- `uninstall.sh`
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

- server runtime target is Linux
- client runtime target is Linux/macOS
- DNS automation is not yet applied automatically; route pushing is implemented first
- the live fallback set is now `D1` + `S1`; `D2` and `H1` are still future work
- IPv6 tunnel/runtime handling is still incomplete
- the stream fallback carrier is a practical generic TCP stream runtime in this repo; it is not yet a polished outer-TLS impersonation layer
- config auto-upgrade rewrites parsed TOML with new defaulted fields, so comments/formatting in older configs may be normalized on startup

## Validation status

The repository currently validates with:

```bash
cargo check --workspace
cargo test --workspace
```

The README is now CLI-first on purpose; the more manual/raw setup details live under `guides/`.
