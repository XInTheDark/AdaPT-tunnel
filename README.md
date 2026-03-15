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
- carrier helpers and live runtime paths for `D1` datagram, `D2` QUIC-datagram, and `S1` encrypted-stream transport
- first-cut persona, policy, and observability layers
- combined server daemon runtime over `D1`, optional `D2`, and optional `S1` (`apt-edge start`)
- client runtime with conservative `D1 -> D2 -> S1` fallback when the optional carriers are configured (`apt-client up`)
- targeted client-side QA bring-up with tunnel ping, DNS/public-egress checks, and a download throughput probe (`apt-client test`)
- guided server initialization (`apt-edge init`)
- guided D2 enablement / certificate generation for existing deployments (`apt-edge utils enable-d2`)
- shared/per-user client bundle provisioning, temporary import handoff, and revocation (`apt-edge add-client`, `apt-client import`, `apt-edge revoke-client`)
- TUN interface wiring, route/NAT orchestration, and best-effort pushed DNS automation
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
- a `bundles/` directory for single-file client bundles
- optionally, a boot-persistent `systemd` service when you say yes to the startup prompt, pass `--install-systemd-service`, or later run `apt-edge utils install-systemd-service`

#### 2) Create a ready-to-use client bundle

```bash
sudo apt-edge add-client --config /etc/adapt/server.toml --name laptop --auth per-user
```

This command:

- allocates a client tunnel IP
- authorizes the client in `server.toml`
- defaults to a dedicated per-user admission key in the guided flow
- generates the client static identity
- writes a single `.aptbundle` file for manual fallback
- starts a short-lived temporary import service and prints an `apt-client import` command plus one-time key

If you need the older shared-deployment admission model for a specific client, pass `--auth shared` instead.

If you later need to revoke that client cleanly:

```bash
sudo apt-edge revoke-client --config /etc/adapt/server.toml --name laptop
```

#### 3) Start the server

```bash
sudo apt-edge start
```

If you enable the startup-service option during `apt-edge init`, the command also writes `/etc/systemd/system/apt-edge.service`, enables it, and starts it immediately. If you skip that during setup, you can install or refresh the same unit later with `apt-edge utils install-systemd-service --config /etc/adapt/server.toml`. In either case, you can manage it with:

```bash
sudo systemctl status apt-edge
sudo journalctl -u apt-edge -f
```

### Client flow

The easiest flow is to run the one-time import command that `apt-edge add-client` prints, then install the privileged local daemon once and connect without `sudo` afterwards:

```bash
apt-client import --server vpn.example.com:40123 --key <temporary-key>
sudo apt-client service install
apt-client up
# or run an automated QA pass that brings the tunnel up temporarily and tears it back down
apt-client test
```

That imports the generated bundle into `~/.adapt-tunnel/client.aptbundle` by default.

If you prefer the manual fallback path, copy the generated client bundle file into `~/.adapt-tunnel/client.aptbundle` on the client device, then run:

```bash
mkdir -p ~/.adapt-tunnel
cp /path/to/laptop.aptbundle ~/.adapt-tunnel/client.aptbundle
sudo apt-client service install
apt-client up
```

With that default install path, the client stores its persistent state in `~/.adapt-tunnel/client.state.toml`.
On first use, the client also creates a blank optional override file at `~/.adapt-tunnel/client.override.toml` for local non-secret tweaks.

On macOS, the client should normally let the OS auto-create a `utun` interface instead of hardcoding a custom TUN name.

When the session comes up, the client now logs the assigned tunnel IP, interface, and routes. If the server pushed DNS servers, the client also applies them automatically where the local platform supports it. The server logs when a client session is established.

If you prefer not to install the bundle into `~/.adapt-tunnel`, you can still run it directly with `--bundle /path/to/laptop.aptbundle`.
In that direct-launch case, the client creates a sidecar override file next to the bundle, for example `laptop.override.toml`.

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
sudo apt-edge add-client --config /etc/adapt/server.toml --name laptop --auth per-user
sudo apt-edge start
```

If you want the server to come back automatically after reboot, answer `y` to the startup-service prompt during `apt-edge init`, pass `--install-systemd-service`, or later run `apt-edge utils install-systemd-service --config /etc/adapt/server.toml`.

### On the client

Run the one-time `apt-client import --server ... --key ...` command shown by `apt-edge add-client`, install the local daemon once, then either connect normally or run the built-in QA pass:

```bash
sudo apt-client service install
apt-client up
# or
apt-client test
```

## CLI reference

### `apt-edge`

#### `apt-edge init`
Guided setup for a new server.

This writes a fresh `server.toml` and key set for the target directory. If you point it at an existing deployment directory, it does not preserve the current authorized client list from the old config.

Useful options:

- `--out-dir` — where to write the server files
- `--bind` — UDP listen address
- `--public-endpoint` — public host:port clients should use
- `--endpoint-id` — deployment identifier
- `--egress-interface` — Linux egress interface for NAT
- `--tunnel-subnet` — tunnel subnet, for example `10.77.0.0/24`
- `--tunnel-subnet6` — optional IPv6 tunnel subnet, for example `fd77:77::/64`
- `--interface-name` — server TUN name
- `--stream-bind` — TCP listen address for the `S1` fallback carrier
- `--stream-public-endpoint` — client-reachable `S1` endpoint, usually `host:443`
- `--stream-decoy-surface` — whether invalid unauthenticated stream input should get a decoy-like HTTP surface
- `--enable-d2` — enable the `D2` QUIC-datagram carrier and generate a pinned server certificate
- `--d2-bind` — UDP listen address for the `D2` QUIC carrier
- `--d2-public-endpoint` — client-reachable `D2` endpoint, usually `host:443`
- `--push-route` — route(s) to push to clients
- `--dns` — DNS server(s) to push to clients
- `--install-systemd-service` — write, enable, and start `/etc/systemd/system/apt-edge.service`
- `--yes` — skip prompts and use defaults for omitted values

#### `apt-edge add-client`
Generate a ready-to-use client bundle and authorize it on the server.

Useful options:

- `--config` — server config path
- `--name` — client name
- `--auth shared|per-user` — choose the admission model; `per-user` is the recommended default
- `--out-file` — where to write the single-file client bundle
- `--no-import` — skip the temporary import service and only write the local bundle file
- `--import-host` — override the public hostname/IP shown in the temporary import command
- `--import-bind` — local bind address for the temporary import service (default `0.0.0.0:0`)
- `--import-timeout-secs` — lifetime of the temporary import service
- `--client-ip` — manually choose the client tunnel IP
- `--client-ipv6` — manually choose the client tunnel IPv6 when the server IPv6 tunnel is enabled
- `--yes` — skip prompts for missing values

#### `apt-edge list-clients`
List the clients currently authorized in the server config.

Useful options:

- `--config` — server config path

#### `apt-edge revoke-client`
Remove an authorized client from the server config and delete its local credential files when they live under the config root.

Useful options:

- `--config` — server config path
- `--name` — client name to revoke
- `--yes` — skip prompts for missing values

#### `apt-edge utils enable-d2`
Enable or refresh the `D2` QUIC-datagram carrier on an existing server config.

Useful options:

- `--config` — server config path
- `--d2-bind` — UDP listen address for the `D2` QUIC carrier
- `--d2-public-endpoint` — client-reachable `D2` endpoint, usually `host:443`
- `--yes` — skip prompts for missing values

#### `apt-edge utils install-systemd-service`
Install or refresh `/etc/systemd/system/apt-edge.service` for an existing server config.

Useful options:

- `--config` — server config path
- `--yes` — skip prompts for missing values

#### `apt-edge start`
Start the combined server daemon.

Useful option:

- `--config` — server config path
- `--mode 0..100` — one-shot numeric mode override (`0` = speed, `50` = balanced, `100` = stealth)

### `apt-client`

#### `apt-client import`
Import a client bundle from the short-lived temporary endpoint printed by `apt-edge add-client`.

Useful options:

- `--server` — temporary `host:port` endpoint printed by `apt-edge add-client`
- `--key` — one-time temporary import key printed by `apt-edge add-client`
- `--bundle` — optional custom path where the imported single-file bundle should be written

By default the imported bundle is stored at `~/.adapt-tunnel/client.aptbundle`.

#### `apt-client service install|uninstall|status`
Install, remove, or inspect the privileged local client daemon that owns TUN/routes/DNS setup.

Typical first-time setup:

```bash
sudo apt-client service install
```

After that, normal client connects and tests do not need `sudo` anymore.

#### `apt-client up`
Connect through the local client daemon using a generated client bundle and stay attached to its live events.

Useful options:

- `--bundle` — path to the single-file client bundle
- `--mode 0..100` — one-shot numeric mode override (`0` = speed, `50` = balanced, `100` = stealth)
- `--carrier auto|d1|d2|s1` — one-shot preferred-carrier override

If omitted, the client first checks `~/.adapt-tunnel/client.aptbundle`, then the current-directory dev fallbacks. It also auto-creates a blank optional override TOML next to the selected bundle so local client-only settings can be edited without changing the bundle itself.

#### `apt-client test`
Bring the tunnel up temporarily through the local daemon and run a lightweight QA pass. The command automatically disconnects after the checks finish.

By default it always tests tunnel reachability with IPv4 ping, tries IPv6 ping when the session exposes an IPv6 tunnel address, and then runs DNS/public-egress/download checks when the active routes include a default route.

Useful options:

- `--bundle` — path to the single-file client bundle
- `--mode 0..100` — one-shot numeric mode override for the QA run
- `--carrier auto|d1|d2|s1` — one-shot preferred-carrier override for the QA run
- `--connect-timeout-secs` — fail if the tunnel does not come up in time
- `--ping-count` — number of ICMP probes per tunnel ping check
- `--dns-host` — hostname used for the DNS resolution check
- `--public-ip-url` — endpoint used for the public-egress-IP check
- `--speedtest-url` — override the default download throughput URL
- `--speedtest-bytes` — byte target for the default throughput endpoint
- `--speedtest-timeout-secs` — timeout for the throughput probe
- `--skip-dns`, `--skip-public-ip`, `--skip-speedtest` — disable specific checks

#### `apt-client tui`
Launch the terminal dashboard wrapper for the local daemon. It shows live status/stats/logs and lets you connect, disconnect, retry, change mode, change carrier, and change bundle from one screen.

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
- `guides/examples/client.toml` — reference for the logical client config embedded inside a bundle

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
- DNS automation is best-effort rather than universal: Linux currently uses `resolvectl`, and macOS temporarily overrides the primary network service DNS while the tunnel is up
- the live carrier set is now `D1`, optional `D2`, and optional `S1`; `H1` remains future work
- IPv6 tunnel addressing, routing, and Linux server forwarding/NAT are supported when the host IPv6 stack is enabled; guided `apt-edge init` now leaves IPv6 off unless you opt in
- the stream fallback carrier is a practical generic TCP stream runtime in this repo; it is not yet a polished outer-TLS impersonation layer
- config auto-upgrade rewrites parsed TOML with new defaulted fields, so comments/formatting in older configs may be normalized on startup

## Validation status

The repository currently validates with:

```bash
cargo check --workspace
cargo test --workspace
```

The README is now CLI-first on purpose; the more manual/raw setup details live under `guides/`.
