# AdaPT Tunnel

Rust workspace implementing the AdaPT tunnel core and the current v2 **H2 public-session** product flow.

## Current status

The `v2` branch now ships a real H2 API-sync baseline end to end:

- `apt-admission` runs on wrapper-free `UG1` / `UG2` / `UG3` / `UG4` envelopes
- `apt-surface-h2` models the public API-sync surface and its legal hidden-upgrade slots
- `apt-runtime` drives real Hyper `h2c` and rustls/TLS H2 sessions, completes hidden upgrade, and carries encrypted tunnel packets inside ordinary API-sync request/response bodies
- `apt-edge`, `apt-client`, `apt-clientd`, and `apt-tunneld` now use the H2 flow directly
- generated bundles and configs are H2-first and pin the server certificate by default
- `apt-harness` includes H2-oriented browser/backend fixture comparison support

Quick validation commands:

```bash
cargo test -q -p apt-runtime runtime::surface_h2::tests::h2c
cargo test -q -p apt-runtime runtime::surface_h2::tests::tls
cargo test -q
```

## Main workflow

### Server operator flow

#### 1) Initialize the server

```bash
sudo apt-edge init
```

When `apt-edge init` asks for the client-facing endpoint, use the server's **real reachable host:port**, for example:

- `203.0.113.10:443`
- `api.example.com:443`

The guided setup creates:

- `/etc/adapt/server.toml` by default
- server admission/static/cookie/ticket keys
- `server-certificate.pem` and `server-private-key.pem` for the H2 API-sync surface
- `bundles/` for single-file client bundles
- optionally a boot-persistent `systemd` service

If you already know the public authority/host name the H2 surface should present, pass `--authority api.example.com`.

#### 2) Generate a client bundle

```bash
sudo apt-edge add-client --config /etc/adapt/server.toml --name laptop --auth per-user
```

This command:

- allocates the client tunnel IP
- authorizes the client in `server.toml`
- defaults to a dedicated per-user admission key in the guided flow
- generates the client static identity
- writes a single `.aptbundle` file
- starts a temporary import service and prints a one-time `apt-client import` command unless you pass `--no-import`

To revoke a client later:

```bash
sudo apt-edge revoke-client --config /etc/adapt/server.toml --name laptop
```

#### 3) Start the server

```bash
sudo apt-edge start --config /etc/adapt/server.toml
```

If you enabled the startup-service option during `apt-edge init`, the server is also installed and started under `systemd`.

Useful follow-up commands:

```bash
sudo systemctl status apt-edge
sudo journalctl -u apt-edge -f
```

### Client flow

The easiest path is:

```bash
apt-client import --server api.example.com:40123 --key <temporary-key>
sudo apt-client service install
apt-client up
# or run the built-in QA pass
apt-client test
```

That imports the generated bundle into `~/.adapt-tunnel/client.aptbundle` by default.

Manual fallback:

```bash
mkdir -p ~/.adapt-tunnel
cp /path/to/laptop.aptbundle ~/.adapt-tunnel/client.aptbundle
sudo apt-client service install
apt-client up
```

With the default install path:

- bundle: `~/.adapt-tunnel/client.aptbundle`
- state: `~/.adapt-tunnel/client.state.toml`
- local override file: `~/.adapt-tunnel/client.override.toml`

On macOS, the client should normally let the OS auto-create a `utun` interface instead of hardcoding a custom TUN name.

## Recommended quickstart

### On the server

```bash
sudo apt-edge init
sudo apt-edge add-client --config /etc/adapt/server.toml --name laptop --auth per-user
sudo apt-edge start
```

### On the client

```bash
apt-client import --server <temporary-host:port> --key <temporary-key>
sudo apt-client service install
apt-client up
```

Or run the QA helper instead of a persistent session:

```bash
apt-client test
```

## CLI reference

### `apt-edge init`

Guided setup for a new H2 API-sync server.

Useful options:

- `--out-dir` — where to write the server files
- `--bind` — TCP/TLS listen address for the public H2 service
- `--public-endpoint` — public host:port clients should use
- `--authority` — HTTP authority / host name exposed by the public API-sync surface
- `--endpoint-id` — deployment identifier
- `--egress-interface` — Linux egress interface for NAT
- `--tunnel-subnet` — tunnel subnet, for example `10.77.0.0/24`
- `--tunnel-subnet6` — optional IPv6 tunnel subnet, for example `fd77:77::/64`
- `--interface-name` — server TUN name
- `--push-route` — route(s) to push to clients
- `--dns` — DNS server(s) to push to clients
- `--install-systemd-service` — write, enable, and start `/etc/systemd/system/apt-edge.service`
- `--yes` — skip prompts and use defaults for omitted values

### `apt-edge add-client`

Generate a ready-to-use H2 client bundle and authorize it on the server.

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

### `apt-edge list-clients`

List the clients currently authorized in the server config.

Useful options:

- `--config` — server config path

### `apt-edge revoke-client`

Remove an authorized client from the server config and delete its local credential files when they live under the config root.

Useful options:

- `--config` — server config path
- `--name` — client name to revoke
- `--yes` — skip prompts for missing values

### `apt-edge utils install-systemd-service`

Install or refresh `/etc/systemd/system/apt-edge.service` for an existing server config.

Useful options:

- `--config` — server config path
- `--yes` — skip prompts for missing values

### `apt-edge start`

Start the combined H2 server daemon.

Useful options:

- `--config` — server config path
- `--mode 0..100` — one-shot numeric mode override (`0` = speed, `50` = balanced, `100` = stealth)

### `apt-client import`

Import a client bundle from the short-lived temporary endpoint printed by `apt-edge add-client`.

Useful options:

- `--server` — temporary `host:port` endpoint printed by `apt-edge add-client`
- `--key` — one-time temporary import key printed by `apt-edge add-client`
- `--bundle` — optional custom path where the imported single-file bundle should be written

### `apt-client service install|uninstall|status`

Install, remove, or inspect the privileged local client daemon that owns TUN/routes/DNS setup.

Typical first-time setup:

```bash
sudo apt-client service install
```

### `apt-client up`

Connect through the local client daemon using a generated client bundle and stay attached to its live events.

Useful options:

- `--bundle` — path to the single-file client bundle
- `--mode 0..100` — one-shot numeric mode override (`0` = speed, `50` = balanced, `100` = stealth)

### `apt-client test`

Bring the tunnel up temporarily through the local daemon and run a lightweight QA pass.

Useful options:

- `--bundle` — path to the single-file client bundle
- `--mode 0..100` — one-shot numeric mode override for the QA run
- `--connect-timeout-secs` — fail if the tunnel does not come up in time
- `--ping-count` — number of ICMP probes per tunnel ping check
- `--dns-host` — hostname used for the DNS resolution check
- `--public-ip-url` — endpoint used for the public-egress-IP check
- `--speedtest-url` — override the default download throughput URL
- `--speedtest-bytes` — byte target for the default throughput endpoint
- `--speedtest-timeout-secs` — timeout for the throughput probe
- `--skip-dns`, `--skip-public-ip`, `--skip-speedtest` — disable specific checks

### `apt-client tui`

Launch the terminal dashboard wrapper for the local daemon. It shows live status, stats, logs, bundle selection, and mode control for the H2 session flow.

## Guides

- `guides/DEPLOYMENT.md` — step-by-step guided H2 deployment
- `guides/MANUAL-CONFIG-SETUP.md` — raw config-file reference for the current H2 product flow
- `guides/MANUAL-TESTING.md` — manual validation checklist for H2 deployments
- `guides/examples/server.toml` — reference H2 server config
- `guides/examples/client.toml` — reference logical client config embedded inside a bundle

## Important current limitations

- server runtime target is Linux
- client runtime target is Linux/macOS
- DNS automation is still best-effort rather than universal
- the shipped product path is H2 API-sync; the H3 sibling remains roadmap work
- the default generated TLS identity is self-signed and aimed at self-contained/lab deployments unless you replace it with origin-backed certificate material
- IPv6 tunnel addressing, routing, and Linux server forwarding/NAT are supported when the host IPv6 stack is enabled
- H2 is testing-ready, but the broader origin-backed deployment polish and H3 follow-on work are still in progress

## Validation status

The repository currently validates with:

```bash
cargo test -q
```
