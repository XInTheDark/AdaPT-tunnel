# Guided deployment flow

This is the **recommended** way to deploy AdaPT now.

It uses the user-friendly CLI flow instead of hand-editing every file first.

## Supported targets for this flow

- server: Linux
- client: Linux or macOS
- transport: `D1` over UDP with optional `D2` over QUIC datagrams
- auth model: shared-deployment or per-user admission keys; the guided flow now defaults to per-user

## 1. Get the binaries

You have two supported options.

### Option A: use the installer script

The fastest way to get a suitable release onto a machine is:

```bash
curl -fsSL https://raw.githubusercontent.com/XInTheDark/AdaPT-tunnel/master/scripts/install.sh | sudo bash -s -- install
```

By default, that script:

- auto-detects the host platform
- prefers the static `x86_64-unknown-linux-musl` asset on `x86_64` Linux
- installs `apt-edge`, `apt-client`, `apt-clientd`, and `apt-tunneld` into `/usr/local/bin`
- installs docs and update metadata into `/usr/local/share/adapt`
- installs an updater command named `adapt-install`
- installs an uninstall command named `adapt-uninstall`

To update later:

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

If you need to install from a fork or alternate repository:

```bash
curl -fsSL https://raw.githubusercontent.com/XInTheDark/AdaPT-tunnel/master/scripts/install.sh | sudo bash -s -- install --repo your-org/AdaPT-tunnel
```

For GitHub Enterprise or another non-default GitHub base, the same script also accepts `--api-base` and `--web-base`.

### Option B: download a GitHub Release bundle

When a GitHub Release is published, CI attaches ready-to-run tarballs for supported targets.

For `x86_64` Linux servers and clients:

- prefer the `x86_64-unknown-linux-musl` bundle when you want the most portable static Linux binary
- the `x86_64-unknown-linux-gnu` bundle is also published, but it is still a glibc-linked build; it is only kept on an `ubuntu-22.04` baseline so it does not pick up the newest glibc requirement from `ubuntu-latest`

Each release bundle contains:

- `apt-edge`
- `apt-client`
- `apt-clientd`
- `apt-tunneld`
- `install.sh`
- `uninstall.sh`
- the guides in this directory
- example config files

After extracting the tarball, the binaries live under `bin/`.

### Option C: build from source

From the repo root:

```bash
cargo build --release
```

Main binaries:

- `target/release/apt-edge`
- `target/release/apt-client`
- `target/release/apt-clientd`
- `target/release/apt-tunneld`

## 2. Initialize the server

On the server:

```bash
sudo ./target/release/apt-edge init
```

The command walks you through the main values, then creates:

- `/etc/adapt/server.toml` by default
- the server key files
- a `bundles/` directory for single-file client bundles
- optional `D2` certificate/key files when you enable `D2`
- optional `/etc/systemd/system/apt-edge.service` when you enable startup during `apt-edge init`, or later via `apt-edge utils install-systemd-service`

If you enable the `D2` QUIC-datagram carrier, the resulting config also carries:

- `d2_bind` for the server-side QUIC listener, typically `0.0.0.0:443`
- `d2_public_endpoint` for the client-facing `D2` endpoint, typically `host:443`
- `d2_certificate` and `d2_private_key` pointing at the generated pinned server identity files

Important:

- for the client-facing endpoint, enter the server's **real client-reachable IP:port or DNS name:port**
- using the raw public IP is completely fine
- whatever you enter there becomes `public_endpoint` in `server.toml` and `server_addr` in generated client bundles
- do not leave an example placeholder there unless that hostname actually resolves for your clients
- if you want the server to survive reboots automatically, answer `y` to the startup-service prompt, pass `--install-systemd-service`, or later run `apt-edge utils install-systemd-service --config /etc/adapt/server.toml`

You can also run it non-interactively, for example:

```bash
./target/release/apt-edge init \
  --out-dir /etc/adapt \
  --bind 0.0.0.0:51820 \
  --public-endpoint vpn.example.com:51820 \
  --enable-d2 \
  --d2-bind 0.0.0.0:443 \
  --d2-public-endpoint vpn.example.com:443 \
  --endpoint-id adapt-prod \
  --egress-interface eth0 \
  --tunnel-subnet 10.77.0.0/24 \
  --interface-name aptsrv0 \
  --push-route 0.0.0.0/0 \
  --dns 1.1.1.1 \
  --dns 1.0.0.1 \
  --install-systemd-service \
  --yes
```

For an existing deployment that already has a `server.toml`, you can enable or refresh `D2` in place with:

```bash
./target/release/apt-edge utils enable-d2 --config /etc/adapt/server.toml --d2-public-endpoint vpn.example.com:443

# install or refresh the boot-time systemd unit later if needed
sudo ./target/release/apt-edge utils install-systemd-service --config /etc/adapt/server.toml
```

## 3. Generate a client bundle

On the server:

```bash
./target/release/apt-edge add-client --config /etc/adapt/server.toml --name laptop --auth per-user
```

This command automatically:

- allocates a free client tunnel IP
- creates a dedicated per-user admission key by default
- generates the client's static keypair
- updates the server's authorized peer list
- writes a single `.aptbundle` file you can copy to the client device

If you need the older shared-deployment model for a particular client, pass `--auth shared`.

You can also override the output file and client IP if needed. The IPv6 assignment is optional and should only be set if the server config has tunnel IPv6 enabled:

```bash
./target/release/apt-edge add-client \
  --config /etc/adapt/server.toml \
  --name laptop \
  --auth per-user \
  --out-file /tmp/laptop.aptbundle \
  --client-ip 10.77.0.2
```

If a device is retired or lost, revoke it cleanly on the server with:

```bash
./target/release/apt-edge revoke-client --config /etc/adapt/server.toml --name laptop
```

## 4. Start the server

On the Linux server:

```bash
sudo ./target/release/apt-edge start --config /etc/adapt/server.toml
```

If you enabled startup-service installation during `apt-edge init`, the server is already enabled and started under `systemd`, so the most useful follow-up commands become:

```bash
sudo systemctl status apt-edge
sudo journalctl -u apt-edge -f
```

Useful one-shot overrides:

- `--mode 100` — most conservative behavior and the default
- `--mode 50` — balanced midpoint
- `--mode 0` — fastest / lowest-shaping anchor

When `d2_bind` is configured, the server listens on the UDP `D1` address plus the optional `D2` QUIC address.

The server must run with privileges sufficient to:

- create/configure the TUN interface
- enable IPv4 forwarding when configured
- install NAT rules when configured

## 5. Copy the client bundle to the client device

Copy the generated `.aptbundle` file from the server to the client.

The bundle is a single compressed custom-format file containing:

- the logical client config
- the client private key
- the deployment or per-user admission key
- the server static public key
- the `D2` endpoint and pinned certificate when the server has `D2` enabled

## 6. Start the client

Recommended: install the bundle into `~/.adapt-tunnel/client.aptbundle` on the client, then install the local daemon once:

```bash
mkdir -p ~/.adapt-tunnel
cp /path/to/laptop.aptbundle ~/.adapt-tunnel/client.aptbundle
sudo ./target/release/apt-client service install
```

Then start the client using the default config location:

```bash
./target/release/apt-client up
```

For a quick automated QA pass instead of a long-lived session, you can also run:

```bash
./target/release/apt-client test
```

When the bundle is installed at `~/.adapt-tunnel/client.aptbundle`, the client stores its persistent state in `~/.adapt-tunnel/client.state.toml`.
On first use, it also creates a blank optional override file at `~/.adapt-tunnel/client.override.toml`.

Useful one-shot overrides:

- `--mode 0..100` — temporary numeric mode override (`0` = speed, `50` = balanced, `100` = stealth)
- `apt-client test --mode <value>` runs the same numeric mode through the built-in QA checks and disconnects automatically when finished
- `--carrier auto|d1|d2` — temporary carrier preference override

The generated bundle now uses `preferred_carrier = "auto"`. When `D2` is present, the automatic order is `D2 -> D1`.

On macOS, the embedded client config leaves `interface_name` unset unless you intentionally rebuild a bundle that targets a specific `utunX` interface.
When the session comes up, the client logs the assigned tunnel IP/interface, applies pushed DNS servers automatically where the local platform supports it, and the server logs the accepted session.
Use the optional override file for local-only edits such as `interface_name`, route preferences, carrier preference, or a custom `state_path` without modifying the bundle itself.

Alternative: if you want to run the bundle directly from another directory:

```bash
./target/release/apt-client up --bundle /path/to/laptop.aptbundle
```

In that direct-launch mode, the client creates a blank sidecar override file next to the bundle, for example `/path/to/laptop.override.toml`.

## 7. Verify the VPN

Use the manual verification checklist in:

- `guides/MANUAL-TESTING.md`

## Notes

- The server runtime is Linux-only right now.
- The client runtime is intended for Linux/macOS.
- Pushed DNS automation is best-effort: Linux currently uses `resolvectl`, and macOS temporarily overrides the primary network service DNS while the client is up.
- Server config files are best-effort auto-upgraded on load so newly added runtime fields appear automatically, but that rewrite normalizes TOML formatting and may drop comments from older files.
- Full tunnel is typically achieved by pushing `0.0.0.0/0`.
- The more raw/manual config-file-oriented flow lives in:
  - `guides/MANUAL-CONFIG-SETUP.md`
