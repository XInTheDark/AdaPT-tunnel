# Guided deployment flow

This is the recommended way to deploy the current AdaPT H2 product path.

## Supported targets for this flow

- server: Linux
- client: Linux or macOS
- public-session surface: H2 API-sync
- auth model: shared-deployment or per-user admission keys; the guided flow defaults to per-user

## 1. Get the binaries

### Option A: use the installer script

```bash
curl -fsSL https://raw.githubusercontent.com/XInTheDark/AdaPT-tunnel/master/scripts/install.sh | sudo bash -s -- install
```

### Option B: download a GitHub Release bundle

Release bundles contain:

- `apt-edge`
- `apt-client`
- `apt-clientd`
- `apt-tunneld`
- `install.sh`
- `uninstall.sh`
- the guides in this directory
- example config files

### Option C: build from source

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

The command creates:

- `/etc/adapt/server.toml` by default
- server admission/static/cookie/ticket keys
- `server-certificate.pem` and `server-private-key.pem`
- a `bundles/` directory for client bundles
- optional `/etc/systemd/system/apt-edge.service`

Important:

- enter the server's **real client-reachable host:port** when asked for `public_endpoint`
- use port `443` unless you intentionally need another H2 endpoint
- enter the public HTTP authority/host name with `--authority` or accept the derived default
- the generated client bundles copy both the public endpoint and the authority/trust material from this server config

Non-interactive example:

```bash
./target/release/apt-edge init \
  --out-dir /etc/adapt \
  --bind 0.0.0.0:443 \
  --public-endpoint api.example.com:443 \
  --authority api.example.com \
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

If you skipped the startup-service option during init, you can install it later with:

```bash
sudo ./target/release/apt-edge utils install-systemd-service --config /etc/adapt/server.toml
```

## 3. Generate a client bundle

On the server:

```bash
./target/release/apt-edge add-client --config /etc/adapt/server.toml --name laptop --auth per-user
```

This automatically:

- allocates a free client tunnel IP
- creates a per-user admission key by default
- generates the client's static keypair
- updates the server's authorized peer list
- writes a single `.aptbundle`
- prints a temporary `apt-client import` command unless you pass `--no-import`

Manual example:

```bash
./target/release/apt-edge add-client \
  --config /etc/adapt/server.toml \
  --name laptop \
  --auth per-user \
  --out-file /tmp/laptop.aptbundle \
  --client-ip 10.77.0.2
```

To revoke a client later:

```bash
./target/release/apt-edge revoke-client --config /etc/adapt/server.toml --name laptop
```

## 4. Start the server

```bash
sudo ./target/release/apt-edge start --config /etc/adapt/server.toml
```

Useful one-shot overrides:

- `--mode 100` — most conservative behavior and the default
- `--mode 50` — balanced midpoint
- `--mode 0` — fastest / lowest-shaping anchor

The server must run with privileges sufficient to:

- create/configure the TUN interface
- enable IPv4 forwarding when configured
- install NAT rules when configured

## 5. Install or import the client bundle

Recommended: use the import command printed by `apt-edge add-client`.

```bash
apt-client import --server <temporary-host:port> --key <temporary-key>
```

Manual fallback:

```bash
mkdir -p ~/.adapt-tunnel
cp /path/to/laptop.aptbundle ~/.adapt-tunnel/client.aptbundle
```

## 6. Install the local client daemon

```bash
sudo ./target/release/apt-client service install
```

After that, normal client runs do not need `sudo`.

## 7. Start the client

```bash
./target/release/apt-client up
```

Or run the built-in QA pass:

```bash
./target/release/apt-client test
```

## 8. Bundle-local state and overrides

With the default install path:

- bundle: `~/.adapt-tunnel/client.aptbundle`
- state: `~/.adapt-tunnel/client.state.toml`
- override file: `~/.adapt-tunnel/client.override.toml`

If you launch a bundle from another path:

```bash
./target/release/apt-client up --bundle /path/to/laptop.aptbundle
```

then the client creates sidecar files such as:

- `/path/to/laptop.state.toml`
- `/path/to/laptop.override.toml`

## 9. Validate the deployment

Use:

- `guides/MANUAL-TESTING.md`
