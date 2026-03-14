# Guided deployment flow

This is the **recommended** way to deploy AdaPT now.

It uses the user-friendly CLI flow instead of hand-editing every file first.

## Supported targets for this flow

- server: Linux
- client: Linux or macOS
- transport: UDP (`D1`)
- auth model: shared deployment admission key + one authorized stable client identity per client

## 1. Get the binaries

You have two supported options.

### Option A: download a GitHub Release bundle

When a GitHub Release is published, CI attaches ready-to-run tarballs for supported targets.

For `x86_64` Linux servers and clients:

- prefer the `x86_64-unknown-linux-musl` bundle when you want the most portable static Linux binary
- the `x86_64-unknown-linux-gnu` bundle is also published, but it is still a glibc-linked build; it is only kept on an `ubuntu-22.04` baseline so it does not pick up the newest glibc requirement from `ubuntu-latest`

Each release bundle contains:

- `apt-edge`
- `apt-client`
- `apt-tunneld`
- the guides in this directory
- example config files

After extracting the tarball, the binaries live under `bin/`.

### Option B: build from source

From the repo root:

```bash
cargo build --release
```

Main binaries:

- `target/release/apt-edge`
- `target/release/apt-client`

## 2. Initialize the server

On the server:

```bash
sudo ./target/release/apt-edge init
```

The command walks you through the main values, then creates:

- `/etc/adapt/server.toml` by default
- the server key files
- a `bundles/` directory for client packages

You can also run it non-interactively, for example:

```bash
./target/release/apt-edge init \
  --out-dir /etc/adapt \
  --bind 0.0.0.0:51820 \
  --public-endpoint vpn.example.com:51820 \
  --endpoint-id adapt-prod \
  --egress-interface eth0 \
  --tunnel-subnet 10.77.0.0/24 \
  --interface-name aptsrv0 \
  --push-route 0.0.0.0/0 \
  --dns 1.1.1.1 \
  --dns 1.0.0.1 \
  --yes
```

## 3. Generate a client bundle

On the server:

```bash
./target/release/apt-edge add-client --config /etc/adapt/server.toml --name laptop
```

This command automatically:

- allocates a free client tunnel IP
- generates the client's static keypair
- updates the server's authorized peer list
- writes a client bundle directory you can copy to the client device

You can override the output directory and client IP if needed:

```bash
./target/release/apt-edge add-client \
  --config /etc/adapt/server.toml \
  --name laptop \
  --out-dir /tmp/laptop-bundle \
  --client-ip 10.77.0.2
```

## 4. Start the server

On the Linux server:

```bash
sudo ./target/release/apt-edge start --config /etc/adapt/server.toml
```

The server must run with privileges sufficient to:

- create/configure the TUN interface
- enable IPv4 forwarding when configured
- install NAT rules when configured

## 5. Copy the client bundle to the client device

Copy the generated bundle directory from the server to the client.

The bundle contains:

- `client.toml`
- `client-static-private.key`
- `client-static-public.key`
- `shared-admission.key`
- `server-static-public.key`
- `START-HERE.txt`

## 6. Start the client

Recommended: install the bundle into `/etc/adapt` on the client:

```bash
sudo mkdir -p /etc/adapt
sudo cp -R /path/to/laptop-bundle/* /etc/adapt/
```

Then start the client using the default config location:

```bash
sudo ./target/release/apt-client up
```

Alternative: if you want to run the bundle directly from another directory:

```bash
sudo ./target/release/apt-client up --config client.toml
```

If `client.toml` is in the current directory, that direct mode still works.

## 7. Verify the VPN

Use the manual verification checklist in:

- `guides/MANUAL-TESTING.md`

## Notes

- The server runtime is Linux-only right now.
- The client runtime is intended for Linux/macOS.
- Full tunnel is typically achieved by pushing `0.0.0.0/0`.
- The more raw/manual config-file-oriented flow lives in:
  - `guides/MANUAL-CONFIG-SETUP.md`
