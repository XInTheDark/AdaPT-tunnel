# Manual config-file setup

This guide is for operators who want the lower-level setup path rather than the guided CLI flow.

If you just want the easiest supported path, use:

- `guides/DEPLOYMENT.md`

## 1. Generate raw server keys

```bash
./target/release/apt-edge gen-keys --out-dir /etc/adapt
```

This produces:

- `/etc/adapt/shared-admission.key`
- `/etc/adapt/server-static-private.key`
- `/etc/adapt/server-static-public.key`
- `/etc/adapt/cookie.key`
- `/etc/adapt/ticket.key`

## 2. Generate a standalone client identity

```bash
./target/release/apt-client gen-identity --out-dir ./adapt-client
```

This produces:

- `./adapt-client/client-static-private.key`
- `./adapt-client/client-static-public.key`

Copy the client public key to the server.

## 3. Prepare the config files manually

Use these templates:

- `guides/examples/server.toml`
- `guides/examples/client.toml`

Key points:

### Server config

- `bind` — UDP listen address
- `public_endpoint` — what clients should dial
- `endpoint_id` — deployment identifier
- key fields support either inline hex or `file:/path`
- `tunnel_local_ipv4` + `tunnel_netmask` define the tunnel subnet
- `push_routes` usually contains `0.0.0.0/0` for full tunnel
- `[[peers]]` must include each authorized client public key and assigned tunnel IP

### Client config

- `server_addr` — server host:port the client should connect to
- `endpoint_id` — must match the server
- `admission_key` — shared deployment key
- `server_static_public_key` — server public key
- `client_static_private_key` — client's stable static private key
- `use_server_pushed_routes = true` is usually the easiest choice

## 4. Start the server

```bash
sudo ./target/release/apt-edge start --config /etc/adapt/server.toml
```

## 5. Start the client

```bash
sudo ./target/release/apt-client up --config ./adapt-client/client.toml
```

## 6. Validate manually

Use:

- `guides/MANUAL-TESTING.md`

## When to use this manual path

Use the manual path when you want:

- complete control over file layout
- pre-generated keys from another system
- hand-edited configs for automation or packaging
- to understand the exact raw config fields behind the guided CLI
