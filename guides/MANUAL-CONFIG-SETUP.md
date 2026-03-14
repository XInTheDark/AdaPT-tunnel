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
./target/release/apt-client gen-identity --out-dir /etc/adapt
```

This produces:

- `/etc/adapt/client-static-private.key`
- `/etc/adapt/client-static-public.key`

Copy the client public key to the server.

## 3. Prepare the config files manually

Use these templates:

- `guides/examples/server.toml`
- `guides/examples/client.toml`

Key points:

### Server config

- `bind` — UDP listen address
- `public_endpoint` — what clients should dial
- `stream_bind` — optional TCP listen address for the `S1` fallback carrier
- `stream_public_endpoint` — optional client-facing `S1` endpoint, usually `host:443`
- `stream_decoy_surface` — whether invalid unauthenticated stream input gets a decoy-like HTTP surface
- `runtime_mode` — default runtime preset (`stealth`, `balanced`, or `speed`)
- `endpoint_id` — deployment identifier
- key fields support either inline hex or `file:/path`
- `tunnel_local_ipv4` + `tunnel_netmask` define the tunnel subnet
- `push_routes` usually contains `0.0.0.0/0` for full tunnel
- `push_dns` is applied automatically where supported by the client platform
- `allow_session_migration` — enables authenticated path revalidation / migration handling
- `[[peers]]` must include each authorized client public key and assigned tunnel IP
- for the recommended per-user model, each `[[peers]]` entry should also set:
  - `auth_profile = "per-user"`
  - `user_id = "..."` (or let it default to `name`)
  - `admission_key = "file:/path/to/user-specific-admission.key"`
- for the older shared-deployment model, leave `auth_profile` at its default (`shared-deployment`) and do not set a peer-specific `admission_key`

### Client config

- `server_addr` — server host:port the client should connect to
- `stream_server_addr` — optional TCP `S1` endpoint for fallback, usually `host:443`
- `runtime_mode` — default runtime preset (`stealth`, `balanced`, or `speed`)
- `preferred_carrier` — `d1`, `s1`, or `auto`
- `endpoint_id` — must match the server
- `auth_profile` — `shared-deployment` or `per-user`
- `admission_key` — either the shared deployment key or the user's dedicated admission key
- `server_static_public_key` — server public key
- `client_static_private_key` — client's stable static private key
- `client_identity` is required for `auth_profile = "per-user"`
- `enable_s1_fallback` — enables conservative UDP-to-stream fallback when `stream_server_addr` is present
- `allow_session_migration` — enables authenticated path revalidation and standby promotion logic
- `standby_health_check_secs` — override for standby probe cadence; `0` keeps the persona-selected sparse cadence
- `use_server_pushed_routes = true` is usually the easiest choice

## 4. Start the server

```bash
sudo ./target/release/apt-edge start --config /etc/adapt/server.toml
```

Optional one-shot override:

- `--mode stealth|balanced|speed`

## 5. Start the client

```bash
sudo ./target/release/apt-client up
```

Optional one-shot overrides:

- `--mode stealth|balanced|speed`
- `--carrier auto|d1|s1`

## 6. Validate manually

Use:

- `guides/MANUAL-TESTING.md`

## Config upgrade behavior

Client and server config files are best-effort normalized on load so newly added defaults appear automatically in older TOML files.

That is convenient for upgrades, but it also means:

- comments may be dropped
- formatting may be normalized
- key ordering may change after a newer binary loads and rewrites the file

## When to use this manual path

Use the manual path when you want:

- complete control over file layout
- pre-generated keys from another system
- hand-edited configs for automation or packaging
- to understand the exact raw config fields behind the guided CLI
