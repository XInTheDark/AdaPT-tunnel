# Manual deployment guide

This guide covers a **single Linux server** and a **Linux or macOS client** using the current combined APT server daemon.

## 1. What this guide assumes

- server OS: Linux
- client OS: Linux or macOS
- transport: UDP (`D1`)
- auth model: one shared deployment admission key, plus an authorized stable client static key per client
- privileges: root/admin access on both ends for TUN setup and routing changes

## 2. Build the binaries

From the repo root:

```bash
cargo build --release
```

Binaries of interest:

- `target/release/apt-edge`
- `target/release/apt-client`

## 3. Generate the server keyset

On the server:

```bash
mkdir -p /etc/adapt /etc/adapt/clients
./target/release/apt-edge gen-keys --out-dir /etc/adapt
```

This produces:

- `/etc/adapt/shared-admission.key`
- `/etc/adapt/server-static-private.key`
- `/etc/adapt/server-static-public.key`
- `/etc/adapt/cookie.key`
- `/etc/adapt/ticket.key`

Keep all of those secret except `server-static-public.key`, which is meant to be copied to clients.

## 4. Generate the client identity

On the client:

```bash
mkdir -p ./adapt-client
./target/release/apt-client gen-identity --out-dir ./adapt-client
```

This produces:

- `./adapt-client/client-static-private.key`
- `./adapt-client/client-static-public.key`

Copy the client public key to the server, for example:

```bash
scp ./adapt-client/client-static-public.key server:/etc/adapt/clients/laptop.client-static-public.key
```

## 5. Copy the required public/shared material to the client

The client needs:

- the shared admission key
- the server static public key

Copy them securely from the server:

```bash
scp server:/etc/adapt/shared-admission.key ./adapt-client/shared-admission.key
scp server:/etc/adapt/server-static-public.key ./adapt-client/server-static-public.key
```

## 6. Prepare the config files

### Server config

Start from `guides/examples/server.toml` and save it as `/etc/adapt/server.toml`.

Update at least:

- `bind`
- `endpoint_id`
- `egress_interface`
- the `[[peers]]` block(s)
- `client_static_public_key` paths
- client tunnel IP assignments

### Client config

Start from `guides/examples/client.toml` and save it near the client key files.

Update at least:

- `server_addr`
- `endpoint_id`
- the key file paths if you changed locations
- optionally `interface_name`

## 7. Open the UDP port on the server

Example for port `51820`:

```bash
sudo ufw allow 51820/udp
```

Or configure your cloud/network firewall to allow inbound UDP on the chosen port.

## 8. Start the server

On the Linux server:

```bash
sudo ./target/release/apt-edge serve --config /etc/adapt/server.toml
```

The server must run as root because it creates the TUN device and may enable forwarding/NAT.

## 9. Start the client

On the client:

```bash
sudo ./target/release/apt-client connect --config ./adapt-client/client.toml
```

The client must run with sufficient privileges to create/configure the TUN device and install routes.

## 10. What the runtime does for you

### Server

When `enable_ipv4_forwarding = true` and `nat_ipv4 = true`, the runtime will:

- create the server TUN device
- enable Linux IPv4 forwarding
- install NAT/masquerade rules using `iptables`

### Client

The client runtime will:

- perform the encrypted admission handshake
- create/configure the client TUN device after the server assigns tunnel parameters
- install the pushed routes
- preserve a direct route to the remote VPN server if full-tunnel routing is pushed

## 11. Current config field reference

### Shared key material fields

All key fields accept either:

- inline 64-character hex, or
- `file:/absolute/or/relative/path`

Fields:

- `admission_key`
- `server_static_private_key`
- `server_static_public_key`
- `cookie_key`
- `ticket_key`
- `client_static_public_key`
- `client_static_private_key`

### Server config

- `bind` — UDP listen address
- `endpoint_id` — logical APT endpoint identifier
- `interface_name` — preferred server TUN name
- `tunnel_local_ipv4` — server-side tunnel IP
- `tunnel_netmask` — IPv4 netmask for the tunnel subnet
- `tunnel_mtu` — TUN/interface MTU
- `egress_interface` — Linux interface used for internet egress/NAT
- `enable_ipv4_forwarding` — toggles `net.ipv4.ip_forward=1`
- `nat_ipv4` — toggles `iptables` masquerading
- `push_routes` — routes delivered to clients after handshake
- `push_dns` — reserved for operator reference / future DNS automation
- `keepalive_secs` — keepalive interval when idle
- `session_idle_timeout_secs` — idle session timeout
- `udp_recv_buffer_bytes` / `udp_send_buffer_bytes` — socket tuning

### Client config

- `server_addr` — remote server UDP address
- `endpoint_id` — expected APT endpoint identifier
- `client_identity` — optional human-readable label
- `bind` — local UDP bind address
- `interface_name` — preferred client TUN name
- `routes` — fallback route list if server pushes none
- `use_server_pushed_routes` — whether to prefer server-pushed routes
- `keepalive_secs` — keepalive interval when idle
- `session_idle_timeout_secs` — idle session timeout
- `handshake_timeout_secs` — timeout per handshake wait step
- `handshake_retries` — handshake retry count
- `state_path` — where the client stores its resume ticket/status snapshot

## 12. Recommended first deployment shape

For the simplest full-tunnel deployment, use:

- server tunnel IP: `10.77.0.1`
- client tunnel IP(s): `10.77.0.x`
- `push_routes = ["0.0.0.0/0"]`
- `nat_ipv4 = true`

That gives you a classic full-tunnel VPN path over the current APT UDP runtime.
