# Deployment guide

## Supported v1 deployment targets

- Server: Linux
- Client: Linux or macOS
- Carrier: `D1` over UDP
- Authentication: shared deployment key + per-client static Noise identity

## Server bootstrap

1. Generate server material:

   ```bash
   cargo run --release -p apt-edge -- gen-keyset --out-dir /etc/adapt
   ```

2. Generate each client identity:

   ```bash
   cargo run --release -p apt-client -- gen-identity --out-dir /etc/adapt/peers/laptop
   ```

3. Copy the client public key to the server and reference it from the server config.
4. Copy the shared admission key and server public key to the client.
5. Fill in `docs/examples/server.example.toml` and `docs/examples/client.example.toml`.

## Server start

Run as root on Linux:

```bash
cargo run --release -p apt-edge -- serve --config /etc/adapt/server.toml
```

The server runtime:

- binds the configured UDP socket
- creates the TUN interface
- enables IPv4 forwarding when configured
- installs IPv4 masquerade rules when configured
- accepts clients whose static public keys are listed in `[[peers]]`

## Client start

Run with privileges sufficient to create/configure a TUN interface:

```bash
cargo run --release -p apt-client -- connect --config /etc/adapt/client.toml
```

The client runtime:

- performs the APT admission handshake over UDP
- creates the TUN interface using server-provided tunnel parameters
- preserves a direct route to the server endpoint
- installs the configured or server-pushed routes
- forwards IP packets through the encrypted tunnel
- persists the resume ticket in `state_path`

## Operational notes

- The v1 runtime is IPv4-focused for interface assignment and routed traffic.
- Full-tunnel mode is achieved by pushing or configuring `0.0.0.0/0`.
- Server-side NAT currently uses Linux `iptables`.
- Split-role edge/tunnel deployment is reserved for a later iteration; v1 uses a combined daemon.
