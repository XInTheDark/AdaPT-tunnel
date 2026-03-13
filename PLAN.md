# Production Implementation Plan

This plan follows `SPEC_v1.md` and the confirmed deployment assumptions for the first usable release:

- **server:** Linux
- **client:** Linux and macOS
- **topology:** combined edge+tunnel server daemon for v1
- **authentication:** shared deployment key first, while keeping the code ready to grow into per-user credentials later
- **primary production carrier:** `D1` over UDP

## 1. Product target for v1

Deliver a **fully usable point-to-site VPN** built on the existing APT protocol core.

The first production release must support:

- a long-running server daemon reachable over UDP
- a long-running client that connects to the server and keeps the tunnel alive
- a real TUN-based datapath
- encrypted transport of full IP packets between client and server
- server-side forwarding/NAT so client traffic can reach the broader network
- configuration files, key material management, and operational docs
- conservative hardening and automated test coverage

## Progress snapshot

Completed since the initial protocol prototype:

- added `crates/apt-runtime` for production config, UDP runtime, TUN wiring, and route/NAT orchestration
- added production-oriented CLI runtime commands (`apt-edge start`, `apt-client up`)
- added guided setup commands (`apt-edge init`, `apt-edge add-client`)
- added deployment and manual testing guides under `guides/`

## 2. Current starting point

Already implemented in the repo:

- shared protocol/domain types
- cryptographic suite integration and key schedule
- admission handshake (`C0 -> S1 -> C2 -> S3`)
- encrypted inner tunnel core with replay protection and rekey support
- carrier helpers for `D1` and `S1`
- first-cut persona, policy, and observability crates
- guided CLI setup flow for server/client usage

Missing before the product is deployable:

- production config model
- runtime orchestration around sockets, timers, and sessions
- TUN integration and OS routing
- combined server daemon mode
- client connect mode
- NAT/forwarding setup
- persistence for resumable client state
- integration/hardening test coverage

## 3. Delivery phases

### Phase A — Production runtime foundation

Objective: add the missing app/runtime layer above the existing protocol engine.

Tasks:
1. Add a shared runtime crate for:
   - config loading
   - key material parsing/loading
   - runtime error types
   - UDP transport helpers
   - session/runtime status structures
2. Define production config models for:
   - combined server daemon
   - client runtime
   - TUN/network settings
   - routing/NAT settings
   - observability
   - persistence
3. Add client identity support suitable for shared-key deployments that may later evolve into richer auth.
4. Add server-to-client tunnel assignment/config delivery during session establishment.

Exit criteria:
- the workspace has a clean production configuration model
- the runtime crate can instantiate the existing admission/tunnel core with real deployment settings

### Phase B — Real UDP server/client runtime

Objective: turn the protocol engine into a long-running encrypted tunnel runtime.

Tasks:
1. Implement a UDP server loop for `D1`:
   - admission handling
   - session creation
   - per-session tunnel state
   - periodic retransmit/rekey ticks
2. Implement a UDP client loop for `D1`:
   - handshake retries
   - session establishment
   - keepalive/rekey tick path
   - reconnect-friendly ticket persistence
3. Add session tables and peer/address tracking.
4. Add operational logging and status reporting.

Exit criteria:
- client and server can establish a session across real UDP sockets
- encrypted tunnel packets flow in both directions without demo-only shortcuts

### Phase C — TUN integration and VPN datapath

Objective: make the runtime usable as an actual VPN.

Tasks:
1. Add async TUN integration for Linux/macOS clients and Linux servers.
2. Configure interface addressing/MTU from runtime parameters.
3. Install routes for client traffic.
4. Preserve the route to the remote server when client default routes are redirected through the tunnel.
5. Inject packets from TUN into the tunnel and write decrypted packets back to TUN.
6. On the server, map tunnel-destination addresses to active sessions.

Exit criteria:
- packets can traverse the TUN interface on client and server
- user traffic can pass through the encrypted tunnel end-to-end

### Phase D — Forwarding, NAT, and operational setup

Objective: make the server function as a practical VPN gateway.

Tasks:
1. Enable Linux IPv4 forwarding when configured.
2. Install NAT/masquerade rules when configured.
3. Add configuration for tunnel subnets, pushed routes, and DNS hints.
4. Add operational commands for key generation / config bootstrap.
5. Document required privileges and service startup expectations.

Exit criteria:
- a Linux server can forward tunneled client traffic to external networks
- a first-time operator can configure and start the system from docs

### Phase E — Hardening, testing, and performance work

Objective: reduce operational risk and tune the first release.

Tasks:
1. Add integration tests for:
   - client/server UDP handshake
   - session establishment
   - tunnel packet exchange
   - reconnect/resumption paths where practical
2. Add negative tests for malformed/invalid traffic.
3. Add benchmarks or stress-oriented checks for session runtime hot paths.
4. Review allocations, batching opportunities, and socket buffer tuning.
5. Update docs/README continuously to match the real state of the code.
6. Commit incrementally as significant milestones land.

Exit criteria:
- the release has clear setup docs
- the runtime is validated beyond unit tests
- the hot path is no longer “demo shaped”

## 4. Definition of done for the first production release

The project will count as “production-usable v1” when all of the following are true:

1. `apt-edge serve --config ...` starts a combined production server daemon.
2. `apt-client connect --config ...` establishes a persistent encrypted session to the server.
3. A TUN device is created/configured and routes are installed.
4. Client traffic can traverse the server to external networks in NAT mode.
5. The README documents real setup and usage instead of prototype-only behavior.
6. The workspace test suite covers both core protocol logic and runtime integration paths.
