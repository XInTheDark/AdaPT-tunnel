Below is a full core spec I would actually hand to an engineering team.

It is "full" in the sense that it defines the trust model, handshake, key schedule, packet semantics, shaping model, carrier abstraction, timers, failure behaviour, and deployment rules. The only thing I am deliberately not freezing into one global visible wire format is the carrier-specific outer serialisation, because doing that would create the exact stable fingerprint this design is meant to avoid.

# Adaptive Persona Tunnel

Version: `APT/1-core`

## 1. Purpose

APT is a stealth-first encrypted tunnelling protocol with three priorities:

1. strong confidentiality and integrity with no plaintext tunnel data
2. resistance to passive fingerprinting and active probing
3. good performance under permissive paths, with graceful degradation under restrictive paths

APT achieves this by splitting the system into:

- a conservative encrypted inner tunnel core
- a stealth-heavy admission plane
- a per-session, per-network behavioural shaping layer
- pluggable outer carrier bindings

The main design choice is that APT does **not** try to have one canonical external identity. Instead, it keeps the secure core stable and makes the outer behaviour variable but bounded.

## 2. Non-goals

APT is not trying to:

- invent new cryptographic primitives
- defeat a full global adversary doing perfect end-to-end timing correlation at internet scale
- provide anonymity by itself
- guarantee that one outer carrier works on every network
- make all traffic look identical across all deployments

## 3. Threat model

APT is designed to resist the following:

- passive DPI looking for stable packet sizes, timing, handshake shapes, keepalive patterns, and fallback sequences
- active probing by a network adversary attempting to elicit a distinguishing response
- replay of admission messages
- state exhaustion attempts against exposed servers
- path interference such as UDP blackholing, MTU clamping, reset injection, and transport-specific throttling

APT does **not** claim to fully resist:

- endpoint compromise
- malware on the client or server
- a truly global observer correlating both ends with long observation windows
- an adversary that fully controls the decoy surface and the server host at the same time

## 4. Architecture

APT has two planes.

### 4.1 Rendezvous plane

The rendezvous plane is used only to:

- authenticate a real client
- establish tunnel keys
- negotiate a carrier family and shaping profile
- prove return reachability before the server amplifies traffic

This plane is stealth-first and stateless until the client proves authenticity and return reachability.

### 4.2 Data plane

The data plane carries actual tunnel packets after session establishment.

This plane is performance-first but remains shape-aware. It can relax shaping when the path is permissive and tighten it again when interference is detected.

## 5. Roles

APT defines three logical roles.

- `Client`: initiates sessions and maintains the local path model.
- `Edge`: exposed endpoint that receives admission traffic and hosts one or more carrier bindings.
- `Tunnel node`: terminates the inner encrypted tunnel.

A small deployment may run `Edge` and `Tunnel node` on the same host. Larger deployments may separate them.

## 6. Cryptographic profile

APT uses conservative, standard cryptography.

### 6.1 Mandatory baseline suite

All implementations MUST support:

- X25519 for elliptic-curve key agreement
- ChaCha20-Poly1305 for tunnel AEAD
- XChaCha20-Poly1305 for admission-plane AEAD
- HKDF-SHA256 for key derivation
- BLAKE2s or SHA-256 for transcript hashing
- Noise `XXpsk2` for the initial tunnel handshake

### 6.2 Optional suite

Implementations MAY support a hybrid post-quantum mode:

- ML-KEM-768 combined with X25519
- combined shared secret = `HKDF( x25519_shared || mlkem_shared )`

This mode SHOULD be optional and policy-controlled because it increases CPU and handshake size.

### 6.3 Security invariants

APT MUST satisfy these invariants:

- all tunnel payload bytes are encrypted before entering the outer carrier layer
- all admission-plane semantics are encrypted
- no unauthenticated request yields a protocol-specific distinguishable response
- authentication and camouflage are separate concerns
- failure mode is always fail-closed

## 7. Identity and provisioning

APT supports two authentication profiles.

### 7.1 Shared-deployment profile

Small deployments MAY use a single deployment admission secret `AK` plus a server static public key `SPK`.

The client is provisioned with:

- server static public key
- admission secret
- endpoint list
- permitted carrier bindings
- optional decoy metadata for stream carriers

This profile is simple but weak for revocation. It is acceptable only for small trusted deployments.

### 7.2 Per-user profile

Production deployments SHOULD use per-user admission credentials.

Each client is provisioned with:

- `user_id`
- `AK_u`, a per-user admission key
- server static public key
- endpoint list
- permitted carrier bindings

The server stores or derives `AK_u` from a master credential system. This enables user-level revocation without rotating the entire deployment.

### 7.3 Server secrets

The server maintains:

- static tunnel keypair `(SSK, SPK)`
- cookie key `CK`, rotated regularly
- resumption ticket encryption key `TK`, rotated regularly
- optional persona master seed `PMK`

## 8. Core design rule about the wire image

APT defines **logical messages**. A carrier binding serialises those messages into carrier-native bytes.

A conforming carrier binding MUST satisfy all of the following:

- it MUST NOT expose a globally stable cleartext APT header on the wire
- it MUST bind admission messages to the current carrier context as AEAD associated data
- it MUST define how invalid input is surfaced without creating a distinctive reply
- it MUST enforce server anti-amplification before return reachability is proven

This is the main reason APT is technically viable as a stealth design. The secure core is fixed. The visible syntax is not.

## 9. Admission handshake

APT initial session establishment uses four logical messages:

1. `C0` client admission capsule
2. `S1` server admission reply
3. `C2` client tunnel-init confirmation
4. `S3` server tunnel confirmation

Initial establishment is 1.5 RTT in the common case. Resumption may reduce this.

## 10. Logical admission messages

## 10.1 C0 client admission capsule

`C0` is an AEAD-encrypted logical structure carried inside a carrier binding.

Logical fields:

```text
C0 {
  version
  auth_profile
  suite_bitmap
  carrier_bitmap
  policy_flags
  epoch_slot
  client_nonce
  path_class
  mtu_class
  rtt_class
  loss_class
  nat_class
  noise_msg1
  optional_resume_ticket
  optional_extensions
  padding
}
```

Field notes:

- `epoch_slot` is a coarse time bucket, for example 300-second buckets.
- `client_nonce` is unique per attempt.
- `noise_msg1` is the first `Noise XXpsk2` handshake message.
- `path_class`, `mtu_class`, `rtt_class`, `loss_class`, and `nat_class` are coarse integers, not raw measurements.
- `padding` is chosen by the client-side scheduler and MUST not reveal a fixed baseline size across all deployments.

Encryption:

- shared-deployment profile: `AEAD key = HKDF(AK, epoch_slot || "admission")`
- per-user profile: `AEAD key = HKDF(AK_u, epoch_slot || "admission")`
- associated data MUST include the carrier binding ID and the server endpoint identifier

Per-user profile MAY include a short rotating lookup hint outside the ciphertext. If present, it MUST rotate at least once per epoch slot and MUST NOT be a stable account identifier.

## 10.2 S1 server admission reply

`S1` is sent only if `C0` decrypts and validates.

Logical fields:

```text
S1 {
  version
  chosen_suite
  chosen_carrier
  chosen_policy
  cookie_expiry
  anti_amplification_cookie
  noise_msg2
  max_record_size
  idle_binding_hint
  optional_resume_accept
  optional_extensions
  padding
}
```

Rules:

- `S1` MUST be no larger than the anti-amplification budget before address validation.
- `noise_msg2` is the second `Noise XXpsk2` handshake message.
- `anti_amplification_cookie` is a stateless cookie bound to source address, carrier binding, `client_nonce`, and a short expiry.

## 10.3 C2 client tunnel-init confirmation

Logical fields:

```text
C2 {
  version
  anti_amplification_cookie
  noise_msg3
  selected_transport_ack
  optional_extensions
  padding
}
```

Rules:

- `noise_msg3` is the third `Noise XXpsk2` handshake message.
- `C2` proves return reachability by echoing the cookie.
- after successful `C2`, the server MAY allocate full session state.

## 10.4 S3 server tunnel confirmation

Logical fields:

```text
S3 {
  version
  session_id
  tunnel_mtu
  rekey_limits
  ticket_issue_flag
  optional_resume_ticket
  optional_extensions
}
```

After `S3`, tunnel data may flow.

## 11. Admission validation rules

The server MUST perform validation in this order:

1. carrier binding validity
2. AEAD decryption of `C0`
3. acceptable `epoch_slot` window
4. replay check on `(credential, client_nonce, epoch_slot)`
5. Noise message validity
6. policy checks

If any step fails, the server MUST follow the carrier binding’s invalid-input behaviour and MUST NOT emit an APT-specific error.

Recommended defaults:

- accept `epoch_slot` within `±1` slot
- retain replay cache entries for at least 2 slots
- cookie validity: 15 to 30 seconds

## 12. Tunnel handshake and key schedule

APT uses `Noise XXpsk2` with the admission key mixed in as the PSK.

This gives:

- forward secrecy from ephemeral Diffie-Hellman
- server authentication via the server static key
- binding of admission authentication to tunnel establishment
- optional client identity inside the encrypted handshake payload

### 12.1 Derived secrets

From the completed Noise handshake, both sides derive:

- `K_send`
- `K_recv`
- `K_ctrl_send`
- `K_ctrl_recv`
- `K_rekey`
- `persona_seed`
- `resume_secret`

Suggested derivation:

```text
master = Noise_handshake_output
K_send       = HKDF(master, "apt send")
K_recv       = HKDF(master, "apt recv")
K_ctrl_send  = HKDF(master, "apt ctrl send")
K_ctrl_recv  = HKDF(master, "apt ctrl recv")
K_rekey      = HKDF(master, "apt rekey")
persona_seed = HKDF(master, "apt persona")
resume_secret= HKDF(master, "apt resume")
```

## 13. Inner tunnel data plane

The APT data plane is a datagram-oriented encrypted tunnel.

It transports full IP packets inside encrypted frames. It does **not** attempt to provide reliable delivery for data packets. Reliability is left to upper layers, as in WireGuard.

### 13.1 Tunnel packet header

APT defines a compact logical packet header:

```text
TunnelPacket {
  flags
  key_phase
  packet_number
  ciphertext
}
```

Rules:

- `packet_number` is monotonically increasing per send direction.
- the AEAD nonce is derived from `packet_number`.
- the header is authenticated as AEAD associated data.
- `ciphertext` contains one or more encrypted frames.

### 13.2 Encrypted frame types

APT frame types are:

- `IP_DATA`: one full IPv4 or IPv6 packet
- `CTRL_ACK`: acknowledgement for reliable control frames
- `PATH_CHALLENGE`
- `PATH_RESPONSE`
- `SESSION_UPDATE`
- `PING`
- `CLOSE`
- `PADDING`

`IP_DATA` frames are never retransmitted by APT.

Reliable control frames such as `SESSION_UPDATE` MUST be retransmitted until acknowledged or expired.

### 13.3 Replay protection

The receiver MUST maintain a sliding replay window over packet numbers.

Recommended default:

- replay window size: 4096 packets minimum

## 14. Rekeying

APT rekeys by sending a `SESSION_UPDATE` control frame carrying a fresh ephemeral contribution encrypted under the current control keys.

Recommended soft limits:

- 1 GiB to 4 GiB transmitted under one key phase
- 15 to 30 minutes wall-clock age

Recommended hard limits:

- 8 GiB transmitted
- 60 minutes wall-clock age

On rekey failure, the session MUST close rather than continue indefinitely on stale keys.

## 15. Resumption

The server MAY issue an opaque resumption ticket in `S3`.

The ticket is encrypted under `TK` and SHOULD include:

- user or credential reference
- server identifier
- expiry
- last successful carrier family
- coarse last-known path class
- resume_secret binding

A resumption ticket MUST NOT contain plaintext user metadata.

On reconnect, the client MAY include the ticket in `C0`. If accepted, the server MAY skip full client re-auth inside the tunnel handshake, but it MUST still require a fresh client nonce, a fresh cookie cycle, and fresh ephemeral key exchange.

## 16. Persona system

This is the distinctive part of APT.

APT does not define one global packet behaviour. Instead it defines a bounded persona generator.

### 16.1 Persona inputs

The persona for a session is derived from:

- `persona_seed`
- coarse local path classes
- chosen carrier family
- policy mode: stealth-first, balanced, or speed-first
- optional remembered profile for the current network

### 16.2 Persona outputs

A persona determines bounded values for:

- send pacing family
- burst size targets
- packet size target bins
- padding budget
- keepalive mode
- idle-resume behaviour
- fragmentation preference
- fallback order among available carriers
- migration thresholds

### 16.3 Persona constraints

A conforming implementation MUST obey all of the following:

- personas MUST vary across deployments and sessions
- personas MUST remain within safe bounded distributions
- personas MUST be coherent for the life of a session
- personas MUST NOT change so often that the flow looks synthetic
- personas MUST NOT create a globally shared default fingerprint

A good mental model is: different sessions should look like different ordinary implementations, not like random noise.

## 17. Local-normality model

Each client maintains a local model of what "ordinary" traffic on the current network path looks like.

This model is local only and MUST NOT inspect payload contents.

### 17.1 Allowed inputs

The model MAY use only coarse metadata such as:

- packet size histograms
- inter-send gap histograms
- burst length histograms
- upstream/downstream byte ratio classes
- RTT class
- loss class
- NAT rebinding observations
- path MTU observations
- connection longevity classes

### 17.2 Disallowed inputs

The model MUST NOT:

- inspect user payload contents
- export raw traffic metadata off-device by default
- train solely on failed sessions
- adapt instantly to every observed outlier

### 17.3 Training rules

The client SHOULD maintain a separate profile per network context.

A network context MAY be keyed locally by a privacy-preserving hash of attributes such as:

- link type
- local gateway identity
- SSID or equivalent local network label
- coarse public route characteristics

Before enough data exists, the client MUST use conservative defaults.

Recommended bootstrap rule:

- remain in default profile until at least one of the following is true:
  - 200 non-tunnel metadata observations exist for the network context
  - 3 successful APT sessions exist on the network context

### 17.4 Poisoning resistance

To reduce model poisoning:

- parameter updates SHOULD be clipped to small step sizes
- the model SHOULD use robust quantiles, not raw means
- tunnel traffic SHOULD contribute less weight than non-tunnel metadata
- suspicious failed attempts SHOULD not immediately rewrite the model

## 18. Scheduler and shaping

The scheduler is responsible for turning encrypted tunnel packets into carrier records without producing a stable outlier pattern.

### 18.1 General rules

The scheduler MAY:

- coalesce several tunnel packets into one carrier record
- split one tunnel packet across multiple carrier records where the carrier permits it
- add bounded padding
- delay transmission within a latency budget
- emit sparse cover traffic during idle periods

The scheduler MUST NOT:

- delay interactive traffic indefinitely for camouflage
- use one fixed keepalive interval across all deployments
- emit unlimited cover traffic
- make the flow strictly periodic under steady-state idle

### 18.2 Latency budgets

Recommended budgets:

- interactive queue age target: under 10 ms additional delay in balanced mode
- bulk queue age target: under 50 ms additional delay in balanced mode
- stealth-first mode MAY exceed these briefly during probation and migration

If the queue age exceeds the configured budget, the scheduler SHOULD prefer delivery over shaping.

### 18.3 Padding budgets

Recommended defaults:

- rendezvous/probation padding budget: up to 25% extra bytes
- steady-state padding budget: up to 5% to 8% extra bytes
- crisis mode under heavy blocking: policy-controlled, temporary increase allowed

Padding SHOULD be drawn from bounded distributions and MUST NOT create a universal fixed packet length.

### 18.4 Keepalive rules

APT keepalives are event-driven and path-aware.

Recommended behaviour:

- if recent application traffic exists, do not send explicit keepalives
- on idle paths with unknown NAT binding lifetime, start with a conservative interval such as 25 seconds with jitter
- once the binding lifetime estimate improves, send keepalives at about 40% to 70% of the estimated timeout, with jitter
- clamp keepalive intervals to a safe range, for example 15 to 120 seconds

## 19. Carrier bindings

A carrier binding is the outer transport used to carry APT logical messages.

APT/1-core requires at least one datagram binding. Good implementations should support both datagram and stream bindings.

### 19.1 Binding requirements

Each binding MUST define:

- how logical APT messages are embedded into the carrier
- maximum record size and fragmentation rules
- what associated-data context is bound into admission AEAD
- invalid-input behaviour
- address validation and anti-amplification handling
- close semantics
- migration behaviour

### 19.2 Recommended reference bindings

A practical implementation should ship at least these:

- `D1`: opaque datagram binding over UDP. Best performance, least application-layer metadata.
- `D2`: encrypted datagram-capable binding over a general encrypted transport when available.
- `S1`: generic stream binding over an encrypted stream carrier. Slower, but survives networks hostile to raw UDP.
- `H1`: request-response binding for highly restrictive environments. Highest overhead, used as a fallback only.

### 19.3 Invalid-input behaviour

For datagram bindings:

- the preferred invalid-input behaviour is silence
- the server MUST not send an unmistakable protocol error on garbage input

For stream or request-response bindings:

- the server MUST either present a decoy surface or return a standards-compliant generic failure
- the server MUST not reveal whether a near-miss admission capsule was "almost valid"

## 20. Policy controller

The policy controller decides how aggressively to shape and when to migrate carriers.

### 20.1 Inputs

The controller SHOULD consider:

- repeated handshake blackholes
- repeated immediate connection resets
- size-specific loss patterns
- MTU blackhole indicators
- sudden RTT inflation
- NAT rebinding frequency
- success or failure of recent fallback attempts

### 20.2 Modes

APT defines three policy modes:

- `stealth-first`
- `balanced`
- `speed-first`

The default for your stated priorities would be `stealth-first`, but with an automatic downgrade to `balanced` once the path proves permissive.

### 20.3 Suggested mode transitions

- start new networks in `stealth-first`
- move to `balanced` after a probation window with stable delivery
- move back to `stealth-first` when interference signals rise
- only use `speed-first` when policy allows and the network has a strong success history

## 21. Mobility and migration

APT sessions SHOULD survive routine path changes.

### 21.1 Address migration

If the client address changes, the client MUST prove path ownership using `PATH_CHALLENGE` and `PATH_RESPONSE` before the server fully trusts the new path.

### 21.2 Carrier migration

APT MAY migrate from one carrier binding to another without reauthenticating the user, provided the migration is authenticated by the current session keys.

Recommended behaviour:

- keep one primary carrier active
- maintain at most one standby path for sparse health checks
- migrate only after repeated evidence of impairment, not on one transient spike

## 22. MTU and fragmentation

APT MUST compute an effective tunnel MTU per carrier.

Rules:

- default tunnel MTU MUST be conservative on unknown paths
- PMTU discovery SHOULD be passive when possible
- if PMTU blackholing is suspected, the client SHOULD step down quickly
- fragmentation SHOULD happen inside the carrier layer only when unavoidable

The data plane SHOULD avoid creating long-lived size signatures such as a universal 1280-byte record.

## 23. Error handling

APT error handling is intentionally quiet.

Rules:

- admission failures do not produce APT-specific errors to unauthenticated peers
- authenticated peers MAY receive encrypted close reasons
- repeated invalid probes SHOULD be rate-limited or silently ignored
- state exhaustion protections MUST prefer dropping unauthenticated work over degrading authenticated sessions

## 24. Logging and telemetry

APT implementations SHOULD log enough for operators to debug deployment issues, but MUST avoid turning telemetry into a fingerprinting liability.

Recommended rules:

- never log plaintext user traffic
- log only coarse path classes by default
- keep local-normality raw histograms local
- make debug logging opt-in and short-lived

## 25. Recommended defaults

If I were freezing a first viable implementation, I would start with these defaults:

- initial policy mode: `stealth-first`
- initial handshake: `Noise XXpsk2`
- admission time bucket: 300 seconds
- replay cache retention: 10 minutes
- cookie lifetime: 20 seconds
- interactive added-latency target: 10 ms
- bulk added-latency target: 50 ms
- steady-state padding budget: 6%
- probation padding budget: 20%
- unknown NAT keepalive interval: 25 seconds with ±35% jitter
- soft rekey: 2 GiB or 20 minutes
- hard rekey: 8 GiB or 60 minutes
- minimum replay window: 4096 packets

Those are conservative enough to be buildable and tuneable.

## 26. Why this is technically viable

This is viable because it avoids the two most common mistakes in stealth tunnel design.

First, it does **not** invent exotic crypto. The security core uses standard, well-understood building blocks.

Second, it does **not** freeze one visible obfuscation syntax. The protocol is defined at the logical-message level and carried by bindings that can vary by deployment and policy.

The genuinely new part is not a magical packet format. It is the combination of:

- stateless authenticated rendezvous
- a strict separation of secure tunnel and camouflage layers
- bounded per-session persona generation
- a local-normality model that tries to avoid stable outlier behaviour
- policy-driven migration between carrier families

That is original enough to matter, but still conservative enough to build.

## 27. What I would build first

If I were turning this into an actual codebase, I would do it in three milestones.

### Milestone 1

Build:

- the inner tunnel core
- the admission handshake
- one datagram binding
- one stream binding
- a simple default persona engine with bounded jitter, coalescing, and padding

Do **not** overcomplicate the model yet.

### Milestone 2

Add:

- per-network local-normality profiles
- carrier migration
- resumption tickets
- decoy surface support for stream bindings
- policy controller with probation and fallback

### Milestone 3

Add:

- optional hybrid PQ mode
- standby path health checks
- better poisoning resistance in the local model
- operator controls for stealth, balance, and speed

## 28. Bottom line

If you want a stealth-first system that is still realistic, this is the shape I would choose:

- `WireGuard-like discipline` for the encrypted core
- `stateless authenticated admission` to resist probing
- `no canonical visible APT wire image`
- `per-session persona generation`
- `local-normality-shaped scheduling`
- `carrier agility with conservative migration`

That is, in my view, more promising than trying to find one clever new fixed obfuscation format and hoping censors do not fingerprint it.

If you want, I can do the next step and turn this into either:

1. an RFC-style document with stricter MUST/SHOULD/MAY language and message diagrams
2. a concrete module/interface spec for an implementation in Rust or Go
3. a threat-analysis review where I try to break this design and point out the weakest parts
