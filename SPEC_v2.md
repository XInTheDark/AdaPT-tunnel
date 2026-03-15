# Adaptive Persona Tunnel v2

Status: design draft for a break-vNext rewrite

This document defines the intended end state for **AdaPT v2**, a stealth-first tunnel redesign that keeps the secure inner core but replaces transport-centric camouflage with a **public-session stealth architecture**.

The main design change from v1 is simple:

**AdaPT v2 must not appear on the public wire as its own visible protocol.**

Instead, a v2 session begins as a real public service session and only upgrades into hidden tunnel mode from within valid application behaviour.

## 1. Purpose

AdaPT v2 has four priorities:

1. keep the secure inner tunnel and credential model conservative and understandable
2. maximise resistance to passive fingerprinting and active probing
3. avoid stable visible AdaPT-specific syntax on the public wire
4. remain implementable by one engineering team without requiring fantasy assumptions about censorship conditions

## 2. Lessons from v1

v1 proved that the inner core and adaptive controller were the strongest parts of the project, while the outer carriers remained weaker than the rhetoric around them.

In particular:

- opaque random-looking UDP is a legitimate technique, but not the same thing as believable public camouflage
- raw custom TCP framing plus a toy HTTP decoy is not credible stealth
- custom QUIC datagrams alone do not become convincing HTTP/3 or browser traffic by virtue of using UDP/443
- random padding and pacing alone are too weak to carry the full stealth burden

AdaPT v2 therefore treats the outer problem as a **public-service behaviour problem**, not a packet-wrapper problem.

## 3. Design goals

AdaPT v2 should:

- behave like a real public service to unauthenticated users and active probers
- embed hidden upgrade traffic inside legal application workflows
- derive per-session cover plans from secrets and local memory without explicit on-wire negotiation
- allow bounded adaptation to different networks without producing a deterministic fallback fingerprint
- keep the high-risk/low-stealth paths opt-in and subordinate to stronger public-session families

## 4. Non-goals

AdaPT v2 is not trying to:

- provide anonymity by itself
- defeat a perfect global end-to-end correlation adversary
- guarantee that every public-service family works on every network
- perfectly mimic every browser/app/ecosystem with one implementation
- retain wire compatibility with v1 `D2`/`S1`

## 5. Threat model

AdaPT v2 is designed to resist:

- passive DPI looking for stable outer handshake shapes, stream structure, retry ladders, timing ecology, and cover-traffic mismatches
- active probing that sends malformed or semi-valid traffic to exposed endpoints
- replay of hidden-upgrade capsules
- pre-auth state/resource exhaustion attempts
- transport interference such as MTU pressure, UDP impairment, stream resets, or path-specific throttling

AdaPT v2 does not claim to defeat:

- endpoint compromise
- malware on the client or server
- large-window end-to-end global timing correlation
- complete compromise of both the host and the public origin being used for camouflage

## 6. Terminology

### 6.1 Public session

A legitimate TLS/H2 or QUIC/H3 application session visible on the wire and valid even for unauthenticated users.

### 6.2 Hidden upgrade

The process by which a public session is covertly converted into a tunnel-bearing session using encrypted capsules embedded in valid application messages.

### 6.3 Cover family

A class of public-session behaviour with its own transport stack, request graph, stream ecology, timing envelopes, and convergence rules.

Examples:

- H2 API-sync family
- H3 object/origin family
- later, optional realtime family

### 6.4 Cover profile

A versioned machine-readable description of a cover family derived from observed traces and compiled into runtime rules.

### 6.5 Session cover plan

A secret-seeded per-session realisation of a cover profile. It specifies which request graph branch is used, where hidden upgrade slots exist, what concurrency/timing envelopes apply, and which side lanes are permitted.

### 6.6 Indistinguishability budget

A bounded runtime budget tracking how much the current session may still deviate from its selected cover family before the runtime must slow down, reshape, converge back to public semantics, or terminate.

### 6.7 Convergence

Returning a session to ordinary public-service behaviour when hidden upgrade fails, becomes unsafe, or must be abandoned.

### 6.8 Shadow lane

A subordinate auxiliary lane that exists only after a public session is established and only when allowed by the cover plan. It is never the first visible behaviour on a hostile path.

## 7. Architecture summary

AdaPT v2 has five logical layers.

1. **Credential and crypto core**
   - per-user or shared-deployment credentials
   - hidden-upgrade key derivation
   - ticket issuance
   - tunnel session secrets

2. **Public service surface**
   - real H2/TLS or H3/QUIC stack
   - real request/response behaviour
   - valid unauthenticated semantics

3. **Hidden-upgrade engine**
   - logical upgrade capsules embedded inside legal app messages
   - stateless-until-validated validation flow
   - upgrade confirmation and ticket delivery

4. **Cover planner and controller**
   - trace-compiled cover profiles
   - secret-seeded per-session plans
   - indistinguishability budgets
   - remembered network selection

5. **Inner tunnel**
   - encrypted tunnel packets
   - rekeying
   - replay protection
   - optional subordinate shadow lanes

## 8. Core public-wire rules

Every v2 stealth carrier MUST satisfy all of the following.

- It MUST expose a real public service, not a toy decoy.
- It MUST remain functionally valid for unauthenticated users.
- It MUST NOT expose an AdaPT-specific public-wire admission handshake.
- It MUST embed hidden-upgrade capsules only in legal application messages.
- It MUST define convergence rules that preserve believable public-service semantics on failure.
- It MUST bound pre-auth resource use before hidden-upgrade validation succeeds.
- It MUST support empirical comparison against real baseline traces of the same family.

## 9. Roles

AdaPT v2 defines four logical roles.

- `Client`: opens public sessions, derives cover plans, performs hidden upgrade, and terminates the local tunnel.
- `Public surface`: the real H2/H3-facing service behaviour presented to the network.
- `Upgrade gateway`: validates hidden-upgrade capsules and issues tunnel session state.
- `Tunnel node`: terminates the inner tunnel and any authorised shadow lanes.

A small deployment may colocate all four roles. A stronger deployment may separate the public surface/origin from the hidden tunnel node.

## 10. Transport families

AdaPT v2 uses three carrier names for continuity, but their semantics change.

### 10.1 `S1` v2

`S1` v2 is the **TLS/H2 public-session family**.

It is no longer a custom length-prefixed TCP stream. It is a real TLS-backed public session, usually expressed through HTTP/2-facing behaviour.

Recommended first v2 baseline:

- HTTPS API-sync behaviour
- request/response semantics
- optional long-polling or websocket-like submodes only when they are part of the honest public service

### 10.2 `D2` v2

`D2` v2 is the **QUIC/H3 public-session family**.

It is no longer "bare custom QUIC datagrams on 443". It is a real H3-facing public session.

Recommended baseline:

- object/origin behaviour over H3
- optional stream-heavy asset/object patterns
- optional H3 datagrams or WebTransport-like shadow lanes only after hidden upgrade and only when the selected cover profile permits them

### 10.3 `D1` v2

`D1` remains an **opaque fallback lane**.

It is not treated as the flagship stealth transport. It is permitted only when:

- explicitly pinned by the operator, or
- authorised by a remembered-safe network ticket, or
- used as a last-resort fallback on non-hostile paths

`D1` is not a public-session family and does not carry stealth claims beyond being an opaque fallback.

## 11. Hidden-upgrade protocol

AdaPT v2 keeps a logical upgrade handshake, but it no longer owns a public wire format.

The logical messages are:

- `UG1` client upgrade capsule
- `UG2` server upgrade reply
- `UG3` client confirmation
- `UG4` server session seal

These are logical objects embedded inside legal application messages chosen by the session cover plan.

### 11.1 `UG1` client upgrade capsule

`UG1` carries:

- version
- auth profile
- suite bitmap
- cover-family identifier
- cover-profile version
- selected graph branch identifier
- epoch slot
- client nonce
- path/network summary
- hidden-upgrade capabilities
- Noise message 1
- optional masked fallback ticket
- opaque extensions

`UG1` is encrypted under a per-epoch admission key and bound via AEAD associated data to:

- cover family
- origin/authority
- request slot identifier
- graph branch identifier
- transport family (`S1` or `D2`)

### 11.2 `UG2` server upgrade reply

`UG2` carries:

- chosen suite
- accepted cover family/version
- chosen graph branch confirmation
- cookie / anti-amplification token
- Noise message 2
- tentative budget class
- shadow-lane eligibility hint
- optional resumption acceptance
- opaque extensions

`UG2` is embedded in a legal server response body or body fragment consistent with the public service.

### 11.3 `UG3` client confirmation

`UG3` carries:

- cookie echo
- Noise message 3
- selected transport acknowledgement
- optional shadow-lane request
- opaque extensions

### 11.4 `UG4` server session seal

`UG4` carries:

- session identifier
- tunnel MTU
- rekey limits
- issued masked fallback tickets
- selected cover-plan budget class
- authorised shadow-lane descriptors
- opaque extensions

### 11.5 Validation rules

- The server remains logically stateless until the client proves authenticity and return reachability.
- Replay checks are keyed by credential identity, client nonce, and epoch slot.
- No invalid `UG1` or `UG3` may cause a distinctive AdaPT-specific outer response.
- Failure must converge into honest public-service behaviour whenever the public service can plausibly continue.

## 12. Binding upgrade capsules to public messages

Hidden-upgrade messages are not placed arbitrarily.

Each cover profile defines one or more **upgrade slots**. An upgrade slot specifies:

- which request or response in a legal graph may carry hidden bytes
- the legal body/media type shape
- minimum and maximum object size budget
- stream placement rules
- timing window constraints
- whether the slot may appear for unauthenticated public users or only on authenticated public paths

Example slot classes:

- JSON field value inside an API request body
- binary object fragment inside an upload or sync blob
- encrypted metadata field of a legitimate request body
- later, optional websocket/webtransport message slots

Every slot must remain syntactically and semantically legal for the public service.

## 13. Cover compiler and profiles

AdaPT v2 introduces a **trace-compiled cover compiler**.

The compiler ingests observed traces from a real public service and emits a versioned cover profile.

A cover profile contains at least:

- `family_id`
- `profile_version`
- transport family (`S1`/`D2`)
- legal request graphs
- legal upgrade slots
- stream concurrency rules
- size/timing envelopes
- idle/convergence rules
- optional shadow-lane rules
- feature weights for indistinguishability budgeting

The compiler may start simple. The first version does not need full automatic inference of every field. But it must produce machine-checked runtime artefacts rather than only human-written personas.

## 14. Session cover planning

Client and server derive a session cover plan from:

- credential material / persona seed
- selected cover family and profile version
- local network memory
- optional masked fallback tickets
- server policy
- requested runtime mode

The cover plan determines:

- which legal request graph branch to use
- where `UG1`/`UG2`/`UG3`/`UG4` may appear
- allowed stream concurrency
- pacing and size envelopes
- whether a shadow lane is permitted
- starting indistinguishability budget
- convergence policy when the budget degrades

The plan must be derived without explicit on-wire negotiation of the plan itself.

## 15. Indistinguishability budget

AdaPT v2 replaces loose shaping heuristics with a measured budget.

The budget tracks deviation from the chosen cover family over at least these observable dimensions:

- burst structure
- stream-open cadence
- request graph ordering
- object size envelopes
- idle gap distribution
- error ecology
- reconnection timing
- shadow-lane usage rate

Suggested runtime states:

- `Green`: normal hidden transfer permitted
- `Amber`: reduced burst size, tighter pacing, fewer shadow-lane opportunities
- `Red`: converge to public behaviour, stop hidden transfer, or terminate cleanly

The budget is not required to be a single scalar internally. A vector or weighted subscore model is acceptable as long as the runtime exposes a clear bounded policy.

## 16. Probe-triggered convergence

AdaPT v2 prefers convergence over bespoke decoys.

Rules:

- Unauthenticated ordinary users must see the public service.
- Invalid hidden-upgrade attempts should, where plausible, remain within public-service semantics.
- If hidden mode becomes ambiguous or unsafe, the session should continue or terminate as the public service normally would.
- Probe handling must be evaluated against honest baseline traces by the harness.

## 17. Masked fallback tickets

Successful sessions may issue **masked fallback tickets** bound to:

- network-context hash
- cover family or family set
- ticket expiry
- confidence / evidence level
- optional remembered-safe shadow-lane allowance

These tickets let a future client:

- prefer a likely-good cover family immediately
- avoid deterministic retry ladders
- restrict risky fallback behaviour to contexts where it has previously worked

Tickets must be sealed and unlinkable to observers.

## 18. Runtime data transport after upgrade

Once hidden upgrade succeeds, the client and server may exchange inner tunnel packets using one or more methods allowed by the cover plan.

Baseline method:

- carry tunnel payloads inside legal public-session message slots following the selected graph/timing rules

Optional method:

- open one or more subordinate shadow lanes if the cover family supports them and the indistinguishability budget is sufficient

The runtime must always be able to fall back to the baseline public-session embedding path.

## 19. Shadow lanes

A shadow lane may be authorised only when all of the following hold:

- the public session is already established
- hidden upgrade is complete
- the selected cover profile allows that lane type
- the current indistinguishability budget is sufficient
- server policy allows it

Candidate shadow lanes in descending preference:

1. H3/WebTransport/H3-datagram subordinate lane under `D2`
2. public-session-consistent subordinate stream under `S1`
3. `D1` direct opaque fallback only with explicit operator policy or remembered-safe ticket

A shadow lane is a privilege, not the baseline data path.

## 20. Deployment models

AdaPT v2 recognises three deployment strengths.

### 20.1 Strong mode

- real public origin or reverse-proxied public service
- separate hidden tunnel logic behind or beside the public service
- strongest stealth story

### 20.2 Medium mode

- same host provides both public service and hidden upgrade logic using a real mainstream stack
- acceptable for many deployments, but weaker than a more naturally distributed origin-backed service

### 20.3 Weak mode

- self-contained lab or convenience deployment
- permitted for testing and migration
- must not be described as the strongest stealth mode in docs

## 21. D1 fallback policy

`D1` is retained because opaque UDP can still be useful operationally, but v2 treats it honestly.

Rules:

- not advertised as the primary stealth path
- not the default first attempt on hostile networks
- available only by explicit operator pin, remembered-safe ticket, or last-resort policy
- separately measured by the harness as an opaque fallback, not as the main camouflage family

## 22. Configuration principles

v2 config and bundle schema MUST:

- use structured transport blocks for `S1` and `D2`
- record public-service family, authority/origin metadata, trust material, and cover-profile selection
- treat D1 policy separately from public-session families
- carry masked fallback ticket state separately from static operator config
- make strong/medium/weak deployment mode explicit in operator-facing docs and warnings

## 23. Compatibility and versioning

- v2 `S1` and `D2` are break-vNext and need not retain v1 wire compatibility
- bundle schema must be versioned distinctly
- a migration path may import old bundles/config and rewrite them into v2 structured blocks when possible
- old legacy modes may be preserved for testing only behind explicit compatibility flags

## 24. Security invariants

AdaPT v2 MUST preserve these invariants.

- The inner tunnel remains end-to-end encrypted before any optional subordinate lane transport touches it.
- Hidden-upgrade capsules are AEAD-protected and context-bound to the selected cover slot and transport family.
- No invalid hidden-upgrade attempt may elicit an AdaPT-specific public-wire signature.
- Pre-auth state and CPU work stay bounded.
- Shadow lanes never outrank the parent public session in trust or visibility.
- The empirical harness remains the gate for future stealth claims.

## 25. Recommended implementation order

The recommended order is:

1. harden v1 and remove misleading defaults
2. build the hidden-upgrade core independent of the old public-wire handshake format
3. ship one real H2 or H3 public-session family end-to-end
4. ship the sibling family
5. add the cover compiler, masked fallback tickets, and indistinguishability-budget controller
6. add subordinate shadow lanes only after the baseline public-session families are empirically credible
