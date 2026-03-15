# Client daemon / TUI / no-sudo client UX plan

## Purpose

`PLAN.md` is the repository's living implementation plan for current and pending non-trivial work. It should stay forward-looking and track only:

- the current milestone and status
- active/pending implementation chunks
- next tasks in expected execution order
- explicit assumptions and non-goals
- estimated latency / bandwidth / CPU impact notes per chunk

## Current milestone

- **Milestone:** privileged local client daemon + terminal dashboard + user-scoped default client install
- **Status:** the core implementation is now shipped in code:
  - new shared `apt-client-control` crate for local control protocol + `~/.adapt-tunnel` path helpers
  - structured client runtime hooks/events in `apt-runtime`
  - new privileged `apt-clientd` daemon with Unix-socket IPC, snapshots/events, reconnect supervision, and periodic latency sampling
  - `apt-client up`, `apt-client test`, and `apt-client tui` now target the daemon instead of requiring a direct privileged runtime launch each time
  - default bundle/import/state/override/socket paths now live under `~/.adapt-tunnel`
  - no implicit `/etc/adapt` client bundle discovery remains in the new default path
  - retriable runtime failures now schedule reconnect attempts automatically, including the reported AEAD/tunnel failure class
  - release packaging/install scripts now include `apt-clientd` so installed client bundles can actually use `apt-client service install`
  - daemon connect behavior now preserves the expected one-shot initial connect semantics: disconnect during `Connecting` cancels startup promptly, first-connect failures surface as errors instead of looping forever, and only post-establishment failures stay on the automatic reconnect path
  - server-side carrier churn no longer crashes `apt-edge` when a stale D2/stream path loses its sender; those sends are now treated as soft path-loss conditions instead of fatal host errors
  - macOS client DNS teardown now restores the prior resolver config and then refreshes resolver caches; route/DNS teardown failures now surface as warnings instead of failing silently
- **Primary remaining goal:** validate the new daemon/service flow on real hosts and polish any behavior gaps found in end-to-end use
- **UX intent:**
  - one-time privileged setup is acceptable (`sudo apt-client service install`)
  - normal daily use should be unprivileged (`apt-client import`, `apt-client up`, `apt-client test`, `apt-client tui`)
  - the TUI is the first-class local wrapper; a GUI remains deferred

## Latest shipped chunk impact note

- **Chunk:** local client daemon + TUI wrapper + `~/.adapt-tunnel` default client install
- **Latency impact:** negligible steady-state dataplane impact; the daemon only adds local supervision/bookkeeping plus an optional periodic RTT probe while connected
- **Bandwidth impact:** negligible steady-state tunnel impact; the only new routine network activity is the bounded latency probe when the daemon has a connected session
- **CPU impact:** small persistent local-process overhead from the daemon while installed/running; the TUI itself is opt-in and only consumes local terminal/UI work when launched
- **Notes:** mode/carrier/bundle changes currently apply by reconnecting through the daemon rather than mutating the live runtime in place

## Assumptions and non-goals

- The default client root is `~/.adapt-tunnel`.
- The default client bundle path is `~/.adapt-tunnel/client.aptbundle`.
- The default daemon socket path is `~/.adapt-tunnel/clientd.sock`.
- The default local override/state files stay next to the selected bundle.
- No implicit `/etc/adapt` bundle discovery remains in the normal client flow.
- Explicit legacy paths are still acceptable when the operator passes them directly (for example `--bundle /etc/adapt/client.aptbundle`).
- One-time privileged installation of the daemon/service is in scope; removing all privileged platform operations is not, because TUN, routes, and DNS changes still require elevation.
- The daemon remains a local wrapper/supervisor, not a remote control plane.
- TUI-first is in scope; a desktop GUI is intentionally deferred.

## Active / pending workstreams

| Chunk | Status | Scope | Estimated impact |
|---|---|---|---|
| Planning/docs maintenance | active | Keep `PLAN.md`, README/guides, and operator/client instructions aligned with the daemon-first client flow | No runtime impact |
| Release packaging hotfix publication | active | Publish refreshed release assets so the installer bundle includes `apt-clientd`; verify future release/install flows match the daemon-first client architecture | Distribution-only cost |
| Post-disconnect teardown validation | active | Reproduce and verify the reported macOS browser-profile hang after disconnect, with focus on resolver/cache cleanup and teardown logs | Brief best-effort resolver refresh on disconnect only |
| Real-host daemon/service validation | pending | Smoke-test `apt-client service install|status|uninstall` and the resulting daemon behavior on actual Linux and macOS hosts | Validation-only cost |
| End-to-end client UX validation | pending | Validate `apt-client import` → `apt-client up` / `apt-client tui` / `apt-client test` with the new `~/.adapt-tunnel` defaults and no daily sudo | Validation-only cost |
| Reconnect/failure-path validation | pending | Confirm automatic recovery on real transient failures, especially AEAD/tunnel failure cases, and tune retry/backoff/logging only if needed | Temporary reconnect delay only during failures |

## Next tasks

1. Publish refreshed release assets so `curl ... install.sh | sudo bash` installs `apt-clientd` alongside `apt-client`, then confirm the release archive contents and installer behavior from a clean machine.
2. Reproduce the reported macOS browser-profile hang around a full connect/disconnect cycle and confirm whether the new DNS/cache teardown removes the stale-loading symptom without regressing normal reconnect behavior.
3. Smoke-test the one-time service install flow on Linux and macOS and confirm the daemon can be reached afterward through `~/.adapt-tunnel/clientd.sock` without sudo.
4. Run an end-to-end client workflow with the new defaults: import a bundle into `~/.adapt-tunnel`, connect with `apt-client up`, inspect/change settings with `apt-client tui`, and run `apt-client test` against the daemon-managed session.
5. Force or capture representative transient failures (including the reported AEAD/tunnel failure class when reproducible) and confirm the daemon reconnect loop behaves correctly, surfaces useful logs/state, and returns to `Connected` without manual intervention when the failure is temporary.
6. After real-host validation, record any required follow-up polish here before starting a separate GUI discussion or broader client UX milestone.

## Validation requirements for this milestone

Required before closing this milestone:

- workspace tests stay green
- `cargo run -p apt-client -- --help` and the new daemon/TUI/service help surfaces stay coherent
- importing a bundle defaults to `~/.adapt-tunnel/client.aptbundle`
- normal client usage does not require sudo after the one-time service install
- the client no longer implicitly falls back to `/etc/adapt/client.aptbundle`
- changing mode/carrier/bundle through the daemon/TUI reconnects cleanly and updates snapshots/events correctly
- daemon snapshots expose session status, tx/rx counters, reconnect state, and RTT information
- transient/retriable runtime failures schedule reconnect attempts automatically instead of leaving the client abruptly disconnected
- terminal cleanup remains correct when the TUI exits normally or on error
