# Changelog

All notable changes to this project are documented in this file. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Added — distribution + showcase

- **libepx_c absorbed as this repo's primary product** (former EPX-CORE
  repo retired); README rewritten as the canonical hub listing every
  language implementation repo.
- **CI/CD**: release workflow (tag `v*`) publishing prebuilt
  libepx_c + headers + CLI tarballs to GitHub Releases, with an optional
  Homebrew tap bump (`packaging/homebrew/epx.rb`); every language repo
  gained CI (sibling-checkout of this repo) and tag-driven publishing to
  its package manager.
- **polychat** (`examples/polychat.cpp`, `polychat_c.c`): serverless,
  relay-less group chat — discovery via the enumerable registry, every
  message a direct encrypted peer link. The identical convention ships
  in all eight language repos; `tools/polychat_showcase.sh` launches all
  ten implementations into one conversation and verifies 90/90
  deliveries (verified passing).

### Added — mid-session key rotation (roadmap item 8c) — EXPERIMENTAL

- Opt-in, client-initiated re-keying of long-lived v2 sessions
  (`Client::enable_key_rotation(RotationPolicy)`; time- and/or
  byte-count-triggered). New REKEY/REKEY_ACK frames sealed under the
  current epoch; fresh X25519 exchange per rotation; per-direction epoch
  switch discipline over the ordered byte stream; per-epoch counter
  spaces + epoch bound into AEAD associated data (no cross-epoch
  replay/splicing); 255-rotation cap per connection.
  `Client::session_epoch()` for introspection.
- **Off by default and clearly flagged**: this is the one roadmap item
  that must not be considered production-ready before external
  cryptographic review (SPEC 6.4). Hosts at 2.1+ always *support*
  inbound rotation on v2 sessions.

### Added — pub/sub (roadmap item 5) and limits (items 6 + 7)

- **`EndpointKind::Topic`** — pub/sub as a first-class endpoint kind.
  `Host::expose_topic(name[, AccessPolicy]) -> TopicHandle`;
  `TopicHandle::publish(bytes)` from any thread; `Client::subscribe(...)
  -> Subscription` (RAII: destruction/unsubscribe() cleanly detaches, and
  the callback receives a final `closed=true` on host shutdown, refusal,
  or connection loss). The library owns subscriber registration,
  per-subscriber delivery, heartbeat-driven dead-subscriber pruning, and
  clean end-of-feed on `Host::stop()` — the pattern
  `examples/groupchat_common.hpp` used to hand-build, now generalized
  into `src/`. Endpoint names starting with `$epx/` are reserved.
- **`ConnectionLimits`** (`Host::set_limits`): pre-handshake per-UID
  connection-attempt cap, per-connection request token bucket
  (delay-then-disconnect-with-ERROR-frame), per-connection subscription
  cap, and a stream-write timeout (backpressure phase 1).
  `Client::set_stream_write_timeout` mirrors the last on the client side;
  `OutputStream::write` now returns `bool`.
- The groupchat example is rewritten on `Topic` — dramatically simpler
  (no listener threads, no hand-rolled heartbeats, no manual shutdown
  disconnect dance); verified as four real processes with scripted stdin.

### Added — enumerable registry + CLI (roadmap item 4)

- `epx::list_services()` / `epx::describe(name)` — enumerate every live
  registered service and read its self-description (identity key, pid,
  optional `Host::set_description` text, and every endpoint with its
  kind, populated automatically from `expose*()`). Stale entries from
  crashed hosts are pruned on the way. Documented loudly as
  unauthenticated metadata; the registry stays a passive store (never a
  relay).
- New `epx` CLI binary: `epx list`, `epx describe <service>`
  (CMake option `EPX_BUILD_CLI`, on by default at top level).

### Added — protocol v2 batch (roadmap items 8a + 8b)

- **Protocol version negotiation (8b).** HELLO/HELLO_ACK carry a trailing
  extension advertising the sender's highest supported version; sessions
  run at `min(client_max, server_max)`. Fully interoperable with v1 peers
  (they ignore the extension; the session runs at v1). Support-window
  policy: current + previous version. See SPEC 6.2.
- **Hardened v2 handshake transcripts.** When a session negotiates v2,
  both sides must present second signatures over domain-separated
  transcripts binding each signer's own identity key, the version offers,
  the negotiated result, and the server's accept/reject status. Any
  single-sided tampering fails closed. See SPEC 6.2.
- **Per-frame key-epoch byte (v2 frame layout)** bound into the AEAD
  associated data — groundwork for mid-session key rotation. SPEC 5.1/6.3.
- **Per-endpoint authorization tiers (8a).** `AccessPolicy` with
  `AccessTier::{Open, PinnedPeers, Certificate, PromptUser}`, settable
  Host-wide (`set_default_access`) and per endpoint (`expose(...,
  AccessPolicy)`). `PromptUser` invokes an application callback
  (`on_authorization_prompt`) answering AllowOnce/AlwaysAllow/Deny, with
  AlwaysAllow/Deny persisted per (peer, service, endpoint) under
  `~/.epx/authz/`. `Certificate` verifies offline-signed credentials
  (`make_credential`, `add_issuer`, `add_credential`, or `*.cred` files
  under `~/.epx/credentials/<service>/`). New RESPONSE status 3 →
  `EpxError::Code::AccessDenied`. See SPEC 7.2.
- `get_stream` now surfaces endpoint-not-found and access-denied as
  immediate errors (previously a missing endpoint stalled until timeout).

### Added

- `examples/groupchat_room.cpp` + `examples/groupchat.cpp`: an N-way group
  chat with dynamic join/leave under custom names, built entirely on top of
  existing `StreamSend` endpoints plus one small rendezvous ("room")
  service — no change to the protocol itself. Each participant exposes its
  own outgoing messages as an independent `feed` stream; joining/leaving
  members are discovered live via the room's `join` stream. See
  `examples/groupchat_common.hpp` for the design writeup.

### Changed

- `StreamWriter::write()` now returns `bool` (previously `void`): `true` if
  the chunk was handed off successfully, `false` if the connection is
  gone. Lets a `StreamSend` handler that produces chunks indefinitely (a
  live feed with no natural end, as in the group chat demo above) detect a
  dead peer and stop, instead of writing into the void forever. Source-
  compatible with existing code that ignores the return value.

## [1.0.0] — 2026-07-17

Initial reference implementation.

### Added

- Core protocol: mutually-authenticated, end-to-end encrypted local IPC.
  SIGMA-style handshake (Ed25519 identity signs a fresh ephemeral X25519
  key per connection), XChaCha20-Poly1305 transport encryption. See
  `docs/SPEC.md`.
- `Host`/`Client` C++ API with pluggable `TrustPolicy`
  (`TrustOnFirstUse`, `RequireKnownPeer`, `AllowAll`).
- Filesystem-based local service registry/discovery (no broker process).
- Four endpoint kinds: `Receive` (request/response), `Send`
  (fire-and-forget), `StreamReceive` (client → host chunk stream via
  `Client::open_stream`), `StreamSend` (host → client chunk stream via
  `Client::get_stream`).
- Non-blocking `Host::run()` with an explicit shutdown lifecycle:
  `request_stop()` (async-signal-safe), `wait_until_stopped()`,
  `stop_on_signals()`, and `before_stop()`/`after_stop()` hooks so an
  application decides how in-flight work is handled on shutdown rather
  than EPX imposing a policy. `run_async()` retained as a deprecated
  alias.
- POSIX transport (Unix domain sockets, Linux/macOS) and a Windows named
  pipe transport (implemented, not yet run-tested — see README).
- Examples: `expose_demo`/`client_demo` (RPC-style demo) and `chat` (a
  two-instance interactive terminal chat using `Send` and `StreamSend`).
- Test suite (`tests/`, registered with CTest): wire-format round-trip
  tests, an in-process Host+Client lifecycle test, and a streaming test
  covering all three non-`Receive` endpoint kinds.

### Known limitations

See `docs/SPEC.md` section 9 — no mid-session key rotation, no rate
limiting/backpressure, thread-per-connection with no pooling, Windows
transport untested, no protocol version negotiation beyond a single-byte
check.
