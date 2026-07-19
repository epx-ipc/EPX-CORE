# EPX v2 — Roadmap and Implementation Brief

This document is a build brief for extending EPX from a single-language
(C++) reference implementation into a real, polyglot, production-grade
local IPC protocol. It assumes the reader (human or agent) has the v1
repository in hand — `docs/SPEC.md` for the wire protocol, `include/epx/epx.hpp`
for the current C++ API, `src/` for the reference implementation, and
`examples/groupchat*` for the pub/sub pattern this roadmap promotes to a
first-class primitive. v1 is not being thrown away: every item below is
additive or is a versioned wire-protocol change, not a rewrite.

## Guiding principles (carried over from v1, do not relitigate)

- **No mandatory broker.** Every real conversation is a direct,
  point-to-point connection between two processes. Discovery metadata may
  become richer (see item 4), but it must never become a relay for
  application traffic — that's the line that keeps EPX differentiated from
  D-Bus.
- **Local only.** Same-machine, OS-local transports only (Unix domain
  sockets / Windows named pipes). Don't let "add a registry daemon" or
  "add flow control" quietly grow into "now it's a network protocol."
- **No hand-rolled cryptography.** New crypto-adjacent work (rate
  limiting is fine; key rotation is not) composes existing audited
  primitives (libsodium) the same way v1 does. Anything that touches the
  handshake or session-key derivation gets flagged below as needing
  outside review before shipping, not just code review.
- **One wire protocol, many languages.** The protocol is the product;
  the C++ library is the reference implementation of it. Every language
  binding must be a thin layer over the same C ABI and the same bytes on
  the wire — no binding gets its own parallel protocol logic.

## Suggested build order

The items below have real dependencies on each other; building them in
list order (1–8, as originally proposed) will cause rework. Suggested
sequencing:

1. **C ABI shim** first, always — every language binding depends on it,
   and writing it surfaces API design mistakes in the C++ core cheaply,
   before nine languages have to live with them.
2. **Wire-protocol v2 batch**, done together as one coordinated version
   bump rather than N separate breaking changes: version negotiation,
   per-endpoint authorization tiers, rate limiting, backpressure, and
   pub/sub as a first-class endpoint kind. These all touch the handshake
   or frame format, so batching them means one migration for downstream
   consumers instead of five.
3. **Mid-session key rotation** is deliberately *not* in that batch. It's
   the highest-risk, most cryptographically delicate item here (see item
   8c) and shouldn't gate the rest of v2 shipping. Treat it as v2.1,
   scoped and reviewed on its own timeline.
4. **Standalone/enumerable registry** can happen in parallel with step 2
   — it's a discovery/filesystem-layer change, not a wire-protocol change
   to the RPC path itself.
5. **Serialization convention + templates** can happen any time; it's
   docs and example projects, not core-library work, and has no
   dependency on anything else in this list.
6. **Language bindings** come last, on top of a *stable* C ABI. Within
   this phase: Rust first (bindgen against the C header is an excellent
   forcing function for catching ABI mistakes before they're load-bearing
   for eight other languages), then Python and Node together (broadest
   immediate reach — most polyglot local-IPC use cases involve at least
   one of these), then Go and C#, then Swift, then Ruby, then Dart last
   (its isolate model makes native-callback threading the hardest of the
   nine — see item 2's Dart notes).

---

## 1. C ABI shim

**Problem.** C++ has no stable ABI across compilers/versions (name
mangling, STL layout, exception unwinding all vary). Every other language
in item 2 needs a boring, stable, C-compatible surface to bind against.

**Design.**

- New `include/epx/epx_c.h` (pure C, no C++ in the header) plus
  `src/c_api.cpp` implementing it against the existing C++ core. The C++
  core is unchanged; this is a wrapper layer, not a rewrite.
- Opaque handles: `epx_host_t*`, `epx_client_t*`, `epx_identity_t*`,
  `epx_output_stream_t*`. No struct layout is exposed across the
  boundary — everything is accessed through functions.
- Errors cross the boundary as return codes (`EPX_OK`, `EPX_ERR_TIMEOUT`,
  `EPX_ERR_CONNECT_FAILED`, `EPX_ERR_HANDSHAKE_REJECTED`,
  `EPX_ERR_NOT_FOUND`, `EPX_ERR_TRANSPORT`, `EPX_ERR_PROTOCOL`, mirroring
  `EpxError::Code`), plus a thread-local `const char* epx_last_error(void)`
  for the human-readable message. No exceptions cross the ABI boundary,
  ever — the shim catches everything internally.
- Callbacks (`Handler`, `StreamReceiveHandler`, `StreamSendHandler`,
  the new authorization-prompt callback from item 8) become C function
  pointers plus a `void* user_data` passed through unchanged, the
  standard C callback idiom. Document explicitly, per callback type,
  which thread it may be invoked from — bindings need this to decide
  whether they need their own thread-hop (e.g. into Python's GIL, into a
  Node event loop via `napi_threadsafe_function`, into a Dart isolate via
  `Dart_PostCObject`).
- Byte buffers cross as `(const uint8_t* data, size_t len)` pairs on the
  way in; on the way out, the shim allocates and the caller owns the
  result until it calls `epx_bytes_free(epx_bytes_t)` — document the
  ownership rule once, in one place, and hold every binding to it.
- Versioning: `EPX_C_ABI_VERSION` integer constant plus a
  `epx_c_abi_version(void)` runtime check function, so a binding built
  against an older header fails loudly instead of corrupting memory
  against a newer `.so`/`.dylib`/`.dll`.
- Ship both a shared library target (what every binding links against)
  and keep the static `libepx` target for existing C++ consumers who
  don't need the shim at all.

**Definition of done.** Every example in `examples/` has a C-ABI
equivalent (`expose_demo_c.c`, etc.) that behaves identically to its C++
counterpart, and `tests/` gains a C-ABI test suite mirroring the existing
CTest coverage, run through the shim rather than the C++ API directly.

---

## 2. Language bindings

**Problem.** Most real polyglot systems won't touch a C++-only library.
Reach is the whole point of this phase.

**Design, per language** (all bind exclusively against `epx_c.h` from
item 1 — no binding talks to the C++ core directly, including Python,
even though pybind11 would be tempting; consistency and a single
maintenance surface matter more than saving one binding some
boilerplate):

- **Rust** — `epx-sys` (raw `bindgen`-generated FFI crate, checked into
  the repo rather than build-script-generated, so `bindgen` isn't a
  build-time dependency for consumers) plus a hand-written `epx` crate on
  top: RAII (`Drop` closes hosts/clients/streams), `Result<T, EpxError>`,
  and streaming exposed as a standard `Iterator`/`Stream` rather than a
  bare callback.
- **Python** — `cffi` (ABI mode, dynamically loading the shared library,
  no compiler needed at install time) wrapped in an idiomatic package;
  ship prebuilt wheels per platform via `cibuildwheel` since "needs a C
  compiler to `pip install`" kills adoption instantly.
- **Node/TypeScript** — a native addon via N-API (`node-addon-api` or,
  cheaper to maintain, `napi-rs` built on top of the Rust binding above);
  Promise-based for `get`/`send`, async iterators for streams; ship
  `.d.ts` types generated from the same source of truth as the docs.
- **Go** — `cgo` wrapper; idiomatic Go surface using channels for
  stream chunks and `context.Context` for cancellation/timeouts, matching
  Go conventions rather than mirroring the C++ API shape.
- **C#/.NET** — P/Invoke (`DllImport`) wrapper, packaged as a NuGet
  package; `Task`-based async API, streams as `IAsyncEnumerable<T>`.
- **Swift** — a Swift Package Manager target with a system-library
  modulemap over `epx_c.h`, plus a Swift-native wrapper using
  `async`/`await` and `AsyncStream` for the streaming kinds. Good fit for
  iOS/macOS distribution specifically.
- **Ruby** — the `ffi` gem binding directly to the shared library
  (`dlopen`, no native compilation step, matching Python's cffi choice
  for the same reason); idiomatic Ruby wrapper using blocks for
  callbacks.
- **Dart (Flutter)** — `dart:ffi` against `epx_c.h`. Flag this one
  explicitly as the hardest binding: Dart's isolate model means a native
  thread invoking a Dart callback directly is unsafe, and needs
  `NativeCallable.listener` / `Dart_PostCObject`-style hand-off back onto
  the correct isolate. Budget real time for this one; don't schedule it
  alongside anything else.
- **C/C++** — already served: C by `epx_c.h` directly, C++ by the
  existing `include/epx/epx.hpp`.

**Definition of done, per binding.** A working port of `chat.cpp` (the
two-party example) in that language, talking over the wire to the actual
C++ `chat` binary — cross-language interop tested for real, not just
same-language-both-sides.

---

## 3. Standard serialization for polyglot payloads

**Problem.** Endpoints pass raw `Bytes` today; every consumer hand-rolls
its own encoding (see the manual length-prefixed envelope in
`examples/chat.cpp`). Fine for one example, real friction across nine
languages and real projects.

**Recommendation: FlatBuffers over Cap'n Proto**, specifically because of
the language list in item 2. FlatBuffers has first-party or well-maintained
support for every language on that list, including Dart and Swift, which
is exactly the pair where Cap'n Proto's language coverage is weakest.
Cap'n Proto's built-in RPC layer is also irrelevant here — EPX already is
the RPC layer — so its main differentiator over FlatBuffers doesn't apply.

**Design.** Don't put a schema system into the wire protocol itself —
`Bytes` payloads stay opaque at the transport level, on purpose, so
someone with a good reason to use something else (protobuf, msgpack, raw
bytes) isn't blocked. Instead:

- Publish a documented convention: define endpoint request/response
  shapes in a `.fbs` schema per service, generate code per language via
  the FlatBuffers compiler, and pass the serialized buffer as the
  endpoint's `Bytes` payload.
- Ship a thin optional per-binding helper (`epx-flatbuffers` companion
  crate/package per language) that just reduces boilerplate around
  "serialize this table, hand it to `client.get()`" — not a required
  dependency.
- Add one worked example (`examples/flatbuffers_demo/`) with a shared
  `.fbs` schema and both a C++ and one other language (Python is the
  highest-value pairing) talking to each other through it, to prove the
  cross-language story end to end.

---

## 4. Standalone, enumerable registry

**Problem.** Today's registry is `publish`/`unpublish`/`lookup(single
name)` only — no "who's out there," which is exactly why
`examples/groupchat_room.cpp` had to hand-build its own membership
service instead of asking the registry directly.

**This has to be designed carefully against the "no broker" principle.**
The registry must stay strictly a passive metadata store — it answers
"what's registered and what does it claim to expose," never "relay this
message to X." The moment it starts forwarding application data, EPX has
quietly become D-Bus. Keep that line explicit in the spec.

**Design — default (no new daemon).** Extend the existing filesystem
registry format:

- When `Host::run()` is called, in addition to today's connection-address
  entry, write a small self-description sidecar (JSON or FlatBuffers,
  see item 3) listing the service name, an optional human-readable
  description string, and every `{endpoint_name, EndpointKind}` pair
  registered via `expose*()` — populated automatically from what's
  already been exposed, no extra work for the developer.
- New API: `epx::registry::list_services()` (enumerate the registry
  directory) and `epx::registry::describe(service_name)` (read one
  sidecar). Exposed through the C ABI too, so every binding gets this for
  free.
- New CLI subcommands: `epx list` and `epx describe <service>`.
- Explicitly document (next to this feature, not buried in a limitations
  section) that registry entries are unauthenticated metadata, exactly
  like today's lookup — enumerating a service doesn't prove anything
  about it; the live handshake is still what actually establishes trust.

**Design — optional stretch (a real daemon).** A lightweight, *opt-in*
`epxregistryd` that processes can register with for push notifications
("tell me the moment a new service matching X appears") instead of
polling the filesystem — useful for something like the group chat's
membership stream, but strictly an optional convenience sitting on top of
the same filesystem registry as its source of truth, never a required
part of the discovery path. Scope this only after the default,
daemon-free version ships and there's a concrete use case asking for it.

---

## 5. Pub/sub as a first-class endpoint kind

**Problem.** `examples/groupchat_common.hpp`'s `Broadcaster` — per-
subscriber queues, heartbeats, dead-peer pruning on a failed write —
is a correct and reusable pattern, hand-built entirely at the application
layer on top of `StreamSend`. If this is a common need (it clearly is;
it's the whole shape of a "live feed"), it belongs in the library.

**Design.**

- New `EndpointKind::Topic`. `Host::expose_topic(name) -> TopicHandle`;
  call `.publish(bytes)` on the handle any time, from any thread. The
  library owns subscriber registration, per-subscriber queuing, the
  heartbeat interval, and dead-subscriber cleanup on a failed write —
  i.e., move `Broadcaster` and the heartbeat loop out of
  `examples/groupchat_common.hpp` and into `src/`, generalized.
- `Client::subscribe(service, topic, on_message) -> Subscription`, an
  RAII handle — destroying it (or calling `.unsubscribe()`) disconnects
  cleanly, which also fixes at the library level the exact shutdown bug
  `examples/groupchat.cpp` had to fix by hand (a quitting participant
  needing to explicitly disconnect from every peer it had subscribed to).
- **Keep `StreamSend` as-is for bounded, producer-driven data** — a
  search-results stream, a file transfer, anything with a natural end.
  `Topic` is specifically for the unbounded/live case. Document a clear
  "which one do I use" table in `docs/SPEC.md` section 8 so this doesn't
  become a second confusing way to do the same thing: `StreamSend` when
  the handler function returning *is* the end of the stream; `Topic` when
  there is no such moment.
- Wire format impact is small — this is mostly a library/API promotion of
  an existing pattern, not a new wire mechanism. Reuse `StreamChunk`
  framing with a topic identifier, or introduce a narrowly-scoped
  `TopicPublish`/`TopicEvent` frame pair if the semantics diverge enough
  from request-correlated `StreamChunk` to warrant it (worth a short
  design spike before committing either way).

---

## 6. Backpressure / flow control

**Problem.** A fast producer on a `StreamSend`/`Topic` handler just
buffers unboundedly on the OS socket today — no application-visible
signal, no way to tune it.

**Design — phased, don't build the complex version first.**

- **Phase 1 (cheap, mostly already half-built):** make backpressure
  *observable* rather than inventing a credit protocol immediately.
  `StreamWriter::write()` already returns `bool` (added in the current
  version, for dead-peer detection) — extend the same idea with an
  optional write timeout, so a write that would block past that timeout
  returns `false` for "backpressured" the same way it does for "peer
  gone," and let the handler decide what to do (drop the chunk, block
  longer, disconnect). Do the same for `Client::OutputStream::write()`.
  This alone covers most real cases without a protocol change.
- **Phase 2 (only if phase 1 proves insufficient in practice):** a real
  credit-based flow control frame, HTTP/2-style — receiver periodically
  grants the sender an allowance (bytes or chunk count) via a small
  control frame, sender pauses once exhausted. Configurable window size,
  sane default, override per connection or per endpoint. Don't build this
  speculatively; build it once phase 1's timeout-based signal turns out
  not to be enough for a real workload (e.g. sustained high-frequency
  telemetry).

---

## 7. Rate limiting

**Problem.** A peer that completes the handshake can send requests as
fast as it wants; nothing today bounds request *rate*, only frame *size*.

**Design.**

- Per-connection token bucket, post-handshake: max requests/sec and max
  concurrent in-flight streams, both configurable with conservative
  defaults. A peer that exceeds the bucket gets delayed first, and
  disconnected with an `Error` frame carrying a clear reason code if it
  keeps exceeding it — don't silently drop, tell the peer why.
- Configurable via a new `ConnectionLimits` struct passed to `Host`
  construction or set per-`Host` (`host.set_rate_limit(...)`), with an
  optional per-endpoint override for particularly sensitive endpoints.
- Separately, **cap pre-handshake connection attempts per peer UID** —
  rate-limiting only after the handshake completes leaves a handshake-
  flood DoS wide open, since the handshake itself does real crypto work
  per attempt. This is a distinct, cheaper check that should land first.

---

## 8. Security model: per-endpoint authorization, real version negotiation, key rotation, and tiered trust with user prompts

This is the highest-value item on the list — it's what would make EPX's
security story genuinely differentiated rather than "TLS-shaped." Split
into three sub-parts because they have very different risk profiles.

### 8a. Tiered `AccessPolicy` with a user-prompt tier

**Design.** Generalize today's `TrustPolicy` (`AllowAll`,
`TrustOnFirstUse`, `RequireKnownPeer`) into a small spectrum, settable
per-`Host` as a default and overridable per-endpoint:

- `Open` — today's `AllowAll`. "Anyone on this machine can ask me
  stuff."
- `PinnedPeers` — today's `TrustOnFirstUse`. First contact is trusted
  and remembered; no further prompting.
- `Certificate` — a formalized version of today's `RequireKnownPeer`:
  instead of only accepting manually-added `allow_peer()` entries, accept
  a credential — the peer's public key plus an optional scope/expiry —
  signed by a declared issuer key. "You need a certificate from our dev
  to ask us stuff" becomes: developer signs a small credential file
  offline, ships it alongside the client app, `Host` verifies the
  signature chain at handshake time. A minimal local CA, not a full PKI.
- `PromptUser` — the new tier, and the one worth building carefully. On
  a connection attempt from a peer with no prior decision recorded, the
  `Host` invokes an application-supplied callback synchronously (this
  needs to reach a UI, so the API should support the caller blocking the
  handshake — with a sane timeout — while a prompt is shown) with the
  peer's identity, the requesting service/endpoint, and an optional
  human-readable reason string the caller can supply. The callback
  returns one of `AllowOnce`, `AlwaysAllow`, or `Deny`. `AlwaysAllow` and
  `Deny` get persisted, keyed by `(peer_pubkey, service, endpoint)`, in
  the same `~/.epx` store used for TOFU pinning today, so the user is
  only ever asked once per (peer, endpoint) pair unless they picked
  `AllowOnce`. This is the "Hey, can XOtherApp share data with us? Allow
  once / Always allow / Deny" UX the brief asked for, and it maps almost
  exactly onto the OS mic/camera/contacts permission pattern people
  already understand — a real usability advantage over D-Bus's opaque
  policy files.
- Per-endpoint override: `expose()` gains an optional `AccessPolicy`
  parameter so a mostly-`Open` service can still mark one sensitive
  endpoint (e.g. `"admin/shutdown"`) as `PromptUser` or `Certificate`
  even while the rest stays open.

**Note.** No wire-protocol change is required for this item — it's a
local authorization decision made *after* the identity is already
cryptographically established by the existing handshake. It's pure API
and storage-format work, which makes it lower-risk and a good first
target within item 8.

### 8b. Real protocol version negotiation

**Problem.** Today's check is a single hardcoded byte equality — no
negotiation, no transition path.

**Design.** `HelloPayload`/`HelloAckPayload` each carry a
`(min_supported, max_supported)` version range instead of one fixed
byte; both sides compute the highest mutually supported version and use
it for the rest of the session. Document a support-window policy (e.g.
"a given release supports the current version and the previous one") so
there's an actual deprecation path instead of a hard cutover.

### 8c. Mid-session key rotation — flag as high-risk, scope separately

**Design sketch.** Periodically (time- or byte-count-triggered) perform
a fresh ephemeral X25519 exchange over the already-authenticated
channel and derive new session keys, with an epoch counter added to the
frame header so both sides agree on which key generation a given frame
was sealed under.

**This is the one item in the entire roadmap that should not ship without
outside cryptographic review** — everything else here is composition of
existing primitives in well-understood ways (the same principle v1 was
built on); an in-session re-keying scheme is exactly the kind of thing
that's easy to get subtly wrong (epoch confusion, replay across epochs,
downgrade attacks on the rotation negotiation itself). Scope it as its
own release (v2.1, per the sequencing note at the top of this document),
get a real review before it ships, and don't let it block anything else
in this roadmap.

---

## Summary table

| # | Item | Touches wire format? | Depends on | Risk |
|---|------|----------------------|------------|------|
| 1 | C ABI shim | No | — | Low |
| 2 | Language bindings | No | Item 1 | Low–Medium (Dart) |
| 3 | Serialization convention | No | — | Low |
| 4 | Enumerable registry | No (filesystem layer only) | — | Low |
| 5 | Pub/sub (`Topic` kind) | Small | — | Low |
| 6 | Backpressure | Small (phase 2 only) | — | Low–Medium |
| 7 | Rate limiting | Small (new Error reason codes) | — | Low |
| 8a | Tiered trust + prompt UX | No | — | Low |
| 8b | Version negotiation | Yes (Hello/HelloAck) | — | Medium |
| 8c | Key rotation | Yes (frame header epoch) | 8b (versioning to introduce it safely) | **High — needs external review** |
