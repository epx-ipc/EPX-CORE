# EPX — Encrypted Process eXchange

Version 2 · Protocol specification

> Protocol v2 is negotiated in-band (section 6.2) and fully backward
> compatible with v1 peers: a v2 build talking to a v1 build runs the
> session at v1. What v2 adds: version negotiation with downgrade-hardened
> transcripts (6.2), a per-frame key-epoch byte enabling mid-session key
> rotation (5.5, 6.3), per-endpoint authorization tiers (7.2), a response
> status for authorization denial (5.3), and protocol-level ERROR frames
> for rate-limit signaling (5.6).

EPX is a local, on-device inter-process communication protocol. It plays the
role classic IPC (Unix sockets, named pipes, D-Bus, COM) plays today, but
with an HTTP-like request/response programming model, a built-in service
directory, and — unlike all of the above by default — every conversation
mutually authenticated and encrypted so that no other program on the
machine, privileged or not by ordinary means, can read or tamper with it in
transit.

This document specifies the protocol on the wire. `README.md` covers
building and using the reference implementation; the API itself is
documented in `include/epx/epx.hpp`.

## 1. Goals and non-goals

Goals:

- A program can **expose** named endpoints without knowing in advance who
  will call them.
- Another program can **discover** an exposed service by name and call an
  endpoint with **request/response** (`get`) or **fire-and-forget**
  (`send`) semantics.
- Every connection is **mutually authenticated**: each side proves control
  of a long-term private key, and the other side decides whether to trust
  that key (allow-list, trust-on-first-use, or open).
- Every byte on the wire, past an initial unencrypted handshake header, is
  **encrypted and integrity-protected**, so a third program on the same
  machine cannot read or modify the conversation even if it can see the
  socket file or pipe name.
- A single connection is reused across many `get`/`send` calls — a
  **conversation** — so only the first call pays for the handshake.

Non-goals (see section 9, Limitations, for detail):

- EPX is not a network protocol. It assumes both parties are processes on
  the same machine and uses OS-local transports (Unix domain sockets,
  Windows named pipes) exclusively.
- EPX does not protect against a compromised kernel, a debugger attached to
  one of the participating processes, or a user with root/Administrator
  access reading process memory directly. Its threat model is "other
  ordinary user-level programs on the same machine," matching what people
  usually mean by "IPC should be private" — not a defense against a fully
  compromised OS.
- EPX does not currently provide anonymous/unauthenticated discovery
  privacy: the registry (section 4) reveals which service names are
  registered to anything that can read the per-user runtime directory
  (which, by permissions, is only the same OS user — see section 4.3).

## 2. Architecture

There is no broker or daemon. Discovery is a plain local file lookup, not a
running process:

```
  Program A (Host)                         Program B (Client)
  ---------------                          -------------------
  epx::Host host("com.acme.notes", id);
  host.expose("search", handler);
  host.run();
    |
    | 1. binds a transport (Unix socket / named pipe)
    | 2. writes a registry entry: name -> (address, public key)
    v
  [ registry entry on disk ]  <---- 3. lookup("com.acme.notes") ---- epx::Client client(id2);
    |                                                                client.get("com.acme.notes", "search", data);
    | 4. accepts connection
    v
  <================ 5. mutually authenticated handshake =================>
    |
  <================ 6. encrypted request/response frames =================>
```

Once the client has the address and expected public key from the registry,
steps 5 and 6 are a direct point-to-point connection between the two
processes — the registry is not involved again until the connection needs
to be re-established (e.g. after the host restarts).

## 3. Identities

Every program that participates in EPX — as a Host, a Client, or both — has
one **long-term identity**: an Ed25519 keypair, generated on first use and
persisted locally (`epx::load_or_create_identity(app_name)`). This is the
program's durable "who are you," analogous to an SSH host key: it does not
change across restarts, and peers pin it the same way an SSH client pins a
host key on first connection.

The identity key is used only to **sign** a fresh ephemeral key at the
start of each connection (section 6) — it never directly encrypts
application data. This separation is what gives EPX forward secrecy (a
leaked long-term key does not expose previously recorded traffic) while
still letting peers durably recognize each other.

## 4. Discovery: the local registry

### 4.1 What it stores

When a Host starts (`Host::run` / `run_async`), it publishes a small record
containing:

| field       | meaning                                                       |
|-------------|----------------------------------------------------------------|
| `version`   | registry entry format version                                 |
| `service`   | the service name (also the file's name)                       |
| `address`   | transport address to dial (socket path / pipe name)            |
| `pubkey`    | the host's long-term Ed25519 public key, hex-encoded          |
| `pid`       | the host process's PID, used to detect and clean up stale entries |
| `endpoints` | comma-separated `name:kind` list of exposed endpoints, populated automatically from `expose*()` |
| `description` | optional human-readable one-liner (`Host::set_description`) |

A Client resolves a service name to this record with `registry::lookup`,
which also verifies the recorded PID is still alive and silently removes
(and treats as "not found") any entry left behind by a process that
crashed without calling `Host::stop()`.

**Enumeration (v2, roadmap item 4).** The registry is also enumerable:
`epx::list_services()` lists every live registered service and
`epx::describe(name)` returns its self-description (identity key, pid,
description, endpoints + kinds); the `epx` CLI (`epx list`,
`epx describe <service>`) is a thin wrapper over the same calls. Two
lines that must not blur: (1) everything here is **unauthenticated
metadata**, exactly like the lookup itself — enumerating a service
proves nothing; only the live handshake does (4.3); and (2) the registry
remains a **passive metadata store** — it answers "what claims to be
registered," and never relays application traffic. The moment it
forwarded a message, EPX would have quietly become a broker; that line
is load-bearing for the whole design (section 2).

### 4.2 Where it lives

- **POSIX**: `$XDG_RUNTIME_DIR/epx/registry/<service>.entry`, falling back
  to `/tmp/epx-<uid>/epx/registry/<service>.entry` if `XDG_RUNTIME_DIR`
  isn't set. The transport socket itself lives alongside it under
  `.../epx/sockets/<service>.sock`.
- **Windows**: `%LOCALAPPDATA%\epx\run\registry\<service>.entry`
  (see README for the current state of Windows support).

### 4.3 Why a plain file is an acceptable discovery mechanism

The registry only ever tells a client *where to dial* and *which key to
expect there* — it is not part of the trust boundary. Even a compromised or
spoofed registry entry cannot impersonate a service: the handshake
(section 6) requires the live peer to *prove*, cryptographically, that it
holds the private key matching whatever public key the client ends up
trusting. A bad registry entry at worst causes a failed handshake, never a
successful impersonation.

The registry directory is created with owner-only permissions
(POSIX mode `0700`/`0600`), so only the current OS user can even enumerate
which services are registered — a coarse first line of defense on
multi-user machines, on top of the cryptographic guarantee above.

## 5. Wire format

### 5.1 Stream framing

Every message on the connection, in both directions, is one frame:

```
uint32  total_length     -- big-endian, byte count of everything below
uint8   frame_type
uint64  counter           -- big-endian; AEAD nonce/replay counter (0 for HELLO/HELLO_ACK)
uint8   epoch             -- v2 sessions only (see below); key generation, 0 until a rekey
bytes   body              -- cleartext for HELLO/HELLO_ACK, AEAD ciphertext+tag otherwise
```

The `epoch` byte exists only on frames of a session negotiated at v2
(section 6.2), and never on HELLO/HELLO_ACK (which precede negotiation).
Both sides know the negotiated version, so the layout is never ambiguous.
For v1 sessions the layout is exactly the v1 spec: no epoch byte.

`total_length` is capped at 16 MiB (`wire::kMaxFrameBytes`); a frame
claiming to be larger is rejected outright, before any allocation, as a
defense against a peer trying to force unbounded memory use.

Frame types:

| value | name       | when                                                    |
|-------|------------|----------------------------------------------------------|
| 0     | HELLO      | client → server, first frame of a connection             |
| 1     | HELLO_ACK  | server → client, reply to HELLO                          |
| 2     | REQUEST    | either direction*, an endpoint call                       |
| 3     | RESPONSE   | reply to a REQUEST (omitted for one-way requests)         |
| 4     | ERROR      | reserved for future protocol-level error signaling         |
| 5     | PING       | liveness check                                            |
| 6     | PONG       | reply to PING                                             |
| 7     | BYE        | graceful close notification                                |
| 8     | STREAM_CHUNK | one chunk of a streamed transfer (either direction — section 5.4) |

\* In this reference implementation requests flow client → host only; the
frame type is direction-agnostic in the wire format so a future version can
support server-initiated calls (e.g. push notifications) over the same
already-authenticated connection without a new handshake.

### 5.2 Handshake payloads (cleartext)

**HELLO** (`wire::HelloPayload`):

```
uint8    version             -- ALWAYS 1 on the wire (legacy byte a v1 peer validates)
byte[32] identity_pubkey     -- sender's long-term Ed25519 public key
byte[32] ephemeral_pubkey    -- fresh X25519 public key, this connection only
byte[16] client_nonce        -- random, anti-replay
uint8    service_name_len
byte[]   service_name        -- which exposed service this HELLO is for
byte[64] signature           -- Ed25519 sig over (ephemeral_pubkey || client_nonce || service_name)
-- v2 trailing extension (a v1 decoder reads the fields above and ignores this):
uint8    max_version         -- highest protocol version the sender speaks (>= 2)
byte[64] signature_v2        -- Ed25519 sig over the v2 hello transcript (6.2)
```

**HELLO_ACK** (`wire::HelloAckPayload`):

```
uint8    version             -- ALWAYS 1 on the wire (legacy byte)
byte[32] identity_pubkey     -- server's long-term Ed25519 public key
byte[32] ephemeral_pubkey    -- fresh X25519 public key, this connection only
byte[16] server_nonce        -- random, anti-replay
byte[16] client_nonce        -- echoed from HELLO, binds the ack to this exchange
uint8    status               -- 0 = accepted, 1 = rejected
byte[64] signature           -- Ed25519 sig over (ephemeral_pubkey || server_nonce || client_nonce)
-- v2 trailing extension:
uint8    max_version
byte[64] signature_v2        -- Ed25519 sig over the v2 ack transcript (6.2)
```

Sending identity and ephemeral public keys in the clear is intentional and
safe: an eavesdropper learns *who* is talking to *whom* (which, recall, is
already visible from filesystem permissions on the registry — see 4.3) but
gains nothing that helps read or forge the encrypted traffic that follows,
because the session keys derive from a fresh ephemeral Diffie-Hellman
exchange, not from anything transmitted.

### 5.3 Application payloads (always encrypted after the handshake)

**REQUEST** (`wire::RequestPayload`):

```
uint64  request_id
uint8   oneway          -- 1 = fire-and-forget, no RESPONSE will follow
uint8   endpoint_len
byte[]  endpoint
uint32  data_len
byte[]  data
```

**RESPONSE** (`wire::ResponsePayload`):

```
uint64  request_id      -- correlates to the REQUEST
uint8   status           -- 0 = ok, 1 = application error, 2 = endpoint not found,
                            3 = access denied (v2; endpoint AccessPolicy refused the peer, see 7.2)
uint32  data_len
byte[]  data              -- response bytes, or a UTF-8 error message if status != 0
```

A status-3 RESPONSE is also the answer to a *stream* request
(`get_stream`) whose endpoint denies the caller — the client library maps
it onto its error type rather than waiting for chunks that will never
come. Denied fire-and-forget requests and denied inbound stream chunks
are dropped silently (they have no response channel by design).

**ERROR** (`wire::ErrorPayload`, v2) — a protocol-level condition,
distinct from a per-request status, sent right before the host closes a
connection it is force-disconnecting:

```
uint16  reason           -- 1 = rate limited, 2 = too many concurrent streams, 3 = protocol
byte[]  message           -- UTF-8, human-readable, for logs
```

### 5.4 Streaming payload

**STREAM_CHUNK** (`wire::StreamChunkPayload`) — one chunk of a streamed
transfer, used in both directions (see 6.1):

```
uint64  request_id     -- for client -> host chunks, chosen by the client and
                          shared by every chunk in the logical stream; for
                          host -> client chunks, echoes the REQUEST that
                          started the stream
uint32  seq             -- 0, 1, 2, ... — informational ordering/sanity check
uint8   is_last          -- 1 on the final chunk of the stream
uint8   endpoint_len
byte[]  endpoint         -- only meaningful client -> host (see 6.1); empty
                          host -> client, where request_id alone correlates
uint32  data_len
byte[]  data
```

## 6. Handshake protocol

EPX's handshake is a small, purpose-built construction in the SIGMA family
(the same family TLS 1.3 and IKEv2 belong to): authenticate a fresh
ephemeral Diffie-Hellman exchange with a long-term signature, rather than
using the long-term key directly for key agreement. Concretely:

```
Client                                                  Server
------                                                  ------
generate ephemeral X25519 keypair (Ce_pk, Ce_sk)
sig_c = Sign(Cid_sk, Ce_pk || client_nonce || service_name)
        --------- HELLO(Cid_pk, Ce_pk, client_nonce, service_name, sig_c) --------->
                                                generate ephemeral X25519 keypair (Se_pk, Se_sk)
                                                verify sig_c against Cid_pk
                                                decide: trust Cid_pk? (section 7)
                                                sig_s = Sign(Sid_sk, Se_pk || server_nonce || client_nonce)
        <-------- HELLO_ACK(Sid_pk, Se_pk, server_nonce, client_nonce, status, sig_s) --------
decide: trust Sid_pk? (section 7)
verify sig_s against Sid_pk
if either side rejected -> close connection
else:
  (rx, tx) = X25519-KDF(Ce_sk, Ce_pk, Se_pk)              (rx, tx) = X25519-KDF(Se_sk, Se_pk, Ce_pk)
  [rx/tx swap between the two sides, giving each a distinct one-way key]
  zero Ce_sk, Se_sk (ephemeral secrets are discarded — this is the forward secrecy step)
```

The client's trust decision on the server's key, and the server's trust
decision on the client's key, are evaluated independently and are described
in section 7 — the handshake itself is agnostic to *which* policy is in
effect; it only enforces that whichever key is trusted must be
cryptographically proven live (via the signature), not merely asserted.

After both signatures verify and both sides accept, `crypto_kx` derives two
32-byte session keys from the ephemeral exchange (`rx` for what this side
reads, `tx` for what it writes — deliberately distinct, so a compromise of
traffic in one direction doesn't help decrypt the other). From this point
every frame's body is sealed with XChaCha20-Poly1305 AEAD under those keys.

### 6.1 Anti-replay

- `client_nonce`/`server_nonce` are single-use per handshake and are bound
  into both signatures, so a captured HELLO/HELLO_ACK pair cannot be
  replayed to start a new session (the peer would generate a fresh nonce
  and reject a mismatched echo).
- Every encrypted frame's AEAD associated data includes its own `counter`
  field, and the counter is required to be exactly the next expected value
  in sequence on each side — a duplicated, reordered, or replayed
  application frame fails to authenticate (or fails the sequence check
  outright) and the connection is dropped rather than silently accepting
  it.

### 6.2 Version negotiation (v2)

Each side advertises the highest protocol version it speaks in the
trailing extension of its handshake payload (5.2); the session runs at
`min(client_max, server_max)`. A pure-v1 peer sends no extension and is
treated as `max_version = 1` — full interoperability, the session simply
runs at v1. A given release supports the current protocol version and the
previous one (the support window), so there is a real deprecation path
rather than a hard cutover.

When the negotiated version is >= 2, both sides MUST present and verify
the v2 signatures over these domain-separated transcripts:

```
hello_v2 = "EPX-v2-hello" || max_version || client_identity_pk
           || ephemeral_pk || client_nonce || service_name

ack_v2   = "EPX-v2-ack" || server_max_version || negotiated_version || status
           || server_identity_pk || client_identity_pk
           || ephemeral_pk || server_nonce || client_nonce
```

Design notes:

- Each signer binds **its own identity key** into its transcript —
  hardening against unknown-key-share-style identity misbinding that the
  v1 transcript (ephemeral key + nonce only) did not rule out by
  signature alone.
- The ack transcript binds the server's **accept/reject `status`** — a
  v1 ack's status byte was unsigned.
- Version offers and the negotiated result are signed on both sides, so
  tampering with either advertisement makes one side's transcript
  disagree with the other's and verification **fails closed** — the
  connection dies rather than silently running at a lower version. The
  one residual case is an interposer stripping *both* extensions, which
  yields an honest v1<->v1 session: equivalent to what a genuine v1 peer
  gets, and requiring a man-in-the-middle position on a direct,
  same-machine socket — outside this protocol's threat model (section 1),
  where no relay exists to interpose on.

### 6.3 Key epochs (v2)

Every post-handshake frame of a v2 session carries an `epoch` byte
(5.1) naming the key generation that sealed it, and the epoch is bound
into the AEAD associated data (`frame_type || counter || epoch`). Epoch 0
is the handshake-derived key pair; each mid-session rekey (an opt-in v2.1
feature — see section 6.4 when enabled) increments it. Binding the epoch
cryptographically means a frame recorded under one key generation can
never authenticate under another, even if the per-epoch counter sequences
happen to align.

### 6.4 Mid-session key rotation (v2 — opt-in, pending external review)

> ⚠ **Review status.** This mechanism is implemented and tested but has
> not yet received the external cryptographic review ROADMAP_V2.md item
> 8c requires before it can be considered production-ready. It ships
> **disabled**; `Client::enable_key_rotation` is an explicit opt-in to a
> pre-review feature. Everything else in this spec is composition of
> audited primitives in standard shapes; an in-session re-keying scheme
> is the one place bespoke protocol design was unavoidable.

Long-lived connections can periodically move to fresh session keys so
that no single key generation protects unbounded traffic, and a key
compromised mid-session exposes at most one epoch of it.

- Rotation is **client-initiated** (the connection originator), triggered
  on its send path by time (`RotationPolicy::interval`) and/or bytes sent
  (`RotationPolicy::max_bytes`). Hosts speaking v2 always support inbound
  rotation regardless of any local setting.
- Frames: `REKEY` (9, client→server) and `REKEY_ACK` (10, server→client),
  both sealed under the **current** epoch's keys with the normal counter
  sequence — an attacker can neither inject nor strip them without
  breaking the AEAD/counter chain. Each carries a fresh X25519 public key
  (32 bytes) as its body.
- Both sides derive the next epoch's key pair from the two fresh
  ephemerals via the same `crypto_kx` construction as the handshake
  (roles preserved); the long-term identity keys are not involved again —
  authentication carries over from the still-running authenticated
  channel the exchange rode in on.
- **Switch discipline** (the transport being an ordered byte stream is
  load-bearing here): the server switches its tx keys immediately after
  the `REKEY_ACK` (same lock: nothing else interleaves), so everything
  after the ack on that direction is epoch e+1 and everything before is
  epoch e. The client switches its tx on processing the ack. Each
  receiver keeps the old epoch's key until the **first** frame tagged
  e+1 arrives (which must carry counter 0 — each epoch is a fresh
  counter space), then wipes it. A frame tagged with any other epoch, or
  an out-of-sequence counter, kills the connection.
- Replay/cross-epoch splicing is excluded twice over: the epoch is bound
  into the AEAD associated data (6.3), *and* each epoch has distinct
  keys.
- The epoch byte caps rotations at 255 per connection; a connection
  needing more must reconnect (fresh handshake), which is strictly
  stronger anyway.

## 7. Trust policies

Both `Host` and `Client` take a `TrustPolicy` (`epx.hpp`):

- **`TrustOnFirstUse`** (default) — asymmetric between the two sides,
  because only one side has a durable name to anchor a pin to:
  - *Client side*: the first identity key seen for a given service name is
    pinned (`~/.epx/known_peers/`). Later connections must present the
    *same* key or are rejected outright — including before the handshake
    completes, if the registry now claims a different key than what's
    pinned (an SSH-style "identity changed" condition, which is exactly
    the scenario TOFU is meant to catch: it protects against impersonation
    *after* the first legitimate contact, not during it).
  - *Server side*: an incoming client presents no name — its identity *is*
    its key — so there is nothing to bind a pin to, and a brand-new key is
    indistinguishable from a legitimate new client. The server therefore
    **accepts and records** every previously-unseen client key
    (`~/.epx/known_clients/`). This recording provides continuity (the
    handler is told, via `PeerInfo::key_was_pinned_now`, whether this
    caller has been seen before) but it is **not access control**: a
    server that must restrict callers uses `RequireKnownPeer` /
    `allow_peer`, or the per-endpoint authorization tiers introduced in
    protocol v2 (`AccessPolicy`).
- **`RequireKnownPeer`** — only identities explicitly added via
  `allow_peer(pubkey)` are ever accepted; anyone else is rejected, every
  time, with no auto-pinning. Use this when you can distribute/pin the
  expected key out of band (e.g. bundled with your app's installer) and
  want no first-contact trust gap at all.
- **`AllowAll`** — any identity is accepted. The channel is still fully
  encrypted and the peer still had to prove control of *some* private key,
  but there is no guarantee it's a key you've seen before. Intended for
  local development only.

### 7.2 Per-endpoint authorization: AccessPolicy tiers (v2)

`TrustPolicy` answers "who may complete a handshake at all"; from v2,
`AccessPolicy` additionally answers, **per endpoint**, "what may an
already-authenticated peer actually call." A Host sets a default tier and
may override it per endpoint (`expose(..., AccessPolicy)`). This is a
purely host-local decision made after the handshake has
cryptographically established the peer's identity — it requires no wire
change beyond RESPONSE status 3 (5.3).

- **`Open`** — any authenticated peer may call. The default (matches v1
  behavior).
- **`PinnedPeers`** — only peers this host has recorded before
  (`allow_peer()` or a prior TrustOnFirstUse recording). Under a
  TrustOnFirstUse host this admits first-contact callers too (they are
  recorded during the same handshake); it bites under
  `TrustPolicy::AllowAll`, where unknown peers authenticate without
  being recorded and are therefore refused here.
- **`Certificate`** — the peer's key must be covered by a **credential**:
  a small offline-signed statement `(peer key, scope, expiry)` whose
  issuer key the host explicitly trusts (`add_issuer()`). Scope is either
  a service name (covers all endpoints) or `service/endpoint`. A minimal
  local CA: one signature, no chains; use short expiries instead of
  revocation. Credentials are installed programmatically
  (`add_credential()`) or dropped as `*.cred` files under
  `~/.epx/credentials/<service>/`, and travel out of band (shipped
  alongside the client app) — the wire protocol is unchanged.
- **`PromptUser`** — on first contact, the host application's prompt
  callback is invoked (synchronously, on the connection's thread) with
  the peer identity, endpoint, and an app-supplied reason string, and
  answers `AllowOnce` (this connection only, not persisted),
  `AlwaysAllow`, or `Deny` (both persisted per
  `(peer key, service, endpoint)` under `~/.epx/authz/`, so the user is
  asked exactly once). No callback registered means deny. This is the
  OS mic/camera-permission pattern applied to IPC.

A denied `get` receives RESPONSE status 3 (surfaced as an
`AccessDenied` error by the client library); a denied `get_stream`
request receives the same status-3 RESPONSE; denied fire-and-forget
requests and denied inbound stream chunks are dropped silently (no
response channel exists for them by design).

## 8. Endpoint kinds and request/response semantics

Every endpoint a `Host` exposes has a declared `EndpointKind` (`epx.hpp`),
chosen by which `expose*` method registered it. The kind determines both
the shape of the handler and which `Client` method a caller must use:

| `EndpointKind`   | registered via                        | called via                    | shape                                              |
|-------------------|----------------------------------------|--------------------------------|-----------------------------------------------------|
| `Receive`          | `Host::expose(endpoint, Handler)`      | `Client::get(...)`             | one request in, one response out, caller blocks     |
| `Send`             | `Host::expose(EndpointKind::Send, ...)` | `Client::send(...)`           | one request in, fire-and-forget, no response        |
| `StreamReceive`    | `Host::expose_stream_receive(...)`     | `Client::open_stream(...)`     | caller pushes a sequence of chunks, host has no response |
| `StreamSend`       | `Host::expose_stream_send(...)`        | `Client::get_stream(...)`      | one request in, host pushes back a sequence of chunks |
| `Topic` (v2)       | `Host::expose_topic(...)`              | `Client::subscribe(...)`       | named broadcast feed: host publishes at will, every subscriber receives every message |

**`StreamSend` vs `Topic` — which one do I use?** By lifetime, not by
shape:

| you have...                                            | use          | because                                                             |
|--------------------------------------------------------|--------------|----------------------------------------------------------------------|
| a bounded transfer (query results, a file, a snapshot) | `StreamSend` | the handler function returning *is* the end of the stream            |
| an unbounded live feed (chat, telemetry, events)       | `Topic`      | there is no such moment; the library owns fan-out, heartbeats, and dead-subscriber pruning |

This is local bookkeeping, not something negotiated on the wire — a
`Receive` and a `Send` endpoint look identical as `REQUEST`/`RESPONSE`
frames (the only difference is whether the host actually emits a
`RESPONSE`, controlled by the request's own `oneway` flag, which
`Client::get`/`Client::send` set appropriately). The streaming kinds
introduce the `STREAM_CHUNK` frame from section 5.4:

- **`StreamReceive`** (client → host, section 5.4): `Client::open_stream`
  returns an `OutputStream` handle; each `.write(chunk)` call sends one
  `STREAM_CHUNK` frame carrying the target endpoint name, and `.finish()`
  (or the handle's destructor) sends a final chunk with `is_last = true`
  and no data. The host dispatches each incoming `STREAM_CHUNK` directly to
  the registered `StreamReceiveHandler` for its `endpoint` field —
  deliberately stateless on the host side; if the handler needs to
  accumulate chunks into a buffer, that's the handler closure's own state,
  not the library's.
- **`StreamSend`** (host → client): `Client::get_stream` sends a normal
  `REQUEST` (so it still gets a `request_id`) and then blocks, invoking the
  supplied callback once per `STREAM_CHUNK` that arrives correlated to that
  `request_id`, until one arrives with `is_last = true`. On the host side,
  the registered `StreamSendHandler` is handed a `StreamWriter` and may
  call `.write(chunk)` any number of times before returning; the library
  automatically appends the final `is_last` chunk once the handler function
  returns, so handlers never need to signal completion themselves.
  `get_stream`'s `timeout` is a *stall* timeout — it resets every time a
  chunk arrives, so a slow-but-still-producing stream won't be cut off,
  only a genuinely stuck one will. `StreamWriter::write()` returns `bool`
  (true if the chunk was handed off successfully) rather than `void`, so a
  handler that produces chunks indefinitely — a live feed with no natural
  end, as opposed to a bounded result set — can detect a dead peer and stop
  producing instead of writing into the void forever. See
  `examples/groupchat.cpp` for a handler built exactly that way: each
  participant's outgoing message feed runs until `write()` first returns
  `false`.

- **`Topic`** (v2): `Client::subscribe` sends a normal `REQUEST` (whose
  `request_id` correlates everything that follows) and returns a
  `Subscription` handle immediately; each message the host later publishes
  arrives as a `STREAM_CHUNK` for that `request_id`. There is no success
  response — the first sign of life is the first message (or heartbeat-
  driven pruning host-side). A *refused* subscription (unknown topic,
  access denied per 7.2, or over the per-connection subscription limit)
  gets a normal error `RESPONSE`, and the subscriber's callback receives a
  single final `closed=true`. Unsubscribing sends a fire-and-forget
  `REQUEST` to the reserved endpoint `$epx/unsubscribe` whose payload is
  the 8-byte original `request_id`. The host sends a final
  `is_last = true` chunk on every live subscription when the topic closes
  (Host shutdown), so subscribers can distinguish a clean end from a
  dropped connection. Hosts heartbeat topic subscribers with cleartext
  `PING` frames (no counter consumed) every few seconds purely so a dead
  subscriber's socket fails a write promptly and gets pruned; clients
  ignore inbound `PING` on the wire. Endpoint names beginning with
  `$epx/` are reserved for the protocol.

Regardless of kind:

- Multiple endpoints, of any mix of kinds, can be exposed by one `Host`
  (one identity, one listening transport, dispatched by the `endpoint`
  field of each frame).
- `Client::get`/`get_stream` throw `EpxError` on timeout, a rejected
  handshake, a transport failure, or an application-level error/not-found
  status.
- A `Client` keeps one open, authenticated connection per target service
  and reuses it across calls — this is what makes a multi-call
  **conversation** cheap, streamed or not: the handshake (public-key
  signature, X25519 exchange) happens once, and every subsequent call to
  the same service is just AEAD seal/open over the already-live session.
  `Client::disconnect(service)` closes it early if needed.

### 8.1 Shutdown lifecycle

`Host::run()` is non-blocking: it publishes the registry entry and starts
accepting connections on a background thread, then returns. This is
deliberate — accepting connections should never be the thing that decides
whether your program's main thread can do other work.

Shutdown is a small explicit state machine rather than a single blocking
call, so an application can decide what "graceful" means for it:

- `request_stop()` only sets an internal flag. It does no locking,
  allocation, or I/O, which makes it the one method on `Host` that's safe
  to call directly from a POSIX signal handler.
- `stop()` does the actual teardown (close listener, close connections,
  join threads, remove the registry entry) and is *not* signal-safe —
  call it from a normal thread only.
- `wait_until_stopped()` bridges the two: it blocks (polling roughly every
  50ms — simple and portable rather than a self-pipe/event object, at the
  cost of that much added shutdown latency) until `request_stop()` or
  `stop()` has been called from anywhere, then runs `stop()` and returns.
- `stop_on_signals({SIGINT, SIGTERM, ...})` is a convenience that installs
  a `std::signal()` handler routing the given signals to `request_stop()`
  for this Host. EPX never touches process-wide signal state on its own —
  this is opt-in, and safe to call from multiple `Host`s in the same
  process (a delivered signal requests a stop on all of them, matching a
  signal's process-wide nature).
- `before_stop()`/`after_stop()` register hooks that run synchronously
  inside `stop()`, in registration order, before and after the actual
  teardown respectively. `before_stop` hooks are the intended place to
  decide how in-flight work is handled: return immediately for "close
  everything now," or block — e.g. on an application-maintained counter of
  active requests/streams — to drain first. EPX does not track in-flight
  requests itself (see section 9); the hook is the seam where an
  application plugs in whatever policy it wants. See
  `examples/expose_demo.cpp` for a worked example.

## 9. Known limitations

This is a reference implementation of protocol version 1, not a finished
product. Documented, deliberate simplifications:

- **No forward secrecy compromise recovery mid-session**: ephemeral keys
  are generated once per *connection*, not rotated within a long-lived
  connection. A very long-lived conversation is exactly as forward-secret
  as a fresh reconnect would be, but doesn't re-key on its own. Rotating
  ephemeral keys periodically on long-lived connections is a natural
  follow-up.
- **No rate limiting or backpressure**: a peer that completes the
  handshake can send requests as fast as it wants; the frame-size cap
  (section 5.1) bounds memory per frame but not request rate. This applies
  to streams too — `StreamWriter`/`OutputStream` have no flow control, so a
  producer much faster than its consumer will just buffer up on the OS
  socket/pipe.
- **`StreamReceive` has no acknowledgement channel**: chunks sent via
  `Client::open_stream` are dispatched to the host's handler with no
  response of any kind, by design (matching `Send`'s fire-and-forget
  model) — if you need the sender to know the host actually processed a
  stream, layer that on top (e.g. a follow-up `Client::get` call once the
  stream finishes).
- **Unix domain socket paths are capped by the kernel** (`sockaddr_un`'s
  `sun_path`, typically ~100 bytes on Linux/macOS/BSD). `transport_posix.cpp`
  throws a clear error rather than silently truncating, but a very long
  `XDG_RUNTIME_DIR` combined with a long service name can hit this limit —
  encountered and worked around in this project's own test suite (see
  `tests/CMakeLists.txt`'s comment) by keeping test state under a short
  path instead of deep inside the build directory.
- **`wait_until_stopped()` polls rather than blocking on an event**: up to
  ~50ms of added latency between a signal/`request_stop()` call and
  `stop()` actually beginning (see section 8.1) — a deliberate simplicity
  trade-off over a platform-specific self-pipe/event-object implementation.
- **Thread-per-connection, no pool**: the reference `Host` spawns one OS
  thread per accepted connection and does not currently reap finished
  connection threads until `Host::stop()`. Fine for the tools-talking-to-
  tools scale EPX targets; a high-fan-in service would want a thread pool.
- **No push-notification discovery**: the registry is enumerable
  (section 4.1) but poll-only — there is no "tell me the moment a new
  service appears" daemon. ROADMAP_V2.md item 4 sketches an opt-in
  `epxregistryd` for that; it is deliberately unbuilt until a concrete
  use case asks for it. Live group membership patterns
  (`examples/groupchat.cpp`) meanwhile use an ordinary rendezvous
  service publishing a `Topic` of membership events, which also has no
  replay: a late subscriber sees events from subscription time onward.
- **Windows named-pipe transport is untested**: written against the
  documented Win32 API and mirrors the POSIX implementation's logic
  exactly, but this reference implementation was developed and verified
  end-to-end on Linux only. See `README.md`.
- **Downgrade-to-v1 by bilateral extension stripping**: see section 6.2 —
  an interposer able to rewrite both handshake frames could strip both v2
  extensions and yield an honest v1 session. Requires a
  man-in-the-middle position on a direct same-machine socket, which is
  outside the threat model; all single-sided tampering fails closed.

## 10. Cryptographic suite summary

| purpose                          | primitive                              |
|-----------------------------------|-----------------------------------------|
| long-term identity / authentication | Ed25519 (`crypto_sign`)               |
| per-session key agreement          | X25519 ephemeral ECDH (`crypto_kx`)    |
| transport encryption                | XChaCha20-Poly1305 AEAD                |
| randomness                          | libsodium `randombytes_buf` (OS CSPRNG) |

All four are provided directly by libsodium; no cryptographic algorithm is
implemented in EPX itself (see `src/crypto.hpp` for the rationale).
