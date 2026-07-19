# EPX — Encrypted Process eXchange

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](CMakeLists.txt)
[![Protocol](https://img.shields.io/badge/protocol-v2-green.svg)](docs/SPEC.md)

A local, on-device IPC protocol with an HTTP-like `expose` / `get` / `send`
programming model, automatic service discovery, and mutually-authenticated,
end-to-end encrypted connections — so no other program on the machine can
read or tamper with a conversation between two of your programs.

**This is the canonical EPX repository** — the source of truth for:

- **the wire protocol** (`docs/SPEC.md`): handshake, crypto suite, trust
  model, threat model, versioning;
- **the reference implementation** (C++17, `src/` + `include/epx/epx.hpp`);
- **the stable C ABI** (`include/epx/epx_c.h` → `libepx_c`): the one
  binding surface every language implementation links against. No binding
  reimplements protocol logic; they all speak through this library.

## Language implementations

Every implementation is its own repository, binds exclusively to this
repo's `libepx_c`, and proves itself with a chat example that
interoperates over the wire with this repo's C++ `chat` binary:

| Repository | Language | Flavor |
|------------|----------|--------|
| [EPX-RUST](https://github.com/epx-ipc/EPX-RUST) | Rust | `epx-sys` FFI crate + RAII `epx` crate, `Result<T, EpxError>` |
| [EPX-PYTHON](https://github.com/epx-ipc/EPX-PYTHON) | Python | cffi ABI mode (no compiler at install), exception taxonomy |
| [EPX-NODE](https://github.com/epx-ipc/EPX-NODE) | Node.js / TypeScript | N-API addon, Promises, async iterators, `.d.ts` |
| [EPX-GO](https://github.com/epx-ipc/EPX-GO) | Go | cgo, channels for streams/topics, `context.Context` |
| [EPX-CSHARP](https://github.com/epx-ipc/EPX-CSHARP) | C# / .NET | P/Invoke, `Task` async, `IAsyncEnumerable` streams |
| [EPX-SWIFT](https://github.com/epx-ipc/EPX-SWIFT) | Swift | SwiftPM, async/await, `AsyncStream` |
| [EPX-RUBY](https://github.com/epx-ipc/EPX-RUBY) | Ruby | ffi gem (dlopen), blocks for callbacks |
| [EPX-DART](https://github.com/epx-ipc/EPX-DART) | Dart | dart:ffi + C ticket bridge for the isolate model |
| *(this repo)* | C, C++ | `epx_c.h` directly / `epx.hpp` |

C and C++ consumers use this repository directly. Everyone starts here:
build EPX-CORE once, and every implementation repo finds `libepx_c` in
`https://github.com/epx-ipc/EPX-COREbuild` (each README documents its overrides).

## What's in this repo

- **`docs/SPEC.md`** — the protocol itself: wire format, handshake, crypto
  suite, trust model, threat model. Read this if you want to reimplement
  EPX in another language, or just understand what security guarantee
  you're actually getting.
- **`docs/SERIALIZATION.md`** — the FlatBuffers payload convention for
  polyglot services, with a worked C++ ↔ Python demo.
- **`docs/ROADMAP_V2.md`** — the build brief this 2.1 release implemented.
- **`include/epx/epx.hpp`** — the C++ API, fully documented inline.
- **`include/epx/epx_c.h`** — the C ABI, fully documented inline
  (ownership rule, callback threading contract, `EPX_C_ABI_VERSION`).
- **`src/`** — the reference implementation (`c_api.cpp` is the shim).
- **`examples/`** — C++ and C demos: `expose_demo`/`client_demo` (RPC),
  `chat` (two-party, the interop reference), `groupchat` (`Topic`
  pub/sub), `flatbuffers_demo` (cross-language payloads).
- **`tools/`** — the `epx` CLI (`epx list` / `epx describe`).
- **`tests/`** — the CTest suite: 9 C++ suites + the C ABI suite.

## Quick example

Expose two endpoints:

```cpp
#include "epx/epx.hpp"

int main() {
    epx::Identity id = epx::load_or_create_identity("com.acme.notes");
    epx::Host host("com.acme.notes", id);

    host.expose("search", [](const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
        epx::Response r;
        r.ok = true;
        r.data = run_search(req); // your logic
        return r;
    });

    host.run();                // non-blocking: binds and returns
    host.wait_until_stopped(); // park this thread until shutdown
}
```

Call it from another program:

```cpp
#include "epx/epx.hpp"

int main() {
    epx::Identity id = epx::load_or_create_identity("com.acme.launcher");
    epx::Client client(id);

    epx::Bytes results = client.get("com.acme.notes", "search", query_bytes());
    // ... use results
}
```

That's the whole model: `expose(endpoint, handler)` on one side,
`get(service, endpoint, data)` / `send(service, endpoint, data)` on the
other. Everything past that — discovery, the handshake, encryption — is
handled by the library. See `include/epx/epx.hpp` for the full API
(`TrustPolicy`, `allow_peer`, `PeerInfo`, error handling, timeouts).

### Endpoint kinds

Every endpoint declares which of four shapes it is (`EndpointKind` in
`epx.hpp`), which determines the matching `Client` call:

| kind             | `Host` registers with        | `Client` calls with     | shape                                    |
|------------------|-------------------------------|---------------------------|--------------------------------------------|
| `Receive`         | `expose(endpoint, handler)`  | `get(...)`                | request → response, caller blocks         |
| `Send`            | `expose(EndpointKind::Send, endpoint, handler)` | `send(...)` | fire-and-forget, no response |
| `StreamReceive`   | `expose_stream_receive(...)` | `open_stream(...)`        | caller pushes a sequence of chunks        |
| `StreamSend`      | `expose_stream_send(...)`    | `get_stream(...)`         | host pushes back a *bounded* sequence of chunks |
| `Topic`           | `expose_topic(...)` → `TopicHandle` | `subscribe(...)` → `Subscription` | unbounded broadcast feed; host `publish()`es at will, every subscriber gets every message |

Rule of thumb for the last two: `StreamSend` when the handler returning
*is* the end of the stream (query results, a file); `Topic` when there is
no such moment (chat, telemetry, live events) — the library then owns
fan-out, per-subscriber delivery, heartbeats, and dead-subscriber
cleanup. See `docs/SPEC.md` section 8.

Streaming example — a host that streams query results back in chunks
instead of one big response:

```cpp
host.expose_stream_send("search", [](const epx::StreamWriter& out, const epx::Bytes& query,
                                      const std::string&, const epx::PeerInfo&) {
    for (auto& result : run_search(query)) {
        out.write(to_bytes(result)); // pushed to the client as soon as it's ready
    }
    // no explicit "done" call needed — sent automatically once this returns
});
```

```cpp
client.get_stream("com.acme.notes", "search", query_bytes(),
    [](const epx::Bytes& chunk, bool is_last) {
        if (!is_last) handle_result(chunk);
    });
```

See `docs/SPEC.md` section 8 for the full semantics, and `examples/chat.cpp` for
a complete program using `Send` (chat messages) and `StreamSend`
(`/history`) together.

## Building

### Dependencies

- A C++17 compiler
- CMake ≥ 3.16
- [libsodium](https://libsodium.org) (this is the *only* third-party
  dependency — EPX implements no cryptographic algorithm itself, see
  `src/crypto.hpp`)

Install libsodium first:

```bash
# Debian / Ubuntu
sudo apt install libsodium-dev

# macOS
brew install libsodium

# Windows
vcpkg install libsodium
```

### Build

```bash
cmake -B build -S .
cmake --build build
```

This produces:

- `build/libepx_c.{dylib,so}` — **the C ABI shared library every language
  implementation links against** (plus the static `libepx.a` for direct
  C++ consumers);
- `build/epx` — the CLI (`epx list` / `epx describe <service>`);
- the example binaries under `build/examples/`: `expose_demo`,
  `client_demo`, `chat`, `groupchat_room`, `groupchat`, and their C
  editions `expose_demo_c`, `client_demo_c`, `chat_c`.

### Try the RPC demo

In one terminal:

```bash
./build/expose_demo
```

In another:

```bash
./build/client_demo
```

You should see the client's `echo`/`time`/`divide` calls succeed, a
deliberate divide-by-zero come back as a caught `EpxError` rather than a
crash, and the host print which peer (OS UID) called each endpoint.

Both programs' identities and pinned peers persist under `~/.epx/`, and the
service registry lives under `$XDG_RUNTIME_DIR/epx/` (or `/tmp/epx-<uid>/`
if that's unset) — delete those to reset trust state and start over.

### Try the chat app

`examples/chat.cpp` is a small interactive terminal program where each
running instance is *both* an EPX `Host` (exposing a `message` and a
`history` endpoint under its own name) and a `Client` (sending to the other
instance's name). Run one instance per terminal:

```bash
# terminal 1
./build/chat alice bob

# terminal 2
./build/chat bob alice
```

(`chat <my-name> <peer-name>` — the two instances just need to name each
other correctly; nothing else needs to match.) Type a line and hit enter to
send it to the peer; type `/history` to pull back a streamed transcript of
everything sent so far (exercising `StreamSend`/`get_stream`), or `/quit` to
exit. Every message is delivered over a mutually-authenticated, encrypted
EPX connection — see the file's header comment for how it's wired up.

### Try polychat — the serverless, polyglot group chat

`examples/polychat.cpp` goes one further than `groupchat`: **no room
process at all**. Discovery rides on the enumerable registry (a passive
file store — not a process, not a relay), and every message flows over a
direct, mutually-authenticated, end-to-end encrypted peer connection:

```bash
./build/examples/polychat ada        # any number of terminals
./build/examples/polychat_c bob      # the C edition joins the same chat
```

Every EPX language repo ships the same port under the same convention
(service prefix `epx.chat.`, Topic `feed`, shared envelope), so **any
mix of the ten implementations converses**. The proof is scripted:

```bash
bash tools/polychat_showcase.sh   # launches all 10 languages, verifies 90/90 deliveries
```

### Try the group chat demo

`examples/groupchat_room.cpp` + `examples/groupchat.cpp` extend the same
idea to any number of participants, with people joining and leaving under
custom names at will. Start the room once:

```bash
./build/groupchat_room
```

Then join from as many terminals as you like:

```bash
./build/groupchat alice
./build/groupchat bob
./build/groupchat carol
```

Each participant is *itself* an EPX `Host`, exposing its own outgoing
messages as a `Topic` "feed" — there's no central chat server relaying
content. The room process only handles discovery: it exposes a `Topic` of
join/leave events plus a `join` endpoint returning the current roster.
When you learn about a member, you open your own direct `Subscription` to
*their* feed. So with three people in the room, each has their own
independent outgoing feed, and everyone else is an independent subscriber
to it — exactly the "N members, N feeds, everyone listens to everyone"
shape, not one shared channel.

Type a line to broadcast it to everyone currently subscribed to you;
`/quit` (or Ctrl+D) leaves cleanly. Two things worth knowing:

- **No history/replay.** A message is only delivered to whoever is already
  subscribed to the sender at the moment it's sent — there's no equivalent
  of `chat.cpp`'s `/history` here. Someone who joins mid-conversation sees
  new messages from that point on, not what came before.
- **Departures arrive as a clean signal.** When a member quits, its
  `Host::stop()` ends its feed for every subscriber (callback gets
  `closed=true`); if it crashes, the dropped connection produces the same
  signal. The hand-rolled heartbeat events and the careful
  disconnect-from-everyone shutdown dance this demo needed before EPX 2.1
  are gone — that machinery lives inside `EndpointKind::Topic` now
  (library-level heartbeats still run under the hood to prune dead
  subscribers promptly; see `docs/SPEC.md` section 8).

See `examples/groupchat_common.hpp` for the design writeup, and this
repo's git history for the pre-2.1 version of these files — the clearest
before/after argument for why `Topic` was promoted into the library.

### Testing

```bash
cmake -B build -S . -DEPX_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Runs `tests/test_protocol.cpp` (wire-format round trips, no libsodium/
network dependency), `tests/test_lifecycle.cpp` (a real Host+Client pair
over an actual socket), `tests/test_streaming.cpp` (all three non-`Receive`
endpoint kinds), and `tests/test_shutdown_hooks.cpp` (hook ordering, a
graceful in-flight drain, and `stop_on_signals()` end to end via
`std::raise`). See `tests/test_util.hpp` for why there's no third-party
test framework dependency, and `CONTRIBUTING.md` for the expectation that
these all pass before a PR.

## Shutdown lifecycle

`Host::run()` is non-blocking: it binds the listener and returns as soon as
it's ready to accept connections (bind/listen failures still throw
synchronously from that call). If the calling thread has nothing else to
do, park it with `wait_until_stopped()`:

```cpp
host.run();
host.stop_on_signals({SIGINT, SIGTERM});  // opt-in; EPX never touches process
                                           // signal state unless you ask it to
host.wait_until_stopped();                // blocks until a stop is requested
```

`stop_on_signals()` wires the given signals to `request_stop()`, which is
async-signal-safe (it only sets a flag — no locks, no I/O) and safe to call
directly from a signal handler. The actual teardown happens on a normal
thread, either via `wait_until_stopped()` or by calling `stop()` yourself.

Before anything is closed, `stop()` runs any `before_stop()` hooks — this
is where your program decides what "graceful" means for it:

```cpp
host.before_stop([] {
    // Options are yours: return immediately (stop() closes everything
    // right away), wait on your own in-flight-request counter to drain
    // cleanly, cancel long-running streams, log the shutdown, etc.
});
host.after_stop([] {
    // Runs last, once the listener/connections are closed and the
    // registry entry is removed.
});
```

See `examples/expose_demo.cpp` for a complete graceful-drain example (waits
up to 3s for in-flight requests to finish) and `docs/SPEC.md` section 8 for
the full semantics.

## Platform support

| Platform | Transport         | Status                                          |
|----------|--------------------|--------------------------------------------------|
| Linux    | Unix domain socket | Developed and verified end-to-end (see `docs/VERIFICATION_NOTES.md`) |
| macOS    | Unix domain socket | Built and full test suite run on macOS arm64 (see `docs/VERIFICATION_NOTES.md`) |
| Windows  | Named pipe         | Implemented (`src/transport_win.cpp`) but **not build- or run-tested** — see the file header for what to double check before relying on it in production |

The handshake, framing, and crypto code (the actual security-relevant
logic) is 100% shared across all three; only the raw byte-stream plumbing
in `transport_*.cpp` differs per platform.

## Security notes (see SPEC.md for full detail)

- Every connection is authenticated with a signed, ephemeral X25519
  key exchange (Ed25519 identity keys sign a fresh key per connection),
  then encrypted with XChaCha20-Poly1305 — giving both mutual
  authentication and forward secrecy.
- Trust is pinning-based (`TrustPolicy`), like SSH host keys: first contact
  is trusted and remembered by default (`TrustOnFirstUse`), or you can
  require an explicit allow-list (`RequireKnownPeer`) if you can distribute
  keys out of band.
- The local service registry is not part of the trust boundary — it only
  tells a client where to dial, and a live handshake still has to
  cryptographically prove the key it claims. See `docs/SPEC.md` section 4.3.
