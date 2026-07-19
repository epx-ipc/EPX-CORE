# Development verification notes

Historical notes on how the v1 reference implementation was verified in
its original build environment, kept out of the README since they
describe the development sandbox, not anything a user needs to do.

**Update (2026-07-18):** the full CMake build and all CTest suites have
since been built and run successfully on a real macOS (arm64) machine
against Homebrew libsodium 1.0.22 — the macOS row of the README's
platform table is verified for real, not just "same code path as
Linux".


The sandbox this was built in doesn't have internet access to fetch
`libsodium-dev`'s headers/package, and can't install system packages. To
still verify the *actual* protocol logic end-to-end rather than just eyeball
it, the build here was linked against a real, official libsodium build
(extracted from an upstream PyNaCl wheel, which statically bundles a
from-source libsodium build) via a small header of function prototypes —
not a reimplementation of any crypto, just declarations, linked against
genuine compiled libsodium code. With that in place:

- `expose_demo` and `client_demo` were run as separate processes and
  completed a full conversation — handshake, `echo`, `time`, `divide`
  (including the application-error path on divide-by-zero), and a
  fire-and-forget `send` — over the real encrypted transport.
- A combined lifecycle test additionally verified `Client` destruction and
  `Host::stop()` both shut down cleanly (this caught and fixed a real bug:
  closing a socket from one thread doesn't reliably unblock a peer thread
  blocked in `recv()`/`accept()` on Linux — fixed with `shutdown()` before
  `close()`, plus a self-connect nudge to unblock a listener's `accept()`).
- A separate test exercised all three non-`Receive` endpoint kinds in one
  process: a `Send` endpoint receiving a fire-and-forget message, a
  `StreamSend` endpoint streaming a 5-4-3-2-1-liftoff countdown back to
  `get_stream`'s callback (including the automatic final chunk), and a
  `StreamReceive` endpoint receiving a 3-chunk upload via `open_stream`/
  `OutputStream` — all delivered correctly with clean shutdown afterward.
- `chat.cpp` was run as two real, separate processes piping scripted input
  in as if typed, confirming messages sent from each instance's stdin
  arrive and print on the other instance's side, and that `/history`
  correctly streams back the transcript.
- `groupchat_room` plus three `groupchat` instances (alice/bob/carol) were
  run as four separate processes with scripted stdin, confirming: each
  joiner receives the correct roster and every other member's message,
  independently; join/leave events are reported correctly and promptly;
  and a participant that sends `/quit` disconnects from every peer it had
  subscribed to and exits cleanly on its own — without needing to be
  killed — even while the other members it was subscribed to stay alive
  and keep sending heartbeats (this caught and fixed a real bug: the
  original shutdown path only disconnected from the room, leaving every
  peer-feed subscriber thread blocked forever against a peer that was
  never going away on its own).

On a normal machine with `libsodium-dev` installed, the CMake build above
uses the exact same source files against the real system libsodium; no
part of the verification process above is specific to this sandbox.

