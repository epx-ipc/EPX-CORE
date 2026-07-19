// Raw, unencrypted frame I/O over a Transport. This layer only knows about
// the length-prefixed [type|counter|body] structure (see protocol.hpp); it
// has no idea whether `body` is cleartext (Hello/HelloAck) or an AEAD
// ciphertext (everything else) — that decision is made by the caller.
#pragma once

#include <optional>
#include <vector>
#include "protocol.hpp"
#include "transport.hpp"

namespace epx::framing {

struct RawFrame {
    epx::wire::FrameType type;
    uint64_t counter = 0;
    uint8_t epoch = 0; // v2 sessions only: which key generation sealed this frame (0 until a rekey)
    std::vector<uint8_t> body;
};

// `with_epoch` selects the frame layout for the session:
//   v1 session (and all HELLO/HELLO_ACK frames): [type|counter|body]
//   v2 session, post-handshake:                  [type|counter|epoch|body]
// Both sides know the negotiated version, so the layout is never ambiguous
// on the wire.
bool write_frame(epx::transport::Transport& t, const RawFrame& f, bool with_epoch = false);

// Returns std::nullopt on EOF, transport error, or a frame exceeding
// wire::kMaxFrameBytes (a defensive cap against a peer trying to make us
// allocate an unbounded buffer).
std::optional<RawFrame> read_frame(epx::transport::Transport& t, bool with_epoch = false);

} // namespace epx::framing
