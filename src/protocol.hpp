// Internal wire-format definitions. See docs/SPEC.md section 4 (Wire Format) for
// the authoritative description; this header just mirrors it in code.
#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include "epx/epx.hpp"
#include "epx/version.hpp" // generated from version.hpp.in by CMake; defines EPX_PROTOCOL_VERSION

namespace epx::wire {

// Protocol version range this build speaks. Negotiation (section 6.2 of
// the spec): each side advertises its max; the session runs at
// min(client_max, server_max), which must be >= kProtocolVersionMin.
constexpr uint8_t kProtocolVersionMin = EPX_PROTOCOL_VERSION_MIN;
constexpr uint8_t kProtocolVersionMax = EPX_PROTOCOL_VERSION_MAX;
// Legacy name; the byte a v1 peer expects to see first in a HELLO.
constexpr uint8_t kProtocolVersion = 1;

// Highest version this process will offer/accept. Normally
// kProtocolVersionMax; tests lower it to exercise cross-version
// negotiation without needing a separately-built v1 binary.
uint8_t max_negotiable_version();
void set_max_negotiable_version_for_testing(uint8_t v);

// Returns the negotiated session version for the two advertised maxima,
// or 0 if the ranges don't overlap (handshake must fail).
inline uint8_t negotiate_version(uint8_t ours, uint8_t theirs) {
    uint8_t v = ours < theirs ? ours : theirs;
    return v >= kProtocolVersionMin ? v : 0;
}

enum class FrameType : uint8_t {
    Hello       = 0,
    HelloAck    = 1,
    Request     = 2,
    Response    = 3,
    Error       = 4,
    Ping        = 5,
    Pong        = 6,
    Bye         = 7,
    StreamChunk = 8, // one chunk of a StreamReceive or StreamSend transfer (see StreamChunkPayload)
    // v2 mid-session key rotation (SPEC 6.4; opt-in, pending external
    // review). Both carry a 32-byte fresh X25519 public key as their
    // (encrypted) body and are sealed under the *current* epoch's keys.
    Rekey    = 9,  // client -> server: begin rotation to epoch+1
    RekeyAck = 10, // server -> client: accept; server switches its tx to epoch+1 right after
};

// Frame on the wire (after the transport-level stream framing is stripped):
//   uint8   type
//   uint64  counter      (big-endian; nonce counter, 0 for Hello/HelloAck)
//   bytes   body         (plaintext for Hello/HelloAck, AEAD ciphertext+tag otherwise)
//
// The whole frame (type + counter + body) is itself prefixed on the stream
// with a uint32 big-endian length covering everything that follows, so a
// reader always knows how many bytes to pull before parsing.

inline void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(uint8_t(v >> 24)); out.push_back(uint8_t(v >> 16));
    out.push_back(uint8_t(v >> 8));  out.push_back(uint8_t(v));
}
inline void put_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 7; i >= 0; --i) out.push_back(uint8_t(v >> (i * 8)));
}
inline uint32_t get_u32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

constexpr uint32_t kMaxFrameBytes = 16u * 1024 * 1024; // 16 MiB hard cap per frame

// ---- Cleartext handshake payloads -------------------------------------

// v2 handshake compatibility scheme: the v1 payload layout is kept intact
// (a v1 decoder reads it and ignores anything after the v1 signature), and
// v2 capability travels in a *trailing extension*: one `max_version` byte
// plus a second, v2 signature over a richer transcript (see
// hello_signed_bytes_v2 below). A pure-v1 peer never sees the extension;
// a v2 peer requires the v2 signature whenever the negotiated version is
// >= 2. `version` stays 1 on the wire so v1 peers accept the frame.
struct HelloPayload {
    uint8_t version = kProtocolVersion;      // legacy byte; always 1 on the wire
    epx::PublicKey identity_pubkey{};        // client's long-term Ed25519 identity
    std::array<uint8_t, 32> ephemeral_pubkey{}; // fresh per-connection X25519 key
    std::array<uint8_t, 16> client_nonce{};
    std::string service_name;                 // which service the client wants to reach
    std::array<uint8_t, 64> signature{};      // v1 sig: ephemeral_pubkey||client_nonce||service_name
    // ---- trailing extension (absent when talking to/from a pure v1 peer) ----
    uint8_t max_version = 1;                  // highest protocol version the sender speaks
    std::array<uint8_t, 64> signature_v2{};   // sig over hello_signed_bytes_v2 (only meaningful if max_version >= 2)
    bool has_v2_extension = false;            // decode-side: was the extension present?
};

struct HelloAckPayload {
    uint8_t version = kProtocolVersion;      // legacy byte; always 1 on the wire
    epx::PublicKey identity_pubkey{};        // server's long-term Ed25519 identity
    std::array<uint8_t, 32> ephemeral_pubkey{};
    std::array<uint8_t, 16> server_nonce{};
    std::array<uint8_t, 16> client_nonce{};   // echoed back, included under signature
    uint8_t status = 0;                       // 0 = ok, 1 = rejected (unknown peer / policy)
    std::array<uint8_t, 64> signature{};      // v1 sig: ephemeral_pubkey||server_nonce||client_nonce
    // ---- trailing extension ----
    uint8_t max_version = 1;
    std::array<uint8_t, 64> signature_v2{};
    bool has_v2_extension = false;
};

// Builds the exact byte string that HELLO / HELLO_ACK signatures cover, so
// both sender and verifier compute identical input.
std::vector<uint8_t> hello_signed_bytes(const std::array<uint8_t, 32>& ephemeral_pubkey,
                                         const std::array<uint8_t, 16>& client_nonce,
                                         const std::string& service_name);

std::vector<uint8_t> hello_ack_signed_bytes(const std::array<uint8_t, 32>& ephemeral_pubkey,
                                             const std::array<uint8_t, 16>& server_nonce,
                                             const std::array<uint8_t, 16>& client_nonce);

// v2 transcripts. Domain-separated ("EPX-v2-hello"/"EPX-v2-ack" prefixes)
// and deliberately richer than v1: they bind the signer's own identity key
// (unknown-key-share hardening), the version advertisement (downgrade
// hardening — any tampering with either side's offer makes one side's
// transcript disagree with the other's and the verification fail closed),
// and, on the ack side, the server's accept/reject decision and the
// negotiated version.
std::vector<uint8_t> hello_signed_bytes_v2(uint8_t max_version,
                                            const epx::PublicKey& client_identity,
                                            const std::array<uint8_t, 32>& ephemeral_pubkey,
                                            const std::array<uint8_t, 16>& client_nonce,
                                            const std::string& service_name);

std::vector<uint8_t> hello_ack_signed_bytes_v2(uint8_t server_max_version,
                                                uint8_t negotiated_version,
                                                uint8_t status,
                                                const epx::PublicKey& server_identity,
                                                const epx::PublicKey& client_identity,
                                                const std::array<uint8_t, 32>& ephemeral_pubkey,
                                                const std::array<uint8_t, 16>& server_nonce,
                                                const std::array<uint8_t, 16>& client_nonce);

// ---- Encrypted application payloads ------------------------------------

struct RequestPayload {
    uint64_t request_id = 0;
    bool oneway = false;
    std::string endpoint;
    Bytes data;
};

struct ResponsePayload {
    uint64_t request_id = 0;
    uint8_t status = 0; // 0 = ok, 1 = error, 2 = not_found, 3 = access_denied (v2)
    Bytes data;         // response data, or UTF-8 error message if status != 0
};

// ERROR frame body (v2): a protocol-level condition the peer should know
// about before the connection closes (rate limit exceeded, too many
// concurrent streams, ...). Distinct from ResponsePayload's status, which
// is per-request and application-visible.
struct ErrorPayload {
    uint16_t reason = 0; // one of kErr* below
    std::string message; // human-readable, for logs
};
constexpr uint16_t kErrRateLimited     = 1;
constexpr uint16_t kErrTooManyStreams  = 2;
constexpr uint16_t kErrProtocol        = 3;

std::vector<uint8_t> encode_error(const ErrorPayload&);
bool decode_error(const std::vector<uint8_t>&, ErrorPayload&);

// One chunk of a StreamReceive (client -> host) or StreamSend (host ->
// client) transfer. `endpoint` is only meaningful client -> host (the
// host has no other way to know which StreamReceive handler a chunk is
// for, since chunks are dispatched independently with no other
// server-side state); host -> client chunks are correlated purely by
// `request_id` and leave `endpoint` empty.
struct StreamChunkPayload {
    uint64_t request_id = 0;
    uint32_t seq = 0;
    bool is_last = false;
    std::string endpoint;
    Bytes data;
};

std::vector<uint8_t> encode_hello(const HelloPayload&);
bool decode_hello(const std::vector<uint8_t>&, HelloPayload&);

std::vector<uint8_t> encode_hello_ack(const HelloAckPayload&);
bool decode_hello_ack(const std::vector<uint8_t>&, HelloAckPayload&);

std::vector<uint8_t> encode_request(const RequestPayload&);
bool decode_request(const std::vector<uint8_t>&, RequestPayload&);

std::vector<uint8_t> encode_response(const ResponsePayload&);
bool decode_response(const std::vector<uint8_t>&, ResponsePayload&);

std::vector<uint8_t> encode_stream_chunk(const StreamChunkPayload&);
bool decode_stream_chunk(const std::vector<uint8_t>&, StreamChunkPayload&);

} // namespace epx::wire
