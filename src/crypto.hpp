// Thin wrapper around libsodium. EPX composes three standard, independently
// well-audited primitives rather than inventing anything new:
//
//   - Identity / authentication:  Ed25519 signatures (crypto_sign)
//   - Key agreement (per session): X25519 ephemeral ECDH (crypto_kx)
//   - Transport encryption:        XChaCha20-Poly1305 AEAD
//
// The handshake is a small SIGMA-style construction: each side generates a
// fresh ephemeral X25519 keypair per connection and signs it with its
// long-term Ed25519 identity key before sending it. The peer checks the
// signature against a pinned/trusted identity key, then both sides run
// ephemeral-ephemeral ECDH to derive session keys. This gives mutual
// authentication of long-term identity *and* forward secrecy (compromising
// a long-term key later does not expose previously recorded sessions),
// without hand-rolling any cryptographic algorithm — every primitive below
// is a direct call into libsodium.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>
#include "epx/epx.hpp"

namespace epx::crypto {

void init(); // must be called once before any other function; throws on failure

// Long-term Ed25519 identity keypair.
epx::Identity generate_identity();

// Ephemeral X25519 keypair, generated fresh for every connection attempt.
struct EphemeralKeyPair {
    std::array<uint8_t, 32> public_key{};
    std::array<uint8_t, 32> secret_key{};
    ~EphemeralKeyPair(); // zeroes the secret key
};
EphemeralKeyPair generate_ephemeral();

// Signs `message` with a long-term Ed25519 secret key. Returns a 64-byte
// detached signature.
std::array<uint8_t, 64> sign(const epx::SecretKey& sk, const std::vector<uint8_t>& message);

// Verifies a detached signature against a long-term Ed25519 public key.
bool verify(const epx::PublicKey& pk, const std::vector<uint8_t>& message, const std::array<uint8_t, 64>& sig);

// Derived once per connection, right after the ephemeral X25519 exchange.
// `rx`/`tx` are the two one-way session keys — deliberately distinct so a
// compromise of the "read" direction's traffic doesn't help decrypt the
// "write" direction and vice versa.
struct SessionKeys {
    std::array<uint8_t, 32> rx{};
    std::array<uint8_t, 32> tx{};
    ~SessionKeys(); // zeroes both keys
};

SessionKeys client_session_keys(const EphemeralKeyPair& self_ephemeral, const std::array<uint8_t, 32>& peer_ephemeral_pk);
SessionKeys server_session_keys(const EphemeralKeyPair& self_ephemeral, const std::array<uint8_t, 32>& peer_ephemeral_pk);

// Seals `plaintext` with `key`, authenticating `frame_type` and `counter`
// as associated data (so an attacker cannot splice a ciphertext from one
// frame type/position into another). Nonce is derived deterministically
// from `counter`; this is safe because each session uses a fresh ephemeral
// key that is never reused across connections, and `counter` is guaranteed
// monotonically increasing within a session (see session.cpp).
std::vector<uint8_t> seal(const std::array<uint8_t, 32>& key,
                           uint64_t counter,
                           uint8_t frame_type,
                           const std::vector<uint8_t>& plaintext);

// Opens a sealed frame. Returns std::nullopt on any authentication failure
// (wrong key, tampered ciphertext, wrong counter/frame_type used as
// associated data).
std::optional<std::vector<uint8_t>> open(const std::array<uint8_t, 32>& key,
                                          uint64_t counter,
                                          uint8_t frame_type,
                                          const std::vector<uint8_t>& ciphertext);

// v2-session variants: the frame's key-generation `epoch` (see the key
// rotation section of docs/SPEC.md) is bound into the associated data, so
// a ciphertext from one epoch cannot be replayed into another even if the
// (fresh-keyed) counter sequence happens to line up.
std::vector<uint8_t> seal_v2(const std::array<uint8_t, 32>& key,
                              uint64_t counter,
                              uint8_t epoch,
                              uint8_t frame_type,
                              const std::vector<uint8_t>& plaintext);

std::optional<std::vector<uint8_t>> open_v2(const std::array<uint8_t, 32>& key,
                                             uint64_t counter,
                                             uint8_t epoch,
                                             uint8_t frame_type,
                                             const std::vector<uint8_t>& ciphertext);

void random_bytes(uint8_t* buf, size_t len);

// sodium_memzero — for callers holding key copies outside SessionKeys.
void wipe(uint8_t* buf, size_t len);

} // namespace epx::crypto
