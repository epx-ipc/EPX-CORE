// The EPX handshake: a small SIGMA-style exchange that authenticates a
// fresh ephemeral X25519 key with a long-term Ed25519 signature (see
// crypto.hpp for the rationale). Trust *decisions* (which pubkeys to
// accept) are made by the caller via the `trust` callback — this file only
// handles wire encoding and cryptographic verification.
#pragma once

#include <functional>
#include <optional>
#include <string>
#include "crypto.hpp"
#include "transport.hpp"
#include "epx/epx.hpp"

namespace epx::handshake {

struct Result {
    epx::crypto::SessionKeys keys;
    epx::PublicKey peer_identity{};
    // Negotiated protocol version for this session (min of the two sides'
    // advertised maxima). 1 when either peer is a pure-v1 build; >= 2
    // enables the epoch'd frame layout, request status 3, ERROR frames,
    // and key rotation.
    uint8_t version = 1;
};

// Client side. `target_service_name` is sent to the server so it knows
// which of its exposed services this connection is for (defense-in-depth
// if a listener is ever shared). `is_trusted` is invoked with the server's
// claimed identity key *before* any handshake bytes are sent back and
// forth are trusted — it must return true only for a key the client is
// willing to talk to (see Client::get in host_client.cpp for how
// TrustPolicy maps onto this).
std::optional<Result> client_handshake(epx::transport::Transport& t,
                                        const epx::Identity& self,
                                        const std::string& target_service_name,
                                        const std::function<bool(const epx::PublicKey& server_identity)>& is_trusted);

// Server side. `own_service_name` must match what the client sent, or the
// connection is rejected. `is_trusted` decides whether to accept the
// client's claimed identity key (allow-list / TOFU / allow-all — see
// Host::expose in host_client.cpp).
std::optional<Result> server_handshake(epx::transport::Transport& t,
                                        const epx::Identity& self,
                                        const std::string& own_service_name,
                                        const std::function<bool(const epx::PublicKey& client_identity)>& is_trusted);

} // namespace epx::handshake
