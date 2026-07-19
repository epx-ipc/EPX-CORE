// AccessTier::Certificate support: a credential is a tiny offline-signed
// statement — "issuer I says peer key P may call scope S until time T" —
// serialized as a short text block (see epx::make_credential in epx.hpp).
// A minimal local CA: one signature, no chains, no revocation lists (use
// short expiries instead). Verification is two separate questions asked in
// two places:
//   - parse() + signature_valid(): is this bytes-wise a credential and did
//     `issuer` really sign it? (checked once, when the credential is
//     installed)
//   - covers(): does it apply to *this* peer, service, endpoint, right
//     now? (checked per authorization decision)
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "epx/epx.hpp"

namespace epx::credentials {

struct Credential {
    epx::PublicKey peer{};
    std::string scope;      // "service" or "service/endpoint"
    uint64_t expires = 0;   // unix seconds, 0 = never
    epx::PublicKey issuer{};
    std::array<uint8_t, 64> signature{};
};

// The exact byte string the issuer signs.
std::vector<uint8_t> signed_bytes(const epx::PublicKey& peer,
                                   const epx::PublicKey& issuer,
                                   const std::string& scope,
                                   uint64_t expires);

std::string serialize(const Credential& c);
std::optional<Credential> parse(const std::string& text);

bool signature_valid(const Credential& c);

// True if the credential covers (peer, service, endpoint) at `now_unix`.
// Scope "svc" covers every endpoint of svc; "svc/ep" covers exactly ep.
bool covers(const Credential& c,
            const epx::PublicKey& peer,
            const std::string& service,
            const std::string& endpoint,
            uint64_t now_unix);

} // namespace epx::credentials
