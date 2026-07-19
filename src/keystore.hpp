// Durable, per-user storage for:
//   - a program's own long-term identity keypair (one per app_name)
//   - the set of peer public keys it has pinned per remote service, used by
//     TrustPolicy::TrustOnFirstUse and RequireKnownPeer (see epx.hpp)
//
// Both live under paths::config_dir() (~/.epx on POSIX) with owner-only
// permissions. Losing this directory means losing the program's identity
// (peers will see it as a "new" program next time) and all pinned peers
// (next connections re-pin under TOFU, or must be re-approved under
// RequireKnownPeer).
#pragma once

#include <optional>
#include <string>
#include "epx/epx.hpp"

namespace epx::keystore {

epx::Identity load_or_create_identity(const std::string& app_name);

// Client side: the single server identity a Client has pinned for a given
// target service name (TrustPolicy::TrustOnFirstUse).
std::optional<epx::PublicKey> load_pinned_peer(const std::string& service_name);
void pin_peer(const std::string& service_name, const epx::PublicKey& pk);

// Host side: the (potentially many) client identities a given exposed
// service has already accepted at least once (TrustPolicy::TrustOnFirstUse).
bool is_known_client(const std::string& host_service_name, const epx::PublicKey& client_pk);
void remember_client(const std::string& host_service_name, const epx::PublicKey& client_pk);

// Persisted AccessTier::PromptUser decisions, keyed by
// (host service, peer key, endpoint) — written when the user answers
// AlwaysAllow (true) or Deny (false); AllowOnce is never persisted.
std::optional<bool> load_authz_decision(const std::string& host_service_name,
                                         const epx::PublicKey& peer_pk,
                                         const std::string& endpoint);
void save_authz_decision(const std::string& host_service_name,
                          const epx::PublicKey& peer_pk,
                          const std::string& endpoint,
                          bool allow);

} // namespace epx::keystore
