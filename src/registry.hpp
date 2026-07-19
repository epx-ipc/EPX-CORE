// Local, filesystem-based service discovery. There is no broker process:
// a registry entry just tells a Client where to dial (the transport
// address) and which long-term identity key to expect there — the actual
// conversation is always a direct, encrypted point-to-point connection.
//
// Entries live under a per-user-private directory (see transport.hpp's
// runtime dir) with mode 0600 so only the current OS user can even read
// which services are registered. This is a coarse first line of defense;
// the real confidentiality/authentication guarantee comes from the
// handshake + AEAD encryption in crypto.hpp/session.hpp, which protects the
// conversation even from other programs running as the *same* user.
#pragma once

#include <optional>
#include <string>
#include <vector>
#include "epx/epx.hpp"

namespace epx::registry {

struct Entry {
    uint8_t version = 1;
    std::string service_name;
    std::string address;         // transport address (see transport.hpp)
    epx::PublicKey identity_pubkey{};
    long pid = -1;
    std::vector<std::string> endpoints; // "name:kind" pairs (see host.cpp kind_to_string)
    std::string description;            // optional, human-readable (Host::set_description)
};

// Writes/overwrites the registry entry for entry.service_name.
void publish(const Entry& entry);

// Removes a previously published entry (called from Host::stop() / dtor).
void unpublish(const std::string& service_name);

// Looks up a service by name. Returns std::nullopt if not found or if the
// entry is stale (owning PID is no longer running).
std::optional<Entry> lookup(const std::string& service_name);

// Enumerates every currently-live registered service name (stale entries
// from crashed hosts are cleaned up and excluded, same as lookup). Backs
// the public epx::list_services()/describe() API and the `epx` CLI.
std::vector<std::string> list();

} // namespace epx::registry
