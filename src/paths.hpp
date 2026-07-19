// Shared, per-platform filesystem locations. Two directories matter:
//
//   runtime_dir()  — ephemeral, per-login-session storage for sockets/pipes
//                    and the service registry. Wiped across reboots; that's
//                    fine, both are re-created whenever a Host runs.
//   config_dir()   — durable, per-user storage for long-term identity keys
//                    and pinned peer keys. Must survive reboots.
//
// Both are created 0700-equivalent (owner-only) on first use, and both
// implementations refuse to reuse a directory that isn't owned by the
// current user.
#pragma once

#include <string>

namespace epx::paths {

std::string runtime_dir();
std::string config_dir();

// mkdir -p (or platform equivalent) with owner-only permissions, refusing
// to proceed if an existing directory is owned by someone else.
void ensure_private_dir(const std::string& path);

} // namespace epx::paths
