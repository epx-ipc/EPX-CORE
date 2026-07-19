#include "keystore.hpp"
#include "paths.hpp"
#include "crypto.hpp"

#include <fstream>
#include <cstdio>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace epx::keystore {

namespace {

std::string identities_dir() { return epx::paths::config_dir() + "/identities"; }
std::string peers_dir() { return epx::paths::config_dir() + "/known_peers"; }

std::string to_hex(const uint8_t* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0xF]);
    }
    return out;
}

bool from_hex(const std::string& hex, uint8_t* out, size_t out_len) {
    if (hex.size() != out_len * 2) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out_len; ++i) {
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = uint8_t((hi << 4) | lo);
    }
    return true;
}

void chmod_private(const std::string& path) {
#if !defined(_WIN32)
    chmod(path.c_str(), 0600);
#else
    (void)path; // TODO: set an explicit owner-only DACL; see README Windows notes
#endif
}

// Writes `content` to `path` such that the file is owner-only (0600) from
// the moment it exists — secrets must never be readable through a default-
// umask window, however brief. `append` = O_APPEND semantics.
bool write_private_file(const std::string& path, const std::string& content, bool append = false) {
#if !defined(_WIN32)
    int flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);
    int fd = ::open(path.c_str(), flags, 0600);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < content.size()) {
        ssize_t n = ::write(fd, content.data() + off, content.size() - off);
        if (n <= 0) { ::close(fd); return false; }
        off += size_t(n);
    }
    ::close(fd);
    return true;
#else
    // Windows: no umask-style exposure window for a user-profile file; the
    // containing directory's ACL is the guard (see chmod_private's TODO).
    std::ofstream out(path, append ? std::ios::app : std::ios::trunc);
    if (!out.is_open()) return false;
    out << content;
    return out.good();
#endif
}

} // namespace

epx::Identity load_or_create_identity(const std::string& app_name) {
    epx::paths::ensure_private_dir(identities_dir());
    std::string path = identities_dir() + "/" + app_name + ".key";

    std::ifstream in(path);
    if (in.is_open()) {
        std::string pk_hex, sk_hex;
        if (std::getline(in, pk_hex) && std::getline(in, sk_hex)) {
            epx::Identity id;
            if (from_hex(pk_hex, id.public_key.data(), id.public_key.size()) &&
                from_hex(sk_hex, id.secret_key.data(), id.secret_key.size())) {
                return id;
            }
        }
    }

    epx::Identity id = epx::crypto::generate_identity();
    std::string tmp = path + ".tmp";
    std::string content = to_hex(id.public_key.data(), id.public_key.size()) + "\n" +
                          to_hex(id.secret_key.data(), id.secret_key.size()) + "\n";
    if (!write_private_file(tmp, content)) {
        throw std::runtime_error("could not write identity file: " + tmp);
    }
    std::rename(tmp.c_str(), path.c_str());
    return id;
}

std::optional<epx::PublicKey> load_pinned_peer(const std::string& service_name) {
    std::ifstream in(peers_dir() + "/" + service_name + ".peer");
    if (!in.is_open()) return std::nullopt;
    std::string hex;
    if (!std::getline(in, hex)) return std::nullopt;
    epx::PublicKey pk{};
    if (!from_hex(hex, pk.data(), pk.size())) return std::nullopt;
    return pk;
}

void pin_peer(const std::string& service_name, const epx::PublicKey& pk) {
    epx::paths::ensure_private_dir(peers_dir());
    std::string path = peers_dir() + "/" + service_name + ".peer";
    std::string tmp = path + ".tmp";
    write_private_file(tmp, to_hex(pk.data(), pk.size()) + "\n");
    std::rename(tmp.c_str(), path.c_str());
}

namespace {
std::string known_clients_dir() { return epx::paths::config_dir() + "/known_clients"; }
std::string known_clients_path(const std::string& host_service_name) {
    return known_clients_dir() + "/" + host_service_name + ".list";
}
} // namespace

namespace {
std::string authz_dir() { return epx::paths::config_dir() + "/authz"; }
std::string authz_path(const std::string& service) { return authz_dir() + "/" + service + ".decisions"; }
} // namespace

// Line format: "<peer-hex> allow|deny <endpoint>" — endpoint last so it may
// contain spaces. Later lines win, so re-deciding just appends.
std::optional<bool> load_authz_decision(const std::string& host_service_name,
                                         const epx::PublicKey& peer_pk,
                                         const std::string& endpoint) {
    std::ifstream in(authz_path(host_service_name));
    if (!in.is_open()) return std::nullopt;
    std::string want = to_hex(peer_pk.data(), peer_pk.size());
    std::optional<bool> decision;
    std::string line;
    while (std::getline(in, line)) {
        size_t s1 = line.find(' ');
        if (s1 == std::string::npos) continue;
        size_t s2 = line.find(' ', s1 + 1);
        if (s2 == std::string::npos) continue;
        if (line.compare(0, s1, want) != 0) continue;
        if (line.compare(s2 + 1, std::string::npos, endpoint) != 0) continue;
        std::string verdict = line.substr(s1 + 1, s2 - s1 - 1);
        if (verdict == "allow") decision = true;
        else if (verdict == "deny") decision = false;
    }
    return decision;
}

void save_authz_decision(const std::string& host_service_name,
                          const epx::PublicKey& peer_pk,
                          const std::string& endpoint,
                          bool allow) {
    epx::paths::ensure_private_dir(authz_dir());
    std::string line = to_hex(peer_pk.data(), peer_pk.size()) +
                       (allow ? " allow " : " deny ") + endpoint + "\n";
    write_private_file(authz_path(host_service_name), line, /*append=*/true);
}

bool is_known_client(const std::string& host_service_name, const epx::PublicKey& client_pk) {
    std::ifstream in(known_clients_path(host_service_name));
    if (!in.is_open()) return false;
    std::string want = to_hex(client_pk.data(), client_pk.size());
    std::string line;
    while (std::getline(in, line)) {
        if (line == want) return true;
    }
    return false;
}

void remember_client(const std::string& host_service_name, const epx::PublicKey& client_pk) {
    if (is_known_client(host_service_name, client_pk)) return;
    epx::paths::ensure_private_dir(known_clients_dir());
    std::string path = known_clients_path(host_service_name);
    write_private_file(path, to_hex(client_pk.data(), client_pk.size()) + "\n", /*append=*/true);
}

} // namespace epx::keystore
