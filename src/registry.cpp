#include "registry.hpp"
#include "paths.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstdio>

#if !defined(_WIN32)
#include <signal.h>
#include <errno.h>
#endif

namespace epx::registry {

namespace {

std::string registry_dir() { return epx::paths::runtime_dir() + "/registry"; }

std::string entry_path(const std::string& service_name) {
    return registry_dir() + "/" + service_name + ".entry";
}

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

bool pid_is_alive(long pid) {
#if !defined(_WIN32)
    if (pid <= 0) return false;
    if (kill(pid_t(pid), 0) == 0) return true;
    return errno != ESRCH;
#else
    (void)pid;
    return true; // liveness check not implemented on Windows; entries are TTL-free there for now
#endif
}

std::string join(const std::vector<std::string>& v, char sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out.push_back(sep);
        out += v[i];
    }
    return out;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, sep)) {
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

} // namespace

void publish(const Entry& e) {
    epx::paths::ensure_private_dir(registry_dir());
    std::string path = entry_path(e.service_name);
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        f << "version=" << int(e.version) << "\n";
        f << "service=" << e.service_name << "\n";
        f << "address=" << e.address << "\n";
        f << "pubkey=" << to_hex(e.identity_pubkey.data(), e.identity_pubkey.size()) << "\n";
        f << "pid=" << e.pid << "\n";
        f << "endpoints=" << join(e.endpoints, ',') << "\n";
        f << "description=" << e.description << "\n";
    }
    std::rename(tmp.c_str(), path.c_str()); // atomic on POSIX; best-effort elsewhere
}

void unpublish(const std::string& service_name) {
    std::remove(entry_path(service_name).c_str());
}

std::optional<Entry> lookup(const std::string& service_name) {
    std::ifstream f(entry_path(service_name));
    if (!f.is_open()) return std::nullopt;

    Entry e;
    e.service_name = service_name;
    std::string line;
    while (std::getline(f, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        // stoi/stol throw on garbage; a malformed entry (truncated write,
        // manual tampering) must read as "not found", never as a crash.
        try {
            if (key == "version") e.version = uint8_t(std::stoi(val));
            else if (key == "service") { /* redundant with filename, ignore */ }
            else if (key == "address") e.address = val;
            else if (key == "pubkey") { if (!from_hex(val, e.identity_pubkey.data(), e.identity_pubkey.size())) return std::nullopt; }
            else if (key == "pid") e.pid = std::stol(val);
            else if (key == "endpoints") e.endpoints = split(val, ',');
            else if (key == "description") e.description = val;
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    if (!pid_is_alive(e.pid)) {
        unpublish(service_name); // clean up a stale entry from a crashed host
        return std::nullopt;
    }
    return e;
}

std::vector<std::string> list() {
    std::vector<std::string> names;
    namespace fs = std::filesystem;
    std::error_code ec;
    for (const auto& de : fs::directory_iterator(registry_dir(), ec)) {
        if (ec) break;
        if (de.path().extension() != ".entry") continue;
        std::string name = de.path().stem().string();
        // lookup() also validates liveness and prunes stale entries, so
        // the returned list only contains services actually running.
        if (lookup(name)) names.push_back(name);
    }
    std::sort(names.begin(), names.end());
    return names;
}

} // namespace epx::registry

namespace epx {

// Public enumeration API (epx.hpp) — a thin, read-only view over the
// internal registry.
std::vector<std::string> list_services() {
    return registry::list();
}

std::optional<ServiceDescription> describe(const std::string& service_name) {
    auto entry = registry::lookup(service_name);
    if (!entry) return std::nullopt;

    ServiceDescription d;
    d.service_name = entry->service_name;
    d.description = entry->description;
    d.pid = entry->pid;
    d.identity_pubkey = entry->identity_pubkey;
    for (const auto& ep : entry->endpoints) {
        size_t colon = ep.find_last_of(':');
        ServiceDescription::Endpoint e;
        e.name = (colon == std::string::npos) ? ep : ep.substr(0, colon);
        std::string kind = (colon == std::string::npos) ? "receive" : ep.substr(colon + 1);
        if (kind == "receive") e.kind = EndpointKind::Receive;
        else if (kind == "send") e.kind = EndpointKind::Send;
        else if (kind == "stream_receive") e.kind = EndpointKind::StreamReceive;
        else if (kind == "stream_send") e.kind = EndpointKind::StreamSend;
        else if (kind == "topic") e.kind = EndpointKind::Topic;
        d.endpoints.push_back(std::move(e));
    }
    return d;
}

} // namespace epx
