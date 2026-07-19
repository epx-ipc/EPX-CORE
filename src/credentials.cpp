#include "credentials.hpp"
#include "crypto.hpp"

#include <sstream>

namespace epx::credentials {

namespace {

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

} // namespace

std::vector<uint8_t> signed_bytes(const epx::PublicKey& peer,
                                   const epx::PublicKey& issuer,
                                   const std::string& scope,
                                   uint64_t expires) {
    static const char* tag = "EPX-credential-v1";
    std::vector<uint8_t> m(tag, tag + 17);
    m.insert(m.end(), peer.begin(), peer.end());
    m.insert(m.end(), issuer.begin(), issuer.end());
    for (int i = 7; i >= 0; --i) m.push_back(uint8_t(expires >> (i * 8)));
    m.insert(m.end(), scope.begin(), scope.end());
    return m;
}

std::string serialize(const Credential& c) {
    std::ostringstream out;
    out << "epx-credential-v1\n"
        << "peer=" << to_hex(c.peer.data(), c.peer.size()) << "\n"
        << "scope=" << c.scope << "\n"
        << "expires=" << c.expires << "\n"
        << "issuer=" << to_hex(c.issuer.data(), c.issuer.size()) << "\n"
        << "sig=" << to_hex(c.signature.data(), c.signature.size()) << "\n";
    return out.str();
}

std::optional<Credential> parse(const std::string& text) {
    std::istringstream in(text);
    std::string line;
    if (!std::getline(in, line) || line != "epx-credential-v1") return std::nullopt;
    Credential c;
    bool have_peer = false, have_scope = false, have_expires = false, have_issuer = false, have_sig = false;
    while (std::getline(in, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        try {
            if (key == "peer") have_peer = from_hex(val, c.peer.data(), c.peer.size());
            else if (key == "scope") { c.scope = val; have_scope = !val.empty(); }
            else if (key == "expires") { c.expires = std::stoull(val); have_expires = true; }
            else if (key == "issuer") have_issuer = from_hex(val, c.issuer.data(), c.issuer.size());
            else if (key == "sig") have_sig = from_hex(val, c.signature.data(), c.signature.size());
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    if (!(have_peer && have_scope && have_expires && have_issuer && have_sig)) return std::nullopt;
    return c;
}

bool signature_valid(const Credential& c) {
    return epx::crypto::verify(c.issuer, signed_bytes(c.peer, c.issuer, c.scope, c.expires), c.signature);
}

bool covers(const Credential& c,
            const epx::PublicKey& peer,
            const std::string& service,
            const std::string& endpoint,
            uint64_t now_unix) {
    if (c.peer != peer) return false;
    if (c.expires != 0 && now_unix > c.expires) return false;
    return c.scope == service || c.scope == service + "/" + endpoint;
}

} // namespace epx::credentials

namespace epx {

// Public helper declared in epx.hpp.
std::string make_credential(const Identity& issuer,
                             const PublicKey& peer,
                             const std::string& scope,
                             uint64_t expires_unix) {
    credentials::Credential c;
    c.peer = peer;
    c.scope = scope;
    c.expires = expires_unix;
    c.issuer = issuer.public_key;
    c.signature = crypto::sign(issuer.secret_key,
                               credentials::signed_bytes(peer, issuer.public_key, scope, expires_unix));
    return credentials::serialize(c);
}

} // namespace epx
