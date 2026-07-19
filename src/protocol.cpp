#include "protocol.hpp"

namespace epx::wire {

namespace {
uint8_t g_max_negotiable = kProtocolVersionMax;
} // namespace

uint8_t max_negotiable_version() { return g_max_negotiable; }
void set_max_negotiable_version_for_testing(uint8_t v) { g_max_negotiable = v; }

namespace {
void put_bytes(std::vector<uint8_t>& out, const uint8_t* p, size_t n) {
    out.insert(out.end(), p, p + n);
}
void put_str8(std::vector<uint8_t>& out, const std::string& s) {
    // length-prefixed with a single byte: endpoint/service names are short.
    out.push_back(uint8_t(s.size() & 0xFF));
    out.insert(out.end(), s.begin(), s.end());
}
bool get_str8(const uint8_t* p, size_t avail, size_t& off, std::string& s) {
    if (off + 1 > avail) return false;
    uint8_t len = p[off]; off += 1;
    if (off + len > avail) return false;
    s.assign(reinterpret_cast<const char*>(p + off), len);
    off += len;
    return true;
}
} // namespace

std::vector<uint8_t> hello_signed_bytes(const std::array<uint8_t, 32>& ephemeral_pubkey,
                                         const std::array<uint8_t, 16>& client_nonce,
                                         const std::string& service_name) {
    std::vector<uint8_t> m;
    m.insert(m.end(), ephemeral_pubkey.begin(), ephemeral_pubkey.end());
    m.insert(m.end(), client_nonce.begin(), client_nonce.end());
    m.insert(m.end(), service_name.begin(), service_name.end());
    return m;
}

std::vector<uint8_t> hello_ack_signed_bytes(const std::array<uint8_t, 32>& ephemeral_pubkey,
                                             const std::array<uint8_t, 16>& server_nonce,
                                             const std::array<uint8_t, 16>& client_nonce) {
    std::vector<uint8_t> m;
    m.insert(m.end(), ephemeral_pubkey.begin(), ephemeral_pubkey.end());
    m.insert(m.end(), server_nonce.begin(), server_nonce.end());
    m.insert(m.end(), client_nonce.begin(), client_nonce.end());
    return m;
}

std::vector<uint8_t> encode_hello(const HelloPayload& h) {
    std::vector<uint8_t> out;
    out.push_back(h.version);
    put_bytes(out, h.identity_pubkey.data(), h.identity_pubkey.size());
    put_bytes(out, h.ephemeral_pubkey.data(), h.ephemeral_pubkey.size());
    put_bytes(out, h.client_nonce.data(), h.client_nonce.size());
    put_str8(out, h.service_name);
    put_bytes(out, h.signature.data(), h.signature.size());
    if (h.max_version >= 2) { // trailing v2 extension; a v1 decoder ignores it
        out.push_back(h.max_version);
        put_bytes(out, h.signature_v2.data(), h.signature_v2.size());
    }
    return out;
}

bool decode_hello(const std::vector<uint8_t>& in, HelloPayload& h) {
    size_t off = 0;
    if (in.size() < 1 + 32 + 32 + 16 + 1) return false;
    h.version = in[off]; off += 1;
    std::memcpy(h.identity_pubkey.data(), in.data() + off, 32); off += 32;
    std::memcpy(h.ephemeral_pubkey.data(), in.data() + off, 32); off += 32;
    std::memcpy(h.client_nonce.data(), in.data() + off, 16); off += 16;
    if (!get_str8(in.data(), in.size(), off, h.service_name)) return false;
    if (off + 64 > in.size()) return false;
    std::memcpy(h.signature.data(), in.data() + off, 64); off += 64;
    h.max_version = 1;
    h.has_v2_extension = false;
    if (in.size() >= off + 1 + 64) { // trailing v2 extension present
        h.max_version = in[off]; off += 1;
        std::memcpy(h.signature_v2.data(), in.data() + off, 64); off += 64;
        h.has_v2_extension = true;
    }
    return true;
}

std::vector<uint8_t> encode_hello_ack(const HelloAckPayload& h) {
    std::vector<uint8_t> out;
    out.push_back(h.version);
    put_bytes(out, h.identity_pubkey.data(), h.identity_pubkey.size());
    put_bytes(out, h.ephemeral_pubkey.data(), h.ephemeral_pubkey.size());
    put_bytes(out, h.server_nonce.data(), h.server_nonce.size());
    put_bytes(out, h.client_nonce.data(), h.client_nonce.size());
    out.push_back(h.status);
    put_bytes(out, h.signature.data(), h.signature.size());
    if (h.max_version >= 2) { // trailing v2 extension; a v1 decoder ignores it
        out.push_back(h.max_version);
        put_bytes(out, h.signature_v2.data(), h.signature_v2.size());
    }
    return out;
}

bool decode_hello_ack(const std::vector<uint8_t>& in, HelloAckPayload& h) {
    if (in.size() < 1 + 32 + 32 + 16 + 16 + 1 + 64) return false;
    size_t off = 0;
    h.version = in[off]; off += 1;
    std::memcpy(h.identity_pubkey.data(), in.data() + off, 32); off += 32;
    std::memcpy(h.ephemeral_pubkey.data(), in.data() + off, 32); off += 32;
    std::memcpy(h.server_nonce.data(), in.data() + off, 16); off += 16;
    std::memcpy(h.client_nonce.data(), in.data() + off, 16); off += 16;
    h.status = in[off]; off += 1;
    std::memcpy(h.signature.data(), in.data() + off, 64); off += 64;
    h.max_version = 1;
    h.has_v2_extension = false;
    if (in.size() >= off + 1 + 64) {
        h.max_version = in[off]; off += 1;
        std::memcpy(h.signature_v2.data(), in.data() + off, 64); off += 64;
        h.has_v2_extension = true;
    }
    return true;
}

std::vector<uint8_t> hello_signed_bytes_v2(uint8_t max_version,
                                            const epx::PublicKey& client_identity,
                                            const std::array<uint8_t, 32>& ephemeral_pubkey,
                                            const std::array<uint8_t, 16>& client_nonce,
                                            const std::string& service_name) {
    static const char* tag = "EPX-v2-hello";
    std::vector<uint8_t> m(tag, tag + 12);
    m.push_back(max_version);
    m.insert(m.end(), client_identity.begin(), client_identity.end());
    m.insert(m.end(), ephemeral_pubkey.begin(), ephemeral_pubkey.end());
    m.insert(m.end(), client_nonce.begin(), client_nonce.end());
    m.insert(m.end(), service_name.begin(), service_name.end());
    return m;
}

std::vector<uint8_t> hello_ack_signed_bytes_v2(uint8_t server_max_version,
                                                uint8_t negotiated_version,
                                                uint8_t status,
                                                const epx::PublicKey& server_identity,
                                                const epx::PublicKey& client_identity,
                                                const std::array<uint8_t, 32>& ephemeral_pubkey,
                                                const std::array<uint8_t, 16>& server_nonce,
                                                const std::array<uint8_t, 16>& client_nonce) {
    static const char* tag = "EPX-v2-ack";
    std::vector<uint8_t> m(tag, tag + 10);
    m.push_back(server_max_version);
    m.push_back(negotiated_version);
    m.push_back(status);
    m.insert(m.end(), server_identity.begin(), server_identity.end());
    m.insert(m.end(), client_identity.begin(), client_identity.end());
    m.insert(m.end(), ephemeral_pubkey.begin(), ephemeral_pubkey.end());
    m.insert(m.end(), server_nonce.begin(), server_nonce.end());
    m.insert(m.end(), client_nonce.begin(), client_nonce.end());
    return m;
}

std::vector<uint8_t> encode_error(const ErrorPayload& e) {
    std::vector<uint8_t> out;
    out.push_back(uint8_t(e.reason >> 8));
    out.push_back(uint8_t(e.reason & 0xFF));
    out.insert(out.end(), e.message.begin(), e.message.end());
    return out;
}

bool decode_error(const std::vector<uint8_t>& in, ErrorPayload& e) {
    if (in.size() < 2) return false;
    e.reason = uint16_t((uint16_t(in[0]) << 8) | in[1]);
    e.message.assign(in.begin() + 2, in.end());
    return true;
}

std::vector<uint8_t> encode_request(const RequestPayload& r) {
    std::vector<uint8_t> out;
    put_u64(out, r.request_id);
    out.push_back(r.oneway ? 1 : 0);
    put_str8(out, r.endpoint);
    put_u32(out, uint32_t(r.data.size()));
    out.insert(out.end(), r.data.begin(), r.data.end());
    return out;
}

bool decode_request(const std::vector<uint8_t>& in, RequestPayload& r) {
    if (in.size() < 8 + 1 + 1) return false;
    size_t off = 0;
    r.request_id = get_u64(in.data() + off); off += 8;
    r.oneway = in[off] != 0; off += 1;
    if (!get_str8(in.data(), in.size(), off, r.endpoint)) return false;
    if (off + 4 > in.size()) return false;
    uint32_t dlen = get_u32(in.data() + off); off += 4;
    if (off + dlen > in.size()) return false;
    r.data.assign(in.begin() + off, in.begin() + off + dlen);
    return true;
}

std::vector<uint8_t> encode_response(const ResponsePayload& r) {
    std::vector<uint8_t> out;
    put_u64(out, r.request_id);
    out.push_back(r.status);
    put_u32(out, uint32_t(r.data.size()));
    out.insert(out.end(), r.data.begin(), r.data.end());
    return out;
}

bool decode_response(const std::vector<uint8_t>& in, ResponsePayload& r) {
    if (in.size() < 8 + 1 + 4) return false;
    size_t off = 0;
    r.request_id = get_u64(in.data() + off); off += 8;
    r.status = in[off]; off += 1;
    uint32_t dlen = get_u32(in.data() + off); off += 4;
    if (off + dlen > in.size()) return false;
    r.data.assign(in.begin() + off, in.begin() + off + dlen);
    return true;
}

std::vector<uint8_t> encode_stream_chunk(const StreamChunkPayload& c) {
    std::vector<uint8_t> out;
    put_u64(out, c.request_id);
    put_u32(out, c.seq);
    out.push_back(c.is_last ? 1 : 0);
    put_str8(out, c.endpoint);
    put_u32(out, uint32_t(c.data.size()));
    out.insert(out.end(), c.data.begin(), c.data.end());
    return out;
}

bool decode_stream_chunk(const std::vector<uint8_t>& in, StreamChunkPayload& c) {
    if (in.size() < 8 + 4 + 1 + 1) return false;
    size_t off = 0;
    c.request_id = get_u64(in.data() + off); off += 8;
    c.seq = get_u32(in.data() + off); off += 4;
    c.is_last = in[off] != 0; off += 1;
    if (!get_str8(in.data(), in.size(), off, c.endpoint)) return false;
    if (off + 4 > in.size()) return false;
    uint32_t dlen = get_u32(in.data() + off); off += 4;
    if (off + dlen > in.size()) return false;
    c.data.assign(in.begin() + off, in.begin() + off + dlen);
    return true;
}

} // namespace epx::wire
