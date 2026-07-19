#include "crypto.hpp"
#include <sodium.h>
#include <cstring>

namespace epx::crypto {

void init() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium failed to initialize");
    }
}

epx::Identity generate_identity() {
    epx::Identity id;
    static_assert(sizeof(id.public_key) == crypto_sign_PUBLICKEYBYTES, "public key size mismatch");
    static_assert(sizeof(id.secret_key) == crypto_sign_SECRETKEYBYTES, "secret key size mismatch");
    if (crypto_sign_keypair(id.public_key.data(), id.secret_key.data()) != 0) {
        throw std::runtime_error("crypto_sign_keypair failed");
    }
    return id;
}

EphemeralKeyPair::~EphemeralKeyPair() {
    sodium_memzero(secret_key.data(), secret_key.size());
}

EphemeralKeyPair generate_ephemeral() {
    EphemeralKeyPair kp;
    static_assert(sizeof(kp.public_key) == crypto_kx_PUBLICKEYBYTES, "size mismatch");
    static_assert(sizeof(kp.secret_key) == crypto_kx_SECRETKEYBYTES, "size mismatch");
    if (crypto_kx_keypair(kp.public_key.data(), kp.secret_key.data()) != 0) {
        throw std::runtime_error("crypto_kx_keypair failed");
    }
    return kp;
}

std::array<uint8_t, 64> sign(const epx::SecretKey& sk, const std::vector<uint8_t>& message) {
    std::array<uint8_t, 64> sig{};
    static_assert(64 == crypto_sign_BYTES, "signature size mismatch");
    unsigned long long siglen = 0;
    crypto_sign_detached(sig.data(), &siglen, message.data(), message.size(), sk.data());
    return sig;
}

bool verify(const epx::PublicKey& pk, const std::vector<uint8_t>& message, const std::array<uint8_t, 64>& sig) {
    return crypto_sign_verify_detached(sig.data(), message.data(), message.size(), pk.data()) == 0;
}

SessionKeys::~SessionKeys() {
    sodium_memzero(rx.data(), rx.size());
    sodium_memzero(tx.data(), tx.size());
}

SessionKeys client_session_keys(const EphemeralKeyPair& self_ephemeral, const std::array<uint8_t, 32>& peer_ephemeral_pk) {
    SessionKeys keys;
    if (crypto_kx_client_session_keys(keys.rx.data(), keys.tx.data(),
                                       self_ephemeral.public_key.data(), self_ephemeral.secret_key.data(),
                                       peer_ephemeral_pk.data()) != 0) {
        throw std::runtime_error("crypto_kx_client_session_keys failed (suspicious peer key)");
    }
    return keys;
}

SessionKeys server_session_keys(const EphemeralKeyPair& self_ephemeral, const std::array<uint8_t, 32>& peer_ephemeral_pk) {
    SessionKeys keys;
    if (crypto_kx_server_session_keys(keys.rx.data(), keys.tx.data(),
                                       self_ephemeral.public_key.data(), self_ephemeral.secret_key.data(),
                                       peer_ephemeral_pk.data()) != 0) {
        throw std::runtime_error("crypto_kx_server_session_keys failed (suspicious peer key)");
    }
    return keys;
}

namespace {
// 24-byte XChaCha20-Poly1305 nonce built from an 8-byte monotonic counter.
// Safe because the key is a fresh, never-reused-across-connections
// ephemeral session key (see client_session_keys/server_session_keys).
std::array<uint8_t, 24> make_nonce(uint64_t counter) {
    static_assert(24 == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, "nonce size mismatch");
    std::array<uint8_t, 24> nonce{};
    for (int i = 0; i < 8; ++i) {
        nonce[i] = uint8_t(counter >> (56 - i * 8));
    }
    return nonce;
}
} // namespace

namespace {
// Shared AEAD path. AD layout: frame_type || counter (v1, ad_len 9), plus
// || epoch for v2 sessions (ad_len 10) — see crypto.hpp.
std::vector<uint8_t> seal_impl(const std::array<uint8_t, 32>& key, uint64_t counter,
                                const uint8_t* ad, size_t ad_len,
                                const std::vector<uint8_t>& plaintext) {
    static_assert(32 == crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "key size mismatch");
    auto nonce = make_nonce(counter);
    std::vector<uint8_t> out(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long out_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data(), &out_len,
        plaintext.data(), plaintext.size(),
        ad, ad_len,
        nullptr,
        nonce.data(),
        key.data());
    out.resize(out_len);
    return out;
}

std::optional<std::vector<uint8_t>> open_impl(const std::array<uint8_t, 32>& key, uint64_t counter,
                                               const uint8_t* ad, size_t ad_len,
                                               const std::vector<uint8_t>& ciphertext) {
    auto nonce = make_nonce(counter);
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) return std::nullopt;
    std::vector<uint8_t> out(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long out_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out.data(), &out_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            ad, ad_len,
            nonce.data(),
            key.data()) != 0) {
        return std::nullopt; // authentication failed
    }
    out.resize(out_len);
    return out;
}

void fill_ad(uint8_t* ad, uint8_t frame_type, uint64_t counter) {
    ad[0] = frame_type;
    for (int i = 0; i < 8; ++i) ad[1 + i] = uint8_t(counter >> (56 - i * 8));
}
} // namespace

std::vector<uint8_t> seal(const std::array<uint8_t, 32>& key, uint64_t counter, uint8_t frame_type,
                           const std::vector<uint8_t>& plaintext) {
    uint8_t ad[9];
    fill_ad(ad, frame_type, counter);
    return seal_impl(key, counter, ad, sizeof(ad), plaintext);
}

std::optional<std::vector<uint8_t>> open(const std::array<uint8_t, 32>& key, uint64_t counter, uint8_t frame_type,
                                          const std::vector<uint8_t>& ciphertext) {
    uint8_t ad[9];
    fill_ad(ad, frame_type, counter);
    return open_impl(key, counter, ad, sizeof(ad), ciphertext);
}

std::vector<uint8_t> seal_v2(const std::array<uint8_t, 32>& key, uint64_t counter, uint8_t epoch,
                              uint8_t frame_type, const std::vector<uint8_t>& plaintext) {
    uint8_t ad[10];
    fill_ad(ad, frame_type, counter);
    ad[9] = epoch;
    return seal_impl(key, counter, ad, sizeof(ad), plaintext);
}

std::optional<std::vector<uint8_t>> open_v2(const std::array<uint8_t, 32>& key, uint64_t counter, uint8_t epoch,
                                             uint8_t frame_type, const std::vector<uint8_t>& ciphertext) {
    uint8_t ad[10];
    fill_ad(ad, frame_type, counter);
    ad[9] = epoch;
    return open_impl(key, counter, ad, sizeof(ad), ciphertext);
}

void random_bytes(uint8_t* buf, size_t len) {
    randombytes_buf(buf, len);
}

void wipe(uint8_t* buf, size_t len) {
    sodium_memzero(buf, len);
}

} // namespace epx::crypto
