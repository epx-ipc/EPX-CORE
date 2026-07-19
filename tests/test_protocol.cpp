// Round-trips every wire payload type through encode_*/decode_* and checks
// the result matches the original. Pure wire-format logic — no sockets, no
// libsodium, no network of any kind — so this test alone is enough to
// catch a framing/field-ordering regression without needing a running
// Host/Client pair.
#include "test_util.hpp"
#include "protocol.hpp"

using namespace epx::wire;

static void test_hello_roundtrip() {
    HelloPayload h;
    h.version = kProtocolVersion;
    for (size_t i = 0; i < h.identity_pubkey.size(); ++i) h.identity_pubkey[i] = uint8_t(i);
    for (size_t i = 0; i < h.ephemeral_pubkey.size(); ++i) h.ephemeral_pubkey[i] = uint8_t(200 + i);
    for (size_t i = 0; i < h.client_nonce.size(); ++i) h.client_nonce[i] = uint8_t(50 + i);
    h.service_name = "com.example.test";
    for (size_t i = 0; i < h.signature.size(); ++i) h.signature[i] = uint8_t(i * 3);

    auto bytes = encode_hello(h);
    HelloPayload out;
    CHECK(decode_hello(bytes, out));
    CHECK_EQ(out.version, h.version);
    CHECK(out.identity_pubkey == h.identity_pubkey);
    CHECK(out.ephemeral_pubkey == h.ephemeral_pubkey);
    CHECK(out.client_nonce == h.client_nonce);
    CHECK_EQ(out.service_name, h.service_name);
    CHECK(out.signature == h.signature);
}

static void test_hello_ack_roundtrip() {
    HelloAckPayload h;
    h.version = kProtocolVersion;
    h.status = 1;
    for (size_t i = 0; i < h.identity_pubkey.size(); ++i) h.identity_pubkey[i] = uint8_t(i * 2);
    for (size_t i = 0; i < h.ephemeral_pubkey.size(); ++i) h.ephemeral_pubkey[i] = uint8_t(i + 7);
    for (size_t i = 0; i < h.server_nonce.size(); ++i) h.server_nonce[i] = uint8_t(i + 1);
    for (size_t i = 0; i < h.client_nonce.size(); ++i) h.client_nonce[i] = uint8_t(i + 2);
    for (size_t i = 0; i < h.signature.size(); ++i) h.signature[i] = uint8_t(255 - i);

    auto bytes = encode_hello_ack(h);
    HelloAckPayload out;
    CHECK(decode_hello_ack(bytes, out));
    CHECK_EQ(out.status, h.status);
    CHECK(out.identity_pubkey == h.identity_pubkey);
    CHECK(out.ephemeral_pubkey == h.ephemeral_pubkey);
    CHECK(out.server_nonce == h.server_nonce);
    CHECK(out.client_nonce == h.client_nonce);
    CHECK(out.signature == h.signature);
}

static void test_request_roundtrip() {
    RequestPayload r;
    r.request_id = 0xDEADBEEFCAFEULL;
    r.oneway = true;
    r.endpoint = "echo";
    r.data = {1, 2, 3, 4, 250, 251};

    auto bytes = encode_request(r);
    RequestPayload out;
    CHECK(decode_request(bytes, out));
    CHECK_EQ(out.request_id, r.request_id);
    CHECK_EQ(out.oneway, r.oneway);
    CHECK_EQ(out.endpoint, r.endpoint);
    CHECK(out.data == r.data);
}

static void test_request_roundtrip_empty_data() {
    RequestPayload r;
    r.request_id = 1;
    r.oneway = false;
    r.endpoint = "time";
    r.data = {};

    auto bytes = encode_request(r);
    RequestPayload out;
    CHECK(decode_request(bytes, out));
    CHECK_EQ(out.endpoint, r.endpoint);
    CHECK(out.data.empty());
}

static void test_response_roundtrip() {
    ResponsePayload r;
    r.request_id = 42;
    r.status = 1;
    r.data = {'b', 'a', 'd'};

    auto bytes = encode_response(r);
    ResponsePayload out;
    CHECK(decode_response(bytes, out));
    CHECK_EQ(out.request_id, r.request_id);
    CHECK_EQ(out.status, r.status);
    CHECK(out.data == r.data);
}

static void test_stream_chunk_roundtrip() {
    StreamChunkPayload c;
    c.request_id = 7;
    c.seq = 3;
    c.is_last = true;
    c.endpoint = "upload";
    c.data = {9, 8, 7};

    auto bytes = encode_stream_chunk(c);
    StreamChunkPayload out;
    CHECK(decode_stream_chunk(bytes, out));
    CHECK_EQ(out.request_id, c.request_id);
    CHECK_EQ(out.seq, c.seq);
    CHECK_EQ(out.is_last, c.is_last);
    CHECK_EQ(out.endpoint, c.endpoint);
    CHECK(out.data == c.data);
}

static void test_hello_v2_extension_roundtrip() {
    HelloPayload h;
    for (size_t i = 0; i < h.identity_pubkey.size(); ++i) h.identity_pubkey[i] = uint8_t(i);
    h.service_name = "svc";
    h.max_version = 2;
    for (size_t i = 0; i < h.signature_v2.size(); ++i) h.signature_v2[i] = uint8_t(i + 11);

    auto bytes = encode_hello(h);
    HelloPayload out;
    CHECK(decode_hello(bytes, out));
    CHECK(out.has_v2_extension);
    CHECK_EQ(out.max_version, uint8_t(2));
    CHECK(out.signature_v2 == h.signature_v2);
    CHECK_EQ(out.version, uint8_t(1)); // legacy byte stays 1 for v1 compat

    // A v1-style hello (no extension) decodes as max_version 1.
    HelloPayload v1;
    v1.service_name = "svc";
    v1.max_version = 1; // encoder omits the extension
    auto v1bytes = encode_hello(v1);
    HelloPayload v1out;
    CHECK(decode_hello(v1bytes, v1out));
    CHECK(!v1out.has_v2_extension);
    CHECK_EQ(v1out.max_version, uint8_t(1));
}

static void test_hello_ack_v2_extension_roundtrip() {
    HelloAckPayload h;
    h.status = 0;
    h.max_version = 2;
    for (size_t i = 0; i < h.signature_v2.size(); ++i) h.signature_v2[i] = uint8_t(i * 5);
    auto bytes = encode_hello_ack(h);
    HelloAckPayload out;
    CHECK(decode_hello_ack(bytes, out));
    CHECK(out.has_v2_extension);
    CHECK_EQ(out.max_version, uint8_t(2));
    CHECK(out.signature_v2 == h.signature_v2);
}

static void test_error_roundtrip() {
    ErrorPayload e;
    e.reason = kErrRateLimited;
    e.message = "slow down";
    auto bytes = encode_error(e);
    ErrorPayload out;
    CHECK(decode_error(bytes, out));
    CHECK_EQ(out.reason, e.reason);
    CHECK_EQ(out.message, e.message);
}

static void test_negotiate_version() {
    CHECK_EQ(negotiate_version(2, 2), uint8_t(2));
    CHECK_EQ(negotiate_version(2, 1), uint8_t(1));
    CHECK_EQ(negotiate_version(1, 2), uint8_t(1));
    CHECK_EQ(negotiate_version(1, 1), uint8_t(1));
    CHECK_EQ(negotiate_version(2, 0), uint8_t(0)); // no overlap -> fail
}

static void test_decode_rejects_truncated_input() {
    RequestPayload r;
    r.request_id = 1;
    r.endpoint = "x";
    r.data = {1, 2, 3, 4, 5};
    auto bytes = encode_request(r);
    bytes.resize(bytes.size() - 1); // truncate: claimed data_len now exceeds what's present

    RequestPayload out;
    CHECK(!decode_request(bytes, out)); // must fail closed, not read out of bounds
}

int main() {
    test_hello_roundtrip();
    test_hello_ack_roundtrip();
    test_request_roundtrip();
    test_request_roundtrip_empty_data();
    test_response_roundtrip();
    test_stream_chunk_roundtrip();
    test_hello_v2_extension_roundtrip();
    test_hello_ack_v2_extension_roundtrip();
    test_error_roundtrip();
    test_negotiate_version();
    test_decode_rejects_truncated_input();
    TEST_MAIN_EXIT();
}
