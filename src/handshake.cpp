#include "handshake.hpp"
#include "framing.hpp"
#include "protocol.hpp"

namespace epx::handshake {

using epx::framing::RawFrame;
using epx::wire::FrameType;
using epx::wire::HelloPayload;
using epx::wire::HelloAckPayload;

std::optional<Result> client_handshake(epx::transport::Transport& t,
                                        const epx::Identity& self,
                                        const std::string& target_service_name,
                                        const std::function<bool(const epx::PublicKey&)>& is_trusted) {
    auto ephemeral = epx::crypto::generate_ephemeral();
    const uint8_t my_max = epx::wire::max_negotiable_version();

    HelloPayload hello;
    hello.identity_pubkey = self.public_key;
    hello.ephemeral_pubkey = ephemeral.public_key;
    epx::crypto::random_bytes(hello.client_nonce.data(), hello.client_nonce.size());
    hello.service_name = target_service_name;
    auto signed_bytes = epx::wire::hello_signed_bytes(hello.ephemeral_pubkey, hello.client_nonce, hello.service_name);
    hello.signature = epx::crypto::sign(self.secret_key, signed_bytes);
    hello.max_version = my_max;
    if (my_max >= 2) {
        auto v2_bytes = epx::wire::hello_signed_bytes_v2(my_max, self.public_key, hello.ephemeral_pubkey,
                                                          hello.client_nonce, hello.service_name);
        hello.signature_v2 = epx::crypto::sign(self.secret_key, v2_bytes);
    }

    RawFrame hello_frame{FrameType::Hello, 0, 0, epx::wire::encode_hello(hello)};
    if (!epx::framing::write_frame(t, hello_frame)) return std::nullopt;

    auto ack_frame = epx::framing::read_frame(t);
    if (!ack_frame || ack_frame->type != FrameType::HelloAck) return std::nullopt;

    HelloAckPayload ack;
    if (!epx::wire::decode_hello_ack(ack_frame->body, ack)) return std::nullopt;
    if (ack.status != 0) return std::nullopt; // server rejected us
    if (ack.client_nonce != hello.client_nonce) return std::nullopt; // anti-replay binding

    // The server's claimed identity must be one the caller is willing to
    // trust *before* we accept the cryptographic proof below.
    if (!is_trusted(ack.identity_pubkey)) return std::nullopt;

    auto ack_signed_bytes = epx::wire::hello_ack_signed_bytes(ack.ephemeral_pubkey, ack.server_nonce, ack.client_nonce);
    if (!epx::crypto::verify(ack.identity_pubkey, ack_signed_bytes, ack.signature)) return std::nullopt;

    // Version negotiation. If both sides speak v2, the ack MUST carry a
    // valid v2 signature over a transcript that includes the negotiated
    // version computed from *our* real advertisement — so any tampering
    // with either side's offer makes verification fail closed rather than
    // silently running at a lower version.
    uint8_t negotiated = epx::wire::negotiate_version(my_max, ack.max_version);
    if (negotiated == 0) return std::nullopt;
    if (negotiated >= 2) {
        if (!ack.has_v2_extension) return std::nullopt;
        auto v2_bytes = epx::wire::hello_ack_signed_bytes_v2(
            ack.max_version, negotiated, ack.status,
            ack.identity_pubkey, self.public_key,
            ack.ephemeral_pubkey, ack.server_nonce, ack.client_nonce);
        if (!epx::crypto::verify(ack.identity_pubkey, v2_bytes, ack.signature_v2)) return std::nullopt;
    }

    Result r;
    r.peer_identity = ack.identity_pubkey;
    r.version = negotiated;
    r.keys = epx::crypto::client_session_keys(ephemeral, ack.ephemeral_pubkey);
    return r;
}

std::optional<Result> server_handshake(epx::transport::Transport& t,
                                        const epx::Identity& self,
                                        const std::string& own_service_name,
                                        const std::function<bool(const epx::PublicKey&)>& is_trusted) {
    auto hello_frame = epx::framing::read_frame(t);
    if (!hello_frame || hello_frame->type != FrameType::Hello) return std::nullopt;

    HelloPayload hello;
    if (!epx::wire::decode_hello(hello_frame->body, hello)) return std::nullopt;
    if (hello.version != epx::wire::kProtocolVersion) return std::nullopt;
    if (hello.service_name != own_service_name) return std::nullopt;

    const uint8_t my_max = epx::wire::max_negotiable_version();
    uint8_t negotiated = epx::wire::negotiate_version(my_max, hello.max_version);
    if (negotiated == 0) return std::nullopt;

    auto signed_bytes = epx::wire::hello_signed_bytes(hello.ephemeral_pubkey, hello.client_nonce, hello.service_name);
    bool sig_ok = epx::crypto::verify(hello.identity_pubkey, signed_bytes, hello.signature);
    if (sig_ok && negotiated >= 2) {
        // The v2 transcript binds the client's identity key and its version
        // advertisement; require it whenever the session will run at v2.
        sig_ok = hello.has_v2_extension &&
                 epx::crypto::verify(hello.identity_pubkey,
                                     epx::wire::hello_signed_bytes_v2(hello.max_version, hello.identity_pubkey,
                                                                       hello.ephemeral_pubkey, hello.client_nonce,
                                                                       hello.service_name),
                                     hello.signature_v2);
    }
    bool trusted = sig_ok && is_trusted(hello.identity_pubkey);

    auto ephemeral = epx::crypto::generate_ephemeral();
    HelloAckPayload ack;
    ack.identity_pubkey = self.public_key;
    ack.ephemeral_pubkey = ephemeral.public_key;
    epx::crypto::random_bytes(ack.server_nonce.data(), ack.server_nonce.size());
    ack.client_nonce = hello.client_nonce;
    ack.status = trusted ? 0 : 1;
    auto ack_signed_bytes = epx::wire::hello_ack_signed_bytes(ack.ephemeral_pubkey, ack.server_nonce, ack.client_nonce);
    ack.signature = epx::crypto::sign(self.secret_key, ack_signed_bytes);
    ack.max_version = my_max;
    if (my_max >= 2) {
        auto v2_bytes = epx::wire::hello_ack_signed_bytes_v2(
            my_max, negotiated, ack.status,
            self.public_key, hello.identity_pubkey,
            ack.ephemeral_pubkey, ack.server_nonce, ack.client_nonce);
        ack.signature_v2 = epx::crypto::sign(self.secret_key, v2_bytes);
    }

    RawFrame ack_frame{FrameType::HelloAck, 0, 0, epx::wire::encode_hello_ack(ack)};
    if (!epx::framing::write_frame(t, ack_frame)) return std::nullopt;

    if (!trusted) return std::nullopt;

    Result r;
    r.peer_identity = hello.identity_pubkey;
    r.version = negotiated;
    r.keys = epx::crypto::server_session_keys(ephemeral, hello.ephemeral_pubkey);
    return r;
}

} // namespace epx::handshake
