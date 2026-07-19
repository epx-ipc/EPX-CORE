#include "epx/epx.hpp"
#include "init.hpp"
#include "transport.hpp"
#include "framing.hpp"
#include "handshake.hpp"
#include "protocol.hpp"
#include "registry.hpp"
#include "keystore.hpp"

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <unordered_map>

namespace epx {

using wire::FrameType;

namespace {

struct StreamSink {
    std::function<void(const Bytes&, bool)> callback;
    bool done = false;
    uint64_t activity = 0; // bumped on every chunk; lets get_stream tell "still flowing" from "stalled"
    // Set when the host answered the stream request with an error RESPONSE
    // (endpoint not found, access denied) instead of chunks.
    bool failed = false;
    uint8_t fail_status = 0;
    std::string fail_message;
    // Subscription sinks (Client::subscribe) live until the feed closes;
    // nobody blocks on them the way get_stream blocks, so the reader owns
    // their cleanup: on is_last (or reader exit) invoke the callback with
    // closed=true and erase the sink.
    bool subscription = false;
};

struct Connection {
    std::shared_ptr<transport::Transport> transport;
    crypto::SessionKeys keys;
    uint8_t version = 1;       // negotiated protocol version for this session
    std::mutex write_mutex;    // serializes seal()+write_frame()+counter bump
    uint64_t tx_counter = 0;
    uint8_t epoch = 0;         // tx key generation (v2; bumped only by rotation)
    std::atomic<uint64_t> next_request_id{1};

    // ---- key rotation (8c; client-initiated, see epx.hpp) -------------
    RotationPolicy rotation;   // both bounds 0 = disabled
    // Guarded by write_mutex (all touched on the send path):
    std::chrono::steady_clock::time_point last_rotation = std::chrono::steady_clock::now();
    uint64_t bytes_since_rotation = 0;
    bool rekey_in_progress = false;
    // The fresh ephemeral we offered in a REKEY, kept until its REKEY_ACK
    // arrives. Guarded by rekey_mutex (reader takes only this, never
    // write_mutex at the same time — no lock cycle with the send path).
    std::mutex rekey_mutex;
    std::optional<crypto::EphemeralKeyPair> pending_eph;

    std::thread reader_thread;
    std::atomic<bool> alive{true};
    // Why the host force-closed us, if it said (ERROR frame): wire::kErr*
    // reason + message, consulted when surfacing errors to blocked callers.
    std::atomic<uint16_t> death_reason{0};
    std::mutex death_mutex;
    std::string death_message;

    std::mutex pending_mutex;
    std::condition_variable pending_cv;
    std::unordered_map<uint64_t, std::optional<wire::ResponsePayload>> pending;

    std::mutex stream_mutex;
    std::condition_variable stream_cv;
    std::unordered_map<uint64_t, StreamSink> stream_sinks;
};

// Precondition: write_mutex held. Raw seal+write of one frame under the
// connection's current tx key/epoch/counter.
bool send_frame_locked(Connection& conn, FrameType type, const std::vector<uint8_t>& plaintext) {
    const bool v2 = conn.version >= 2;
    auto ct = v2 ? crypto::seal_v2(conn.keys.tx, conn.tx_counter, conn.epoch, uint8_t(type), plaintext)
                 : crypto::seal(conn.keys.tx, conn.tx_counter, uint8_t(type), plaintext);
    bool ok = framing::write_frame(*conn.transport, framing::RawFrame{type, conn.tx_counter, conn.epoch, ct}, v2);
    conn.tx_counter++;
    return ok;
}

// Precondition: write_mutex held. If the rotation policy says a rotation
// is due, offer a fresh ephemeral in a REKEY frame (still under the
// current epoch). The actual key switch happens when the reader thread
// processes the REKEY_ACK; until then we keep sending under the current
// keys, which stays valid because the server keeps them until it sees our
// first next-epoch frame.
void maybe_begin_rekey_locked(Connection& conn) {
    const auto& p = conn.rotation;
    if (conn.version < 2 || conn.rekey_in_progress || conn.epoch >= 255) return;
    if (p.interval.count() == 0 && p.max_bytes == 0) return;
    bool due = false;
    if (p.interval.count() > 0 &&
        std::chrono::steady_clock::now() - conn.last_rotation >= p.interval) due = true;
    if (p.max_bytes > 0 && conn.bytes_since_rotation >= p.max_bytes) due = true;
    if (!due) return;

    auto eph = crypto::generate_ephemeral();
    std::vector<uint8_t> body(eph.public_key.begin(), eph.public_key.end());
    if (!send_frame_locked(conn, FrameType::Rekey, body)) return; // dead conn; reader will notice
    {
        std::lock_guard<std::mutex> lock(conn.rekey_mutex);
        conn.pending_eph = eph; // copy; the local's secret is zeroed at scope end
    }
    conn.rekey_in_progress = true;
}

// Seals + sends one frame on `conn`, serialized under its write_mutex and
// using its shared tx counter. Used for Request, StreamChunk (from
// OutputStream), anything the client originates.
bool seal_and_send(Connection& conn, FrameType type, const std::vector<uint8_t>& plaintext) {
    std::lock_guard<std::mutex> lock(conn.write_mutex);
    maybe_begin_rekey_locked(conn);
    bool ok = send_frame_locked(conn, type, plaintext);
    conn.bytes_since_rotation += plaintext.size();
    return ok;
}

} // namespace

struct Client::Impl {
    Identity identity;
    TrustPolicy policy;
    std::atomic<int> stream_write_timeout_ms{0}; // applied to connections opened after set
    std::mutex rotation_mutex;
    RotationPolicy rotation_policy; // copied into connections opened after set

    std::mutex allow_mutex;
    std::set<PublicKey> allowed_peers;

    std::mutex conns_mutex;
    std::unordered_map<std::string, std::shared_ptr<Connection>> conns;

    bool is_client_side_trusted(TrustPolicy p, const std::string& target_service,
                                const registry::Entry& entry, const PublicKey& claimed) {
        if (claimed != entry.identity_pubkey) return false; // registry/handshake mismatch
        switch (p) {
            case TrustPolicy::AllowAll:
                return true;
            case TrustPolicy::RequireKnownPeer: {
                std::lock_guard<std::mutex> lock(allow_mutex);
                return allowed_peers.count(claimed) > 0;
            }
            case TrustPolicy::TrustOnFirstUse: {
                auto pinned = keystore::load_pinned_peer(target_service);
                if (pinned) return *pinned == claimed;
                return true; // first contact; pinned after a successful handshake below
            }
        }
        return false;
    }

    void reader_loop(std::shared_ptr<Connection> conn) {
        const bool v2 = conn->version >= 2;

        // Receive-side key state, confined to this thread. `rx_pending`
        // holds the next epoch's key between our REKEY_ACK processing and
        // the server's first frame actually sealed under it (the ordered
        // byte stream guarantees no old-epoch frame follows that one).
        std::array<uint8_t, 32> rx_key = conn->keys.rx;
        uint8_t rx_epoch = 0;
        uint64_t rx_counter = 0;
        std::optional<std::array<uint8_t, 32>> rx_pending;

        // Counter/epoch validation + AEAD open in one place. Any failure
        // (bad counter, unknown epoch, failed authentication) reads as
        // nullopt and the caller drops the connection.
        auto open_checked = [&](const framing::RawFrame& f) -> std::optional<std::vector<uint8_t>> {
            if (!v2) {
                if (f.counter != rx_counter) return std::nullopt;
                auto o = crypto::open(rx_key, f.counter, uint8_t(f.type), f.body);
                if (o) rx_counter++;
                return o;
            }
            if (f.epoch == rx_epoch) {
                if (f.counter != rx_counter) return std::nullopt;
                auto o = crypto::open_v2(rx_key, f.counter, f.epoch, uint8_t(f.type), f.body);
                if (o) rx_counter++;
                return o;
            }
            if (rx_pending && f.epoch == uint8_t(rx_epoch + 1)) {
                if (f.counter != 0) return std::nullopt; // new epoch starts a fresh counter space
                auto o = crypto::open_v2(*rx_pending, 0, f.epoch, uint8_t(f.type), f.body);
                if (o) {
                    crypto::wipe(rx_key.data(), rx_key.size());
                    rx_key = *rx_pending;
                    rx_pending.reset();
                    rx_epoch++;
                    rx_counter = 1;
                }
                return o;
            }
            return std::nullopt;
        };

        while (conn->alive.load()) {
            auto frame = framing::read_frame(*conn->transport, v2);
            if (!frame) break;
            if (frame->type == FrameType::Pong || frame->type == FrameType::Ping) continue;

            if (frame->type == FrameType::RekeyAck) {
                // The server accepted our rotation offer: derive the new
                // keys, switch our tx immediately, and arm rx_pending for
                // the server's first next-epoch frame.
                auto opened = open_checked(*frame);
                if (!opened || opened->size() != 32) break;
                std::optional<crypto::EphemeralKeyPair> eph;
                {
                    std::lock_guard<std::mutex> lock(conn->rekey_mutex);
                    eph.swap(conn->pending_eph);
                }
                if (!eph) break; // unsolicited ack: protocol violation
                std::array<uint8_t, 32> server_eph{};
                std::memcpy(server_eph.data(), opened->data(), 32);
                auto nk = crypto::client_session_keys(*eph, server_eph);
                {
                    std::lock_guard<std::mutex> lock(conn->write_mutex);
                    crypto::wipe(conn->keys.tx.data(), conn->keys.tx.size());
                    conn->keys.tx = nk.tx;
                    conn->epoch++;
                    conn->tx_counter = 0;
                    conn->rekey_in_progress = false;
                    conn->bytes_since_rotation = 0;
                    conn->last_rotation = std::chrono::steady_clock::now();
                }
                rx_pending = nk.rx;
                continue;
            }

            if (frame->type == FrameType::Error) {
                // The host is about to close us and says why; remember the
                // reason so blocked get()/get_stream() calls can report it.
                auto opened = open_checked(*frame);
                if (!opened) break;
                wire::ErrorPayload err;
                if (wire::decode_error(*opened, err)) {
                    std::lock_guard<std::mutex> lock(conn->death_mutex);
                    conn->death_message = err.message;
                    conn->death_reason.store(err.reason);
                }
                break;
            }

            if (frame->type == FrameType::StreamChunk) {
                auto opened = open_checked(*frame);
                if (!opened) break;

                wire::StreamChunkPayload chunk;
                if (!wire::decode_stream_chunk(*opened, chunk)) break;

                std::function<void(const Bytes&, bool)> cb;
                bool have_sink = false;
                bool is_subscription = false;
                {
                    std::lock_guard<std::mutex> lock(conn->stream_mutex);
                    auto it = conn->stream_sinks.find(chunk.request_id);
                    if (it != conn->stream_sinks.end()) {
                        cb = it->second.callback;
                        it->second.activity++;
                        have_sink = true;
                        is_subscription = it->second.subscription;
                        if (chunk.is_last) it->second.done = true;
                    }
                }
                if (have_sink && cb) cb(chunk.data, chunk.is_last);
                if (chunk.is_last) {
                    std::lock_guard<std::mutex> lock(conn->stream_mutex);
                    if (is_subscription) conn->stream_sinks.erase(chunk.request_id);
                    conn->stream_cv.notify_all();
                }
                continue;
            }

            if (frame->type != FrameType::Response) continue;
            auto opened = open_checked(*frame);
            if (!opened) break;

            wire::ResponsePayload resp;
            if (!wire::decode_response(*opened, resp)) break;

            {
                std::lock_guard<std::mutex> lock(conn->pending_mutex);
                auto it = conn->pending.find(resp.request_id);
                if (it != conn->pending.end()) {
                    it->second = resp;
                    conn->pending_cv.notify_all();
                    continue;
                }
            }
            // A RESPONSE with no pending get() may target an in-flight
            // get_stream() or subscribe(): the host answers a denied/
            // not-found request with a normal error RESPONSE, not chunks.
            {
                std::function<void(const Bytes&, bool)> closed_cb;
                {
                    std::lock_guard<std::mutex> lock(conn->stream_mutex);
                    auto it = conn->stream_sinks.find(resp.request_id);
                    if (it != conn->stream_sinks.end()) {
                        it->second.failed = true;
                        it->second.fail_status = resp.status;
                        it->second.fail_message.assign(resp.data.begin(), resp.data.end());
                        it->second.done = true;
                        if (it->second.subscription) { // refused: deliver closed=true and forget
                            closed_cb = it->second.callback;
                            conn->stream_sinks.erase(it);
                        }
                        conn->stream_cv.notify_all();
                    }
                }
                if (closed_cb) closed_cb({}, true);
            }
        }
        conn->alive.store(false);
        {
            std::lock_guard<std::mutex> lock(conn->pending_mutex);
            conn->pending_cv.notify_all(); // wake any get() waiting on a now-dead connection
        }
        // Subscriptions never see the socket die on their own — deliver the
        // final closed=true to each of them here, on the reader's way out.
        std::vector<std::function<void(const Bytes&, bool)>> closed_cbs;
        {
            std::lock_guard<std::mutex> lock(conn->stream_mutex);
            for (auto it = conn->stream_sinks.begin(); it != conn->stream_sinks.end();) {
                if (it->second.subscription) {
                    if (it->second.callback) closed_cbs.push_back(it->second.callback);
                    it = conn->stream_sinks.erase(it);
                } else {
                    ++it;
                }
            }
            conn->stream_cv.notify_all(); // wake any get_stream() waiting on a now-dead connection
        }
        for (auto& cb : closed_cbs) cb({}, true);
    }

    std::shared_ptr<Connection> get_or_connect(const std::string& target_service) {
        {
            std::lock_guard<std::mutex> lock(conns_mutex);
            auto it = conns.find(target_service);
            if (it != conns.end() && it->second->alive.load()) return it->second;
        }

        auto entry = registry::lookup(target_service);
        if (!entry) {
            throw EpxError(EpxError::Code::NotFound, "no such service registered: " + target_service);
        }

        if (policy == TrustPolicy::RequireKnownPeer) {
            std::lock_guard<std::mutex> lock(allow_mutex);
            if (!allowed_peers.count(entry->identity_pubkey)) {
                throw EpxError(EpxError::Code::HandshakeRejected,
                                "peer identity for '" + target_service + "' is not in the allow-list");
            }
        }
        if (policy == TrustPolicy::TrustOnFirstUse) {
            auto pinned = keystore::load_pinned_peer(target_service);
            if (pinned && *pinned != entry->identity_pubkey) {
                throw EpxError(EpxError::Code::HandshakeRejected,
                                "peer identity for '" + target_service + "' changed since it was last trusted");
            }
        }

        auto raw_t = transport::connect(entry->address);
        if (!raw_t) {
            throw EpxError(EpxError::Code::ConnectFailed, "could not connect to service: " + target_service);
        }
        std::shared_ptr<transport::Transport> t(raw_t.release());

        bool freshly_pinned = (policy == TrustPolicy::TrustOnFirstUse && !keystore::load_pinned_peer(target_service));

        auto trust_fn = [&](const PublicKey& claimed) {
            return is_client_side_trusted(policy, target_service, *entry, claimed);
        };
        // Bound the handshake so a host that accepts the connection but
        // never answers the HELLO can't hang this call forever. Cleared on
        // success — after that, per-call timeouts are the caller's business.
        t->set_recv_timeout(5000);
        auto hs = handshake::client_handshake(*t, identity, target_service, trust_fn);
        if (!hs) {
            t->close();
            throw EpxError(EpxError::Code::HandshakeRejected, "handshake failed or was rejected for: " + target_service);
        }
        t->set_recv_timeout(0);
        if (freshly_pinned) {
            keystore::pin_peer(target_service, hs->peer_identity);
        }
        if (int wt = stream_write_timeout_ms.load(); wt > 0) {
            t->set_send_timeout(wt); // backpressure phase 1 (see epx.hpp)
        }

        auto conn = std::make_shared<Connection>();
        conn->transport = t;
        conn->keys.rx = hs->keys.rx;
        conn->keys.tx = hs->keys.tx;
        conn->version = hs->version;
        {
            std::lock_guard<std::mutex> lock(rotation_mutex);
            conn->rotation = rotation_policy;
        }
        conn->reader_thread = std::thread([this, conn] { reader_loop(conn); });

        {
            std::lock_guard<std::mutex> lock(conns_mutex);
            conns[target_service] = conn;
        }
        return conn;
    }

    void close_connection(const std::string& target_service) {
        std::shared_ptr<Connection> conn;
        {
            std::lock_guard<std::mutex> lock(conns_mutex);
            auto it = conns.find(target_service);
            if (it == conns.end()) return;
            conn = it->second;
            conns.erase(it);
        }
        conn->alive.store(false);
        conn->transport->close();
        {
            std::lock_guard<std::mutex> lock(conn->pending_mutex);
            conn->pending_cv.notify_all();
        }
        {
            std::lock_guard<std::mutex> lock(conn->stream_mutex);
            conn->stream_cv.notify_all();
        }
        if (conn->reader_thread.joinable()) conn->reader_thread.join();
    }
};

Client::Client(Identity identity, TrustPolicy policy) : impl_(std::make_unique<Impl>()) {
    detail::ensure_sodium_init();
    impl_->identity = identity;
    impl_->policy = policy;
}

Client::~Client() {
    std::vector<std::string> targets;
    {
        std::lock_guard<std::mutex> lock(impl_->conns_mutex);
        for (auto& kv : impl_->conns) targets.push_back(kv.first);
    }
    for (auto& t : targets) impl_->close_connection(t);
}

void Client::allow_peer(const PublicKey& peer_public_key) {
    std::lock_guard<std::mutex> lock(impl_->allow_mutex);
    impl_->allowed_peers.insert(peer_public_key);
}

const PublicKey& Client::public_key() const { return impl_->identity.public_key; }

Bytes Client::get(const std::string& target_service, const std::string& endpoint, const Bytes& data,
                   std::chrono::milliseconds timeout) {
    auto conn = impl_->get_or_connect(target_service);

    uint64_t request_id = conn->next_request_id.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(conn->pending_mutex);
        conn->pending[request_id] = std::nullopt;
    }

    wire::RequestPayload req;
    req.request_id = request_id;
    req.oneway = false;
    req.endpoint = endpoint;
    req.data = data;

    bool sent = seal_and_send(*conn, FrameType::Request, wire::encode_request(req));
    if (!sent) {
        std::lock_guard<std::mutex> lock2(conn->pending_mutex);
        conn->pending.erase(request_id);
        throw EpxError(EpxError::Code::Transport, "failed to send request to: " + target_service);
    }

    std::unique_lock<std::mutex> lock(conn->pending_mutex);
    bool arrived = conn->pending_cv.wait_for(lock, timeout, [&] {
        return !conn->alive.load() || conn->pending[request_id].has_value();
    });

    if (!arrived) {
        conn->pending.erase(request_id);
        throw EpxError(EpxError::Code::Timeout, "request to '" + target_service + "/" + endpoint + "' timed out");
    }
    if (!conn->pending[request_id].has_value()) {
        conn->pending.erase(request_id);
        if (conn->death_reason.load() == wire::kErrRateLimited) {
            std::lock_guard<std::mutex> dl(conn->death_mutex);
            throw EpxError(EpxError::Code::RateLimited,
                            "disconnected by '" + target_service + "': " + conn->death_message);
        }
        throw EpxError(EpxError::Code::Transport, "connection to '" + target_service + "' closed before a response arrived");
    }

    wire::ResponsePayload resp = *conn->pending[request_id];
    conn->pending.erase(request_id);
    lock.unlock();

    if (resp.status == 2) {
        throw EpxError(EpxError::Code::NotFound, "endpoint not found: " + endpoint);
    }
    if (resp.status == 3) {
        throw EpxError(EpxError::Code::AccessDenied,
                        "access denied by '" + target_service + "' for endpoint '" + endpoint + "'");
    }
    if (resp.status == 1) {
        throw EpxError(EpxError::Code::Protocol, std::string(resp.data.begin(), resp.data.end()));
    }
    return resp.data;
}

void Client::send(const std::string& target_service, const std::string& endpoint, const Bytes& data) {
    auto conn = impl_->get_or_connect(target_service);

    wire::RequestPayload req;
    req.request_id = conn->next_request_id.fetch_add(1);
    req.oneway = true;
    req.endpoint = endpoint;
    req.data = data;

    bool ok = seal_and_send(*conn, FrameType::Request, wire::encode_request(req));
    if (!ok) {
        throw EpxError(EpxError::Code::Transport, "failed to send to: " + target_service);
    }
}

void Client::get_stream(const std::string& target_service, const std::string& endpoint, const Bytes& data,
                         const std::function<void(const Bytes&, bool)>& on_chunk,
                         std::chrono::milliseconds timeout) {
    auto conn = impl_->get_or_connect(target_service);

    uint64_t request_id = conn->next_request_id.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(conn->stream_mutex);
        StreamSink sink;
        sink.callback = on_chunk;
        conn->stream_sinks[request_id] = std::move(sink);
    }

    wire::RequestPayload req;
    req.request_id = request_id;
    req.oneway = false;
    req.endpoint = endpoint;
    req.data = data;

    bool sent = seal_and_send(*conn, FrameType::Request, wire::encode_request(req));
    if (!sent) {
        std::lock_guard<std::mutex> lock(conn->stream_mutex);
        conn->stream_sinks.erase(request_id);
        throw EpxError(EpxError::Code::Transport, "failed to send stream request to: " + target_service);
    }

    std::unique_lock<std::mutex> lock(conn->stream_mutex);
    for (;;) {
        uint64_t activity_before = 0;
        if (auto it0 = conn->stream_sinks.find(request_id); it0 != conn->stream_sinks.end()) {
            activity_before = it0->second.activity;
        }
        bool progressed = conn->stream_cv.wait_for(lock, timeout, [&] {
            auto it = conn->stream_sinks.find(request_id);
            return !conn->alive.load() || it == conn->stream_sinks.end() || it->second.done ||
                   it->second.activity != activity_before;
        });
        auto it = conn->stream_sinks.find(request_id);
        bool done = (it == conn->stream_sinks.end()) || it->second.done;
        bool dead = !conn->alive.load();

        if (!progressed && !done) {
            conn->stream_sinks.erase(request_id);
            throw EpxError(EpxError::Code::Timeout, "stream '" + target_service + "/" + endpoint + "' stalled (no chunk within timeout)");
        }
        if (it != conn->stream_sinks.end() && it->second.failed) {
            uint8_t status = it->second.fail_status;
            std::string msg = it->second.fail_message;
            conn->stream_sinks.erase(request_id);
            if (status == 2) throw EpxError(EpxError::Code::NotFound, "endpoint not found: " + endpoint);
            if (status == 3) throw EpxError(EpxError::Code::AccessDenied,
                                             "access denied by '" + target_service + "' for stream '" + endpoint + "'");
            throw EpxError(EpxError::Code::Protocol, msg.empty() ? "stream request failed" : msg);
        }
        if (done) {
            conn->stream_sinks.erase(request_id);
            return;
        }
        if (dead) {
            conn->stream_sinks.erase(request_id);
            if (conn->death_reason.load() == wire::kErrRateLimited) {
                std::lock_guard<std::mutex> dl(conn->death_mutex);
                throw EpxError(EpxError::Code::RateLimited,
                                "disconnected by '" + target_service + "': " + conn->death_message);
            }
            throw EpxError(EpxError::Code::Transport, "connection to '" + target_service + "' closed mid-stream");
        }
        // Otherwise: a chunk arrived but the stream isn't done yet — loop
        // and keep waiting, resetting the stall timer.
    }
}

struct Client::OutputStream::Impl {
    std::shared_ptr<Connection> conn;
    std::string target_service;
    std::string endpoint;
    uint64_t request_id = 0;
    uint32_t seq = 0;
    bool finished = false;
};

Client::OutputStream::OutputStream(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Client::OutputStream::OutputStream(OutputStream&&) noexcept = default;
Client::OutputStream& Client::OutputStream::operator=(OutputStream&&) noexcept = default;

Client::OutputStream::~OutputStream() {
    if (impl_) finish();
}

bool Client::OutputStream::write(const Bytes& chunk) {
    if (!impl_ || impl_->finished) return false;
    wire::StreamChunkPayload payload;
    payload.request_id = impl_->request_id;
    payload.seq = impl_->seq++;
    payload.is_last = false;
    payload.endpoint = impl_->endpoint;
    payload.data = chunk;
    return seal_and_send(*impl_->conn, FrameType::StreamChunk, wire::encode_stream_chunk(payload));
}

void Client::OutputStream::finish() {
    if (!impl_ || impl_->finished) return;
    impl_->finished = true;
    wire::StreamChunkPayload payload;
    payload.request_id = impl_->request_id;
    payload.seq = impl_->seq++;
    payload.is_last = true;
    payload.endpoint = impl_->endpoint;
    seal_and_send(*impl_->conn, FrameType::StreamChunk, wire::encode_stream_chunk(payload));
}

Client::OutputStream Client::open_stream(const std::string& target_service, const std::string& endpoint) {
    auto conn = impl_->get_or_connect(target_service);
    auto impl = std::make_unique<OutputStream::Impl>();
    impl->conn = conn;
    impl->target_service = target_service;
    impl->endpoint = endpoint;
    impl->request_id = conn->next_request_id.fetch_add(1);
    return OutputStream(std::move(impl));
}

void Client::set_stream_write_timeout(int ms) {
    impl_->stream_write_timeout_ms.store(ms);
}

void Client::enable_key_rotation(RotationPolicy policy) {
    std::lock_guard<std::mutex> lock(impl_->rotation_mutex);
    impl_->rotation_policy = policy;
}

int Client::session_epoch(const std::string& target_service) const {
    std::shared_ptr<Connection> conn;
    {
        std::lock_guard<std::mutex> lock(impl_->conns_mutex);
        auto it = impl_->conns.find(target_service);
        if (it == impl_->conns.end() || !it->second->alive.load()) return -1;
        conn = it->second;
    }
    std::lock_guard<std::mutex> lock(conn->write_mutex);
    return int(conn->epoch);
}

// ---- Topic subscriptions ------------------------------------------------

struct Client::Subscription::Impl {
    std::shared_ptr<Connection> conn;
    uint64_t request_id = 0;
    // Shared with the sink's callback wrapper, which flips it on the final
    // closed=true delivery (host shutdown, refusal, connection loss).
    std::shared_ptr<std::atomic<bool>> active;
};

Client::Subscription::Subscription() = default;
Client::Subscription::Subscription(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Client::Subscription::Subscription(Subscription&&) noexcept = default;
Client::Subscription& Client::Subscription::operator=(Subscription&&) noexcept = default;

Client::Subscription::~Subscription() {
    if (impl_) unsubscribe();
}

bool Client::Subscription::active() const {
    return impl_ && impl_->active->load();
}

void Client::Subscription::unsubscribe() {
    if (!impl_ || !impl_->active->exchange(false)) return;
    auto& conn = impl_->conn;
    {
        std::lock_guard<std::mutex> lock(conn->stream_mutex);
        conn->stream_sinks.erase(impl_->request_id);
    }
    if (conn->alive.load()) {
        // Tell the host to stop publishing to us; oneway — nothing to wait for.
        wire::RequestPayload req;
        req.request_id = conn->next_request_id.fetch_add(1);
        req.oneway = true;
        req.endpoint = "$epx/unsubscribe";
        wire::put_u64(req.data, impl_->request_id);
        seal_and_send(*conn, FrameType::Request, wire::encode_request(req));
    }
}

Client::Subscription Client::subscribe(const std::string& target_service,
                                        const std::string& topic,
                                        std::function<void(const Bytes&, bool)> on_message) {
    auto conn = impl_->get_or_connect(target_service);

    uint64_t request_id = conn->next_request_id.fetch_add(1);
    auto active = std::make_shared<std::atomic<bool>>(true);

    {
        std::lock_guard<std::mutex> lock(conn->stream_mutex);
        StreamSink sink;
        sink.subscription = true;
        sink.callback = [active, cb = std::move(on_message)](const Bytes& data, bool closed) {
            if (closed) active->store(false);
            if (cb) cb(data, closed);
        };
        conn->stream_sinks[request_id] = std::move(sink);
    }

    wire::RequestPayload req;
    req.request_id = request_id;
    req.oneway = false; // so a refusal (denied / unknown topic / limit) gets a RESPONSE back
    req.endpoint = topic;

    if (!seal_and_send(*conn, FrameType::Request, wire::encode_request(req))) {
        {
            std::lock_guard<std::mutex> lock(conn->stream_mutex);
            conn->stream_sinks.erase(request_id);
        }
        throw EpxError(EpxError::Code::Transport, "failed to send subscribe to: " + target_service);
    }

    auto impl = std::make_unique<Subscription::Impl>();
    impl->conn = conn;
    impl->request_id = request_id;
    impl->active = active;
    return Subscription(std::move(impl));
}

void Client::disconnect(const std::string& target_service) {
    impl_->close_connection(target_service);
}

} // namespace epx
