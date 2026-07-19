#include "epx/epx.hpp"
#include "init.hpp"
#include "transport.hpp"
#include "framing.hpp"
#include "handshake.hpp"
#include "protocol.hpp"
#include "registry.hpp"
#include "keystore.hpp"
#include "credentials.hpp"
#include "paths.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <set>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace epx {

namespace {
long current_pid() {
#if defined(_WIN32)
    return long(_getpid());
#else
    return long(getpid());
#endif
}

std::string kind_to_string(EndpointKind k) {
    switch (k) {
        case EndpointKind::Receive:       return "receive";
        case EndpointKind::Send:          return "send";
        case EndpointKind::StreamReceive: return "stream_receive";
        case EndpointKind::StreamSend:    return "stream_send";
        case EndpointKind::Topic:         return "topic";
    }
    return "unknown";
}

// Endpoint names beginning with this prefix belong to the protocol itself
// (currently: "$epx/unsubscribe") and can't be exposed by applications.
constexpr const char* kReservedPrefix = "$epx/";
constexpr const char* kUnsubscribeEndpoint = "$epx/unsubscribe";

void check_endpoint_name(const std::string& endpoint) {
    if (endpoint.rfind(kReservedPrefix, 0) == 0) {
        throw std::invalid_argument("endpoint names starting with \"" + std::string(kReservedPrefix) +
                                     "\" are reserved by EPX: " + endpoint);
    }
}

// How often topic subscribers are heartbeat-pinged so a silently vanished
// peer is noticed within this interval rather than at the next publish
// (see docs/SPEC.md section 8, Topic).
constexpr auto kTopicHeartbeatInterval = std::chrono::seconds(3);

// How long a freshly-accepted connection gets to complete the handshake
// before its thread gives up (see Impl::handle_connection).
constexpr int kHandshakeTimeoutMs = 5000;

// Classic token bucket. Not thread-safe by itself; callers hold their own
// lock (the per-UID map mutex) or confine it to one thread (per-connection
// request bucket).
struct TokenBucket {
    double tokens = 0;
    double rate = 0;   // tokens per second
    double burst = 0;
    std::chrono::steady_clock::time_point last = std::chrono::steady_clock::now();

    void refill() {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - last).count();
        last = now;
        tokens = std::min(burst, tokens + elapsed * rate);
    }
    bool try_take() {
        refill();
        if (tokens >= 1.0) { tokens -= 1.0; return true; }
        return false;
    }
    // Seconds until one token will be available (0 if one already is).
    double seconds_until_token() {
        refill();
        if (tokens >= 1.0) return 0.0;
        return (1.0 - tokens) / rate;
    }
};

// Fixed-size, signal-safe registry backing Host::stop_on_signals(). Every
// element has static storage duration, so it's zero-initialized (all
// nullptr) before any constructor runs — no runtime initialization race.
// Only ever touched via relaxed atomic load/compare_exchange, so the
// signal trampoline below does no locking, allocation, or anything else
// that isn't async-signal-safe.
constexpr size_t kMaxSignalHosts = 8;
std::atomic<Host*> g_signal_hosts[kMaxSignalHosts] = {};

void register_signal_host(Host* h) {
    for (auto& slot : g_signal_hosts) {
        Host* expected = nullptr;
        if (slot.compare_exchange_strong(expected, h)) return;
    }
    // Table full: silently skip rather than allocating a growable
    // container that might later need to be touched from signal context.
}

void unregister_signal_host(Host* h) {
    for (auto& slot : g_signal_hosts) {
        Host* expected = h;
        slot.compare_exchange_strong(expected, nullptr);
    }
}

extern "C" void epx_signal_trampoline(int /*sig*/) {
    for (auto& slot : g_signal_hosts) {
        Host* h = slot.load(std::memory_order_relaxed);
        if (h) h->request_stop();
    }
}
} // namespace

using wire::FrameType;

// Shareable per-connection send state. The connection's own thread reads
// frames; *any* thread that can reach this object (topic publishers, the
// heartbeat thread, the connection thread's replies) may send on it — all
// sends serialize on tx_mutex, which also keeps the AEAD counter and the
// multi-syscall frame write atomic per frame.
struct ConnState {
    std::shared_ptr<transport::Transport> t;
    std::array<uint8_t, 32> tx_key{};
    bool v2 = false;
    uint8_t epoch = 0;
    std::mutex tx_mutex;
    uint64_t tx_counter = 0;
    std::atomic<bool> alive{true};

    ~ConnState() { crypto::wipe(tx_key.data(), tx_key.size()); }

    bool send_sealed(FrameType type, const std::vector<uint8_t>& plaintext) {
        std::lock_guard<std::mutex> lock(tx_mutex);
        if (!alive.load()) return false;
        auto ct = v2 ? crypto::seal_v2(tx_key, tx_counter, epoch, uint8_t(type), plaintext)
                     : crypto::seal(tx_key, tx_counter, uint8_t(type), plaintext);
        bool ok = framing::write_frame(*t, framing::RawFrame{type, tx_counter, epoch, ct}, v2);
        tx_counter++;
        if (!ok) alive.store(false);
        return ok;
    }

    bool send_chunk(uint64_t request_id, uint32_t seq, bool is_last, const Bytes& data) {
        wire::StreamChunkPayload chunk;
        chunk.request_id = request_id;
        chunk.seq = seq;
        chunk.is_last = is_last;
        chunk.data = data;
        return send_sealed(FrameType::StreamChunk, wire::encode_stream_chunk(chunk));
    }

    // Cleartext liveness probe (no AEAD counter consumed). Its only job is
    // making a dead socket fail a write *now* instead of at the next
    // publish.
    bool send_ping() {
        std::lock_guard<std::mutex> lock(tx_mutex);
        if (!alive.load()) return false;
        bool ok = framing::write_frame(*t, framing::RawFrame{FrameType::Ping, 0, 0, {}}, v2);
        if (!ok) alive.store(false);
        return ok;
    }

    // Key rotation (8c), server side: send the REKEY_ACK under the
    // *current* epoch, then atomically (same tx_mutex hold) switch tx to
    // the new key/epoch — so on the ordered byte stream, everything after
    // the ack is provably next-epoch and nothing before it is.
    bool send_rekey_ack_and_switch(const std::array<uint8_t, 32>& eph_pk,
                                   const std::array<uint8_t, 32>& new_tx_key) {
        std::lock_guard<std::mutex> lock(tx_mutex);
        if (!alive.load()) return false;
        std::vector<uint8_t> body(eph_pk.begin(), eph_pk.end());
        auto ct = crypto::seal_v2(tx_key, tx_counter, epoch, uint8_t(FrameType::RekeyAck), body);
        bool ok = framing::write_frame(*t, framing::RawFrame{FrameType::RekeyAck, tx_counter, epoch, ct}, true);
        if (!ok) { alive.store(false); return false; }
        crypto::wipe(tx_key.data(), tx_key.size());
        tx_key = new_tx_key;
        epoch++;
        tx_counter = 0;
        return true;
    }
};

// One registered endpoint: a kind tag plus whichever handler variant
// matches it (the other two are left empty/default-constructed), plus the
// endpoint's AccessPolicy (nullopt = use the Host-wide default).
struct EndpointEntry {
    EndpointKind kind = EndpointKind::Receive;
    Handler unary;
    StreamReceiveHandler stream_recv;
    StreamSendHandler stream_send;
    std::optional<AccessPolicy> access;
};

// The library-owned broadcaster behind one Topic endpoint (roadmap item
// 5): subscriber registration, per-subscriber delivery, pruning on failed
// writes. Lock order note: publish/heartbeat take `mu` then a sub's
// ConnState::tx_mutex; nothing ever takes them in the other order.
struct TopicHandle::Impl {
    struct Sub {
        std::shared_ptr<ConnState> cs;
        uint64_t request_id = 0; // correlates chunks to the client's subscribe call
        uint32_t seq = 0;
    };
    std::mutex mu;
    std::vector<Sub> subs;

    size_t publish(const Bytes& message) {
        std::lock_guard<std::mutex> lock(mu);
        size_t delivered = 0;
        for (auto it = subs.begin(); it != subs.end();) {
            if (it->cs->alive.load() && it->cs->send_chunk(it->request_id, it->seq++, false, message)) {
                delivered++;
                ++it;
            } else {
                it = subs.erase(it); // dead peer: prune on failed write
            }
        }
        return delivered;
    }

    size_t count() {
        std::lock_guard<std::mutex> lock(mu);
        return subs.size();
    }

    void add(std::shared_ptr<ConnState> cs, uint64_t request_id) {
        std::lock_guard<std::mutex> lock(mu);
        subs.push_back(Sub{std::move(cs), request_id, 0});
    }

    void remove(const std::shared_ptr<ConnState>& cs, uint64_t request_id) {
        std::lock_guard<std::mutex> lock(mu);
        for (auto it = subs.begin(); it != subs.end(); ++it) {
            if (it->cs == cs && it->request_id == request_id) { subs.erase(it); return; }
        }
    }

    void remove_conn(const std::shared_ptr<ConnState>& cs) {
        std::lock_guard<std::mutex> lock(mu);
        for (auto it = subs.begin(); it != subs.end();) {
            if (it->cs == cs) it = subs.erase(it); else ++it;
        }
    }

    // Tells every subscriber the feed is over (final is_last chunk) and
    // forgets them. Called from Host::stop() before connections close, so
    // clients see a clean closed=true instead of a dropped socket.
    void close_all() {
        std::lock_guard<std::mutex> lock(mu);
        for (auto& s : subs) {
            s.cs->send_chunk(s.request_id, s.seq++, true, {});
        }
        subs.clear();
    }

    void heartbeat() {
        std::lock_guard<std::mutex> lock(mu);
        for (auto it = subs.begin(); it != subs.end();) {
            if (it->cs->send_ping()) ++it; else it = subs.erase(it);
        }
    }
};

size_t TopicHandle::publish(const Bytes& message) const { return impl_ ? impl_->publish(message) : 0; }
size_t TopicHandle::subscriber_count() const { return impl_ ? impl_->count() : 0; }

struct Host::Impl {
    std::string service_name;
    std::string description; // published in the registry self-description
    Identity identity;
    TrustPolicy policy;

    std::mutex handlers_mutex;
    std::unordered_map<std::string, EndpointEntry> handlers;

    std::mutex allow_mutex;
    std::set<PublicKey> allowed_peers;

    // ---- authorization state (AccessTier, item 8a) --------------------
    AccessPolicy default_access;              // Host-wide default: Open
    AuthorizationPrompt prompt;               // PromptUser callback (may be empty)
    std::mutex authz_mutex;                   // guards prompt + issuers + creds
    std::set<PublicKey> issuers;
    std::vector<credentials::Credential> creds;

    // ---- rate limiting (item 7) ---------------------------------------
    ConnectionLimits limits;
    std::mutex uid_buckets_mutex;
    std::unordered_map<long, TokenBucket> uid_buckets; // pre-handshake attempt caps

    // ---- topics (item 5) ----------------------------------------------
    std::mutex topics_mutex;
    std::unordered_map<std::string, std::shared_ptr<TopicHandle::Impl>> topics;
    std::thread heartbeat_thread;

    std::shared_ptr<TopicHandle::Impl> find_topic(const std::string& name) {
        std::lock_guard<std::mutex> lock(topics_mutex);
        auto it = topics.find(name);
        return it == topics.end() ? nullptr : it->second;
    }

    void heartbeat_loop() {
        auto last_beat = std::chrono::steady_clock::now();
        while (running.load()) {
            // Short sleep steps so stop() isn't delayed by a full interval.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto now = std::chrono::steady_clock::now();
            if (now - last_beat < kTopicHeartbeatInterval) continue;
            last_beat = now;
            std::vector<std::shared_ptr<TopicHandle::Impl>> snapshot;
            {
                std::lock_guard<std::mutex> lock(topics_mutex);
                for (auto& kv : topics) snapshot.push_back(kv.second);
            }
            for (auto& topic : snapshot) topic->heartbeat();
        }
    }

    // True if this connection attempt is within the pre-handshake budget
    // for its UID. Called before any handshake crypto runs.
    bool admit_connection(long uid) {
        if (limits.handshakes_per_uid_per_sec == 0) return true;
        std::lock_guard<std::mutex> lock(uid_buckets_mutex);
        auto& b = uid_buckets[uid];
        if (b.rate == 0) { // freshly created
            b.rate = limits.handshakes_per_uid_per_sec;
            b.burst = limits.handshake_burst > 0 ? limits.handshake_burst : 1;
            b.tokens = b.burst;
        }
        return b.try_take();
    }

    std::unique_ptr<transport::Listener> listener;
    std::thread accept_thread;

    std::mutex conns_mutex;
    std::vector<std::shared_ptr<transport::Transport>> live_conns;
    std::vector<std::thread> conn_threads;

    std::atomic<bool> running{false};
    std::atomic<bool> stop_requested{false};

    std::mutex hooks_mutex;
    std::vector<std::function<void()>> before_stop_hooks;
    std::vector<std::function<void()>> after_stop_hooks;

    bool is_trusted(const PublicKey& client_pk, bool* pinned_now) {
        {
            std::lock_guard<std::mutex> lock(allow_mutex);
            if (allowed_peers.count(client_pk)) return true;
        }
        switch (policy) {
            case TrustPolicy::AllowAll:
                return true;
            case TrustPolicy::RequireKnownPeer:
                return false; // not in the explicit allow-list checked above
            case TrustPolicy::TrustOnFirstUse:
                // Accept-and-record: every previously-unseen client key is
                // remembered and accepted (see the TrustPolicy docs in
                // epx.hpp for why host-side "TOFU" cannot reject-by-default
                // the way the client side does). PeerInfo::key_was_pinned_now
                // tells the handler when this connection did the recording.
                if (keystore::is_known_client(service_name, client_pk)) return true;
                keystore::remember_client(service_name, client_pk);
                if (pinned_now) *pinned_now = true;
                return true;
        }
        return false;
    }

    // Is `peer` allowed to call `endpoint` under `policy`? `conn_cache`
    // remembers this connection's earlier answers, both to avoid re-checking
    // per request and to give PromptDecision::AllowOnce its "this
    // connection only" scope.
    bool authorize(const PeerInfo& peer, const std::string& endpoint, const AccessPolicy& policy,
                   std::unordered_map<std::string, bool>& conn_cache) {
        auto cached = conn_cache.find(endpoint);
        if (cached != conn_cache.end()) return cached->second;

        bool allowed = false;
        switch (policy.tier) {
            case AccessTier::Open:
                allowed = true;
                break;
            case AccessTier::PinnedPeers: {
                {
                    std::lock_guard<std::mutex> lock(allow_mutex);
                    allowed = allowed_peers.count(peer.public_key) > 0;
                }
                if (!allowed) allowed = keystore::is_known_client(service_name, peer.public_key);
                break;
            }
            case AccessTier::Certificate: {
                uint64_t now = uint64_t(std::time(nullptr));
                std::lock_guard<std::mutex> lock(authz_mutex);
                for (const auto& c : creds) {
                    if (issuers.count(c.issuer) &&
                        credentials::covers(c, peer.public_key, service_name, endpoint, now)) {
                        allowed = true;
                        break;
                    }
                }
                break;
            }
            case AccessTier::PromptUser: {
                auto persisted = keystore::load_authz_decision(service_name, peer.public_key, endpoint);
                if (persisted) {
                    allowed = *persisted;
                    break;
                }
                AuthorizationPrompt cb;
                {
                    std::lock_guard<std::mutex> lock(authz_mutex);
                    cb = prompt;
                }
                if (!cb) { allowed = false; break; } // no way to ask -> deny
                PromptDecision d = cb(peer, endpoint, policy.prompt_reason);
                allowed = (d != PromptDecision::Deny);
                if (d == PromptDecision::AlwaysAllow || d == PromptDecision::Deny) {
                    keystore::save_authz_decision(service_name, peer.public_key, endpoint, allowed);
                }
                break;
            }
        }
        conn_cache[endpoint] = allowed;
        return allowed;
    }

    void load_credentials_from_disk() {
        namespace fs = std::filesystem;
        std::string dir = paths::config_dir() + "/credentials/" + service_name;
        std::error_code ec;
        for (const auto& de : fs::directory_iterator(dir, ec)) {
            if (ec) break;
            if (de.path().extension() != ".cred") continue;
            std::ifstream in(de.path());
            std::stringstream ss;
            ss << in.rdbuf();
            auto c = credentials::parse(ss.str());
            if (c && credentials::signature_valid(*c)) {
                std::lock_guard<std::mutex> lock(authz_mutex);
                creds.push_back(*c);
            }
        }
    }

    void handle_connection(std::shared_ptr<transport::Transport> t) {
        // Pre-handshake per-UID cap: the handshake below does real crypto
        // work per attempt, so a flood is refused before any of it runs.
        if (!admit_connection(t->peer_uid())) {
            t->close();
            return;
        }

        // Bound the handshake: a peer that connects and then goes silent
        // must not pin down this thread forever (cheap DoS otherwise, since
        // the Host is thread-per-connection). Cleared on success below.
        t->set_recv_timeout(kHandshakeTimeoutMs);
        bool pinned_now = false;
        auto trust_fn = [this, &pinned_now](const PublicKey& pk) { return is_trusted(pk, &pinned_now); };
        auto hs = handshake::server_handshake(*t, identity, service_name, trust_fn);
        if (!hs) { t->close(); return; }
        t->set_recv_timeout(0);
        if (limits.stream_write_timeout_ms > 0) {
            // Backpressure phase 1: a peer not draining its socket makes
            // writes fail after this long instead of blocking the handler
            // forever; surfaces as false from StreamWriter::write().
            t->set_send_timeout(limits.stream_write_timeout_ms);
        }

        // Negotiated session version decides the frame layout (v2 adds the
        // key-epoch byte) and which AEAD associated-data shape to use.
        const bool v2 = hs->version >= 2;

        // Sends go through a shared ConnState so topic publishers and the
        // heartbeat thread can write to this connection too (all serialized
        // on its tx_mutex). Receives stay exclusive to this thread.
        auto cs = std::make_shared<ConnState>();
        cs->t = t;
        cs->tx_key = hs->keys.tx;
        cs->v2 = v2;

        PeerInfo peer_info;
        peer_info.public_key = hs->peer_identity;
        peer_info.peer_uid = t->peer_uid();
        peer_info.key_was_pinned_now = pinned_now;

        std::unordered_map<std::string, bool> authz_cache; // per-connection decisions

        // Topics this connection subscribed to, so they can be detached on
        // any exit path (the shutdown correctness groupchat v1 had to
        // hand-roll — now library-owned).
        std::vector<std::pair<std::shared_ptr<TopicHandle::Impl>, uint64_t>> my_subs;

        // Post-handshake request rate limiting (item 7): confined to this
        // thread, so the bucket needs no lock.
        TokenBucket req_bucket;
        uint32_t delayed_in_a_row = 0;
        if (limits.max_requests_per_sec > 0) {
            req_bucket.rate = limits.max_requests_per_sec;
            req_bucket.burst = limits.request_burst > 0 ? limits.request_burst : 1;
            req_bucket.tokens = req_bucket.burst;
        }

        // Receive-side key state (this thread only); see the client's
        // reader_loop for the mirror-image of the epoch transition logic.
        std::array<uint8_t, 32> rx_key = hs->keys.rx;
        uint8_t rx_epoch = 0;
        uint64_t rx_counter = 0;
        std::optional<std::array<uint8_t, 32>> rx_pending;

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
                if (f.counter != 0) return std::nullopt;
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

        auto send_stream_chunk = [&](uint64_t request_id, uint32_t seq, bool is_last, const Bytes& data) -> bool {
            return cs->send_chunk(request_id, seq, is_last, data);
        };

        while (running.load()) {
            auto frame = framing::read_frame(*t, v2);
            if (!frame) break;

            if (frame->type == FrameType::Ping) {
                std::lock_guard<std::mutex> lock(cs->tx_mutex);
                framing::write_frame(*t, framing::RawFrame{FrameType::Pong, 0, 0, {}}, v2);
                continue;
            }
            if (frame->type == FrameType::Pong) continue;
            if (frame->type == FrameType::Bye) break;

            if (frame->type == FrameType::Rekey) {
                // Client-initiated key rotation (8c). Hosts at protocol v2
                // always support inbound rotation; the *initiation* opt-in
                // lives client-side.
                if (!v2) break; // invalid in a v1 session
                auto opened = open_checked(*frame);
                if (!opened || opened->size() != 32) break;
                if (cs->epoch >= 255) break; // epoch space exhausted; force a fresh connection
                std::array<uint8_t, 32> client_eph{};
                std::memcpy(client_eph.data(), opened->data(), 32);
                auto eph = crypto::generate_ephemeral();
                auto nk = crypto::server_session_keys(eph, client_eph);
                if (!cs->send_rekey_ack_and_switch(eph.public_key, nk.tx)) break;
                rx_pending = nk.rx;
                continue;
            }

            if (frame->type == FrameType::StreamChunk) {
                auto opened = open_checked(*frame);
                if (!opened) break;

                wire::StreamChunkPayload chunk;
                if (!wire::decode_stream_chunk(*opened, chunk)) break;

                StreamReceiveHandler handler;
                AccessPolicy access = default_access;
                {
                    std::lock_guard<std::mutex> lock(handlers_mutex);
                    auto it = handlers.find(chunk.endpoint);
                    if (it != handlers.end() && it->second.kind == EndpointKind::StreamReceive) {
                        handler = it->second.stream_recv;
                        if (it->second.access) access = *it->second.access;
                    }
                }
                // Denied inbound chunks are dropped, not answered — a
                // StreamReceive endpoint has no response channel (same
                // fire-and-forget contract as Send).
                if (handler && authorize(peer_info, chunk.endpoint, access, authz_cache)) {
                    handler(chunk.data, chunk.is_last, chunk.endpoint, peer_info);
                }
                continue;
            }

            if (frame->type != FrameType::Request) continue;
            auto opened = open_checked(*frame); // counter/epoch check + AEAD open; nullopt = drop conn
            if (!opened) break;

            wire::RequestPayload req;
            if (!wire::decode_request(*opened, req)) break;

            // Rate limit: delay first (wait for the next token), disconnect
            // with a stated reason only if the peer stays saturated.
            if (limits.max_requests_per_sec > 0) {
                if (req_bucket.try_take()) {
                    delayed_in_a_row = 0;
                } else {
                    delayed_in_a_row++;
                    if (delayed_in_a_row > limits.disconnect_after_delayed) {
                        wire::ErrorPayload err;
                        err.reason = wire::kErrRateLimited;
                        err.message = "request rate limit exceeded (" +
                                      std::to_string(limits.max_requests_per_sec) + "/s)";
                        cs->send_sealed(FrameType::Error, wire::encode_error(err));
                        break; // close below — the peer was told why
                    }
                    double wait_s = req_bucket.seconds_until_token();
                    if (wait_s > 0) {
                        std::this_thread::sleep_for(std::chrono::duration<double>(wait_s));
                    }
                    req_bucket.try_take(); // consume the token we waited for
                }
            }

            EndpointEntry entry;
            bool found = false;
            {
                std::lock_guard<std::mutex> lock(handlers_mutex);
                auto it = handlers.find(req.endpoint);
                if (it != handlers.end()) { entry = it->second; found = true; }
            }

            auto reply = [&](uint8_t status, const Bytes& data) {
                if (req.oneway) return;
                wire::ResponsePayload resp;
                resp.request_id = req.request_id;
                resp.status = status;
                resp.data = data;
                cs->send_sealed(FrameType::Response, wire::encode_response(resp));
            };

            // Protocol-internal endpoint: drop a topic subscription this
            // connection made earlier (payload = the subscribe request_id).
            if (req.endpoint == kUnsubscribeEndpoint) {
                if (req.data.size() == 8) {
                    uint64_t sub_id = wire::get_u64(req.data.data());
                    for (auto it = my_subs.begin(); it != my_subs.end(); ++it) {
                        if (it->second == sub_id) {
                            it->first->remove(cs, sub_id);
                            my_subs.erase(it);
                            break;
                        }
                    }
                }
                continue;
            }

            if (!found) {
                reply(2, {}); // not_found
                continue;
            }

            {
                AccessPolicy access = entry.access ? *entry.access : default_access;
                if (!authorize(peer_info, req.endpoint, access, authz_cache)) {
                    static const char* denied = "access denied";
                    reply(3, Bytes(denied, denied + 13));
                    continue;
                }
            }

            if (entry.kind == EndpointKind::Topic) {
                if (limits.max_subscriptions > 0 && my_subs.size() >= limits.max_subscriptions) {
                    static const char* msg = "subscription limit exceeded";
                    reply(1, Bytes(msg, msg + 27));
                    continue;
                }
                if (auto topic = find_topic(req.endpoint)) {
                    topic->add(cs, req.request_id);
                    my_subs.emplace_back(topic, req.request_id);
                    // No response frame: the subscription's chunks (and its
                    // final is_last) correlate via the request_id.
                }
                continue;
            }

            switch (entry.kind) {
                case EndpointKind::Receive:
                case EndpointKind::Send: {
                    Response app_resp = entry.unary(req.data, req.endpoint, peer_info);
                    if (app_resp.ok) {
                        reply(0, app_resp.data);
                    } else {
                        reply(1, Bytes(app_resp.error.begin(), app_resp.error.end()));
                    }
                    break;
                }
                case EndpointKind::StreamSend: {
                    uint32_t seq = 0;
                    StreamWriter writer([&](const Bytes& chunk) -> bool {
                        return send_stream_chunk(req.request_id, seq++, false, chunk);
                    });
                    entry.stream_send(writer, req.data, req.endpoint, peer_info);
                    send_stream_chunk(req.request_id, seq++, true, {}); // end-of-stream marker (best effort)
                    break;
                }
                case EndpointKind::StreamReceive: {
                    // A plain Request on a StreamReceive endpoint is a
                    // protocol/usage error — the caller should be using
                    // Client::open_stream (which sends StreamChunk frames,
                    // handled above), not Client::get/send.
                    reply(1, Bytes{'w','r','o','n','g',' ','c','a','l','l',' ','s','h','a','p','e'});
                    break;
                }
                case EndpointKind::Topic:
                    break; // handled before this switch
            }
        }
        // Detach this connection from every topic before the transport
        // goes away, so publishers stop attempting writes to it.
        cs->alive.store(false);
        for (auto& sub : my_subs) sub.first->remove_conn(cs);
        t->close();
    }

    void accept_loop() {
        while (running.load()) {
            auto t = listener->accept();
            if (!t) break;
            if (!running.load()) { t->close(); break; } // woken by stop()'s close(); nothing to serve
            std::shared_ptr<transport::Transport> shared_t(t.release());
            {
                std::lock_guard<std::mutex> lock(conns_mutex);
                live_conns.push_back(shared_t);
            }
            conn_threads.emplace_back([this, shared_t] { handle_connection(shared_t); });
        }
    }

    void publish_registry(const std::string& address) {
        registry::Entry entry;
        entry.service_name = service_name;
        entry.address = address;
        entry.identity_pubkey = identity.public_key;
        entry.pid = current_pid();
        entry.description = description;
        {
            std::lock_guard<std::mutex> lock(handlers_mutex);
            for (auto& kv : handlers) {
                entry.endpoints.push_back(kv.first + ":" + kind_to_string(kv.second.kind));
            }
        }
        registry::publish(entry);
    }
};

Host::Host(std::string service_name, Identity identity, TrustPolicy policy)
    : impl_(std::make_unique<Impl>()) {
    detail::ensure_sodium_init();
    impl_->service_name = std::move(service_name);
    impl_->identity = identity;
    impl_->policy = policy;
}

Host::~Host() {
    unregister_signal_host(this); // must happen before impl_ is torn down below
    stop();
}

void Host::expose(EndpointKind kind, const std::string& endpoint, Handler handler) {
    expose(kind, endpoint, std::move(handler), AccessPolicy{});
    // The no-policy overloads mark the entry as "use the Host default";
    // undo the explicit policy the call above just set.
    std::lock_guard<std::mutex> lock(impl_->handlers_mutex);
    impl_->handlers[endpoint].access.reset();
}

void Host::expose(EndpointKind kind, const std::string& endpoint, Handler handler, AccessPolicy access) {
    check_endpoint_name(endpoint);
    if (kind != EndpointKind::Receive && kind != EndpointKind::Send) {
        throw std::invalid_argument("expose(kind, ...) with a Handler requires EndpointKind::Receive or Send; "
                                     "use expose_stream_receive/expose_stream_send for the streaming kinds");
    }
    EndpointEntry entry;
    entry.kind = kind;
    entry.unary = std::move(handler);
    entry.access = std::move(access);
    std::lock_guard<std::mutex> lock(impl_->handlers_mutex);
    impl_->handlers[endpoint] = std::move(entry);
}

void Host::expose(const std::string& endpoint, Handler handler) {
    expose(EndpointKind::Receive, endpoint, std::move(handler));
}

void Host::expose(const std::string& endpoint, Handler handler, AccessPolicy access) {
    expose(EndpointKind::Receive, endpoint, std::move(handler), std::move(access));
}

void Host::expose_stream_receive(const std::string& endpoint, StreamReceiveHandler handler) {
    expose_stream_receive(endpoint, std::move(handler), AccessPolicy{});
    std::lock_guard<std::mutex> lock(impl_->handlers_mutex);
    impl_->handlers[endpoint].access.reset();
}

void Host::expose_stream_receive(const std::string& endpoint, StreamReceiveHandler handler, AccessPolicy access) {
    check_endpoint_name(endpoint);
    EndpointEntry entry;
    entry.kind = EndpointKind::StreamReceive;
    entry.stream_recv = std::move(handler);
    entry.access = std::move(access);
    std::lock_guard<std::mutex> lock(impl_->handlers_mutex);
    impl_->handlers[endpoint] = std::move(entry);
}

void Host::expose_stream_send(const std::string& endpoint, StreamSendHandler handler) {
    expose_stream_send(endpoint, std::move(handler), AccessPolicy{});
    std::lock_guard<std::mutex> lock(impl_->handlers_mutex);
    impl_->handlers[endpoint].access.reset();
}

void Host::expose_stream_send(const std::string& endpoint, StreamSendHandler handler, AccessPolicy access) {
    check_endpoint_name(endpoint);
    EndpointEntry entry;
    entry.kind = EndpointKind::StreamSend;
    entry.stream_send = std::move(handler);
    entry.access = std::move(access);
    std::lock_guard<std::mutex> lock(impl_->handlers_mutex);
    impl_->handlers[endpoint] = std::move(entry);
}

TopicHandle Host::expose_topic(const std::string& topic) {
    auto h = expose_topic(topic, AccessPolicy{});
    std::lock_guard<std::mutex> lock(impl_->handlers_mutex);
    impl_->handlers[topic].access.reset();
    return h;
}

TopicHandle Host::expose_topic(const std::string& topic, AccessPolicy access) {
    check_endpoint_name(topic);
    auto impl = std::make_shared<TopicHandle::Impl>();
    {
        std::lock_guard<std::mutex> lock(impl_->topics_mutex);
        impl_->topics[topic] = impl;
    }
    EndpointEntry entry;
    entry.kind = EndpointKind::Topic;
    entry.access = std::move(access);
    {
        std::lock_guard<std::mutex> lock(impl_->handlers_mutex);
        impl_->handlers[topic] = std::move(entry);
    }
    return TopicHandle(impl);
}

void Host::set_default_access(AccessPolicy access) {
    impl_->default_access = std::move(access);
}

void Host::set_limits(ConnectionLimits limits) {
    impl_->limits = limits;
}

void Host::set_description(std::string description) {
    impl_->description = std::move(description);
}

void Host::on_authorization_prompt(AuthorizationPrompt prompt) {
    std::lock_guard<std::mutex> lock(impl_->authz_mutex);
    impl_->prompt = std::move(prompt);
}

void Host::add_issuer(const PublicKey& issuer_public_key) {
    std::lock_guard<std::mutex> lock(impl_->authz_mutex);
    impl_->issuers.insert(issuer_public_key);
}

bool Host::add_credential(const std::string& credential_text) {
    auto c = credentials::parse(credential_text);
    if (!c || !credentials::signature_valid(*c)) return false;
    std::lock_guard<std::mutex> lock(impl_->authz_mutex);
    impl_->creds.push_back(*c);
    return true;
}

void Host::allow_peer(const PublicKey& peer_public_key) {
    std::lock_guard<std::mutex> lock(impl_->allow_mutex);
    impl_->allowed_peers.insert(peer_public_key);
}

const PublicKey& Host::public_key() const { return impl_->identity.public_key; }

void Host::run() {
    if (impl_->running.exchange(true)) return; // already running
    impl_->load_credentials_from_disk();
    std::string address = transport::default_address_for_service(impl_->service_name);
    impl_->listener = transport::listen(address); // throws synchronously on bind/listen failure
    impl_->publish_registry(address);
    impl_->accept_thread = std::thread([this] { impl_->accept_loop(); });
    bool have_topics;
    {
        std::lock_guard<std::mutex> lock(impl_->topics_mutex);
        have_topics = !impl_->topics.empty();
    }
    if (have_topics) {
        impl_->heartbeat_thread = std::thread([this] { impl_->heartbeat_loop(); });
    }
}

void Host::run_async() { run(); }

void Host::before_stop(std::function<void()> hook) {
    std::lock_guard<std::mutex> lock(impl_->hooks_mutex);
    impl_->before_stop_hooks.push_back(std::move(hook));
}

void Host::after_stop(std::function<void()> hook) {
    std::lock_guard<std::mutex> lock(impl_->hooks_mutex);
    impl_->after_stop_hooks.push_back(std::move(hook));
}

void Host::request_stop() noexcept {
    impl_->stop_requested.store(true, std::memory_order_relaxed);
}

bool Host::stopped() const noexcept {
    return !impl_->running.load();
}

void Host::stop() {
    if (!impl_->running.exchange(false)) return; // already stopped (or never started)

    // Run before_stop hooks first: this is the application's chance to
    // decide how in-flight work is handled (drain, cancel, ignore) before
    // anything is forcibly closed below.
    {
        std::vector<std::function<void()>> hooks;
        {
            std::lock_guard<std::mutex> lock(impl_->hooks_mutex);
            hooks = impl_->before_stop_hooks;
        }
        for (auto& h : hooks) if (h) h();
    }

    // Tell every topic subscriber the feed is over (clean is_last chunk)
    // while the connections are still up, then tear down.
    {
        std::vector<std::shared_ptr<TopicHandle::Impl>> snapshot;
        {
            std::lock_guard<std::mutex> lock(impl_->topics_mutex);
            for (auto& kv : impl_->topics) snapshot.push_back(kv.second);
        }
        for (auto& topic : snapshot) topic->close_all();
    }
    if (impl_->heartbeat_thread.joinable()) impl_->heartbeat_thread.join();

    if (impl_->listener) impl_->listener->close();
    {
        std::lock_guard<std::mutex> lock(impl_->conns_mutex);
        for (auto& c : impl_->live_conns) c->close();
    }
    if (impl_->accept_thread.joinable()) impl_->accept_thread.join();
    for (auto& th : impl_->conn_threads) if (th.joinable()) th.join();
    registry::unpublish(impl_->service_name);

    {
        std::vector<std::function<void()>> hooks;
        {
            std::lock_guard<std::mutex> lock(impl_->hooks_mutex);
            hooks = impl_->after_stop_hooks;
        }
        for (auto& h : hooks) if (h) h();
    }
}

void Host::wait_until_stopped() {
    while (impl_->running.load() && !impl_->stop_requested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    stop(); // no-op if something else already fully stopped this Host
}

void Host::stop_on_signals(std::initializer_list<int> signals) {
    register_signal_host(this);
    for (int sig : signals) {
        std::signal(sig, &epx_signal_trampoline);
    }
}

} // namespace epx
