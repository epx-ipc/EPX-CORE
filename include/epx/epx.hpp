// EPX — Encrypted Process eXchange
// Public API. This is the only header application code needs to include.
//
// Model:
//   - A program that wants to offer functionality calls Host::expose("endpoint", handler)
//     for each endpoint it wants reachable, then Host::run()/run_async(). Every endpoint
//     has a declared EndpointKind (Receive, Send, StreamReceive, StreamSend — see below)
//     that says which shape of call it expects.
//   - A program that wants to call into another program constructs a Client and calls
//     Client::get(service, endpoint, data) for request/response (Receive endpoints),
//     Client::send(...) for fire-and-forget (Send endpoints), Client::open_stream(...)
//     to push a sequence of chunks (StreamReceive endpoints), or Client::get_stream(...)
//     to pull a sequence of chunks (StreamSend endpoints).
//   - Every connection is mutually authenticated (public-key identities, pinned like SSH
//     host keys) and every message on the wire is encrypted + integrity-protected.
//     Nothing that isn't a party to the handshake — including other programs running
//     on the same machine — can read or tamper with the conversation.
//
// See docs/SPEC.md for the wire protocol, threat model, and crypto details.

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "epx/version.hpp" // generated from version.hpp.in by CMake

namespace epx {

using Bytes = std::vector<uint8_t>;

// Identity keys are Ed25519 (libsodium crypto_sign): a 32-byte public key
// and a 64-byte secret key (libsodium packs the seed + public key together).
// Ed25519 is used here purely to *authenticate* a fresh, per-session X25519
// key exchange (see docs/SPEC.md section 5) — it is never used to encrypt
// anything itself.
constexpr size_t kPublicKeyBytes = 32;
constexpr size_t kSecretKeyBytes = 64;

using PublicKey = std::array<uint8_t, kPublicKeyBytes>;
using SecretKey = std::array<uint8_t, kSecretKeyBytes>;

// A program's durable cryptographic identity. Generated once and persisted
// (see load_or_create_identity); this is what peers pin/trust, analogous to
// an SSH host key. Every session additionally negotiates fresh ephemeral
// X25519 keys authenticated by this identity, so compromising this secret
// key does not expose the content of past sessions (forward secrecy).
struct Identity {
    PublicKey public_key{};
    SecretKey secret_key{};
};

// Loads the identity for `app_name` from the local per-user keystore,
// generating and persisting a new one on first run.
// POSIX: ~/.epx/identities/<app_name>.key (mode 0600)
// Windows: %LOCALAPPDATA%\epx\identities\<app_name>.key (ACL restricted to the user)
Identity load_or_create_identity(const std::string& app_name);

// How a Host or Client decides whether to trust a peer's long-term public key.
//
// The two sides are not symmetric, and it matters:
//   - Client side: the service *name* is the anchor. The first key seen for
//     "com.acme.notes" is pinned, and any later key claiming that name is
//     rejected (SSH-style "identity changed"). Real protection after first
//     contact.
//   - Host side: an incoming client has no name to anchor a pin to — its
//     identity IS its key, so a brand-new key is indistinguishable from a
//     legitimate new client. Under TrustOnFirstUse a Host therefore
//     *accepts and records* every previously-unseen client key
//     (~/.epx/known_clients/) rather than rejecting anyone. That recording
//     enables continuity ("have I seen this caller before?" — surfaced as
//     PeerInfo::key_was_pinned_now) but is NOT access control. A Host that
//     needs to restrict callers must use RequireKnownPeer/allow_peer.
enum class TrustPolicy {
    // Client side: pin-on-first-contact per service name, reject changes.
    // Host side: accept-and-record (see the asymmetry note above).
    // Good default for same-user, same-machine tooling; does not protect
    // the client against an attacker who wins the very first connection
    // (classic TOFU caveat) — use RequireKnownPeer for anything sensitive.
    TrustOnFirstUse,

    // Only peers whose public key was pre-registered via Host::allow_peer /
    // a peers file are accepted. Anyone else is rejected during handshake.
    RequireKnownPeer,

    // No pinning at all: any peer is accepted. The channel is still fully
    // encrypted, but there is no identity guarantee. Useful for local
    // experimentation only.
    AllowAll,
};

// Information about the remote party of a request, handed to endpoint
// handlers so they can make authorization decisions.
struct PeerInfo {
    PublicKey public_key{};
    // Reserved for a future protocol version in which a caller declares
    // its own service name during the handshake; always empty in this
    // version (a Client isn't necessarily a Host and has no name of its
    // own to declare). If your endpoint needs to know who's calling
    // *by name* rather than by public key, have the caller include it in
    // the request payload itself (see examples/chat.cpp).
    std::string service_name;
    long peer_uid = -1;         // OS-verified UID of the connecting process (-1 if unknown)
    bool key_was_pinned_now = false; // true if this is a brand-new TOFU pin
};

// Returned by an endpoint handler.
struct Response {
    bool ok = true;
    Bytes data;
    std::string error; // human-readable, only meaningful if ok == false
};

using Handler = std::function<Response(const Bytes& request, const std::string& endpoint, const PeerInfo& peer)>;

// Thrown by Client::get on timeout, transport failure, or a rejected handshake.
class EpxError : public std::runtime_error {
public:
    enum class Code {
        Timeout, ConnectFailed, HandshakeRejected, NotFound, Transport, Protocol,
        // The peer authenticated fine but the endpoint's AccessPolicy said
        // no (denied by a prompt decision, missing credential, etc).
        AccessDenied,
        // The host disconnected us for exceeding its rate limits (see
        // ConnectionLimits); the message carries the host's stated reason.
        RateLimited,
    };
    EpxError(Code c, const std::string& msg) : std::runtime_error(msg), code(c) {}
    Code code;
};

// -----------------------------------------------------------------------
// Per-endpoint authorization (protocol v2, roadmap item 8a)
// -----------------------------------------------------------------------
// TrustPolicy (above) decides who may complete a handshake at all;
// AccessPolicy decides, per endpoint, what an already-authenticated peer
// may actually call. The tiers form a spectrum from "anyone on this
// machine" to "ask the user":
enum class AccessTier : uint8_t {
    // Any peer that completed the handshake may call this endpoint.
    Open,

    // Only peers this host has seen and recorded before (allow_peer() or a
    // prior TrustOnFirstUse recording). Under a TrustOnFirstUse host this
    // admits first-time callers too (they're recorded during the same
    // handshake); its bite is under TrustPolicy::AllowAll, where unknown
    // peers complete the handshake but are NOT recorded — and therefore
    // can't touch PinnedPeers endpoints.
    PinnedPeers,

    // The peer's public key must be covered by a credential file: a small
    // statement (peer key, scope, expiry) signed offline by an issuer key
    // this host explicitly trusts via Host::add_issuer(). A minimal local
    // CA, not a full PKI — see make_credential() and docs/SPEC.md §7.2.
    Certificate,

    // No recorded decision -> the host's AuthorizationPrompt callback is
    // invoked (synchronously; wire it to a UI dialog) and the answer is
    // persisted per (peer key, service, endpoint) unless it was AllowOnce.
    // No callback registered -> deny. The mic/camera-permission UX.
    PromptUser,
};

struct AccessPolicy {
    AccessTier tier = AccessTier::Open;
    // Shown to the user by a PromptUser callback — the app's one-line
    // answer to "why is this program asking?".
    std::string prompt_reason;
};

enum class PromptDecision : uint8_t {
    Deny = 0,       // persisted: this (peer, endpoint) is refused from now on
    AllowOnce = 1,  // allowed for the current connection only; ask again next time
    AlwaysAllow = 2 // persisted: never ask again for this (peer, endpoint)
};

// Invoked by a Host (on the connection's own thread) when a peer with no
// recorded decision calls a PromptUser endpoint. Block as long as the user
// needs — but note the calling peer is waiting on its own request timeout.
using AuthorizationPrompt = std::function<PromptDecision(
    const PeerInfo& peer, const std::string& endpoint, const std::string& reason)>;

// Creates the serialized credential text for AccessTier::Certificate: the
// issuer signs (peer key, scope, expiry). `scope` is either a service name
// ("com.acme.notes" — covers every endpoint) or service/endpoint
// ("com.acme.notes/admin"). `expires_unix` is seconds since the epoch,
// 0 = never expires. Distribute the returned text to the host any way you
// like: Host::add_credential(text) programmatically, or drop it as a file
// under ~/.epx/credentials/<service>/<anything>.cred and the Host loads it
// at run().
std::string make_credential(const Identity& issuer,
                             const PublicKey& peer,
                             const std::string& scope,
                             uint64_t expires_unix);

// -----------------------------------------------------------------------
// Endpoint kinds
// -----------------------------------------------------------------------
// Every endpoint declares which shape of call it expects. This is purely
// local bookkeeping on the Host (it decides how to dispatch an incoming
// frame) — the wire format doesn't need the caller to declare it up front,
// but the caller does need to use the matching Client method, the same way
// you wouldn't PUT to a REST endpoint documented as GET-only.
enum class EndpointKind {
    // Client calls Client::get(): one request in, one response out,
    // caller blocks for the reply. The classic RPC call.
    Receive,

    // Client calls Client::send(): one request in, fire-and-forget — no
    // response is read or sent. Cheapest option when the caller doesn't
    // need an acknowledgement (e.g. delivering a chat message).
    Send,

    // Client calls Client::open_stream(): the *caller* pushes a sequence
    // of chunks to this endpoint over time (e.g. uploading a large or
    // continuously-produced buffer), terminated by OutputStream::finish()
    // (or its destructor). No response is sent back per chunk.
    StreamReceive,

    // Client calls Client::get_stream(): one request in, then the *host*
    // pushes back a sequence of chunks over time (e.g. streaming query
    // results, a large buffer) until it signals completion. Use this for
    // BOUNDED data — the handler function returning IS the end of the
    // stream. For an unbounded live feed, use Topic below.
    StreamSend,

    // Registered via Host::expose_topic(), consumed via
    // Client::subscribe(): a named, unbounded broadcast feed. The host
    // publishes messages at any time from any thread via the returned
    // TopicHandle; every current subscriber receives every message. The
    // library owns subscriber registration, per-subscriber delivery,
    // heartbeats, and dead-subscriber cleanup — the pattern
    // examples/groupchat_common.hpp used to hand-build. There is no
    // history/replay: a subscriber sees messages published after it
    // subscribed. Choose by lifetime: StreamSend when the stream has a
    // natural end, Topic when it doesn't.
    Topic,
};

// Invoked once per chunk as it arrives on a StreamReceive endpoint.
// `is_last` is true on the final call for a given logical stream (which
// may or may not carry trailing data).
using StreamReceiveHandler = std::function<void(const Bytes& chunk, bool is_last,
                                                  const std::string& endpoint, const PeerInfo& peer)>;

// Handed to a StreamSend handler so it can push zero or more chunks back
// to the caller. The library automatically sends a final "end of stream"
// marker once the handler function returns — no explicit finish() needed.
class StreamWriter {
public:
    // Returns true if the chunk was handed off to the transport
    // successfully, false if the connection is gone (peer disconnected,
    // socket error, etc). A handler that produces chunks indefinitely
    // (e.g. a live feed with no natural end) should check this and stop
    // producing once it turns false, rather than blocking or looping
    // forever against a dead peer.
    bool write(const Bytes& chunk) const { return write_fn_ ? write_fn_(chunk) : false; }

    // Constructed only by Host internals.
    explicit StreamWriter(std::function<bool(const Bytes&)> write_fn) : write_fn_(std::move(write_fn)) {}

private:
    std::function<bool(const Bytes&)> write_fn_;
};

using StreamSendHandler = std::function<void(const StreamWriter& out, const Bytes& request,
                                              const std::string& endpoint, const PeerInfo& peer)>;

// Returned by Host::expose_topic(). A cheap, copyable handle; publish()
// may be called from any thread, at any time relative to run()/stop().
// Messages published while nobody is subscribed are simply dropped (a
// Topic is a live feed, not a queue).
class TopicHandle {
public:
    TopicHandle() = default;

    // Broadcasts `message` to every current subscriber. Returns how many
    // subscribers it was written to (subscribers whose connection turned
    // out to be dead are pruned, not counted). Thread-safe.
    size_t publish(const Bytes& message) const;

    // Current live subscriber count (dead ones are pruned by heartbeats,
    // failed publishes, and unsubscribes — so this may lag reality by up
    // to one heartbeat interval for silently-vanished peers). Thread-safe.
    size_t subscriber_count() const;

private:
    friend class Host;
    struct Impl;
    explicit TopicHandle(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}
    std::shared_ptr<Impl> impl_;
};

// -----------------------------------------------------------------------
// Service enumeration (roadmap item 4)
// -----------------------------------------------------------------------
// What a running Host publishes about itself, readable by anyone on the
// same OS user account via describe(). IMPORTANT: this is unauthenticated
// metadata, exactly like the lookup a Client does before dialing —
// enumerating a service proves nothing about it; only the live handshake
// establishes trust (docs/SPEC.md section 4.3). The registry stays a
// passive store: it answers "what claims to be here," it never relays
// application traffic.
struct ServiceDescription {
    std::string service_name;
    std::string description;   // Host::set_description, may be empty
    long pid = -1;
    PublicKey identity_pubkey{};
    struct Endpoint {
        std::string name;
        EndpointKind kind = EndpointKind::Receive;
    };
    std::vector<Endpoint> endpoints;
};

// Every service currently registered *and live* on this machine for the
// current OS user (stale entries from crashed hosts are pruned), sorted.
std::vector<std::string> list_services();

// The self-description a live service published, or nullopt if it isn't
// registered/running.
std::optional<ServiceDescription> describe(const std::string& service_name);

// -----------------------------------------------------------------------
// Rate limiting / flow control (roadmap items 6 + 7)
// -----------------------------------------------------------------------
// All limits are per-Host, applied per connection (and per OS UID for the
// pre-handshake cap). Zeros mean "unlimited/disabled" — the v1-compatible
// default. Set via Host::set_limits() before run().
struct ConnectionLimits {
    // Pre-handshake: connection attempts allowed per OS UID. The handshake
    // does real signature/DH work, so this cheap cap must exist *before*
    // any post-handshake limiting means anything. Attempts beyond the
    // bucket are closed immediately, before any crypto.
    uint32_t handshakes_per_uid_per_sec = 0; // 0 = uncapped
    uint32_t handshake_burst = 20;

    // Post-handshake: request rate per connection (token bucket). A peer
    // exceeding it is *delayed* first (the connection thread simply waits
    // for the next token before serving). A peer so far over the limit
    // that it stays saturated is disconnected with an ERROR frame
    // (reason=rate limited) after `disconnect_after_delayed` consecutive
    // delayed requests — the peer is told why, not silently dropped.
    uint32_t max_requests_per_sec = 0;       // 0 = unlimited
    uint32_t request_burst = 32;
    uint32_t disconnect_after_delayed = 100;

    // Concurrent long-lived subscriptions (Topic endpoints) per
    // connection; a subscribe beyond this is refused (see
    // Host::expose_topic). Bounded streams (StreamSend handlers) are
    // served synchronously per connection and need no cap.
    uint32_t max_subscriptions = 32;

    // Backpressure phase 1: if > 0, any write on a connection that can't
    // make progress for this long fails, surfacing as `false` from
    // StreamWriter::write() exactly like a dead peer — the producing
    // handler decides whether to drop, wait, or stop. 0 = writes block
    // indefinitely (v1 behavior).
    int stream_write_timeout_ms = 0;
};

// -----------------------------------------------------------------------
// Host: exposes one or more named endpoints under a single service name.
// -----------------------------------------------------------------------
class Host {
public:
    // `service_name` is how clients address this program (e.g. "com.example.notes").
    // It must be unique on the local machine for the current OS user.
    Host(std::string service_name, Identity identity, TrustPolicy policy = TrustPolicy::TrustOnFirstUse);
    ~Host();

    Host(const Host&) = delete;
    Host& operator=(const Host&) = delete;

    // Registers `handler` to be invoked for requests addressed to `endpoint`.
    // Must be called before run()/run_async(). `kind` must be Receive or
    // Send (use expose_stream_receive/expose_stream_send for the streaming
    // kinds below) — it only affects how mismatched calls are reported,
    // not how the frame is decrypted or dispatched. The `access` overloads
    // attach a per-endpoint AccessPolicy; without one the endpoint uses the
    // Host-wide default (set_default_access, itself defaulting to Open).
    void expose(EndpointKind kind, const std::string& endpoint, Handler handler);
    void expose(EndpointKind kind, const std::string& endpoint, Handler handler, AccessPolicy access);

    // Convenience overloads: same as expose(EndpointKind::Receive, ...).
    void expose(const std::string& endpoint, Handler handler);
    void expose(const std::string& endpoint, Handler handler, AccessPolicy access);

    // Registers a handler that is invoked once per chunk as a client
    // streams data to this endpoint via Client::open_stream(...).
    void expose_stream_receive(const std::string& endpoint, StreamReceiveHandler handler);
    void expose_stream_receive(const std::string& endpoint, StreamReceiveHandler handler, AccessPolicy access);

    // Registers a handler that is invoked once per request and may push
    // zero or more chunks back via the StreamWriter it's given, for
    // clients calling Client::get_stream(...).
    void expose_stream_send(const std::string& endpoint, StreamSendHandler handler);
    void expose_stream_send(const std::string& endpoint, StreamSendHandler handler, AccessPolicy access);

    // Rate limits / flow control for this Host (see ConnectionLimits).
    // Must be called before run().
    void set_limits(ConnectionLimits limits);

    // Optional human-readable one-liner published in this service's
    // registry self-description (see epx::describe / `epx describe`).
    // Must be called before run().
    void set_description(std::string description);

    // Exposes a named broadcast topic (EndpointKind::Topic). Clients join
    // it with Client::subscribe() and receive everything published on the
    // returned handle from then on. Must be called before run(). Topic
    // names beginning with "$epx/" are reserved for the protocol itself
    // (as are all endpoint names — expose* throws on them).
    TopicHandle expose_topic(const std::string& topic);
    TopicHandle expose_topic(const std::string& topic, AccessPolicy access);

    // ---- Authorization (see AccessTier above; protocol v2) ------------
    //
    // Host-wide default for endpoints exposed without an explicit policy.
    // Open by default (v1-compatible behavior). Must be called before run().
    void set_default_access(AccessPolicy access);

    // Callback for AccessTier::PromptUser endpoints. Without one, every
    // un-persisted PromptUser decision is a deny.
    void on_authorization_prompt(AuthorizationPrompt prompt);

    // Trusts `issuer` to sign credentials for AccessTier::Certificate
    // endpoints (see make_credential()).
    void add_issuer(const PublicKey& issuer_public_key);

    // Installs one serialized credential (the text make_credential()
    // returned). Returns false if it doesn't parse. Credentials whose
    // issuer isn't trusted or whose scope/expiry doesn't match are simply
    // never used — installing them isn't an error. Host::run() also loads
    // every *.cred file under ~/.epx/credentials/<service_name>/.
    bool add_credential(const std::string& credential_text);

    // Pre-authorizes a specific peer public key under RequireKnownPeer policy.
    void allow_peer(const PublicKey& peer_public_key);

    // Publishes the registry entry and starts accepting connections on a
    // background thread. Returns as soon as the listener is bound and the
    // registry entry is published — bind/listen failures (e.g. another
    // instance already running) still throw synchronously from this call,
    // but accepting connections itself never blocks the caller. Pair with
    // wait_until_stopped() if the calling thread has nothing else to do
    // and should simply park until shutdown (see the lifecycle methods
    // below).
    void run();

    // Deprecated alias for run() — run() has been non-blocking since
    // EPX 1.0; kept only so existing call sites keep compiling.
    [[deprecated("run() is now non-blocking; call run() then wait_until_stopped() if you need to block")]]
    void run_async();

    // ---- Shutdown lifecycle -------------------------------------------
    //
    // Stops accepting new connections, closes existing ones, removes the
    // registry entry, and runs any before_stop()/after_stop() hooks (see
    // below). Idempotent — safe to call more than once, from any thread.
    // Blocks until every connection-handler thread has actually returned,
    // so it is NOT safe to call from a signal handler (it locks mutexes
    // and joins threads) — use request_stop() from a signal handler
    // instead and let a normal thread call stop() (directly, or via
    // wait_until_stopped()).
    void stop();

    // Registers a hook to run at the very start of stop(), before the
    // listener or any existing connection is touched. This is the
    // insertion point for deciding how in-flight work is handled: return
    // immediately to let stop() close everything right away ("kill"
    // semantics), or block here — e.g. waiting on your own counter of
    // active requests/streams — to drain gracefully first. Hooks run
    // synchronously, in registration order, on whichever thread calls
    // stop(). Must be called before run().
    void before_stop(std::function<void()> hook);

    // Registers a hook to run at the very end of stop(), after the
    // listener/connections are closed and the registry entry is removed.
    // Same threading/ordering rules as before_stop(). Must be called
    // before run().
    void after_stop(std::function<void()> hook);

    // Async-signal-safe: sets an internal flag and returns. Does no
    // locking, allocation, or I/O, so — unlike stop() — this IS safe to
    // call directly from a POSIX signal handler (e.g. for SIGTERM). It
    // does not perform the shutdown itself; pair it with a normal thread
    // blocked in wait_until_stopped() (or polling stopped() and calling
    // stop() itself) to actually run the teardown. See stop_on_signals()
    // for a ready-made version of this pattern.
    void request_stop() noexcept;

    // True once stop() has fully completed (or hasn't started); does not
    // by itself indicate a stop is *in progress* — check this from a
    // polling loop if you're not using wait_until_stopped().
    bool stopped() const noexcept;

    // Blocks the calling thread until request_stop() (or stop()) has been
    // invoked from anywhere, then runs stop() (a no-op if something else
    // already fully stopped this Host) and returns. Intended as the
    // "main thread has nothing else to do" counterpart to run()'s
    // non-blocking accept loop:
    //
    //   host.run();
    //   host.stop_on_signals({SIGINT, SIGTERM});
    //   host.wait_until_stopped();
    //
    // Implemented as a short polling loop (checked roughly every 50ms) —
    // simple and portable rather than using a self-pipe/event object, at
    // the cost of up to ~50ms of added shutdown latency after a signal.
    void wait_until_stopped();

    // Convenience: registers this Host to call request_stop() when any of
    // `signals` is delivered to the process (e.g. {SIGINT, SIGTERM}),
    // using plain ISO C signal() — portable, but note that termination
    // signal semantics differ across platforms (notably Windows). Safe to
    // call from multiple Host instances in the same process; a delivered
    // signal requests a stop on all of them, matching a signal's
    // process-wide nature. Registration uses a small fixed-size table
    // (8 Hosts); additional calls beyond that are silently ignored rather
    // than allocating from within what may later run in signal context.
    void stop_on_signals(std::initializer_list<int> signals);

    const PublicKey& public_key() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// -----------------------------------------------------------------------
// Mid-session key rotation (roadmap 8c) — EXPERIMENTAL, OFF BY DEFAULT
// -----------------------------------------------------------------------
// When enabled on a Client, long-lived v2 sessions periodically re-run an
// ephemeral X25519 exchange over the already-authenticated channel and
// move to fresh session keys (a new "epoch"; see docs/SPEC.md 6.3/6.4),
// bounding how much traffic any single key generation ever protects.
//
// ⚠ This feature is implemented and tested but has NOT yet received the
// external cryptographic review docs/ROADMAP_V2.md item 8c calls for. It
// ships disabled; enabling it is an explicit opt-in to a pre-review
// mechanism. Hosts built at 2.1+ always *support* inbound rotation on v2
// sessions regardless of this setting (it's the client that initiates).
struct RotationPolicy {
    // Rotate when either bound is reached, checked on the client's send
    // path. Zero disables that bound; both zero (the default) disables
    // rotation entirely.
    std::chrono::seconds interval{0}; // rotate this long after the last rotation
    uint64_t max_bytes = 0;           // rotate after this many plaintext bytes sent
};

// -----------------------------------------------------------------------
// Client: talks to endpoints exposed by other programs.
// -----------------------------------------------------------------------
class Client {
public:
    explicit Client(Identity identity, TrustPolicy policy = TrustPolicy::TrustOnFirstUse);
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    void allow_peer(const PublicKey& peer_public_key);

    // Request/response. Reuses an existing encrypted session to `target_service`
    // if one is open (this is what makes a multi-call "conversation" cheap —
    // only the first call pays for the handshake). Blocks until a response
    // arrives or `timeout` elapses.
    Bytes get(const std::string& target_service,
              const std::string& endpoint,
              const Bytes& data,
              std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    // Fire-and-forget: delivery to the peer's transport is confirmed, but no
    // application-level response is awaited.
    void send(const std::string& target_service,
              const std::string& endpoint,
              const Bytes& data);

    // Calls a StreamSend endpoint. Blocks the calling thread until the host
    // signals the end of the stream or `timeout` elapses (measured from the
    // last time *any* chunk arrived, so a slow-but-still-flowing stream
    // won't time out — only a stalled one will). `on_chunk` is invoked once
    // per chunk, including the final one (with is_last == true), from a
    // background reader thread — keep it quick and thread-safe.
    void get_stream(const std::string& target_service,
                     const std::string& endpoint,
                     const Bytes& data,
                     const std::function<void(const Bytes& chunk, bool is_last)>& on_chunk,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    // A handle for pushing a sequence of chunks to a StreamReceive
    // endpoint. Move-only; finish() (or the destructor) sends the "end of
    // stream" marker. No response is read back — see EndpointKind::StreamReceive.
    class OutputStream {
    public:
        OutputStream(OutputStream&&) noexcept;
        OutputStream& operator=(OutputStream&&) noexcept;
        OutputStream(const OutputStream&) = delete;
        OutputStream& operator=(const OutputStream&) = delete;
        ~OutputStream();

        // Returns true if the chunk was handed off to the transport, false
        // if the connection is gone or the write stayed blocked past the
        // client's stream-write timeout (see set_stream_write_timeout) —
        // the same dead-peer/backpressure signal StreamWriter::write gives
        // handlers on the host side. (Returned void before 2.1; source-
        // compatible for callers that ignored it.)
        bool write(const Bytes& chunk);
        void finish(); // idempotent; also called automatically by the destructor

    private:
        friend class Client;
        struct Impl;
        explicit OutputStream(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> impl_;
    };

    // Opens a stream to a StreamReceive endpoint on `target_service`.
    OutputStream open_stream(const std::string& target_service, const std::string& endpoint);

    // A live subscription to a Topic endpoint (see EndpointKind::Topic).
    // Move-only RAII: destroying it (or calling unsubscribe()) both stops
    // local delivery and tells the host to drop the subscription, so a
    // quitting subscriber never leaves the host publishing into the void —
    // the shutdown bug examples/groupchat.cpp had to fix by hand, solved
    // at the library level.
    class Subscription {
    public:
        Subscription(); // empty handle; active() == false
        Subscription(Subscription&&) noexcept;
        Subscription& operator=(Subscription&&) noexcept;
        Subscription(const Subscription&) = delete;
        Subscription& operator=(const Subscription&) = delete;
        ~Subscription();

        void unsubscribe(); // idempotent
        // True until unsubscribe() is called or the feed is closed by the
        // host / connection loss (the callback's closed=true delivery).
        bool active() const;

    private:
        friend class Client;
        struct Impl;
        explicit Subscription(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> impl_;
    };

    // Subscribes to `topic` on `target_service`. `on_message` is invoked
    // once per published message, from the connection's background reader
    // thread (keep it quick and thread-safe), and one final time with
    // closed=true (and an empty payload) when the feed ends — host
    // shutdown, connection loss, subscription refused (unknown topic /
    // access denied / subscription limit), or unsubscribe.
    Subscription subscribe(const std::string& target_service,
                            const std::string& topic,
                            std::function<void(const Bytes& message, bool closed)> on_message);

    // Backpressure phase 1, client side: if > 0, a write on any of this
    // Client's connections that can't make progress for this long fails
    // (OutputStream::write returns false) instead of blocking forever.
    // Applies to connections opened after the call. 0 = block (default).
    void set_stream_write_timeout(int ms);

    // Opts this Client into mid-session key rotation (see RotationPolicy —
    // experimental, pending external review, off by default). Applies to
    // connections opened after the call; only effective on v2 sessions.
    void enable_key_rotation(RotationPolicy policy);

    // Introspection: the current key epoch of the open session to
    // `target_service` (0 until a rotation has happened), or -1 if no
    // session is open. Mostly useful for diagnostics and tests.
    int session_epoch(const std::string& target_service) const;

    // Closes the session to `target_service`, if any. Sessions are also
    // closed automatically when the Client is destroyed.
    void disconnect(const std::string& target_service);

    const PublicKey& public_key() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace epx
