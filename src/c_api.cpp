// The C ABI shim: epx_c.h implemented against the C++ core. Pure wrapper
// layer — no protocol logic lives here, and no exception or C++ type ever
// crosses the extern "C" boundary. Every entry point that can fail wraps
// its body in guarded() below, which converts EpxError codes 1:1 and
// anything else into EPX_ERR_INTERNAL + a thread-local message.
#define EPX_C_BUILDING 1
#include "epx/epx_c.h"

#include "epx/epx.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

thread_local std::string t_last_error = "no error";

epx_status_t map_code(epx::EpxError::Code c) {
    switch (c) {
        case epx::EpxError::Code::Timeout:            return EPX_ERR_TIMEOUT;
        case epx::EpxError::Code::ConnectFailed:      return EPX_ERR_CONNECT_FAILED;
        case epx::EpxError::Code::HandshakeRejected:  return EPX_ERR_HANDSHAKE_REJECTED;
        case epx::EpxError::Code::NotFound:           return EPX_ERR_NOT_FOUND;
        case epx::EpxError::Code::Transport:          return EPX_ERR_TRANSPORT;
        case epx::EpxError::Code::Protocol:           return EPX_ERR_PROTOCOL;
        case epx::EpxError::Code::AccessDenied:       return EPX_ERR_ACCESS_DENIED;
        case epx::EpxError::Code::RateLimited:        return EPX_ERR_RATE_LIMITED;
    }
    return EPX_ERR_INTERNAL;
}

template <typename Fn>
epx_status_t guarded(Fn&& fn) {
    try {
        fn();
        return EPX_OK;
    } catch (const epx::EpxError& e) {
        t_last_error = e.what();
        return map_code(e.code);
    } catch (const std::invalid_argument& e) {
        t_last_error = e.what();
        return EPX_ERR_INVALID_ARGUMENT;
    } catch (const std::exception& e) {
        t_last_error = e.what();
        return EPX_ERR_INTERNAL;
    } catch (...) {
        t_last_error = "unknown internal error";
        return EPX_ERR_INTERNAL;
    }
}

epx_bytes_t to_c_bytes(const epx::Bytes& b) {
    epx_bytes_t out{nullptr, 0};
    if (!b.empty()) {
        out.data = static_cast<uint8_t*>(std::malloc(b.size()));
        std::memcpy(out.data, b.data(), b.size());
        out.len = b.size();
    }
    return out;
}

char* to_c_string(const std::string& s) {
    char* out = static_cast<char*>(std::malloc(s.size() + 1));
    std::memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

epx::Bytes to_cpp_bytes(const uint8_t* data, size_t len) {
    return (data && len) ? epx::Bytes(data, data + len) : epx::Bytes{};
}

void fill_peer(epx_peer_info_t& out, const epx::PeerInfo& in) {
    std::memcpy(out.public_key, in.public_key.data(), 32);
    out.peer_uid = in.peer_uid;
    out.key_was_pinned_now = in.key_was_pinned_now ? 1 : 0;
}

epx::PublicKey to_pk(const uint8_t key[32]) {
    epx::PublicKey pk{};
    std::memcpy(pk.data(), key, 32);
    return pk;
}

epx::AccessPolicy to_policy(epx_access_tier_t tier, const char* reason) {
    epx::AccessPolicy p;
    p.tier = static_cast<epx::AccessTier>(tier);
    if (reason) p.prompt_reason = reason;
    return p;
}

} // namespace

/* Opaque handle definitions — plain structs owning the C++ objects. */
struct epx_identity { epx::Identity id; };
struct epx_host { epx::Host host; };
struct epx_client { epx::Client client; };
struct epx_output_stream { epx::Client::OutputStream stream; };
struct epx_topic { epx::TopicHandle handle; };
struct epx_subscription { epx::Client::Subscription sub; };
struct epx_response_writer { epx::Response resp; };
struct epx_stream_writer { const epx::StreamWriter* writer; };

extern "C" {

/* ---- version / errors / memory ---------------------------------------- */

uint32_t epx_c_abi_version(void) { return EPX_C_ABI_VERSION; }
const char* epx_version_string(void) { return epx::kVersionString; }
const char* epx_last_error(void) { return t_last_error.c_str(); }

void epx_bytes_free(epx_bytes_t bytes) { std::free(bytes.data); }
void epx_string_free(char* s) { std::free(s); }
void epx_string_list_free(char** list, size_t count) {
    if (!list) return;
    for (size_t i = 0; i < count; ++i) std::free(list[i]);
    std::free(list);
}

/* ---- identity --------------------------------------------------------- */

epx_status_t epx_identity_load_or_create(const char* app_name, epx_identity_t** out_identity) {
    if (!app_name || !out_identity) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        *out_identity = new epx_identity{epx::load_or_create_identity(app_name)};
    });
}

void epx_identity_free(epx_identity_t* identity) { delete identity; }

void epx_identity_public_key(const epx_identity_t* identity, uint8_t out_key[32]) {
    if (identity && out_key) std::memcpy(out_key, identity->id.public_key.data(), 32);
}

/* ---- credentials ------------------------------------------------------ */

epx_status_t epx_make_credential(const epx_identity_t* issuer, const uint8_t peer_public_key[32],
                                 const char* scope, uint64_t expires_unix, char** out_credential_text) {
    if (!issuer || !peer_public_key || !scope || !out_credential_text) {
        t_last_error = "NULL argument";
        return EPX_ERR_INVALID_ARGUMENT;
    }
    return guarded([&] {
        *out_credential_text = to_c_string(
            epx::make_credential(issuer->id, to_pk(peer_public_key), scope, expires_unix));
    });
}

/* ---- host ------------------------------------------------------------- */

epx_status_t epx_host_create(const char* service_name, const epx_identity_t* identity,
                             epx_trust_policy_t policy, epx_host_t** out_host) {
    if (!service_name || !identity || !out_host) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        *out_host = new epx_host{epx::Host(service_name, identity->id,
                                            static_cast<epx::TrustPolicy>(policy))};
    });
}

void epx_host_free(epx_host_t* host) { delete host; } /* Host dtor stops it */

void epx_respond_ok(epx_response_writer_t* response, const uint8_t* data, size_t len) {
    if (!response) return;
    response->resp.ok = true;
    response->resp.data = to_cpp_bytes(data, len);
    response->resp.error.clear();
}

void epx_respond_error(epx_response_writer_t* response, const char* message) {
    if (!response) return;
    response->resp.ok = false;
    response->resp.data.clear();
    response->resp.error = message ? message : "error";
}

namespace {
epx::Handler wrap_handler(epx_handler_fn handler, void* user_data) {
    return [handler, user_data](const epx::Bytes& req, const std::string& endpoint,
                                const epx::PeerInfo& peer) -> epx::Response {
        epx_response_writer writer;
        writer.resp.ok = true; /* neither respond call = empty ok */
        epx_peer_info_t cpeer;
        fill_peer(cpeer, peer);
        handler(req.empty() ? nullptr : req.data(), req.size(), endpoint.c_str(), &cpeer, &writer, user_data);
        return writer.resp;
    };
}
} // namespace

epx_status_t epx_host_expose(epx_host_t* host, epx_endpoint_kind_t kind, const char* endpoint,
                             epx_handler_fn handler, void* user_data) {
    if (!host || !endpoint || !handler) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        host->host.expose(static_cast<epx::EndpointKind>(kind), endpoint, wrap_handler(handler, user_data));
    });
}

epx_status_t epx_host_expose_access(epx_host_t* host, epx_endpoint_kind_t kind, const char* endpoint,
                                    epx_handler_fn handler, void* user_data,
                                    epx_access_tier_t tier, const char* prompt_reason) {
    if (!host || !endpoint || !handler) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        host->host.expose(static_cast<epx::EndpointKind>(kind), endpoint,
                           wrap_handler(handler, user_data), to_policy(tier, prompt_reason));
    });
}

namespace {
epx::StreamReceiveHandler wrap_stream_recv(epx_stream_recv_fn handler, void* user_data) {
    return [handler, user_data](const epx::Bytes& chunk, bool is_last,
                                const std::string& endpoint, const epx::PeerInfo& peer) {
        epx_peer_info_t cpeer;
        fill_peer(cpeer, peer);
        handler(chunk.empty() ? nullptr : chunk.data(), chunk.size(), is_last ? 1 : 0,
                endpoint.c_str(), &cpeer, user_data);
    };
}

epx::StreamSendHandler wrap_stream_send(epx_stream_send_fn handler, void* user_data) {
    return [handler, user_data](const epx::StreamWriter& out, const epx::Bytes& req,
                                const std::string& endpoint, const epx::PeerInfo& peer) {
        epx_stream_writer cwriter{&out};
        epx_peer_info_t cpeer;
        fill_peer(cpeer, peer);
        handler(&cwriter, req.empty() ? nullptr : req.data(), req.size(),
                endpoint.c_str(), &cpeer, user_data);
    };
}
} // namespace

int epx_stream_writer_write(epx_stream_writer_t* out, const uint8_t* chunk, size_t len) {
    if (!out || !out->writer) return 0;
    return out->writer->write(to_cpp_bytes(chunk, len)) ? 1 : 0;
}

epx_status_t epx_host_expose_stream_receive(epx_host_t* host, const char* endpoint,
                                            epx_stream_recv_fn handler, void* user_data) {
    if (!host || !endpoint || !handler) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] { host->host.expose_stream_receive(endpoint, wrap_stream_recv(handler, user_data)); });
}

epx_status_t epx_host_expose_stream_receive_access(epx_host_t* host, const char* endpoint,
                                                   epx_stream_recv_fn handler, void* user_data,
                                                   epx_access_tier_t tier, const char* prompt_reason) {
    if (!host || !endpoint || !handler) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        host->host.expose_stream_receive(endpoint, wrap_stream_recv(handler, user_data),
                                          to_policy(tier, prompt_reason));
    });
}

epx_status_t epx_host_expose_stream_send(epx_host_t* host, const char* endpoint,
                                         epx_stream_send_fn handler, void* user_data) {
    if (!host || !endpoint || !handler) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] { host->host.expose_stream_send(endpoint, wrap_stream_send(handler, user_data)); });
}

epx_status_t epx_host_expose_stream_send_access(epx_host_t* host, const char* endpoint,
                                                epx_stream_send_fn handler, void* user_data,
                                                epx_access_tier_t tier, const char* prompt_reason) {
    if (!host || !endpoint || !handler) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        host->host.expose_stream_send(endpoint, wrap_stream_send(handler, user_data),
                                       to_policy(tier, prompt_reason));
    });
}

epx_status_t epx_host_expose_topic(epx_host_t* host, const char* topic, epx_topic_t** out_topic) {
    if (!host || !topic || !out_topic) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] { *out_topic = new epx_topic{host->host.expose_topic(topic)}; });
}

epx_status_t epx_host_expose_topic_access(epx_host_t* host, const char* topic,
                                          epx_access_tier_t tier, const char* prompt_reason,
                                          epx_topic_t** out_topic) {
    if (!host || !topic || !out_topic) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        *out_topic = new epx_topic{host->host.expose_topic(topic, to_policy(tier, prompt_reason))};
    });
}

size_t epx_topic_publish(epx_topic_t* topic, const uint8_t* message, size_t len) {
    if (!topic) return 0;
    return topic->handle.publish(to_cpp_bytes(message, len));
}

size_t epx_topic_subscriber_count(const epx_topic_t* topic) {
    return topic ? topic->handle.subscriber_count() : 0;
}

void epx_topic_free(epx_topic_t* topic) { delete topic; }

void epx_host_on_authorization_prompt(epx_host_t* host, epx_prompt_fn prompt, void* user_data) {
    if (!host) return;
    if (!prompt) {
        host->host.on_authorization_prompt(nullptr);
        return;
    }
    host->host.on_authorization_prompt(
        [prompt, user_data](const epx::PeerInfo& peer, const std::string& endpoint,
                            const std::string& reason) -> epx::PromptDecision {
            epx_peer_info_t cpeer;
            fill_peer(cpeer, peer);
            return static_cast<epx::PromptDecision>(prompt(&cpeer, endpoint.c_str(), reason.c_str(), user_data));
        });
}

void epx_host_add_issuer(epx_host_t* host, const uint8_t issuer_public_key[32]) {
    if (host && issuer_public_key) host->host.add_issuer(to_pk(issuer_public_key));
}

int epx_host_add_credential(epx_host_t* host, const char* credential_text) {
    if (!host || !credential_text) return 0;
    return host->host.add_credential(credential_text) ? 1 : 0;
}

void epx_host_set_default_access(epx_host_t* host, epx_access_tier_t tier, const char* prompt_reason) {
    if (host) host->host.set_default_access(to_policy(tier, prompt_reason));
}

void epx_host_set_limits(epx_host_t* host, const epx_connection_limits_t* limits) {
    if (!host || !limits) return;
    epx::ConnectionLimits l;
    l.handshakes_per_uid_per_sec = limits->handshakes_per_uid_per_sec;
    l.handshake_burst = limits->handshake_burst;
    l.max_requests_per_sec = limits->max_requests_per_sec;
    l.request_burst = limits->request_burst;
    l.disconnect_after_delayed = limits->disconnect_after_delayed;
    l.max_subscriptions = limits->max_subscriptions;
    l.stream_write_timeout_ms = limits->stream_write_timeout_ms;
    host->host.set_limits(l);
}

void epx_host_set_description(epx_host_t* host, const char* description) {
    if (host) host->host.set_description(description ? description : "");
}

void epx_host_allow_peer(epx_host_t* host, const uint8_t peer_public_key[32]) {
    if (host && peer_public_key) host->host.allow_peer(to_pk(peer_public_key));
}

epx_status_t epx_host_run(epx_host_t* host) {
    if (!host) { t_last_error = "NULL host"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] { host->host.run(); });
}

void epx_host_stop(epx_host_t* host) { if (host) host->host.stop(); }
void epx_host_request_stop(epx_host_t* host) { if (host) host->host.request_stop(); }
int epx_host_stopped(const epx_host_t* host) { return host ? (host->host.stopped() ? 1 : 0) : 1; }
void epx_host_wait_until_stopped(epx_host_t* host) { if (host) host->host.wait_until_stopped(); }

void epx_host_stop_on_signals(epx_host_t* host, const int* signals, size_t count) {
    if (!host || !signals) return;
    /* std::initializer_list can't be built at runtime; forward each one. */
    for (size_t i = 0; i < count; ++i) host->host.stop_on_signals({signals[i]});
}

void epx_host_before_stop(epx_host_t* host, epx_hook_fn hook, void* user_data) {
    if (host && hook) host->host.before_stop([hook, user_data] { hook(user_data); });
}

void epx_host_after_stop(epx_host_t* host, epx_hook_fn hook, void* user_data) {
    if (host && hook) host->host.after_stop([hook, user_data] { hook(user_data); });
}

void epx_host_public_key(const epx_host_t* host, uint8_t out_key[32]) {
    if (host && out_key) std::memcpy(out_key, host->host.public_key().data(), 32);
}

/* ---- client ----------------------------------------------------------- */

epx_status_t epx_client_create(const epx_identity_t* identity, epx_trust_policy_t policy,
                               epx_client_t** out_client) {
    if (!identity || !out_client) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        *out_client = new epx_client{epx::Client(identity->id, static_cast<epx::TrustPolicy>(policy))};
    });
}

void epx_client_free(epx_client_t* client) { delete client; }

void epx_client_allow_peer(epx_client_t* client, const uint8_t peer_public_key[32]) {
    if (client && peer_public_key) client->client.allow_peer(to_pk(peer_public_key));
}

void epx_client_public_key(const epx_client_t* client, uint8_t out_key[32]) {
    if (client && out_key) std::memcpy(out_key, client->client.public_key().data(), 32);
}

epx_status_t epx_client_get(epx_client_t* client, const char* service, const char* endpoint,
                            const uint8_t* data, size_t len, uint32_t timeout_ms,
                            epx_bytes_t* out_response) {
    if (!client || !service || !endpoint || !out_response) {
        t_last_error = "NULL argument";
        return EPX_ERR_INVALID_ARGUMENT;
    }
    return guarded([&] {
        auto resp = client->client.get(service, endpoint, to_cpp_bytes(data, len),
                                        std::chrono::milliseconds(timeout_ms ? timeout_ms : 5000));
        *out_response = to_c_bytes(resp);
    });
}

epx_status_t epx_client_send(epx_client_t* client, const char* service, const char* endpoint,
                             const uint8_t* data, size_t len) {
    if (!client || !service || !endpoint) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] { client->client.send(service, endpoint, to_cpp_bytes(data, len)); });
}

epx_status_t epx_client_get_stream(epx_client_t* client, const char* service, const char* endpoint,
                                   const uint8_t* data, size_t len,
                                   epx_chunk_fn on_chunk, void* user_data, uint32_t timeout_ms) {
    if (!client || !service || !endpoint || !on_chunk) {
        t_last_error = "NULL argument";
        return EPX_ERR_INVALID_ARGUMENT;
    }
    return guarded([&] {
        client->client.get_stream(service, endpoint, to_cpp_bytes(data, len),
                                   [on_chunk, user_data](const epx::Bytes& chunk, bool is_last) {
                                       on_chunk(chunk.empty() ? nullptr : chunk.data(), chunk.size(),
                                                is_last ? 1 : 0, user_data);
                                   },
                                   std::chrono::milliseconds(timeout_ms ? timeout_ms : 5000));
    });
}

epx_status_t epx_client_open_stream(epx_client_t* client, const char* service, const char* endpoint,
                                    epx_output_stream_t** out_stream) {
    if (!client || !service || !endpoint || !out_stream) {
        t_last_error = "NULL argument";
        return EPX_ERR_INVALID_ARGUMENT;
    }
    return guarded([&] {
        *out_stream = new epx_output_stream{client->client.open_stream(service, endpoint)};
    });
}

int epx_output_stream_write(epx_output_stream_t* stream, const uint8_t* chunk, size_t len) {
    if (!stream) return 0;
    return stream->stream.write(to_cpp_bytes(chunk, len)) ? 1 : 0;
}

void epx_output_stream_finish(epx_output_stream_t* stream) { if (stream) stream->stream.finish(); }
void epx_output_stream_free(epx_output_stream_t* stream) { delete stream; } /* dtor finishes */

epx_status_t epx_client_subscribe(epx_client_t* client, const char* service, const char* topic,
                                  epx_topic_msg_fn on_message, void* user_data,
                                  epx_subscription_t** out_subscription) {
    if (!client || !service || !topic || !on_message || !out_subscription) {
        t_last_error = "NULL argument";
        return EPX_ERR_INVALID_ARGUMENT;
    }
    return guarded([&] {
        auto sub = client->client.subscribe(service, topic,
            [on_message, user_data](const epx::Bytes& message, bool closed) {
                on_message(message.empty() ? nullptr : message.data(), message.size(),
                           closed ? 1 : 0, user_data);
            });
        *out_subscription = new epx_subscription{std::move(sub)};
    });
}

void epx_subscription_unsubscribe(epx_subscription_t* subscription) {
    if (subscription) subscription->sub.unsubscribe();
}

int epx_subscription_active(const epx_subscription_t* subscription) {
    return subscription ? (subscription->sub.active() ? 1 : 0) : 0;
}

void epx_subscription_free(epx_subscription_t* subscription) { delete subscription; }

void epx_client_disconnect(epx_client_t* client, const char* service) {
    if (client && service) client->client.disconnect(service);
}

void epx_client_set_stream_write_timeout(epx_client_t* client, int32_t ms) {
    if (client) client->client.set_stream_write_timeout(ms);
}

void epx_client_enable_key_rotation(epx_client_t* client, uint64_t interval_seconds, uint64_t max_bytes) {
    if (!client) return;
    epx::RotationPolicy p;
    p.interval = std::chrono::seconds(interval_seconds);
    p.max_bytes = max_bytes;
    client->client.enable_key_rotation(p);
}

int32_t epx_client_session_epoch(const epx_client_t* client, const char* service) {
    if (!client || !service) return -1;
    return client->client.session_epoch(service);
}

/* ---- service enumeration ---------------------------------------------- */

epx_status_t epx_list_services(char*** out_names, size_t* out_count) {
    if (!out_names || !out_count) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        auto names = epx::list_services();
        char** list = static_cast<char**>(std::malloc(sizeof(char*) * (names.empty() ? 1 : names.size())));
        for (size_t i = 0; i < names.size(); ++i) list[i] = to_c_string(names[i]);
        *out_names = list;
        *out_count = names.size();
    });
}

epx_status_t epx_describe(const char* service, epx_service_description_t** out_description) {
    if (!service || !out_description) { t_last_error = "NULL argument"; return EPX_ERR_INVALID_ARGUMENT; }
    return guarded([&] {
        auto d = epx::describe(service);
        if (!d) throw epx::EpxError(epx::EpxError::Code::NotFound,
                                     std::string("no live service registered as '") + service + "'");
        auto* out = static_cast<epx_service_description_t*>(std::malloc(sizeof(epx_service_description_t)));
        out->service_name = to_c_string(d->service_name);
        out->description = to_c_string(d->description);
        out->pid = d->pid;
        std::memcpy(out->identity_pubkey, d->identity_pubkey.data(), 32);
        out->endpoint_count = d->endpoints.size();
        out->endpoints = static_cast<epx_endpoint_desc_t*>(
            std::malloc(sizeof(epx_endpoint_desc_t) * (d->endpoints.empty() ? 1 : d->endpoints.size())));
        for (size_t i = 0; i < d->endpoints.size(); ++i) {
            out->endpoints[i].name = to_c_string(d->endpoints[i].name);
            out->endpoints[i].kind = static_cast<epx_endpoint_kind_t>(d->endpoints[i].kind);
        }
        *out_description = out;
    });
}

void epx_service_description_free(epx_service_description_t* description) {
    if (!description) return;
    std::free(description->service_name);
    std::free(description->description);
    for (size_t i = 0; i < description->endpoint_count; ++i) std::free(description->endpoints[i].name);
    std::free(description->endpoints);
    std::free(description);
}

} /* extern "C" */
