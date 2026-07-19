/* EPX — Encrypted Process eXchange: stable C ABI.
 *
 * This is THE binding surface: every language binding (Rust, Python,
 * Node, Go, C#, Swift, Ruby, Dart) links against this header + the
 * libepx_c shared library and nothing else. No C++ type ever crosses
 * this boundary; no exception ever propagates through it.
 *
 * Conventions, once, for every function below:
 *
 *  - HANDLES are opaque pointers (epx_host_t*, ...). Create with the
 *    matching *_create or *_load function, destroy with the matching *_free.
 *    Every *_free tolerates NULL. Handles are NOT thread-safe to destroy
 *    while other calls on the same handle are in flight; everything else
 *    is as thread-safe as the underlying C++ API (hosts/clients are).
 *
 *  - ERRORS: functions that can fail return epx_status_t. On any nonzero
 *    return, epx_last_error() gives a human-readable message for the
 *    calling thread (valid until that thread's next failing epx_* call).
 *
 *  - BYTE BUFFERS in: (const uint8_t* data, size_t len) — borrowed for
 *    the duration of the call only; the library copies what it keeps.
 *    NULL data with len 0 is a valid empty buffer.
 *
 *  - BYTE BUFFERS out: epx_bytes_t owned by the CALLER, released with
 *    epx_bytes_free(). Same ownership rule for out-strings
 *    (epx_string_free) and lists. This is the single ownership rule of
 *    the whole ABI: if a function hands you memory, you free it with the
 *    matching epx_*_free — never with free()/delete directly.
 *
 *  - CALLBACK THREADING (bindings: read this twice; you almost certainly
 *    need a thread-hop into your runtime):
 *      * epx_handler_fn, epx_stream_recv_fn, epx_stream_send_fn, and
 *        epx_prompt_fn run on the HOST's per-connection worker threads —
 *        never the thread that called epx_host_run().
 *      * epx_chunk_fn (get_stream) runs on the CLIENT connection's
 *        background reader thread while the calling thread blocks.
 *      * epx_topic_msg_fn runs on the CLIENT connection's background
 *        reader thread, at any time after epx_client_subscribe returns.
 *      * epx_hook_fn (before/after stop) runs on whichever thread called
 *        epx_host_stop()/epx_host_wait_until_stopped().
 *    Every callback receives the void* user_data it was registered with,
 *    unchanged. Callbacks must not throw (C can't) and must not call
 *    *_free on the handle that is invoking them.
 *
 * Versioning: EPX_C_ABI_VERSION bumps on ANY breaking change to this
 * header. A binding should call epx_c_abi_version() at load time and
 * refuse to run against a mismatched library — loudly failing beats
 * silently corrupting memory.
 */
#ifndef EPX_C_H
#define EPX_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  if defined(EPX_C_BUILDING)
#    define EPX_C_API __declspec(dllexport)
#  else
#    define EPX_C_API __declspec(dllimport)
#  endif
#else
#  define EPX_C_API __attribute__((visibility("default")))
#endif

/* ---- version ---------------------------------------------------------- */

#define EPX_C_ABI_VERSION 1

EPX_C_API uint32_t epx_c_abi_version(void);
/* The underlying core library's release version, e.g. "2.1.0". Static
 * storage — do not free. */
EPX_C_API const char* epx_version_string(void);

/* ---- status / errors -------------------------------------------------- */

typedef enum epx_status {
    EPX_OK = 0,
    EPX_ERR_TIMEOUT = 1,
    EPX_ERR_CONNECT_FAILED = 2,
    EPX_ERR_HANDSHAKE_REJECTED = 3,
    EPX_ERR_NOT_FOUND = 4,
    EPX_ERR_TRANSPORT = 5,
    EPX_ERR_PROTOCOL = 6,
    EPX_ERR_ACCESS_DENIED = 7,
    EPX_ERR_RATE_LIMITED = 8,
    EPX_ERR_INVALID_ARGUMENT = 100,
    EPX_ERR_INTERNAL = 101
} epx_status_t;

/* Message for the calling thread's most recent failing epx_* call.
 * Thread-local; never NULL; do not free. */
EPX_C_API const char* epx_last_error(void);

/* ---- memory ----------------------------------------------------------- */

typedef struct epx_bytes {
    uint8_t* data; /* NULL iff len == 0 */
    size_t len;
} epx_bytes_t;

EPX_C_API void epx_bytes_free(epx_bytes_t bytes);
EPX_C_API void epx_string_free(char* s);
EPX_C_API void epx_string_list_free(char** list, size_t count);

/* ---- enums mirroring the C++ API -------------------------------------- */

typedef enum epx_trust_policy {
    EPX_TRUST_ON_FIRST_USE = 0,
    EPX_TRUST_REQUIRE_KNOWN_PEER = 1,
    EPX_TRUST_ALLOW_ALL = 2
} epx_trust_policy_t;

typedef enum epx_endpoint_kind {
    EPX_KIND_RECEIVE = 0,
    EPX_KIND_SEND = 1,
    EPX_KIND_STREAM_RECEIVE = 2,
    EPX_KIND_STREAM_SEND = 3,
    EPX_KIND_TOPIC = 4
} epx_endpoint_kind_t;

typedef enum epx_access_tier {
    EPX_ACCESS_OPEN = 0,
    EPX_ACCESS_PINNED_PEERS = 1,
    EPX_ACCESS_CERTIFICATE = 2,
    EPX_ACCESS_PROMPT_USER = 3
} epx_access_tier_t;

typedef enum epx_prompt_decision {
    EPX_PROMPT_DENY = 0,
    EPX_PROMPT_ALLOW_ONCE = 1,
    EPX_PROMPT_ALWAYS_ALLOW = 2
} epx_prompt_decision_t;

/* The remote party of a request, for authorization decisions. Borrowed:
 * valid only for the duration of the callback it is passed to. */
typedef struct epx_peer_info {
    uint8_t public_key[32];
    long peer_uid;           /* OS-verified UID, -1 if unavailable */
    int key_was_pinned_now;  /* nonzero on a brand-new TOFU recording */
} epx_peer_info_t;

/* ---- opaque handles --------------------------------------------------- */

typedef struct epx_identity epx_identity_t;
typedef struct epx_host epx_host_t;
typedef struct epx_client epx_client_t;
typedef struct epx_output_stream epx_output_stream_t;
typedef struct epx_topic epx_topic_t;
typedef struct epx_subscription epx_subscription_t;
typedef struct epx_response_writer epx_response_writer_t; /* only inside epx_handler_fn */
typedef struct epx_stream_writer epx_stream_writer_t;     /* only inside epx_stream_send_fn */

/* ---- identity --------------------------------------------------------- */

EPX_C_API epx_status_t epx_identity_load_or_create(const char* app_name, epx_identity_t** out_identity);
EPX_C_API void epx_identity_free(epx_identity_t* identity);
EPX_C_API void epx_identity_public_key(const epx_identity_t* identity, uint8_t out_key[32]);

/* ---- credentials (AccessTier certificate) ----------------------------- */

/* Serialized credential text, caller-owned (epx_string_free). `scope` is
 * "service" or "service/endpoint"; expires_unix 0 = never. */
EPX_C_API epx_status_t epx_make_credential(const epx_identity_t* issuer,
                                           const uint8_t peer_public_key[32],
                                           const char* scope,
                                           uint64_t expires_unix,
                                           char** out_credential_text);

/* ---- host ------------------------------------------------------------- */

EPX_C_API epx_status_t epx_host_create(const char* service_name,
                                       const epx_identity_t* identity,
                                       epx_trust_policy_t policy,
                                       epx_host_t** out_host);
/* Implies epx_host_stop() if still running. */
EPX_C_API void epx_host_free(epx_host_t* host);

/* Unary handler (Receive/Send endpoints). Respond through `response`
 * (valid only until the callback returns): call exactly one of
 * epx_respond_ok / epx_respond_error, or neither for an empty-ok. For
 * EPX_KIND_SEND endpoints the response is never transmitted. */
typedef void (*epx_handler_fn)(const uint8_t* request, size_t request_len,
                               const char* endpoint,
                               const epx_peer_info_t* peer,
                               epx_response_writer_t* response,
                               void* user_data);
EPX_C_API void epx_respond_ok(epx_response_writer_t* response, const uint8_t* data, size_t len);
EPX_C_API void epx_respond_error(epx_response_writer_t* response, const char* message);

EPX_C_API epx_status_t epx_host_expose(epx_host_t* host,
                                       epx_endpoint_kind_t kind, /* RECEIVE or SEND */
                                       const char* endpoint,
                                       epx_handler_fn handler,
                                       void* user_data);
EPX_C_API epx_status_t epx_host_expose_access(epx_host_t* host,
                                              epx_endpoint_kind_t kind,
                                              const char* endpoint,
                                              epx_handler_fn handler,
                                              void* user_data,
                                              epx_access_tier_t tier,
                                              const char* prompt_reason /* may be NULL */);

/* StreamReceive: invoked once per inbound chunk. */
typedef void (*epx_stream_recv_fn)(const uint8_t* chunk, size_t chunk_len, int is_last,
                                   const char* endpoint,
                                   const epx_peer_info_t* peer,
                                   void* user_data);
EPX_C_API epx_status_t epx_host_expose_stream_receive(epx_host_t* host, const char* endpoint,
                                                      epx_stream_recv_fn handler, void* user_data);
EPX_C_API epx_status_t epx_host_expose_stream_receive_access(epx_host_t* host, const char* endpoint,
                                                             epx_stream_recv_fn handler, void* user_data,
                                                             epx_access_tier_t tier, const char* prompt_reason);

/* StreamSend: push chunks through `out` (valid only until the callback
 * returns); the end-of-stream marker is sent automatically afterwards.
 * epx_stream_writer_write returns 1 on success, 0 when the peer is gone
 * or the write timed out (backpressure) — stop producing on 0. */
typedef void (*epx_stream_send_fn)(epx_stream_writer_t* out,
                                   const uint8_t* request, size_t request_len,
                                   const char* endpoint,
                                   const epx_peer_info_t* peer,
                                   void* user_data);
EPX_C_API int epx_stream_writer_write(epx_stream_writer_t* out, const uint8_t* chunk, size_t len);
EPX_C_API epx_status_t epx_host_expose_stream_send(epx_host_t* host, const char* endpoint,
                                                   epx_stream_send_fn handler, void* user_data);
EPX_C_API epx_status_t epx_host_expose_stream_send_access(epx_host_t* host, const char* endpoint,
                                                          epx_stream_send_fn handler, void* user_data,
                                                          epx_access_tier_t tier, const char* prompt_reason);

/* Topic (pub/sub). The returned epx_topic_t* is owned by the caller
 * (epx_topic_free) and stays usable until the HOST is freed; freeing the
 * topic handle does not close the topic. */
EPX_C_API epx_status_t epx_host_expose_topic(epx_host_t* host, const char* topic, epx_topic_t** out_topic);
EPX_C_API epx_status_t epx_host_expose_topic_access(epx_host_t* host, const char* topic,
                                                    epx_access_tier_t tier, const char* prompt_reason,
                                                    epx_topic_t** out_topic);
/* Returns the number of subscribers the message was delivered to.
 * Callable from any thread. */
EPX_C_API size_t epx_topic_publish(epx_topic_t* topic, const uint8_t* message, size_t len);
EPX_C_API size_t epx_topic_subscriber_count(const epx_topic_t* topic);
EPX_C_API void epx_topic_free(epx_topic_t* topic);

/* Authorization (see the C++ AccessTier docs). */
typedef epx_prompt_decision_t (*epx_prompt_fn)(const epx_peer_info_t* peer,
                                               const char* endpoint,
                                               const char* reason,
                                               void* user_data);
EPX_C_API void epx_host_on_authorization_prompt(epx_host_t* host, epx_prompt_fn prompt, void* user_data);
EPX_C_API void epx_host_add_issuer(epx_host_t* host, const uint8_t issuer_public_key[32]);
/* Returns 1 if the credential parsed + verified, 0 otherwise. */
EPX_C_API int epx_host_add_credential(epx_host_t* host, const char* credential_text);
EPX_C_API void epx_host_set_default_access(epx_host_t* host, epx_access_tier_t tier, const char* prompt_reason);

/* Rate limiting / flow control (all zeros = unlimited, the default). */
typedef struct epx_connection_limits {
    uint32_t handshakes_per_uid_per_sec;
    uint32_t handshake_burst;
    uint32_t max_requests_per_sec;
    uint32_t request_burst;
    uint32_t disconnect_after_delayed;
    uint32_t max_subscriptions;
    int32_t stream_write_timeout_ms;
} epx_connection_limits_t;
EPX_C_API void epx_host_set_limits(epx_host_t* host, const epx_connection_limits_t* limits);

EPX_C_API void epx_host_set_description(epx_host_t* host, const char* description);
EPX_C_API void epx_host_allow_peer(epx_host_t* host, const uint8_t peer_public_key[32]);

/* Non-blocking (binds + returns); see the C++ Host::run docs. */
EPX_C_API epx_status_t epx_host_run(epx_host_t* host);
EPX_C_API void epx_host_stop(epx_host_t* host);
EPX_C_API void epx_host_request_stop(epx_host_t* host); /* async-signal-safe */
EPX_C_API int epx_host_stopped(const epx_host_t* host);
EPX_C_API void epx_host_wait_until_stopped(epx_host_t* host);
EPX_C_API void epx_host_stop_on_signals(epx_host_t* host, const int* signals, size_t count);

typedef void (*epx_hook_fn)(void* user_data);
EPX_C_API void epx_host_before_stop(epx_host_t* host, epx_hook_fn hook, void* user_data);
EPX_C_API void epx_host_after_stop(epx_host_t* host, epx_hook_fn hook, void* user_data);

EPX_C_API void epx_host_public_key(const epx_host_t* host, uint8_t out_key[32]);

/* ---- client ----------------------------------------------------------- */

EPX_C_API epx_status_t epx_client_create(const epx_identity_t* identity,
                                         epx_trust_policy_t policy,
                                         epx_client_t** out_client);
EPX_C_API void epx_client_free(epx_client_t* client);
EPX_C_API void epx_client_allow_peer(epx_client_t* client, const uint8_t peer_public_key[32]);
EPX_C_API void epx_client_public_key(const epx_client_t* client, uint8_t out_key[32]);

/* Request/response. On EPX_OK, *out_response is caller-owned
 * (epx_bytes_free). timeout_ms 0 = the library default (5000). */
EPX_C_API epx_status_t epx_client_get(epx_client_t* client,
                                      const char* service, const char* endpoint,
                                      const uint8_t* data, size_t len,
                                      uint32_t timeout_ms,
                                      epx_bytes_t* out_response);

EPX_C_API epx_status_t epx_client_send(epx_client_t* client,
                                       const char* service, const char* endpoint,
                                       const uint8_t* data, size_t len);

/* Blocks until the stream ends / stalls past timeout_ms (0 = default
 * 5000; it's a stall timeout, reset by every chunk). on_chunk runs on the
 * connection's reader thread, including once with is_last=1. */
typedef void (*epx_chunk_fn)(const uint8_t* chunk, size_t len, int is_last, void* user_data);
EPX_C_API epx_status_t epx_client_get_stream(epx_client_t* client,
                                             const char* service, const char* endpoint,
                                             const uint8_t* data, size_t len,
                                             epx_chunk_fn on_chunk, void* user_data,
                                             uint32_t timeout_ms);

/* Client->host chunk stream. Write returns 1 ok / 0 dead-or-backpressured.
 * epx_output_stream_free implies finish. */
EPX_C_API epx_status_t epx_client_open_stream(epx_client_t* client,
                                              const char* service, const char* endpoint,
                                              epx_output_stream_t** out_stream);
EPX_C_API int epx_output_stream_write(epx_output_stream_t* stream, const uint8_t* chunk, size_t len);
EPX_C_API void epx_output_stream_finish(epx_output_stream_t* stream);
EPX_C_API void epx_output_stream_free(epx_output_stream_t* stream);

/* Topic subscription. on_message runs on the connection's reader thread;
 * the final delivery has closed=1 (host shutdown, refusal, connection
 * loss). epx_subscription_free implies unsubscribe. */
typedef void (*epx_topic_msg_fn)(const uint8_t* message, size_t len, int closed, void* user_data);
EPX_C_API epx_status_t epx_client_subscribe(epx_client_t* client,
                                            const char* service, const char* topic,
                                            epx_topic_msg_fn on_message, void* user_data,
                                            epx_subscription_t** out_subscription);
EPX_C_API void epx_subscription_unsubscribe(epx_subscription_t* subscription);
EPX_C_API int epx_subscription_active(const epx_subscription_t* subscription);
EPX_C_API void epx_subscription_free(epx_subscription_t* subscription);

EPX_C_API void epx_client_disconnect(epx_client_t* client, const char* service);
EPX_C_API void epx_client_set_stream_write_timeout(epx_client_t* client, int32_t ms);

/* Key rotation (EXPERIMENTAL — see the C++ RotationPolicy docs and SPEC
 * 6.4; off unless enabled, pending external cryptographic review). */
EPX_C_API void epx_client_enable_key_rotation(epx_client_t* client,
                                              uint64_t interval_seconds,
                                              uint64_t max_bytes);
/* Current key epoch of the open session (0 before any rotation), or -1
 * if no session is open to `service`. */
EPX_C_API int32_t epx_client_session_epoch(const epx_client_t* client, const char* service);

/* ---- service enumeration ---------------------------------------------- */

/* Names of every live registered service; caller frees with
 * epx_string_list_free(names, count). Unauthenticated metadata. */
EPX_C_API epx_status_t epx_list_services(char*** out_names, size_t* out_count);

typedef struct epx_endpoint_desc {
    char* name;
    epx_endpoint_kind_t kind;
} epx_endpoint_desc_t;

typedef struct epx_service_description {
    char* service_name;
    char* description; /* may be empty, never NULL */
    long pid;
    uint8_t identity_pubkey[32];
    epx_endpoint_desc_t* endpoints;
    size_t endpoint_count;
} epx_service_description_t;

EPX_C_API epx_status_t epx_describe(const char* service, epx_service_description_t** out_description);
EPX_C_API void epx_service_description_free(epx_service_description_t* description);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* EPX_C_H */
