/* C ABI test suite: exercises the shim end to end from pure C, over real
 * sockets, mirroring the C++ core's own coverage:
 *   - abi/version sanity
 *   - identity round trip
 *   - Receive echo + application error + not-found mapping
 *   - fire-and-forget Send
 *   - StreamSend (host->client chunks) and StreamReceive (client->host)
 *   - Topic publish/subscribe + unsubscribe + closed delivery
 *   - AccessTier prompt deny -> EPX_ERR_ACCESS_DENIED
 *   - credential mint + install
 *   - service enumeration (list + describe)
 */
#include <epx/epx_c.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failures = 0;
#define CHECK(cond)                                                        \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "CHECK FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failures++;                                                   \
        }                                                                   \
    } while (0)

static void msleep(int ms) { usleep(ms * 1000); }

/* ---- handlers --------------------------------------------------------- */

static void echo_handler(const uint8_t* req, size_t len, const char* endpoint,
                         const epx_peer_info_t* peer, epx_response_writer_t* resp, void* ud) {
    (void)endpoint; (void)peer; (void)ud;
    epx_respond_ok(resp, req, len);
}

static void fail_handler(const uint8_t* req, size_t len, const char* endpoint,
                         const epx_peer_info_t* peer, epx_response_writer_t* resp, void* ud) {
    (void)req; (void)len; (void)endpoint; (void)peer; (void)ud;
    epx_respond_error(resp, "deliberate failure");
}

static int g_send_received = 0;
static void send_handler(const uint8_t* req, size_t len, const char* endpoint,
                         const epx_peer_info_t* peer, epx_response_writer_t* resp, void* ud) {
    (void)endpoint; (void)peer; (void)resp; (void)ud;
    if (len == 3 && memcmp(req, "hey", 3) == 0) g_send_received = 1;
}

static void countdown_handler(epx_stream_writer_t* out, const uint8_t* req, size_t len,
                              const char* endpoint, const epx_peer_info_t* peer, void* ud) {
    (void)req; (void)len; (void)endpoint; (void)peer; (void)ud;
    for (uint8_t i = 5; i > 0; i--) {
        CHECK(epx_stream_writer_write(out, &i, 1) == 1);
    }
}

static int g_upload_chunks = 0;
static int g_upload_done = 0;
static void upload_handler(const uint8_t* chunk, size_t len, int is_last, const char* endpoint,
                           const epx_peer_info_t* peer, void* ud) {
    (void)chunk; (void)endpoint; (void)peer; (void)ud;
    if (len > 0) g_upload_chunks++;
    if (is_last) g_upload_done = 1;
}

static epx_prompt_decision_t deny_prompt(const epx_peer_info_t* peer, const char* endpoint,
                                         const char* reason, void* ud) {
    (void)peer; (void)endpoint; (void)reason; (void)ud;
    return EPX_PROMPT_DENY;
}

/* ---- stream/topic client callbacks ------------------------------------ */

static uint8_t g_chunks[16];
static int g_chunk_count = 0;
static int g_stream_last = 0;
static void on_chunk(const uint8_t* chunk, size_t len, int is_last, void* ud) {
    (void)ud;
    if (len == 1 && g_chunk_count < 16) g_chunks[g_chunk_count++] = chunk[0];
    if (is_last) g_stream_last = 1;
}

static int g_topic_msgs = 0;
static int g_topic_closed = 0;
static void on_topic_msg(const uint8_t* msg, size_t len, int closed, void* ud) {
    (void)ud;
    if (closed) { g_topic_closed++; return; }
    if (len == 4 && memcmp(msg, "news", 4) == 0) g_topic_msgs++;
}

int main(void) {
    CHECK(epx_c_abi_version() == EPX_C_ABI_VERSION);
    CHECK(strlen(epx_version_string()) >= 5); /* "2.1.0" */

    epx_identity_t* hid = NULL;
    CHECK(epx_identity_load_or_create("epx.test.c.host", &hid) == EPX_OK);
    uint8_t hpk[32] = {0};
    epx_identity_public_key(hid, hpk);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero |= hpk[i];
    CHECK(nonzero != 0);

    epx_host_t* host = NULL;
    CHECK(epx_host_create("epx.test.c.host", hid, EPX_TRUST_ON_FIRST_USE, &host) == EPX_OK);
    epx_host_set_description(host, "C ABI test host");
    CHECK(epx_host_expose(host, EPX_KIND_RECEIVE, "echo", echo_handler, NULL) == EPX_OK);
    CHECK(epx_host_expose(host, EPX_KIND_RECEIVE, "fail", fail_handler, NULL) == EPX_OK);
    CHECK(epx_host_expose(host, EPX_KIND_SEND, "notify", send_handler, NULL) == EPX_OK);
    CHECK(epx_host_expose_stream_send(host, "countdown", countdown_handler, NULL) == EPX_OK);
    CHECK(epx_host_expose_stream_receive(host, "upload", upload_handler, NULL) == EPX_OK);
    epx_topic_t* topic = NULL;
    CHECK(epx_host_expose_topic(host, "feed", &topic) == EPX_OK);
    CHECK(epx_host_expose_access(host, EPX_KIND_RECEIVE, "secret", echo_handler, NULL,
                                 EPX_ACCESS_PROMPT_USER, "test reason") == EPX_OK);
    epx_host_on_authorization_prompt(host, deny_prompt, NULL);
    CHECK(epx_host_run(host) == EPX_OK);
    msleep(150);

    epx_identity_t* cid = NULL;
    CHECK(epx_identity_load_or_create("epx.test.c.client", &cid) == EPX_OK);
    epx_client_t* client = NULL;
    CHECK(epx_client_create(cid, EPX_TRUST_ON_FIRST_USE, &client) == EPX_OK);

    /* echo round trip */
    {
        epx_bytes_t out = {NULL, 0};
        const uint8_t msg[] = "ping!";
        CHECK(epx_client_get(client, "epx.test.c.host", "echo", msg, 5, 0, &out) == EPX_OK);
        CHECK(out.len == 5 && memcmp(out.data, "ping!", 5) == 0);
        epx_bytes_free(out);
    }

    /* application error -> EPX_ERR_PROTOCOL with message */
    {
        epx_bytes_t out = {NULL, 0};
        CHECK(epx_client_get(client, "epx.test.c.host", "fail", NULL, 0, 0, &out) == EPX_ERR_PROTOCOL);
        CHECK(strstr(epx_last_error(), "deliberate failure") != NULL);
    }

    /* unknown endpoint -> EPX_ERR_NOT_FOUND */
    {
        epx_bytes_t out = {NULL, 0};
        CHECK(epx_client_get(client, "epx.test.c.host", "nope", NULL, 0, 0, &out) == EPX_ERR_NOT_FOUND);
    }

    /* unknown service -> EPX_ERR_NOT_FOUND */
    {
        epx_bytes_t out = {NULL, 0};
        CHECK(epx_client_get(client, "epx.test.c.ghost", "echo", NULL, 0, 0, &out) == EPX_ERR_NOT_FOUND);
    }

    /* fire-and-forget */
    {
        const uint8_t msg[] = "hey";
        CHECK(epx_client_send(client, "epx.test.c.host", "notify", msg, 3) == EPX_OK);
        msleep(150);
        CHECK(g_send_received == 1);
    }

    /* host->client stream */
    {
        CHECK(epx_client_get_stream(client, "epx.test.c.host", "countdown", NULL, 0,
                                    on_chunk, NULL, 0) == EPX_OK);
        CHECK(g_chunk_count == 5);
        CHECK(g_stream_last == 1);
        CHECK(g_chunks[0] == 5 && g_chunks[4] == 1);
    }

    /* client->host stream */
    {
        epx_output_stream_t* up = NULL;
        CHECK(epx_client_open_stream(client, "epx.test.c.host", "upload", &up) == EPX_OK);
        const uint8_t part[] = "part";
        CHECK(epx_output_stream_write(up, part, 4) == 1);
        CHECK(epx_output_stream_write(up, part, 4) == 1);
        CHECK(epx_output_stream_write(up, part, 4) == 1);
        epx_output_stream_free(up); /* implies finish */
        msleep(200);
        CHECK(g_upload_chunks == 3);
        CHECK(g_upload_done == 1);
    }

    /* topic pub/sub */
    {
        epx_subscription_t* sub = NULL;
        CHECK(epx_client_subscribe(client, "epx.test.c.host", "feed", on_topic_msg, NULL, &sub) == EPX_OK);
        msleep(200);
        CHECK(epx_topic_subscriber_count(topic) == 1);
        CHECK(epx_topic_publish(topic, (const uint8_t*)"news", 4) == 1);
        msleep(200);
        CHECK(g_topic_msgs == 1);
        CHECK(epx_subscription_active(sub) == 1);
        epx_subscription_unsubscribe(sub);
        CHECK(epx_subscription_active(sub) == 0);
        msleep(200);
        CHECK(epx_topic_subscriber_count(topic) == 0);
        epx_subscription_free(sub);
    }

    /* prompt deny -> access denied */
    {
        epx_bytes_t out = {NULL, 0};
        CHECK(epx_client_get(client, "epx.test.c.host", "secret", NULL, 0, 0, &out) == EPX_ERR_ACCESS_DENIED);
    }

    /* credentials mint + install */
    {
        char* cred = NULL;
        uint8_t cpk[32];
        epx_identity_public_key(cid, cpk);
        CHECK(epx_make_credential(hid, cpk, "epx.test.c.host", 0, &cred) == EPX_OK);
        CHECK(cred != NULL && strstr(cred, "epx-credential-v1") == cred);
        CHECK(epx_host_add_credential(host, cred) == 1);
        CHECK(epx_host_add_credential(host, "garbage") == 0);
        epx_string_free(cred);
    }

    /* enumeration */
    {
        char** names = NULL;
        size_t count = 0;
        CHECK(epx_list_services(&names, &count) == EPX_OK);
        int found = 0;
        for (size_t i = 0; i < count; i++) {
            if (strcmp(names[i], "epx.test.c.host") == 0) found = 1;
        }
        CHECK(found == 1);
        epx_string_list_free(names, count);

        epx_service_description_t* d = NULL;
        CHECK(epx_describe("epx.test.c.host", &d) == EPX_OK);
        CHECK(strcmp(d->service_name, "epx.test.c.host") == 0);
        CHECK(strcmp(d->description, "C ABI test host") == 0);
        CHECK(d->endpoint_count == 7); /* echo, fail, notify, countdown, upload, feed, secret */
        epx_service_description_free(d);

        CHECK(epx_describe("epx.test.c.ghost2", &d) == EPX_ERR_NOT_FOUND);
    }

    epx_topic_free(topic);
    epx_client_free(client);
    epx_host_free(host);
    epx_identity_free(cid);
    epx_identity_free(hid);

    if (g_failures > 0) {
        fprintf(stderr, "\n%d check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
