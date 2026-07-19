/* C ABI port of EPX-CORE/examples/expose_demo.cpp: exposes echo/time/
 * divide under "com.example.demo" and serves until Ctrl+C. Run
 * client_demo_c (or the C++ client_demo — same wire) against it. */
#include <epx/epx_c.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void echo_handler(const uint8_t* req, size_t len, const char* endpoint,
                         const epx_peer_info_t* peer, epx_response_writer_t* resp, void* ud) {
    (void)endpoint; (void)ud;
    printf("[echo] %zu bytes from uid %ld\n", len, peer->peer_uid);
    epx_respond_ok(resp, req, len);
}

static void time_handler(const uint8_t* req, size_t len, const char* endpoint,
                         const epx_peer_info_t* peer, epx_response_writer_t* resp, void* ud) {
    (void)req; (void)len; (void)endpoint; (void)ud;
    printf("[time] request from uid %ld\n", peer->peer_uid);
    char buf[64];
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_now);
    epx_respond_ok(resp, (const uint8_t*)buf, strlen(buf));
}

/* Request: two decimal numbers separated by a space ("10 4"). */
static void divide_handler(const uint8_t* req, size_t len, const char* endpoint,
                           const epx_peer_info_t* peer, epx_response_writer_t* resp, void* ud) {
    (void)endpoint; (void)peer; (void)ud;
    char in[64] = {0};
    if (len >= sizeof(in)) len = sizeof(in) - 1;
    memcpy(in, req, len);
    long a = 0, b = 0;
    if (sscanf(in, "%ld %ld", &a, &b) != 2) {
        epx_respond_error(resp, "expected two numbers, e.g. \"10 4\"");
        return;
    }
    if (b == 0) {
        epx_respond_error(resp, "division by zero");
        return;
    }
    char out[64];
    snprintf(out, sizeof(out), "%ld", a / b);
    epx_respond_ok(resp, (const uint8_t*)out, strlen(out));
}

static void notify_handler(const uint8_t* req, size_t len, const char* endpoint,
                           const epx_peer_info_t* peer, epx_response_writer_t* resp, void* ud) {
    (void)endpoint; (void)peer; (void)resp; (void)ud;
    printf("[notify] fire-and-forget: %.*s\n", (int)len, (const char*)req);
}

int main(void) {
    epx_identity_t* id = NULL;
    if (epx_identity_load_or_create("com.example.demo", &id) != EPX_OK) {
        fprintf(stderr, "identity: %s\n", epx_last_error());
        return 1;
    }

    epx_host_t* host = NULL;
    if (epx_host_create("com.example.demo", id, EPX_TRUST_ON_FIRST_USE, &host) != EPX_OK) {
        fprintf(stderr, "host: %s\n", epx_last_error());
        return 1;
    }
    epx_host_set_description(host, "C ABI demo service (echo/time/divide)");
    epx_host_expose(host, EPX_KIND_RECEIVE, "echo", echo_handler, NULL);
    epx_host_expose(host, EPX_KIND_RECEIVE, "time", time_handler, NULL);
    epx_host_expose(host, EPX_KIND_RECEIVE, "divide", divide_handler, NULL);
    epx_host_expose(host, EPX_KIND_SEND, "notify", notify_handler, NULL);

    if (epx_host_run(host) != EPX_OK) {
        fprintf(stderr, "run: %s\n", epx_last_error());
        return 1;
    }
    int sigs[] = {SIGINT, SIGTERM};
    epx_host_stop_on_signals(host, sigs, 2);

    printf("com.example.demo serving (C ABI). Ctrl+C to stop.\n");
    epx_host_wait_until_stopped(host);

    epx_host_free(host);
    epx_identity_free(id);
    return 0;
}
