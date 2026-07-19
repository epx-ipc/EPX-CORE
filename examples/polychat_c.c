/* polychat, C edition — serverless, relay-less, polyglot group chat over
 * the C ABI. See polychat.cpp for the shared convention: service
 * "epx.chat.<name>.<suffix>", description = display name, Topic "feed",
 * envelope [1-byte sender length][sender][text], discovery by polling
 * the registry every 2s. Any mix of the language ports converses.
 *
 * Usage: ./polychat_c <name>     (/quit or Ctrl+D to leave)
 */
#include <epx/epx_c.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PREFIX "epx.chat."
#define MAX_PEERS 64

static char g_my_service[256];
static epx_client_t* g_client;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_followed[MAX_PEERS][256];
static epx_subscription_t* g_subs[MAX_PEERS];
static int g_followed_n = 0;
static volatile int g_running = 1;

typedef struct { char who[128]; } peer_ctx_t;

static void on_feed(const uint8_t* message, size_t len, int closed, void* user_data) {
    peer_ctx_t* ctx = user_data;
    if (closed) {
        printf("\r\033[K* %s left\n> ", ctx->who);
        fflush(stdout);
        return;
    }
    if (len == 0) return;
    uint8_t name_len = message[0];
    if ((size_t)1 + name_len > len) return;
    printf("\r\033[K%.*s: %.*s\n> ", (int)name_len, (const char*)message + 1,
           (int)(len - 1 - name_len), (const char*)message + 1 + name_len);
    fflush(stdout);
}

static int epxc_subscribe_compat(const char* svc, peer_ctx_t* ctx, epx_subscription_t** out);

static int already_followed(const char* svc) {
    for (int i = 0; i < g_followed_n; i++) {
        if (strcmp(g_followed[i], svc) == 0) return 1;
    }
    return 0;
}

static void* discovery_loop(void* arg) {
    (void)arg;
    while (g_running) {
        char** names = NULL;
        size_t count = 0;
        if (epx_list_services(&names, &count) == EPX_OK) {
            for (size_t i = 0; i < count; i++) {
                const char* svc = names[i];
                if (strncmp(svc, PREFIX, strlen(PREFIX)) != 0) continue;
                if (strcmp(svc, g_my_service) == 0) continue;
                pthread_mutex_lock(&g_mu);
                int seen = already_followed(svc) || g_followed_n >= MAX_PEERS;
                pthread_mutex_unlock(&g_mu);
                if (seen) continue;

                peer_ctx_t* ctx = calloc(1, sizeof(*ctx)); /* lives as long as the sub */
                epx_service_description_t* d = NULL;
                if (epx_describe(svc, &d) == EPX_OK) {
                    snprintf(ctx->who, sizeof(ctx->who), "%s",
                             d->description[0] ? d->description : svc);
                    epx_service_description_free(d);
                } else {
                    snprintf(ctx->who, sizeof(ctx->who), "%s", svc);
                }

                epx_subscription_t* sub = NULL;
                if (epxc_subscribe_compat(svc, ctx, &sub) == EPX_OK) {
                    pthread_mutex_lock(&g_mu);
                    snprintf(g_followed[g_followed_n], sizeof(g_followed[0]), "%s", svc);
                    g_subs[g_followed_n] = sub;
                    g_followed_n++;
                    pthread_mutex_unlock(&g_mu);
                    printf("\r\033[K* %s joined\n> ", ctx->who);
                    fflush(stdout);
                } else {
                    free(ctx); /* races with peer startup/shutdown; retry next poll */
                }
            }
            epx_string_list_free(names, count);
        }
        for (int i = 0; i < 20 && g_running; i++) usleep(100 * 1000);
    }
    return NULL;
}

/* tiny wrapper so the call site above stays readable */
static int epxc_subscribe_compat(const char* svc, peer_ctx_t* ctx, epx_subscription_t** out) {
    return epx_client_subscribe(g_client, svc, "feed", on_feed, ctx, out);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 2;
    }
    const char* name = argv[1];

    srand((unsigned)(time(NULL) ^ getpid()));
    snprintf(g_my_service, sizeof(g_my_service), PREFIX "%s.%08x", name, (unsigned)rand());

    epx_identity_t* id = NULL;
    if (epx_identity_load_or_create(g_my_service, &id) != EPX_OK) {
        fprintf(stderr, "identity: %s\n", epx_last_error());
        return 1;
    }
    epx_host_t* host = NULL;
    if (epx_host_create(g_my_service, id, EPX_TRUST_ON_FIRST_USE, &host) != EPX_OK) {
        fprintf(stderr, "host: %s\n", epx_last_error());
        return 1;
    }
    epx_host_set_description(host, name);
    epx_topic_t* feed = NULL;
    if (epx_host_expose_topic(host, "feed", &feed) != EPX_OK ||
        epx_host_run(host) != EPX_OK) {
        fprintf(stderr, "run: %s\n", epx_last_error());
        return 1;
    }
    if (epx_client_create(id, EPX_TRUST_ON_FIRST_USE, &g_client) != EPX_OK) {
        fprintf(stderr, "client: %s\n", epx_last_error());
        return 1;
    }

    pthread_t disco;
    pthread_create(&disco, NULL, discovery_loop, NULL);

    printf("polychat (C) — you are '%s' (%s)\n", name, g_my_service);
    printf("No server, no relay: peers appear as they start. /quit to leave.\n> ");
    fflush(stdout);

    char line[900];
    size_t name_len = strlen(name);
    if (name_len > 255) name_len = 255;
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        if (strcmp(line, "/quit") == 0) break;
        if (n == 0) { printf("> "); fflush(stdout); continue; }

        uint8_t buf[1200];
        buf[0] = (uint8_t)name_len;
        memcpy(buf + 1, name, name_len);
        memcpy(buf + 1 + name_len, line, n);
        epx_topic_publish(feed, buf, 1 + name_len + n);
        printf("> ");
        fflush(stdout);
    }

    g_running = 0;
    pthread_join(disco, NULL);
    epx_host_stop(host); /* peers' subscriptions to us close cleanly -> "left" */
    for (int i = 0; i < g_followed_n; i++) epx_subscription_free(g_subs[i]);
    epx_client_free(g_client);
    epx_topic_free(feed);
    epx_host_free(host);
    epx_identity_free(id);
    return 0;
}
