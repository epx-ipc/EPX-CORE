/* C ABI port of EPX-CORE/examples/chat.cpp — wire-compatible with the C++
 * chat binary, which is the point: run `./chat_c alice bob` against the
 * C++ `./chat bob alice` and they interoperate over the same encrypted
 * protocol. This file is also the reference every language binding's chat
 * port mirrors (same service naming, same [1-byte name length][name][text]
 * envelope, same "message" Send + "history" StreamSend endpoints).
 *
 * Usage: ./chat_c <my-name> <peer-name>    (/history, /quit)
 */
#include <epx/epx_c.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char* g_transcript[1024];
static size_t g_transcript_len = 0;

static void log_line(const char* line) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_transcript_len < 1024) g_transcript[g_transcript_len++] = strdup(line);
    pthread_mutex_unlock(&g_log_mutex);
}

/* "message" (Send): [1-byte sender length][sender][text] */
static void message_handler(const uint8_t* req, size_t len, const char* endpoint,
                            const epx_peer_info_t* peer, epx_response_writer_t* resp, void* ud) {
    (void)endpoint; (void)peer; (void)resp; (void)ud;
    if (len == 0) return;
    uint8_t name_len = req[0];
    if ((size_t)1 + name_len > len) return;
    char line[1024];
    snprintf(line, sizeof(line), "%.*s: %.*s",
             (int)name_len, (const char*)req + 1,
             (int)(len - 1 - name_len), (const char*)req + 1 + name_len);
    log_line(line);
    printf("\r\033[K%s\n> ", line);
    fflush(stdout);
}

/* "history" (StreamSend): one transcript line per chunk */
static void history_handler(epx_stream_writer_t* out, const uint8_t* req, size_t len,
                            const char* endpoint, const epx_peer_info_t* peer, void* ud) {
    (void)req; (void)len; (void)endpoint; (void)peer; (void)ud;
    pthread_mutex_lock(&g_log_mutex);
    size_t n = g_transcript_len;
    char** snapshot = malloc(sizeof(char*) * (n ? n : 1));
    for (size_t i = 0; i < n; i++) snapshot[i] = strdup(g_transcript[i]);
    pthread_mutex_unlock(&g_log_mutex);
    for (size_t i = 0; i < n; i++) {
        epx_stream_writer_write(out, (const uint8_t*)snapshot[i], strlen(snapshot[i]));
        free(snapshot[i]);
    }
    free(snapshot);
}

static void history_chunk(const uint8_t* chunk, size_t len, int is_last, void* ud) {
    (void)ud;
    if (!is_last && len > 0) printf("  %.*s\n", (int)len, (const char*)chunk);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <my-name> <peer-name>\n", argv[0]);
        return 2;
    }
    const char* my_name = argv[1];
    const char* peer_name = argv[2];

    char app_name[256];
    snprintf(app_name, sizeof(app_name), "com.epx.chat.%s", my_name);

    epx_identity_t* id = NULL;
    if (epx_identity_load_or_create(app_name, &id) != EPX_OK) {
        fprintf(stderr, "identity: %s\n", epx_last_error());
        return 1;
    }
    epx_host_t* host = NULL;
    if (epx_host_create(my_name, id, EPX_TRUST_ON_FIRST_USE, &host) != EPX_OK) {
        fprintf(stderr, "host: %s\n", epx_last_error());
        return 1;
    }
    epx_host_expose(host, EPX_KIND_SEND, "message", message_handler, NULL);
    epx_host_expose_stream_send(host, "history", history_handler, NULL);
    if (epx_host_run(host) != EPX_OK) {
        fprintf(stderr, "run: %s\n", epx_last_error());
        return 1;
    }

    epx_client_t* client = NULL;
    if (epx_client_create(id, EPX_TRUST_ON_FIRST_USE, &client) != EPX_OK) {
        fprintf(stderr, "client: %s\n", epx_last_error());
        return 1;
    }

    uint8_t pk[32];
    epx_host_public_key(host, pk);
    printf("EPX chat (C ABI) — you are '%s', talking to '%s'\n", my_name, peer_name);
    printf("Identity pubkey: ");
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\nType a message and press Enter to send. Commands: /history, /quit\n> ");
    fflush(stdout);

    char line[900];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';

        if (strcmp(line, "/quit") == 0) break;

        if (strcmp(line, "/history") == 0) {
            printf("--- %s's transcript ---\n", peer_name);
            fflush(stdout);
            epx_status_t st = epx_client_get_stream(client, peer_name, "history", NULL, 0,
                                                    history_chunk, NULL, 0);
            if (st != EPX_OK) {
                printf("(couldn't fetch history from '%s': %s)\n", peer_name, epx_last_error());
            }
            printf("--- end of transcript ---\n> ");
            fflush(stdout);
            continue;
        }

        if (n == 0) { printf("> "); fflush(stdout); continue; }

        char logged[1024];
        snprintf(logged, sizeof(logged), "%s: %s", my_name, line);
        log_line(logged);

        /* envelope: [1-byte name length][name][text] */
        uint8_t buf[1024];
        size_t name_len = strlen(my_name);
        if (name_len > 255) name_len = 255;
        buf[0] = (uint8_t)name_len;
        memcpy(buf + 1, my_name, name_len);
        memcpy(buf + 1 + name_len, line, n);
        if (epx_client_send(client, peer_name, "message", buf, 1 + name_len + n) != EPX_OK) {
            printf("(couldn't reach '%s' — is it running? %s)\n", peer_name, epx_last_error());
        }
        printf("> ");
        fflush(stdout);
    }

    epx_client_free(client);
    epx_host_free(host);
    epx_identity_free(id);
    return 0;
}
