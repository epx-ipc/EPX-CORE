/* C ABI port of EPX-CORE/examples/client_demo.cpp: calls the demo
 * service's echo/time/divide endpoints (run expose_demo_c — or the C++
 * expose_demo, same wire — first). */
#include <epx/epx_c.h>

#include <stdio.h>
#include <string.h>

static int call_get(epx_client_t* c, const char* endpoint, const char* payload) {
    epx_bytes_t out = {NULL, 0};
    epx_status_t st = epx_client_get(c, "com.example.demo", endpoint,
                                     (const uint8_t*)payload, payload ? strlen(payload) : 0,
                                     0, &out);
    if (st != EPX_OK) {
        printf("%-8s(%s) -> error %d: %s\n", endpoint, payload ? payload : "", st, epx_last_error());
        return 0;
    }
    printf("%-8s(%s) -> %.*s\n", endpoint, payload ? payload : "", (int)out.len, (const char*)out.data);
    epx_bytes_free(out);
    return 1;
}

int main(void) {
    epx_identity_t* id = NULL;
    if (epx_identity_load_or_create("com.example.democlient", &id) != EPX_OK) {
        fprintf(stderr, "identity: %s\n", epx_last_error());
        return 1;
    }
    epx_client_t* client = NULL;
    if (epx_client_create(id, EPX_TRUST_ON_FIRST_USE, &client) != EPX_OK) {
        fprintf(stderr, "client: %s\n", epx_last_error());
        return 1;
    }

    int ok = 1;
    ok &= call_get(client, "echo", "hello over the C ABI");
    ok &= call_get(client, "time", NULL);
    ok &= call_get(client, "divide", "10 4");

    /* deliberate divide-by-zero: expect a clean application error */
    {
        epx_bytes_t out = {NULL, 0};
        epx_status_t st = epx_client_get(client, "com.example.demo", "divide",
                                         (const uint8_t*)"1 0", 3, 0, &out);
        if (st == EPX_ERR_PROTOCOL) {
            printf("divide  (1 0) -> application error, as expected: %s\n", epx_last_error());
        } else {
            printf("divide  (1 0) -> UNEXPECTED status %d\n", st);
            ok = 0;
        }
    }

    if (epx_client_send(client, "com.example.demo", "notify",
                        (const uint8_t*)"bye from C", 10) == EPX_OK) {
        printf("notify  (fire-and-forget) -> sent\n");
    } else {
        printf("notify -> error: %s\n", epx_last_error());
        ok = 0;
    }

    epx_client_free(client);
    epx_identity_free(id);
    return ok ? 0 : 1;
}
