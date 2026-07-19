// Talks to the service exposed by expose_demo.cpp. Run expose_demo first.
//
// Demonstrates a "conversation": three separate get() calls plus one
// send() reuse a single encrypted, authenticated session under the hood
// (only the first call pays for the handshake).
#include "epx/epx.hpp"
#include <cstdio>
#include <string>

static epx::Bytes to_bytes(const std::string& s) { return epx::Bytes(s.begin(), s.end()); }
static std::string to_string(const epx::Bytes& b) { return std::string(b.begin(), b.end()); }

int main() {
    epx::Identity id = epx::load_or_create_identity("com.example.client");
    epx::Client client(id, epx::TrustPolicy::TrustOnFirstUse);

    const std::string service = "com.example.demo";

    try {
        auto echoed = client.get(service, "echo", to_bytes("hello over an encrypted local channel"));
        std::printf("echo ->  %s\n", to_string(echoed).c_str());

        auto time_resp = client.get(service, "time", {});
        std::printf("time ->  %s\n", to_string(time_resp).c_str());

        auto div_resp = client.get(service, "divide", to_bytes("10,4"));
        std::printf("divide -> %s\n", to_string(div_resp).c_str());

        // Application-level error path: divide by zero comes back as a
        // thrown EpxError with Code::Protocol, not a crashed connection.
        try {
            client.get(service, "divide", to_bytes("10,0"));
        } catch (const epx::EpxError& e) {
            std::printf("divide(10,0) rejected as expected: %s\n", e.what());
        }

        // Fire-and-forget: no response is awaited.
        client.send(service, "echo", to_bytes("fire and forget"));
        std::printf("sent one-way message (no response expected)\n");

    } catch (const epx::EpxError& e) {
        std::fprintf(stderr, "EPX error: %s\n", e.what());
        return 1;
    }

    return 0;
}
