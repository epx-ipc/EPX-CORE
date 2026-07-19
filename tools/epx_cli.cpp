// `epx` — command-line window into the local service registry.
//
//   epx list                 every live registered service, one per line
//   epx describe <service>   a service's self-description: identity key,
//                            pid, description, and every endpoint + kind
//
// Everything printed here is unauthenticated metadata (docs/SPEC.md
// section 4.3): it tells you what *claims* to be registered; only a live
// handshake proves anything.
#include "epx/epx.hpp"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

const char* kind_name(epx::EndpointKind k) {
    switch (k) {
        case epx::EndpointKind::Receive:       return "receive        (call with: get)";
        case epx::EndpointKind::Send:          return "send           (call with: send)";
        case epx::EndpointKind::StreamReceive: return "stream_receive (call with: open_stream)";
        case epx::EndpointKind::StreamSend:    return "stream_send    (call with: get_stream)";
        case epx::EndpointKind::Topic:         return "topic          (call with: subscribe)";
    }
    return "unknown";
}

int usage(const char* argv0) {
    std::fprintf(stderr,
                 "usage: %s list\n"
                 "       %s describe <service-name>\n",
                 argv0, argv0);
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) return usage(argv[0]);

    if (std::strcmp(argv[1], "list") == 0) {
        auto names = epx::list_services();
        if (names.empty()) {
            std::printf("no services registered\n");
            return 0;
        }
        for (const auto& n : names) {
            auto d = epx::describe(n);
            if (d && !d->description.empty()) {
                std::printf("%-40s %s\n", n.c_str(), d->description.c_str());
            } else {
                std::printf("%s\n", n.c_str());
            }
        }
        return 0;
    }

    if (std::strcmp(argv[1], "describe") == 0) {
        if (argc != 3) return usage(argv[0]);
        auto d = epx::describe(argv[2]);
        if (!d) {
            std::fprintf(stderr, "no live service registered as '%s'\n", argv[2]);
            return 1;
        }
        std::printf("service:     %s\n", d->service_name.c_str());
        if (!d->description.empty()) std::printf("description: %s\n", d->description.c_str());
        std::printf("pid:         %ld\n", d->pid);
        std::printf("pubkey:      ");
        for (auto b : d->identity_pubkey) std::printf("%02x", b);
        std::printf("\n");
        std::printf("endpoints:   %zu\n", d->endpoints.size());
        for (const auto& ep : d->endpoints) {
            std::printf("  %-24s %s\n", ep.name.c_str(), kind_name(ep.kind));
        }
        std::printf("\nnote: registry metadata is unauthenticated; only a live handshake\n"
                    "proves the service holds the key above (see docs/SPEC.md 4.3).\n");
        return 0;
    }

    return usage(argv[0]);
}
