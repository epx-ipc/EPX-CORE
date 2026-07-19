// polychat — serverless, relay-less, polyglot group chat.
//
// Unlike examples/groupchat*, there is NO room process at all: discovery
// rides on the enumerable registry (protocol v2, roadmap item 4), which
// is a passive per-user file store — not a process, not a relay. Every
// message flows over a direct, mutually-authenticated, end-to-end
// encrypted peer-to-peer connection.
//
// THE POLYCHAT CONVENTION (identical in every EPX language repo, which
// is the whole point — start any mix of the ports in any terminals and
// they all converse):
//   - service name:  "epx.chat.<name>.<8-hex-suffix>"  (name: no dots)
//   - description:   the display name (read by peers via describe())
//   - one Topic:     "feed" — this participant's outgoing messages
//   - envelope:      [1-byte sender-name length][sender][utf-8 text]
//                    (same as the two-party chat example)
//   - discovery:     poll list_services() every 2s for the "epx.chat."
//                    prefix; subscribe directly to every new member's
//                    feed; a subscription's closed=true IS the leave
//                    signal (clean quit or crash alike).
//
// Usage: ./polychat <name>     (/quit or Ctrl+D to leave)
#include "epx/epx.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>

namespace {

constexpr const char* kPrefix = "epx.chat.";

std::mutex g_io_mutex;

void print_async(const std::string& text) {
    std::lock_guard<std::mutex> lock(g_io_mutex);
    std::printf("\r\033[K%s\n> ", text.c_str());
    std::fflush(stdout);
}

std::string random_suffix() {
    static thread_local std::mt19937_64 rng(std::random_device{}() ^
                                             uint64_t(std::chrono::steady_clock::now().time_since_epoch().count()));
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", uint32_t(rng()));
    return std::string(buf);
}

epx::Bytes encode_envelope(const std::string& sender, const std::string& text) {
    epx::Bytes out;
    out.push_back(uint8_t(sender.size() & 0xFF));
    out.insert(out.end(), sender.begin(), sender.end());
    out.insert(out.end(), text.begin(), text.end());
    return out;
}

std::pair<std::string, std::string> decode_envelope(const epx::Bytes& b) {
    if (b.empty()) return {"?", ""};
    uint8_t len = b[0];
    if (size_t(1) + len > b.size()) return {"?", std::string(b.begin(), b.end())};
    return {std::string(b.begin() + 1, b.begin() + 1 + len),
            std::string(b.begin() + 1 + len, b.end())};
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 2;
    }
    const std::string name = argv[1];
    const std::string my_service = kPrefix + name + "." + random_suffix();

    epx::Identity identity = epx::load_or_create_identity(my_service);
    epx::Host host(my_service, identity);
    host.set_description(name);
    epx::TopicHandle feed = host.expose_topic("feed");
    host.run();

    epx::Client client(identity);

    std::mutex subs_mutex;
    std::unordered_map<std::string, epx::Client::Subscription> subs;
    std::atomic<bool> running{true};

    // Discovery: the registry is the rendezvous. Poll it, follow anyone
    // new, and let each subscription's own closed signal report leaves.
    std::thread discovery([&] {
        while (running.load()) {
            try {
                for (const auto& svc : epx::list_services()) {
                    if (svc.rfind(kPrefix, 0) != 0 || svc == my_service) continue;
                    {
                        std::lock_guard<std::mutex> lock(subs_mutex);
                        if (subs.count(svc)) continue;
                    }
                    std::string who = svc;
                    if (auto d = epx::describe(svc); d && !d->description.empty()) who = d->description;
                    try {
                        auto sub = client.subscribe(svc, "feed",
                            [who](const epx::Bytes& message, bool closed) {
                                if (closed) {
                                    print_async("* " + who + " left");
                                    return;
                                }
                                auto [sender, text] = decode_envelope(message);
                                print_async(sender + ": " + text);
                            });
                        {
                            std::lock_guard<std::mutex> lock(subs_mutex);
                            subs.emplace(svc, std::move(sub));
                        }
                        print_async("* " + who + " joined");
                    } catch (const epx::EpxError&) {
                        // Registered but unreachable (races with startup or
                        // shutdown) — the next poll retries.
                    }
                }
            } catch (const epx::EpxError&) {
                // registry hiccup; retry next round
            }
            for (int i = 0; i < 20 && running.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    });

    {
        std::lock_guard<std::mutex> lock(g_io_mutex);
        std::printf("polychat (C++) — you are '%s' (%s)\n", name.c_str(), my_service.c_str());
        std::printf("No server, no relay: peers appear as they start. /quit to leave.\n> ");
        std::fflush(stdout);
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "/quit") break;
        if (line.empty()) { std::printf("> "); std::fflush(stdout); continue; }
        feed.publish(encode_envelope(name, line));
        std::printf("> ");
        std::fflush(stdout);
    }

    running.store(false);
    discovery.join();
    host.stop(); // every peer's subscription to us sees a clean close -> "* name left"
    {
        std::lock_guard<std::mutex> lock(subs_mutex);
        subs.clear();
    }
    return 0;
}
