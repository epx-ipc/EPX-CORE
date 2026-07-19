// An interactive N-way group chat, built on EndpointKind::Topic plus one
// small rendezvous service (groupchat_room.cpp) — see groupchat_common.hpp
// for the full design. In short: this process is both a Host, exposing its
// own outgoing messages as a Topic "feed", and a Client holding a
// Subscription to every *other* participant's feed, discovering who else
// is around via the room's "events" topic. Every member's output is
// genuinely its own independent feed — there is no central relay of chat
// content.
//
// Worth comparing against this file's pre-2.1 git history: the per-peer
// listener threads, hand-rolled heartbeats, and the careful manual
// disconnect-from-everyone dance on quit are all gone — a Subscription's
// callback gets closed=true when a peer quits (its Host::stop() ends the
// feed cleanly) or crashes (the connection drops), and dropping our own
// Subscriptions + stopping our Host is the entire shutdown story.
//
// Usage:
//   ./groupchat_room                     # in one terminal, once
//   ./groupchat alice                    # in another terminal
//   ./groupchat bob                      # in another, and so on
//   ./groupchat carol my-room-name       # to join a non-default room
//
// Type a line and press Enter to broadcast it to everyone currently
// connected. "/quit" (or Ctrl+D) leaves the room.
#include "epx/epx.hpp"
#include "groupchat_common.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <unordered_map>

using namespace groupchat;

namespace {

std::mutex g_io_mutex;

void print_async(const std::string& text) {
    std::lock_guard<std::mutex> lock(g_io_mutex);
    std::printf("\r\033[K%s\n> ", text.c_str());
    std::fflush(stdout);
}

std::string random_suffix() {
    static thread_local std::mt19937_64 rng(std::random_device{}() ^
                                             uint64_t(std::chrono::steady_clock::now().time_since_epoch().count()));
    uint32_t v = uint32_t(rng());
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", v);
    return std::string(buf);
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::fprintf(stderr, "usage: %s <display-name> [room-name]\n", argv[0]);
        std::fprintf(stderr, "example: %s alice   (start ./groupchat_room first, in its own terminal)\n", argv[0]);
        return 2;
    }
    const std::string display_name = argv[1];
    const std::string room_service = (argc == 3) ? argv[2] : kDefaultRoomService;

    // The display name is what people see; the service name is what EPX
    // uses for discovery/addressing and must be unique on this machine.
    // Deriving it from the display name plus a random suffix means two
    // people (or two terminals run by the same person, e.g. for a demo)
    // can both be "alice" without colliding.
    const std::string my_service = "com.epx.groupchat.member." + display_name + "." + random_suffix();

    epx::Identity identity = epx::load_or_create_identity(my_service);

    epx::Host host(my_service, identity, epx::TrustPolicy::TrustOnFirstUse);
    epx::TopicHandle feed = host.expose_topic("feed"); // our own outgoing messages
    host.run();

    epx::Client client(identity, epx::TrustPolicy::TrustOnFirstUse);

    // One Subscription per other member's feed. Guarded because entries are
    // added from the room-events reader thread and dropped on the main
    // thread at quit.
    std::mutex subs_mutex;
    std::unordered_map<std::string, epx::Client::Subscription> feed_subs;

    // Called whenever the room reports a member — from the join snapshot or
    // a live Present event. Subscribes directly to *their* feed.
    auto follow_member = [&](const std::string& name, const std::string& service) {
        if (service == my_service) return;
        {
            std::lock_guard<std::mutex> lock(subs_mutex);
            if (feed_subs.count(service)) return; // already following
        }
        try {
            auto sub = client.subscribe(service, "feed",
                [name](const epx::Bytes& message, bool closed) {
                    if (closed) {
                        // Their Host ended the feed (clean /quit) or the
                        // connection dropped (crash) — either way they're gone.
                        print_async("* " + name + " left");
                        return;
                    }
                    Event ev = decode_event(message);
                    if (ev.kind == EventKind::Message) print_async(ev.name + ": " + ev.text);
                });
            std::lock_guard<std::mutex> lock(subs_mutex);
            feed_subs.emplace(service, std::move(sub));
            print_async("* " + name + " joined");
        } catch (const epx::EpxError&) {
            // Their host isn't reachable (races with a very fresh join, or
            // they vanished already) — skip; a live Present will retry.
        }
    };

    // Live membership: subscribe to the room's events topic, then register
    // ourselves; the join response is a snapshot of everyone already here.
    epx::Client::Subscription room_events;
    try {
        room_events = client.subscribe(room_service, "events",
            [&](const epx::Bytes& message, bool closed) {
                if (closed) { print_async("(the room went away)"); return; }
                Event ev = decode_event(message);
                if (ev.kind == EventKind::Present) follow_member(ev.name, ev.service);
                // Left events are informational here — the authoritative
                // "they're gone" signal is our own feed subscription closing.
            });
        Event me{EventKind::Present, display_name, my_service, ""};
        epx::Bytes roster = client.get(room_service, "join", encode_event(me));
        for (const Event& ev : decode_event_list(roster)) {
            follow_member(ev.name, ev.service);
        }
    } catch (const epx::EpxError& e) {
        std::fprintf(stderr, "could not join room '%s' — is groupchat_room running? (%s)\n",
                     room_service.c_str(), e.what());
        host.stop();
        return 1;
    }

    {
        std::lock_guard<std::mutex> lock(g_io_mutex);
        std::printf("EPX group chat — you are '%s' in room '%s'\n", display_name.c_str(), room_service.c_str());
        std::printf("Identity pubkey: ");
        for (auto b : host.public_key()) std::printf("%02x", b);
        std::printf("\n");
        std::printf("Type a message and press Enter to broadcast it. /quit to leave.\n> ");
        std::fflush(stdout);
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "/quit") break;
        if (line.empty()) { std::printf("> "); std::fflush(stdout); continue; }
        feed.publish(encode_event({EventKind::Message, display_name, "", line}));
        std::printf("> ");
        std::fflush(stdout);
    }

    // Leaving, in full: tell the room (best-effort), stop our Host (which
    // ends our feed cleanly for every subscriber — they see closed=true,
    // not a dropped socket), and let RAII drop our subscriptions.
    try {
        client.send(room_service, "leave", encode_event({EventKind::Left, display_name, my_service, ""}));
    } catch (const epx::EpxError&) {
        // Room already gone; our subscribers still see a clean close below.
    }
    host.stop();
    {
        std::lock_guard<std::mutex> lock(subs_mutex);
        feed_subs.clear(); // each Subscription unsubscribes on destruction
    }
    return 0;
}
