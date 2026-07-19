// The group chat's rendezvous point. Run exactly one of these; any number
// of groupchat.cpp instances can then join the same room by name.
//
// This process never sees a single character of chat text — its only job
// is membership. Three endpoints (see groupchat_common.hpp for the whole
// demo's design):
//
//   "events" (Topic)   — Present/Left membership events, broadcast to every
//                        subscribed member. All the fan-out, per-subscriber
//                        delivery, heartbeating and dead-subscriber pruning
//                        that this demo used to hand-build now comes from
//                        EndpointKind::Topic.
//   "join"   (Receive) — registers (display name, service name); the
//                        response is a roster snapshot of everyone already
//                        present. Registration and snapshot happen under
//                        one lock so a concurrent join can't be missed or
//                        double-seen by the new member.
//   "leave"  (Send)    — clean departure: unregister + broadcast Left.
//                        (A crashed member never calls this — that's fine;
//                        the other members notice directly when their own
//                        subscription to its feed closes.)
//
// Usage:
//   ./groupchat_room                  # default room name
//   ./groupchat_room my-room-name     # run a separate, independently
//                                     # named room alongside others
#include "epx/epx.hpp"
#include "groupchat_common.hpp"

#include <csignal>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

using namespace groupchat;

int main(int argc, char** argv) {
    std::string room_service = (argc > 1) ? argv[1] : kDefaultRoomService;

    epx::Identity identity = epx::load_or_create_identity("com.epx.groupchat.room." + room_service);
    epx::Host host(room_service, identity, epx::TrustPolicy::TrustOnFirstUse);

    epx::TopicHandle events = host.expose_topic("events");

    std::mutex members_mutex;
    std::unordered_map<std::string, std::string> members; // service -> display name

    host.expose("join", [&](const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
        Event joiner = decode_event(req);
        std::vector<Event> snapshot;
        size_t member_count;
        {
            std::lock_guard<std::mutex> lock(members_mutex);
            for (auto& [svc, name] : members) {
                snapshot.push_back(Event{EventKind::Present, name, svc, ""});
            }
            members[joiner.service] = joiner.name;
            member_count = members.size();
        }
        events.publish(encode_event(Event{EventKind::Present, joiner.name, joiner.service, ""}));

        std::printf("* %s joined (%zu member%s)\n", joiner.name.c_str(), member_count,
                    member_count == 1 ? "" : "s");
        std::fflush(stdout);

        epx::Response r;
        r.ok = true;
        r.data = encode_event_list(snapshot);
        return r;
    });

    host.expose(epx::EndpointKind::Send, "leave", [&](const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
        Event leaver = decode_event(req);
        size_t member_count;
        {
            std::lock_guard<std::mutex> lock(members_mutex);
            auto it = members.find(leaver.service);
            if (it != members.end()) leaver.name = it->second;
            members.erase(leaver.service);
            member_count = members.size();
        }
        events.publish(encode_event(Event{EventKind::Left, leaver.name, leaver.service, ""}));

        std::printf("* %s left (%zu member%s)\n", leaver.name.c_str(), member_count,
                    member_count == 1 ? "" : "s");
        std::fflush(stdout);
        return epx::Response{}; // Send endpoint: never delivered, shape only
    });

    host.run();
    host.stop_on_signals({SIGINT, SIGTERM});

    std::string join_hint = (room_service == kDefaultRoomService) ? "" : (" " + room_service);
    std::printf("group chat room '%s' is running — leave this process running, then start\n", room_service.c_str());
    std::printf("participants elsewhere with: ./groupchat <name>%s\n", join_hint.c_str());
    std::printf("(Ctrl+C to stop)\n");
    std::fflush(stdout);

    host.wait_until_stopped();
    return 0;
}
