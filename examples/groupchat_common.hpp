// Shared plumbing for the group chat demo (groupchat_room.cpp +
// groupchat.cpp). None of this is part of the EPX library — how you encode
// your application's messages is your call (see docs/SPEC.md section 8 and
// the FlatBuffers convention in ROADMAP_V2.md item 3 for the recommended
// approach in real polyglot projects; this demo hand-rolls a tiny codec to
// stay dependency-free).
//
// The group chat's shape, end to end (since EPX 2.1, built on
// EndpointKind::Topic — compare this file's git history for what the same
// demo required when the fan-out, heartbeats, and dead-peer pruning had to
// be hand-built on StreamSend):
//
//   - One small "room" process (groupchat_room.cpp) exists purely for
//     discovery/rendezvous. It never sees chat text. It exposes:
//       * a Topic, "events", carrying Present/Left membership events, and
//       * a Receive endpoint, "join", that registers you and returns a
//         roster snapshot of everyone already present, and
//       * a Send endpoint, "leave", for clean departures.
//   - Every participant (groupchat.cpp) is *itself* an EPX Host exposing
//     its own Topic, "feed" — the live stream of chat lines *that
//     participant* sends. Chat messages never pass through the room; they
//     flow directly, peer to peer: N members means N independent feeds,
//     and each member holds its own Subscription to every other feed.
//   - Departure detection is the library's job now: when a member quits
//     (Host::stop sends every subscriber a clean end-of-feed) or crashes
//     (the connection drops), each subscriber's callback receives
//     closed=true — no hand-rolled heartbeat events, no manual disconnect
//     dance on shutdown.
#pragma once

#include "epx/epx.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace groupchat {

// One event carried over the room's "events" topic, a member's "feed"
// topic, or the "join" request/response. Which fields are meaningful
// depends on `kind`:
//   Message — name (sender), text
//   Present — name, service  (a member is/became known)
//   Left    — name, service  (a member said goodbye via "leave")
enum class EventKind : uint8_t { Message = 0, Present = 1, Left = 2 };

struct Event {
    EventKind kind = EventKind::Message;
    std::string name;
    std::string service;
    std::string text;
};

inline epx::Bytes encode_event(const Event& e) {
    epx::Bytes out;
    auto put8 = [&](const std::string& s) {
        uint8_t len = uint8_t(std::min<size_t>(s.size(), 255));
        out.push_back(len);
        out.insert(out.end(), s.begin(), s.begin() + len);
    };
    out.push_back(uint8_t(e.kind));
    put8(e.name);
    put8(e.service);
    uint16_t text_len = uint16_t(std::min<size_t>(e.text.size(), 65535));
    out.push_back(uint8_t(text_len >> 8));
    out.push_back(uint8_t(text_len & 0xFF));
    out.insert(out.end(), e.text.begin(), e.text.begin() + text_len);
    return out;
}

inline Event decode_event(const epx::Bytes& b) {
    Event e;
    size_t pos = 0;
    if (pos >= b.size()) return e;
    e.kind = EventKind(b[pos++]);
    auto get8 = [&](std::string& out_s) {
        if (pos >= b.size()) return;
        uint8_t len = b[pos++];
        if (pos + len > b.size()) len = uint8_t(b.size() - pos);
        out_s.assign(b.begin() + pos, b.begin() + pos + len);
        pos += len;
    };
    get8(e.name);
    get8(e.service);
    if (pos + 2 <= b.size()) {
        uint16_t text_len = (uint16_t(b[pos]) << 8) | uint16_t(b[pos + 1]);
        pos += 2;
        if (pos + text_len > b.size()) text_len = uint16_t(b.size() - pos);
        e.text.assign(b.begin() + pos, b.begin() + pos + text_len);
        pos += text_len;
    }
    return e;
}

// The "join" response is a roster snapshot: a sequence of events, each
// u16-length-prefixed.
inline epx::Bytes encode_event_list(const std::vector<Event>& events) {
    epx::Bytes out;
    for (const auto& e : events) {
        epx::Bytes one = encode_event(e);
        out.push_back(uint8_t(one.size() >> 8));
        out.push_back(uint8_t(one.size() & 0xFF));
        out.insert(out.end(), one.begin(), one.end());
    }
    return out;
}

inline std::vector<Event> decode_event_list(const epx::Bytes& b) {
    std::vector<Event> events;
    size_t pos = 0;
    while (pos + 2 <= b.size()) {
        uint16_t len = (uint16_t(b[pos]) << 8) | uint16_t(b[pos + 1]);
        pos += 2;
        if (pos + len > b.size()) break;
        events.push_back(decode_event(epx::Bytes(b.begin() + pos, b.begin() + pos + len)));
        pos += len;
    }
    return events;
}

constexpr const char* kDefaultRoomService = "com.epx.groupchat.room";

} // namespace groupchat
