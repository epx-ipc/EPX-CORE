// A minimal interactive terminal chat between two EPX programs.
//
// Each running instance is BOTH:
//   - an epx::Host, exposing its own name as a service with two endpoints:
//       "message" (EndpointKind::Send)      — receives one chat line, no ack
//       "history" (EndpointKind::StreamSend) — streams back this instance's
//                                              transcript, chunk by chunk
//   - an epx::Client, used to call the *other* instance's "message"/
//     "history" endpoints.
//
// Usage: run one instance per terminal, each naming itself and its peer:
//
//   # terminal 1
//   ./chat alice bob
//
//   # terminal 2
//   ./chat bob alice
//
// Type a line and press enter to send it; "/history" pulls a streamed
// transcript from the peer; "/quit" exits. Every message travels over a
// mutually-authenticated, end-to-end encrypted EPX connection — nothing
// else running on either machine's OS user account can read it.
#include "epx/epx.hpp"

#include <cstdio>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

namespace {

std::mutex g_io_mutex;   // guards concurrent stdout writes (input loop vs. incoming-message thread)
std::mutex g_log_mutex;  // guards the local transcript used to answer "/history"
std::vector<std::string> g_transcript;

epx::Bytes to_bytes(const std::string& s) { return epx::Bytes(s.begin(), s.end()); }
std::string to_string(const epx::Bytes& b) { return std::string(b.begin(), b.end()); }

// Tiny envelope so the receiving endpoint knows who sent a line without
// needing anything from the protocol itself: [1-byte name length][name][text].
// (PeerInfo::public_key already cryptographically identifies the sender;
// this is purely so we can print a human-readable name.)
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
    std::string sender(b.begin() + 1, b.begin() + 1 + len);
    std::string text(b.begin() + 1 + len, b.end());
    return {sender, text};
}

void log_line(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_transcript.push_back(line);
}

// Redraws the "> " prompt after printing something asynchronously so the
// terminal doesn't look stuck — a small usability nicety, not a protocol
// concern. Clears the current line first in case the user had started
// typing (their in-progress text is left alone by the terminal's own line
// discipline either way; this just keeps the prompt visible).
void print_async(const std::string& text) {
    std::lock_guard<std::mutex> lock(g_io_mutex);
    std::printf("\r\033[K%s\n> ", text.c_str());
    std::fflush(stdout);
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <my-name> <peer-name>\n", argv[0]);
        std::fprintf(stderr, "example: %s alice bob   (run '%s bob alice' in another terminal)\n", argv[0], argv[0]);
        return 2;
    }
    const std::string my_name = argv[1];
    const std::string peer_name = argv[2];

    epx::Identity identity = epx::load_or_create_identity("com.epx.chat." + my_name);
    epx::Host host(my_name, identity, epx::TrustPolicy::TrustOnFirstUse);

    host.expose(epx::EndpointKind::Send, "message", [&](const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
        auto [sender, text] = decode_envelope(req);
        std::string line = sender + ": " + text;
        log_line(line);
        print_async(line);
        epx::Response r; r.ok = true; return r; // ignored by Client::send, but harmless to fill in
    });

    host.expose_stream_send("history", [](const epx::StreamWriter& out, const epx::Bytes&, const std::string&, const epx::PeerInfo&) {
        std::vector<std::string> snapshot;
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            snapshot = g_transcript;
        }
        for (auto& line : snapshot) out.write(to_bytes(line));
    });

    host.run(); // non-blocking: returns once the listener is bound

    epx::Client client(identity, epx::TrustPolicy::TrustOnFirstUse);

    {
        std::lock_guard<std::mutex> lock(g_io_mutex);
        std::printf("EPX chat — you are '%s', talking to '%s'\n", my_name.c_str(), peer_name.c_str());
        std::printf("Identity pubkey: ");
        for (auto b : host.public_key()) std::printf("%02x", b);
        std::printf("\n");
        std::printf("Type a message and press Enter to send. Commands: /history, /quit\n> ");
        std::fflush(stdout);
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "/quit") break;

        if (line == "/history") {
            try {
                std::lock_guard<std::mutex> lock(g_io_mutex);
                std::printf("--- %s's transcript ---\n", peer_name.c_str());
                std::fflush(stdout);
                client.get_stream(peer_name, "history", {}, [](const epx::Bytes& chunk, bool is_last) {
                    if (!is_last && !chunk.empty()) std::printf("  %s\n", to_string(chunk).c_str());
                });
                std::printf("--- end of transcript ---\n> ");
                std::fflush(stdout);
            } catch (const epx::EpxError& e) {
                std::lock_guard<std::mutex> lock(g_io_mutex);
                std::printf("(couldn't fetch history from '%s': %s)\n> ", peer_name.c_str(), e.what());
                std::fflush(stdout);
            }
            continue;
        }

        if (line.empty()) { std::printf("> "); std::fflush(stdout); continue; }

        log_line(my_name + ": " + line);
        try {
            client.send(peer_name, "message", encode_envelope(my_name, line));
        } catch (const epx::EpxError& e) {
            std::lock_guard<std::mutex> lock(g_io_mutex);
            std::printf("(couldn't reach '%s' — is it running? %s)\n", peer_name.c_str(), e.what());
        }
        std::printf("> ");
        std::fflush(stdout);
    }

    host.stop();
    return 0;
}
