// Exposes a small service ("com.example.demo") with three endpoints:
//   echo   — returns whatever bytes it was sent
//   time   — returns the current Unix time as a decimal string
//   divide — demonstrates an application-level error (distinct from a
//            transport/crypto failure)
//
// Also demonstrates EPX's shutdown lifecycle: Host::run() is non-blocking,
// so this program parks on wait_until_stopped() instead; stop_on_signals()
// wires SIGINT/SIGTERM to a graceful shutdown; before_stop()/after_stop()
// hooks show how an application decides what "graceful" means for it
// (here: wait up to 3s for in-flight handlers to finish before letting
// stop() forcibly close anything).
//
// Run this first, in one terminal:
//   ./expose_demo
// Then run client_demo in another terminal. Press Ctrl+C (or send SIGTERM)
// to see the graceful shutdown sequence.
#include "epx/epx.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

using namespace std::chrono_literals;

static std::string bytes_to_string(const epx::Bytes& b) {
    return std::string(b.begin(), b.end());
}
static epx::Bytes string_to_bytes(const std::string& s) {
    return epx::Bytes(s.begin(), s.end());
}

namespace {
// A minimal "how many handlers are currently running" tracker, purely for
// this demo's graceful-drain before_stop hook — EPX itself doesn't track
// this (see docs/SPEC.md section 8: it's an application concern).
std::mutex g_inflight_mutex;
std::condition_variable g_inflight_cv;
int g_inflight = 0;

struct InflightGuard {
    InflightGuard() {
        std::lock_guard<std::mutex> lock(g_inflight_mutex);
        ++g_inflight;
    }
    ~InflightGuard() {
        std::lock_guard<std::mutex> lock(g_inflight_mutex);
        if (--g_inflight == 0) g_inflight_cv.notify_all();
    }
};
} // namespace

int main() {
    // Every program has one durable identity, generated on first run and
    // reused after that (~/.epx/identities/com.example.demo.key).
    epx::Identity id = epx::load_or_create_identity("com.example.demo");

    // TrustOnFirstUse: the first client that connects gets pinned and is
    // silently trusted on every later connection; a client presenting a
    // *different* key later for the same claimed identity would still be
    // accepted here (server-side TOFU just remembers every key it has ever
    // seen) — use TrustPolicy::RequireKnownPeer + allow_peer(...) if you
    // want to restrict a service to a specific, pre-approved set of callers.
    epx::Host host("com.example.demo", id, epx::TrustPolicy::TrustOnFirstUse);

    host.expose("echo", [](const epx::Bytes& req, const std::string&, const epx::PeerInfo& peer) {
        InflightGuard guard;
        std::printf("[echo] %zu bytes from peer uid=%ld\n", req.size(), peer.peer_uid);
        epx::Response r;
        r.ok = true;
        r.data = req;
        return r;
    });

    host.expose("time", [](const epx::Bytes&, const std::string&, const epx::PeerInfo&) {
        InflightGuard guard;
        auto now = std::chrono::system_clock::now().time_since_epoch();
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(now).count();
        epx::Response r;
        r.ok = true;
        r.data = string_to_bytes(std::to_string(secs));
        return r;
    });

    host.expose("divide", [](const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
        InflightGuard guard;
        // Expects "a,b" and returns a/b as text, or an application-level
        // error (distinct from a transport/crypto failure) on bad input.
        std::string s = bytes_to_string(req);
        auto comma = s.find(',');
        epx::Response r;
        if (comma == std::string::npos) {
            r.ok = false;
            r.error = "expected 'a,b'";
            return r;
        }
        try {
            double a = std::stod(s.substr(0, comma));
            double b = std::stod(s.substr(comma + 1));
            if (b == 0) { r.ok = false; r.error = "division by zero"; return r; }
            r.ok = true;
            r.data = string_to_bytes(std::to_string(a / b));
        } catch (...) {
            r.ok = false;
            r.error = "could not parse numbers";
        }
        return r;
    });

    // --- Shutdown lifecycle -------------------------------------------
    //
    // before_stop runs first, before the listener or any live connection
    // is touched: this program chooses to wait (up to 3s) for in-flight
    // handlers to finish, so a request that's already being processed
    // gets to complete and reply rather than being cut off mid-flight. A
    // program that doesn't care about that could simply not register a
    // before_stop hook at all, and stop() would close everything
    // immediately — EPX doesn't impose either policy.
    host.before_stop([] {
        std::printf("\nshutting down — waiting up to 3s for in-flight requests to finish...\n");
        std::unique_lock<std::mutex> lock(g_inflight_mutex);
        bool drained = g_inflight_cv.wait_for(lock, 3s, [] { return g_inflight == 0; });
        std::printf(drained ? "all requests finished cleanly\n"
                             : "timed out waiting — closing remaining connections anyway\n");
    });

    host.after_stop([] {
        std::printf("goodbye\n");
    });

    std::printf("com.example.demo listening — identity pubkey (share this if using RequireKnownPeer):\n  ");
    for (auto b : host.public_key()) std::printf("%02x", b);
    std::printf("\n");
    std::printf("Endpoints exposed: echo, time, divide. Press Ctrl+C to stop.\n");

    host.run();                                // non-blocking: returns once the listener is bound
    host.stop_on_signals({SIGINT, SIGTERM});    // Ctrl+C / `kill <pid>` now trigger the sequence above
    host.wait_until_stopped();                  // park this thread until that happens
    return 0;
}
