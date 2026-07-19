// End-to-end: a real Host and a real Client, in one process, talking over
// an actual Unix domain socket with the full handshake and AEAD encryption
// — not a mock. Verifies a Receive-endpoint round trip and, just as
// importantly, that both Client destruction and Host::stop() return
// promptly instead of hanging (a real regression this test would have
// caught — see docs/VERIFICATION_NOTES.md).
//
// Uses a private HOME/XDG_RUNTIME_DIR (set by tests/CMakeLists.txt via
// ENVIRONMENT) so this test's identities/registry never collide with a
// real EPX install or with other tests running in parallel.
#include "test_util.hpp"
#include "epx/epx.hpp"

#include <chrono>
#include <string>
#include <thread>

using namespace std::chrono_literals;

static epx::Bytes to_bytes(const std::string& s) { return epx::Bytes(s.begin(), s.end()); }
static std::string to_string(const epx::Bytes& b) { return std::string(b.begin(), b.end()); }

int main() {
    epx::Identity hid = epx::load_or_create_identity("epx.test.lifecycle.host");
    epx::Host host("epx.test.lifecycle.host", hid, epx::TrustPolicy::TrustOnFirstUse);

    host.expose("echo", [](const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
        epx::Response r;
        r.ok = true;
        r.data = req;
        return r;
    });
    host.expose("fail", [](const epx::Bytes&, const std::string&, const epx::PeerInfo&) {
        epx::Response r;
        r.ok = false;
        r.error = "deliberate failure";
        return r;
    });

    host.run();
    std::this_thread::sleep_for(200ms);

    epx::Identity cid = epx::load_or_create_identity("epx.test.lifecycle.client");
    {
        epx::Client client(cid, epx::TrustPolicy::TrustOnFirstUse);

        auto resp = client.get("epx.test.lifecycle.host", "echo", to_bytes("ping"));
        CHECK_EQ(to_string(resp), std::string("ping"));

        bool threw = false;
        try {
            client.get("epx.test.lifecycle.host", "fail", {});
        } catch (const epx::EpxError& e) {
            threw = true;
            CHECK(e.code == epx::EpxError::Code::Protocol);
        }
        CHECK(threw);

        bool not_found = false;
        try {
            client.get("epx.test.lifecycle.host", "no-such-endpoint", {});
        } catch (const epx::EpxError& e) {
            not_found = true;
            CHECK(e.code == epx::EpxError::Code::NotFound);
        }
        CHECK(not_found);

        // A second call reuses the existing connection rather than
        // re-handshaking — this doesn't assert timing (too flaky), but
        // exercises the code path.
        auto resp2 = client.get("epx.test.lifecycle.host", "echo", to_bytes("pong"));
        CHECK_EQ(to_string(resp2), std::string("pong"));

        // Client destructor runs here. If close_connection() ever
        // regresses to blocking forever (see README's shutdown()-before-
        // close() note), this test hangs until CTest's TIMEOUT kills it —
        // which is itself a clear failure signal.
    }

    host.stop(); // same regression risk on the host side; must return promptly

    TEST_MAIN_EXIT();
}
