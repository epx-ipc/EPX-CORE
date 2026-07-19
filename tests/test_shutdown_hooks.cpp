// Verifies the non-blocking run()/wait_until_stopped() lifecycle: hook
// ordering (before_stop then after_stop), that before_stop can gracefully
// drain an in-flight request before stop() forcibly closes anything, and
// that stop_on_signals() actually wires a delivered signal through to
// request_stop() -> wait_until_stopped() waking up.
#include "test_util.hpp"
#include "epx/epx.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

static epx::Bytes to_bytes(const std::string& s) { return epx::Bytes(s.begin(), s.end()); }

int main() {
    epx::Identity hid = epx::load_or_create_identity("epx.test.shutdown.host");
    epx::Host host("epx.test.shutdown.host", hid, epx::TrustPolicy::TrustOnFirstUse);

    std::mutex order_mutex;
    std::vector<std::string> order;
    std::atomic<bool> handler_started{false};
    std::atomic<bool> handler_finished{false};

    host.expose("slow", [&](const epx::Bytes&, const std::string&, const epx::PeerInfo&) {
        handler_started.store(true);
        std::this_thread::sleep_for(300ms); // simulate in-flight work
        handler_finished.store(true);
        epx::Response r;
        r.ok = true;
        r.data = to_bytes("done");
        return r;
    });

    host.before_stop([&] {
        std::lock_guard<std::mutex> lock(order_mutex);
        order.push_back("before_stop");
        // Give the in-flight "slow" handler a chance to finish rather
        // than being cut off — a real program might wait on its own
        // in-flight counter here (see examples/expose_demo.cpp); this
        // test just sleeps slightly longer than the handler takes.
        std::this_thread::sleep_for(400ms);
    });
    host.after_stop([&] {
        std::lock_guard<std::mutex> lock(order_mutex);
        order.push_back("after_stop");
    });

    CHECK(host.stopped()); // never started yet
    host.run();
    CHECK(!host.stopped());
    std::this_thread::sleep_for(200ms);

    epx::Identity cid = epx::load_or_create_identity("epx.test.shutdown.client");
    epx::Client client(cid, epx::TrustPolicy::TrustOnFirstUse);

    bool client_saw_response = false;
    std::string client_response;
    std::thread caller([&] {
        try {
            auto resp = client.get("epx.test.shutdown.host", "slow", {}, 2000ms);
            client_response.assign(resp.begin(), resp.end());
            client_saw_response = true;
        } catch (const epx::EpxError&) {
            // Left client_saw_response false; checked below.
        }
    });

    // Wait until the handler has actually started, then request a stop
    // via the same path a signal handler would use (async-signal-safe:
    // only touches an atomic).
    while (!handler_started.load()) std::this_thread::sleep_for(10ms);
    host.request_stop();

    host.wait_until_stopped(); // should block through before_stop's drain wait, then return
    caller.join();

    CHECK(host.stopped());
    CHECK(handler_finished.load());
    CHECK(client_saw_response);
    CHECK_EQ(client_response, std::string("done"));

    {
        std::lock_guard<std::mutex> lock(order_mutex);
        CHECK_EQ(order.size(), size_t(2));
        if (order.size() == 2) {
            CHECK_EQ(order[0], std::string("before_stop"));
            CHECK_EQ(order[1], std::string("after_stop"));
        }
    }

    // --- stop_on_signals(): a second Host, stopped via a real signal ---
    epx::Identity hid2 = epx::load_or_create_identity("epx.test.shutdown.host2");
    epx::Host host2("epx.test.shutdown.host2", hid2, epx::TrustPolicy::TrustOnFirstUse);
    host2.expose("ping", [](const epx::Bytes&, const std::string&, const epx::PeerInfo&) {
        epx::Response r; r.ok = true; return r;
    });
    host2.run();
    host2.stop_on_signals({SIGTERM});
    CHECK(!host2.stopped());

    std::raise(SIGTERM); // synchronously invokes the trampoline -> host2.request_stop()
    host2.wait_until_stopped();
    CHECK(host2.stopped());

    TEST_MAIN_EXIT();
}
