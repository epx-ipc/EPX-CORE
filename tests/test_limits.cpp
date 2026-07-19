// Rate limiting (roadmap item 7) end to end:
//   - A request rate over the configured budget is *delayed*, not dropped:
//     a burst larger than the bucket takes measurably longer than the
//     burst allowance alone would.
//   - A peer that stays saturated past disconnect_after_delayed is
//     disconnected with an ERROR frame, surfacing as
//     EpxError::Code::RateLimited (not a bare transport error) at the
//     client.
//   - The pre-handshake per-UID cap refuses connection attempts beyond
//     the bucket before any handshake work happens (observed as connect/
//     handshake failures), and recovers once the bucket refills.
#include "test_util.hpp"
#include "epx/epx.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

static epx::Response ok_handler(const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
    epx::Response r;
    r.ok = true;
    r.data = req;
    return r;
}

int main() {
    if (const char* home = std::getenv("HOME")) {
        std::error_code ec;
        std::filesystem::remove_all(std::string(home) + "/.epx", ec);
    }

    // ---- request-rate delay then disconnect ------------------------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.limits.host");
        epx::Host host("epx.test.limits.host", hid);
        epx::ConnectionLimits limits;
        limits.max_requests_per_sec = 50;
        limits.request_burst = 5;
        limits.disconnect_after_delayed = 20;
        host.set_limits(limits);
        host.expose("echo", ok_handler);
        host.run();
        std::this_thread::sleep_for(100ms);

        epx::Identity cid = epx::load_or_create_identity("epx.test.limits.client");

        // 15 requests: 5 burst tokens + 10 delayed at 50/s ≈ >= ~150ms.
        {
            epx::Client client(cid);
            auto t0 = Clock::now();
            for (int i = 0; i < 15; ++i) {
                client.get("epx.test.limits.host", "echo", {1});
            }
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0);
            CHECK(elapsed >= 120ms); // delayed, not waved through
        }

        // Hammer far past disconnect_after_delayed: must end in RateLimited.
        {
            epx::Client client(cid);
            bool rate_limited = false;
            try {
                for (int i = 0; i < 200; ++i) {
                    client.get("epx.test.limits.host", "echo", {1});
                }
            } catch (const epx::EpxError& e) {
                rate_limited = (e.code == epx::EpxError::Code::RateLimited);
            }
            CHECK(rate_limited);
        }

        host.stop();
    }

    // ---- pre-handshake per-UID cap --------------------------------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.limits.host2");
        epx::Host host("epx.test.limits.host2", hid);
        epx::ConnectionLimits limits;
        limits.handshakes_per_uid_per_sec = 2;
        limits.handshake_burst = 2;
        host.set_limits(limits);
        host.expose("echo", ok_handler);
        host.run();
        std::this_thread::sleep_for(100ms);

        epx::Identity cid = epx::load_or_create_identity("epx.test.limits.client2");

        // Each Client below opens (at most) one fresh connection. The first
        // two attempts fit the burst; the third is refused pre-handshake.
        int successes = 0, failures = 0;
        for (int i = 0; i < 3; ++i) {
            try {
                epx::Client client(cid);
                client.get("epx.test.limits.host2", "echo", {1});
                successes++;
            } catch (const epx::EpxError&) {
                failures++;
            }
        }
        CHECK_EQ(successes, 2);
        CHECK_EQ(failures, 1);

        // After a refill interval the same UID is admitted again.
        std::this_thread::sleep_for(700ms);
        bool recovered = false;
        try {
            epx::Client client(cid);
            client.get("epx.test.limits.host2", "echo", {1});
            recovered = true;
        } catch (const epx::EpxError&) {
        }
        CHECK(recovered);

        host.stop();
    }

    TEST_MAIN_EXIT();
}
