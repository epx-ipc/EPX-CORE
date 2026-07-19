// Mid-session key rotation (roadmap 8c — opt-in, off by default):
//   - off by default: many requests, epoch stays 0
//   - byte-count-triggered: epoch advances, every request still round-trips
//   - repeated rotation: epoch climbs past 2 with payload integrity intact
//   - time-triggered: epoch advances after the interval elapses
//   - host->client streaming still works after rotations (server tx
//     switched epochs; client rx followed)
#include "test_util.hpp"
#include "epx/epx.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

static epx::Response echo_handler(const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
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

    epx::Identity hid = epx::load_or_create_identity("epx.test.rotation.host");
    epx::Host host("epx.test.rotation.host", hid);
    host.expose("echo", echo_handler);
    host.expose_stream_send("count", [](const epx::StreamWriter& out, const epx::Bytes&,
                                         const std::string&, const epx::PeerInfo&) {
        for (uint8_t i = 0; i < 5; ++i) out.write(epx::Bytes{i});
    });
    host.run();
    std::this_thread::sleep_for(100ms);

    // ---- off by default --------------------------------------------------
    {
        epx::Identity cid = epx::load_or_create_identity("epx.test.rotation.off");
        epx::Client client(cid);
        for (int i = 0; i < 20; ++i) {
            auto out = client.get("epx.test.rotation.host", "echo", epx::Bytes(100, 0x42));
            CHECK_EQ(out.size(), size_t(100));
        }
        CHECK_EQ(client.session_epoch("epx.test.rotation.host"), 0);
    }

    // ---- byte-triggered rotation, repeated, with integrity ---------------
    {
        epx::Identity cid = epx::load_or_create_identity("epx.test.rotation.bytes");
        epx::Client client(cid);
        epx::RotationPolicy p;
        p.max_bytes = 2000; // rotate every ~2KB sent
        client.enable_key_rotation(p);

        for (int i = 0; i < 40; ++i) {
            epx::Bytes payload(500, uint8_t(i));
            auto out = client.get("epx.test.rotation.host", "echo", payload);
            CHECK(out == payload); // integrity across every epoch boundary
        }
        int epoch = client.session_epoch("epx.test.rotation.host");
        CHECK(epoch >= 3); // 40 * 500B = 20KB sent; multiple rotations must have happened

        // Streaming from the host still works on the rotated session.
        std::vector<uint8_t> got;
        client.get_stream("epx.test.rotation.host", "count", {}, [&](const epx::Bytes& chunk, bool is_last) {
            if (!is_last) got.insert(got.end(), chunk.begin(), chunk.end());
        });
        CHECK_EQ(got.size(), size_t(5));
        for (uint8_t i = 0; i < 5; ++i) CHECK_EQ(got[i], i);
    }

    // ---- time-triggered rotation ----------------------------------------
    {
        epx::Identity cid = epx::load_or_create_identity("epx.test.rotation.time");
        epx::Client client(cid);
        epx::RotationPolicy p;
        p.interval = 1s;
        client.enable_key_rotation(p);

        client.get("epx.test.rotation.host", "echo", {1});
        CHECK_EQ(client.session_epoch("epx.test.rotation.host"), 0); // too early
        std::this_thread::sleep_for(1200ms);
        client.get("epx.test.rotation.host", "echo", {2}); // triggers the rekey offer
        // The ack arrives asynchronously; the next request rides epoch 1.
        std::this_thread::sleep_for(200ms);
        auto out = client.get("epx.test.rotation.host", "echo", {3});
        CHECK_EQ(out.size(), size_t(1));
        CHECK(client.session_epoch("epx.test.rotation.host") >= 1);
    }

    host.stop();
    TEST_MAIN_EXIT();
}
