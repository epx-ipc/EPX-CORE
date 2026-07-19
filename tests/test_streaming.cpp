// Exercises the three non-Receive EndpointKinds end-to-end over a real
// connection: Send (fire-and-forget), StreamSend (host pushes chunks back
// via get_stream), and StreamReceive (client pushes chunks via
// open_stream/OutputStream). See docs/SPEC.md section 8.
#include "test_util.hpp"
#include "epx/epx.hpp"

#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

static epx::Bytes to_bytes(const std::string& s) { return epx::Bytes(s.begin(), s.end()); }
static std::string to_string(const epx::Bytes& b) { return std::string(b.begin(), b.end()); }

int main() {
    epx::Identity hid = epx::load_or_create_identity("epx.test.streaming.host");
    epx::Host host("epx.test.streaming.host", hid, epx::TrustPolicy::TrustOnFirstUse);

    std::mutex log_mutex;
    std::vector<std::string> received_sends;
    host.expose(epx::EndpointKind::Send, "notify", [&](const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
        std::lock_guard<std::mutex> lock(log_mutex);
        received_sends.push_back(to_string(req));
        epx::Response r; r.ok = true; return r;
    });

    host.expose_stream_send("countdown", [](const epx::StreamWriter& out, const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
        int n = std::stoi(to_string(req));
        for (int i = n; i >= 1; --i) out.write(to_bytes(std::to_string(i)));
        out.write(to_bytes("liftoff"));
    });

    std::vector<std::string> uploaded_chunks;
    bool upload_done = false;
    host.expose_stream_receive("upload", [&](const epx::Bytes& chunk, bool is_last, const std::string&, const epx::PeerInfo&) {
        std::lock_guard<std::mutex> lock(log_mutex);
        if (!chunk.empty()) uploaded_chunks.push_back(to_string(chunk));
        if (is_last) upload_done = true;
    });

    host.run();
    std::this_thread::sleep_for(200ms);

    epx::Identity cid = epx::load_or_create_identity("epx.test.streaming.client");
    epx::Client client(cid, epx::TrustPolicy::TrustOnFirstUse);

    // --- Send ---
    client.send("epx.test.streaming.host", "notify", to_bytes("hello-oneway"));
    std::this_thread::sleep_for(150ms);
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        CHECK_EQ(received_sends.size(), size_t(1));
        if (!received_sends.empty()) CHECK_EQ(received_sends[0], std::string("hello-oneway"));
    }

    // --- StreamSend / get_stream ---
    std::vector<std::string> chunks_seen;
    bool got_last = false;
    client.get_stream("epx.test.streaming.host", "countdown", to_bytes("5"),
        [&](const epx::Bytes& chunk, bool is_last) {
            chunks_seen.push_back(to_string(chunk));
            if (is_last) got_last = true;
        });
    CHECK(got_last);
    // 5,4,3,2,1,liftoff, plus the library's automatic empty end-of-stream marker.
    CHECK_EQ(chunks_seen.size(), size_t(7));
    std::vector<std::string> expected = {"5", "4", "3", "2", "1", "liftoff", ""};
    CHECK(chunks_seen == expected);

    // --- StreamReceive / open_stream ---
    {
        auto out = client.open_stream("epx.test.streaming.host", "upload");
        out.write(to_bytes("chunk-A"));
        out.write(to_bytes("chunk-B"));
        out.write(to_bytes("chunk-C"));
        out.finish();
    }
    std::this_thread::sleep_for(250ms);
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        CHECK(upload_done);
        std::vector<std::string> expected_upload = {"chunk-A", "chunk-B", "chunk-C"};
        CHECK(uploaded_chunks == expected_upload);
    }

    host.stop();
    TEST_MAIN_EXIT();
}
