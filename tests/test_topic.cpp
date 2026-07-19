// Topic pub/sub (roadmap item 5) end to end:
//   - publish with no subscribers delivers to 0, doesn't crash
//   - two subscribers each receive every message, in order
//   - unsubscribe() stops delivery for that subscriber only (host-side
//     subscriber_count reflects it), the other keeps receiving
//   - Subscription RAII destructor unsubscribes
//   - a denied Topic (PromptUser with no callback = deny) delivers exactly
//     one closed=true and nothing else
//   - max_subscriptions refuses the (N+1)th subscribe with closed=true
//   - Host::stop() delivers closed=true to live subscribers
#include "test_util.hpp"
#include "epx/epx.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

static epx::Bytes to_bytes(const std::string& s) { return epx::Bytes(s.begin(), s.end()); }

// Waits (bounded) for `pred` to become true; topics are asynchronous by
// nature, so tests poll rather than guess at sleeps.
template <typename Pred>
static bool eventually(Pred pred, std::chrono::milliseconds budget = 3000ms) {
    auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return pred();
}

struct Collector {
    std::mutex mu;
    std::vector<std::string> messages;
    std::atomic<int> closed{0};

    auto callback() {
        return [this](const epx::Bytes& b, bool is_closed) {
            if (is_closed) { closed++; return; }
            std::lock_guard<std::mutex> lock(mu);
            messages.emplace_back(b.begin(), b.end());
        };
    }
    size_t count() {
        std::lock_guard<std::mutex> lock(mu);
        return messages.size();
    }
    std::string at(size_t i) {
        std::lock_guard<std::mutex> lock(mu);
        return i < messages.size() ? messages[i] : "<out of range>";
    }
};

int main() {
    if (const char* home = std::getenv("HOME")) {
        std::error_code ec;
        std::filesystem::remove_all(std::string(home) + "/.epx", ec);
    }

    // ---- basic fan-out + unsubscribe ------------------------------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.topic.host");
        epx::Host host("epx.test.topic.host", hid);
        epx::TopicHandle feed = host.expose_topic("feed");
        host.run();
        std::this_thread::sleep_for(100ms);

        CHECK_EQ(feed.publish(to_bytes("nobody listening")), size_t(0));

        epx::Identity id_a = epx::load_or_create_identity("epx.test.topic.a");
        epx::Identity id_b = epx::load_or_create_identity("epx.test.topic.b");
        epx::Client a(id_a), b(id_b);
        Collector ca, cb;

        auto sub_a = a.subscribe("epx.test.topic.host", "feed", ca.callback());
        auto sub_b = b.subscribe("epx.test.topic.host", "feed", cb.callback());
        CHECK(eventually([&] { return feed.subscriber_count() == 2; }));

        CHECK_EQ(feed.publish(to_bytes("one")), size_t(2));
        CHECK_EQ(feed.publish(to_bytes("two")), size_t(2));
        CHECK(eventually([&] { return ca.count() == 2 && cb.count() == 2; }));
        CHECK_EQ(ca.at(0), std::string("one"));
        CHECK_EQ(ca.at(1), std::string("two"));
        CHECK_EQ(cb.at(0), std::string("one"));

        // Unsubscribe a; only b keeps receiving.
        CHECK(sub_a.active());
        sub_a.unsubscribe();
        CHECK(!sub_a.active());
        CHECK(eventually([&] { return feed.subscriber_count() == 1; }));
        feed.publish(to_bytes("three"));
        CHECK(eventually([&] { return cb.count() == 3; }));
        std::this_thread::sleep_for(100ms);
        CHECK_EQ(ca.count(), size_t(2)); // a stopped at two

        // RAII: dropping sub_b unsubscribes too.
        {
            auto moved = std::move(sub_b);
        }
        CHECK(eventually([&] { return feed.subscriber_count() == 0; }));

        host.stop();
    }

    // ---- denied topic: exactly one closed=true, no messages -------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.topic.host2");
        epx::Host host("epx.test.topic.host2", hid);
        // PromptUser with no prompt callback registered = deny everyone.
        epx::TopicHandle feed = host.expose_topic("private-feed",
            epx::AccessPolicy{epx::AccessTier::PromptUser, ""});
        host.run();
        std::this_thread::sleep_for(100ms);

        epx::Identity cid = epx::load_or_create_identity("epx.test.topic.c");
        epx::Client c(cid);
        Collector col;
        auto sub = c.subscribe("epx.test.topic.host2", "private-feed", col.callback());
        CHECK(eventually([&] { return col.closed.load() == 1; }));
        CHECK(!sub.active());
        feed.publish(to_bytes("should reach nobody"));
        std::this_thread::sleep_for(100ms);
        CHECK_EQ(col.count(), size_t(0));
        CHECK_EQ(feed.subscriber_count(), size_t(0));
        host.stop();
    }

    // ---- max_subscriptions ----------------------------------------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.topic.host3");
        epx::Host host("epx.test.topic.host3", hid);
        epx::ConnectionLimits limits;
        limits.max_subscriptions = 2;
        host.set_limits(limits);
        epx::TopicHandle feed = host.expose_topic("feed");
        host.run();
        std::this_thread::sleep_for(100ms);

        epx::Identity cid = epx::load_or_create_identity("epx.test.topic.d");
        epx::Client c(cid);
        Collector c1, c2, c3;
        auto s1 = c.subscribe("epx.test.topic.host3", "feed", c1.callback());
        auto s2 = c.subscribe("epx.test.topic.host3", "feed", c2.callback());
        auto s3 = c.subscribe("epx.test.topic.host3", "feed", c3.callback()); // over the limit
        CHECK(eventually([&] { return c3.closed.load() == 1; }));
        CHECK(eventually([&] { return feed.subscriber_count() == 2; }));
        CHECK(c1.closed.load() == 0 && c2.closed.load() == 0);
        host.stop();
    }

    // ---- Host::stop() closes live subscriptions cleanly -----------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.topic.host4");
        epx::Host host("epx.test.topic.host4", hid);
        epx::TopicHandle feed = host.expose_topic("feed");
        host.run();
        std::this_thread::sleep_for(100ms);

        epx::Identity cid = epx::load_or_create_identity("epx.test.topic.e");
        epx::Client c(cid);
        Collector col;
        auto sub = c.subscribe("epx.test.topic.host4", "feed", col.callback());
        CHECK(eventually([&] { return feed.subscriber_count() == 1; }));
        feed.publish(to_bytes("last words"));
        CHECK(eventually([&] { return col.count() == 1; }));

        host.stop();
        CHECK(eventually([&] { return col.closed.load() >= 1; }));
        CHECK(!sub.active());
    }

    TEST_MAIN_EXIT();
}
