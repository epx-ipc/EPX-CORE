// Enumerable registry (roadmap item 4):
//   - list_services() sees a running Host and stops seeing it after stop()
//   - describe() returns the description and every endpoint with its kind,
//     populated automatically from what was exposed
//   - a stale entry (crashed host: dead pid) is excluded from list_services
//     and cleaned off disk as a side effect
#include "test_util.hpp"
#include "epx/epx.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

using namespace std::chrono_literals;

static bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

int main() {
    epx::Identity hid = epx::load_or_create_identity("epx.test.registry.host");
    epx::Host host("epx.test.registry.host", hid);
    host.set_description("registry test service");
    host.expose("ask", [](const epx::Bytes&, const std::string&, const epx::PeerInfo&) {
        return epx::Response{};
    });
    host.expose(epx::EndpointKind::Send, "notify", [](const epx::Bytes&, const std::string&, const epx::PeerInfo&) {
        return epx::Response{};
    });
    host.expose_stream_send("results", [](const epx::StreamWriter&, const epx::Bytes&,
                                           const std::string&, const epx::PeerInfo&) {});
    host.expose_topic("news");
    host.run();
    std::this_thread::sleep_for(100ms);

    auto names = epx::list_services();
    CHECK(contains(names, "epx.test.registry.host"));

    auto d = epx::describe("epx.test.registry.host");
    CHECK(d.has_value());
    CHECK_EQ(d->service_name, std::string("epx.test.registry.host"));
    CHECK_EQ(d->description, std::string("registry test service"));
    CHECK(d->pid > 0);
    CHECK_EQ(d->endpoints.size(), size_t(4));
    auto kind_of = [&](const std::string& name) -> epx::EndpointKind {
        for (auto& ep : d->endpoints) {
            if (ep.name == name) return ep.kind;
        }
        return epx::EndpointKind(255);
    };
    CHECK(kind_of("ask") == epx::EndpointKind::Receive);
    CHECK(kind_of("notify") == epx::EndpointKind::Send);
    CHECK(kind_of("results") == epx::EndpointKind::StreamSend);
    CHECK(kind_of("news") == epx::EndpointKind::Topic);

    // A stale entry from a "crashed" host: valid format, dead pid.
    {
        const char* xdg = std::getenv("XDG_RUNTIME_DIR");
        CHECK(xdg != nullptr);
        std::string dir = std::string(xdg) + "/epx/registry";
        std::filesystem::create_directories(dir);
        std::ofstream f(dir + "/epx.test.registry.ghost.entry");
        f << "version=1\nservice=epx.test.registry.ghost\naddress=/nonexistent.sock\n"
          << "pubkey=" << std::string(64, 'a') << "\npid=999999999\nendpoints=\ndescription=\n";
    }
    auto names2 = epx::list_services();
    CHECK(!contains(names2, "epx.test.registry.ghost"));
    CHECK(!epx::describe("epx.test.registry.ghost").has_value());

    host.stop();
    auto names3 = epx::list_services();
    CHECK(!contains(names3, "epx.test.registry.host"));

    TEST_MAIN_EXIT();
}
