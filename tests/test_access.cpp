// Protocol v2 authorization (roadmap 8a) and version negotiation (8b),
// end to end over a real socket:
//   - PromptUser tier: callback invoked with the right peer/endpoint/reason,
//     AllowOnce allows without persisting, Deny persists and throws
//     AccessDenied at the caller, AlwaysAllow persists (no re-prompt on a
//     fresh connection).
//   - Certificate tier: a credential minted by a trusted issuer admits
//     exactly the peer it names; everyone else gets AccessDenied.
//   - PinnedPeers tier under TrustPolicy::AllowAll: unrecorded peers are
//     denied (the one case where PinnedPeers bites — see epx.hpp).
//   - Negotiation: a v1-capped client still talks to a v2 host (session
//     runs at v1), exercising the trailing-extension compatibility path.
//
// Uses a private HOME/XDG_RUNTIME_DIR (tests/CMakeLists.txt) so persisted
// decisions from one run don't leak into the next — each test run starts
// from a clean slate because CTest's sandbox dir is wiped by the harness
// setup below.
#include "test_util.hpp"
#include "epx/epx.hpp"
#include "protocol.hpp" // set_max_negotiable_version_for_testing

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>

using namespace std::chrono_literals;

static epx::Bytes to_bytes(const std::string& s) { return epx::Bytes(s.begin(), s.end()); }

static epx::Response ok_handler(const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
    epx::Response r;
    r.ok = true;
    r.data = req;
    return r;
}

int main() {
    // Start from a clean slate even if a previous run left state behind.
    if (const char* home = std::getenv("HOME")) {
        std::error_code ec;
        std::filesystem::remove_all(std::string(home) + "/.epx", ec);
    }

    // ---- PromptUser tier -------------------------------------------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.access.host");
        epx::Host host("epx.test.access.host", hid);

        std::atomic<int> prompts{0};
        std::string seen_endpoint, seen_reason;
        epx::PromptDecision next_decision = epx::PromptDecision::AllowOnce;

        host.on_authorization_prompt([&](const epx::PeerInfo&, const std::string& ep, const std::string& reason) {
            prompts++;
            seen_endpoint = ep;
            seen_reason = reason;
            return next_decision;
        });

        host.expose("open-ep", ok_handler); // default access: Open
        host.expose("guarded", ok_handler,
                    epx::AccessPolicy{epx::AccessTier::PromptUser, "test wants to read your data"});
        host.run();
        std::this_thread::sleep_for(100ms);

        epx::Identity cid = epx::load_or_create_identity("epx.test.access.client");

        // AllowOnce: allowed now, but nothing persisted.
        {
            epx::Client client(cid);
            CHECK_EQ(client.get("epx.test.access.host", "open-ep", to_bytes("x")).size(), size_t(1));
            CHECK_EQ(prompts.load(), 0); // Open endpoint never prompts

            next_decision = epx::PromptDecision::AllowOnce;
            auto out = client.get("epx.test.access.host", "guarded", to_bytes("hi"));
            CHECK_EQ(out.size(), size_t(2));
            CHECK_EQ(prompts.load(), 1);
            CHECK_EQ(seen_endpoint, std::string("guarded"));
            CHECK_EQ(seen_reason, std::string("test wants to read your data"));

            // Same connection: cached, no second prompt.
            client.get("epx.test.access.host", "guarded", to_bytes("hi"));
            CHECK_EQ(prompts.load(), 1);
        }

        // Fresh connection after AllowOnce: prompted again (not persisted).
        {
            epx::Client client(cid);
            next_decision = epx::PromptDecision::AlwaysAllow;
            client.get("epx.test.access.host", "guarded", to_bytes("hi"));
            CHECK_EQ(prompts.load(), 2);
        }

        // Fresh connection after AlwaysAllow: no prompt (persisted).
        {
            epx::Client client(cid);
            client.get("epx.test.access.host", "guarded", to_bytes("hi"));
            CHECK_EQ(prompts.load(), 2);
        }

        host.stop();
    }

    // ---- Deny persists and surfaces as AccessDenied ---------------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.access.host2");
        epx::Host host("epx.test.access.host2", hid);
        host.on_authorization_prompt([&](const epx::PeerInfo&, const std::string&, const std::string&) {
            return epx::PromptDecision::Deny;
        });
        host.expose("secret", ok_handler, epx::AccessPolicy{epx::AccessTier::PromptUser, ""});
        host.run();
        std::this_thread::sleep_for(100ms);

        epx::Identity cid = epx::load_or_create_identity("epx.test.access.client");
        epx::Client client(cid);
        bool denied = false;
        try {
            client.get("epx.test.access.host2", "secret", {});
        } catch (const epx::EpxError& e) {
            denied = (e.code == epx::EpxError::Code::AccessDenied);
        }
        CHECK(denied);
        host.stop();
    }

    // ---- Certificate tier ------------------------------------------------
    {
        epx::Identity issuer = epx::load_or_create_identity("epx.test.access.issuer");
        epx::Identity good = epx::load_or_create_identity("epx.test.access.goodclient");
        epx::Identity bad = epx::load_or_create_identity("epx.test.access.badclient");

        epx::Identity hid = epx::load_or_create_identity("epx.test.access.host3");
        epx::Host host("epx.test.access.host3", hid);
        host.add_issuer(issuer.public_key);
        std::string cred = epx::make_credential(issuer, good.public_key, "epx.test.access.host3", 0);
        CHECK(host.add_credential(cred));
        CHECK(!host.add_credential("not a credential"));
        host.expose("cert-only", ok_handler, epx::AccessPolicy{epx::AccessTier::Certificate, ""});
        host.run();
        std::this_thread::sleep_for(100ms);

        {
            epx::Client client(good);
            auto out = client.get("epx.test.access.host3", "cert-only", to_bytes("ab"));
            CHECK_EQ(out.size(), size_t(2));
        }
        {
            epx::Client client(bad);
            bool denied = false;
            try {
                client.get("epx.test.access.host3", "cert-only", {});
            } catch (const epx::EpxError& e) {
                denied = (e.code == epx::EpxError::Code::AccessDenied);
            }
            CHECK(denied);
        }
        host.stop();
    }

    // ---- PinnedPeers under AllowAll -------------------------------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.access.host4");
        epx::Host host("epx.test.access.host4", hid, epx::TrustPolicy::AllowAll);
        host.expose("pinned-only", ok_handler, epx::AccessPolicy{epx::AccessTier::PinnedPeers, ""});
        host.run();
        std::this_thread::sleep_for(100ms);

        // AllowAll lets the handshake through but records nothing, so an
        // unknown peer must be denied at the endpoint.
        epx::Identity cid = epx::load_or_create_identity("epx.test.access.stranger");
        epx::Client client(cid);
        bool denied = false;
        try {
            client.get("epx.test.access.host4", "pinned-only", {});
        } catch (const epx::EpxError& e) {
            denied = (e.code == epx::EpxError::Code::AccessDenied);
        }
        CHECK(denied);
        host.stop();
    }

    // ---- Version negotiation: v1-capped client vs v2 host ---------------
    {
        epx::Identity hid = epx::load_or_create_identity("epx.test.access.host5");
        epx::Host host("epx.test.access.host5", hid);
        host.expose("echo", ok_handler);
        host.run();
        std::this_thread::sleep_for(100ms);

        // Cap this process's *client* handshake at v1. (Host threads read
        // the cap at handshake time too, but the host side of negotiation
        // takes min(client_max, host_max) and the client's HELLO already
        // fixed client_max=1, so the session lands on v1 either way.)
        epx::wire::set_max_negotiable_version_for_testing(1);
        {
            epx::Identity cid = epx::load_or_create_identity("epx.test.access.v1client");
            epx::Client client(cid);
            auto out = client.get("epx.test.access.host5", "echo", to_bytes("v1!"));
            CHECK_EQ(out.size(), size_t(3));
        }
        epx::wire::set_max_negotiable_version_for_testing(epx::wire::kProtocolVersionMax);

        // And back at v2 on a fresh connection.
        {
            epx::Identity cid = epx::load_or_create_identity("epx.test.access.v2client");
            epx::Client client(cid);
            auto out = client.get("epx.test.access.host5", "echo", to_bytes("v2!!"));
            CHECK_EQ(out.size(), size_t(4));
        }
        host.stop();
    }

    TEST_MAIN_EXIT();
}
