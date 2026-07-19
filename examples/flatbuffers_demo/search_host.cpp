// FlatBuffers-over-EPX demo, host side (see docs/SERIALIZATION.md and
// search.fbs). Exposes one ordinary Receive endpoint, "search", whose
// request/response payloads are FlatBuffers — EPX itself stays a dumb
// byte pipe, exactly as the convention prescribes. Run
// search_client.py (Python) against it to prove the cross-language
// story: same schema, two languages, one encrypted wire.
#include "epx/epx.hpp"
#include "search_generated.h"

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <string>
#include <vector>

namespace {

// A toy corpus to "search".
const std::vector<std::string> kCorpus = {
    "EPX protocol specification",
    "FlatBuffers serialization convention",
    "Mutually authenticated handshake design",
    "Topic pub/sub fan-out notes",
    "Key rotation review checklist",
};

} // namespace

int main() {
    epx::Identity id = epx::load_or_create_identity("com.epx.demo.fbsearch");
    epx::Host host("com.epx.demo.fbsearch", id);
    host.set_description("FlatBuffers demo: search over EPX");

    host.expose("search", [](const epx::Bytes& req, const std::string&, const epx::PeerInfo&) {
        epx::Response out;

        // Verify + decode the FlatBuffers request.
        flatbuffers::Verifier verifier(req.data(), req.size());
        if (!epxdemo::VerifySearchRequestBuffer(verifier)) {
            out.ok = false;
            out.error = "payload is not a valid SearchRequest buffer";
            return out;
        }
        const auto* request = epxdemo::GetSearchRequest(req.data());
        const std::string query = request->query()->str();
        const int limit = request->limit();

        // Build the FlatBuffers response.
        flatbuffers::FlatBufferBuilder builder;
        std::vector<flatbuffers::Offset<epxdemo::SearchResult>> results;
        for (const auto& doc : kCorpus) {
            auto haystack = doc;
            auto needle = query;
            std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
            std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);
            if (haystack.find(needle) != std::string::npos && int(results.size()) < limit) {
                results.push_back(epxdemo::CreateSearchResult(
                    builder, builder.CreateString(doc), 1.0f - 0.1f * float(results.size())));
            }
        }
        auto response = epxdemo::CreateSearchResponse(builder, builder.CreateVector(results));
        builder.Finish(response);

        out.ok = true;
        out.data.assign(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
        std::printf("[search] \"%s\" -> %zu result(s)\n", query.c_str(), results.size());
        std::fflush(stdout);
        return out;
    });

    host.run();
    host.stop_on_signals({SIGINT, SIGTERM});
    std::printf("com.epx.demo.fbsearch serving; try: python3 search_client.py \"protocol\"\n");
    std::fflush(stdout);
    host.wait_until_stopped();
    return 0;
}
