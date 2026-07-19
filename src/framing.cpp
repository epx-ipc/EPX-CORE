#include "framing.hpp"

namespace epx::framing {

bool write_frame(epx::transport::Transport& t, const RawFrame& f, bool with_epoch) {
    std::vector<uint8_t> header;
    header.push_back(uint8_t(f.type));
    epx::wire::put_u64(header, f.counter);
    if (with_epoch) header.push_back(f.epoch);

    uint32_t total_len = uint32_t(header.size() + f.body.size());
    std::vector<uint8_t> len_prefix;
    epx::wire::put_u32(len_prefix, total_len);

    if (!t.send_all(len_prefix.data(), len_prefix.size())) return false;
    if (!t.send_all(header.data(), header.size())) return false;
    if (!f.body.empty() && !t.send_all(f.body.data(), f.body.size())) return false;
    return true;
}

std::optional<RawFrame> read_frame(epx::transport::Transport& t, bool with_epoch) {
    uint8_t len_buf[4];
    if (!t.recv_all(len_buf, 4)) return std::nullopt;
    uint32_t total_len = epx::wire::get_u32(len_buf);
    const uint32_t header_len = with_epoch ? 1 + 8 + 1 : 1 + 8;
    if (total_len < header_len || total_len > epx::wire::kMaxFrameBytes) return std::nullopt;

    std::vector<uint8_t> rest(total_len);
    if (!t.recv_all(rest.data(), rest.size())) return std::nullopt;

    RawFrame f;
    f.type = epx::wire::FrameType(rest[0]);
    f.counter = epx::wire::get_u64(rest.data() + 1);
    if (with_epoch) f.epoch = rest[9];
    f.body.assign(rest.begin() + header_len, rest.end());
    return f;
}

} // namespace epx::framing
