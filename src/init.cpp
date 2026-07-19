#include "init.hpp"
#include "crypto.hpp"
#include <mutex>

namespace epx::detail {

void ensure_sodium_init() {
    static std::once_flag flag;
    std::call_once(flag, [] { epx::crypto::init(); });
}

} // namespace epx::detail
