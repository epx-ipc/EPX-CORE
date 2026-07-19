#include "epx/epx.hpp"
#include "init.hpp"
#include "keystore.hpp"

namespace epx {

Identity load_or_create_identity(const std::string& app_name) {
    epx::detail::ensure_sodium_init();
    return epx::keystore::load_or_create_identity(app_name);
}

} // namespace epx
