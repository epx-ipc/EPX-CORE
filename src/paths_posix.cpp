#include "paths.hpp"

#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <stdexcept>

namespace epx::paths {

void ensure_private_dir(const std::string& path) {
    std::string cur;
    size_t pos = 0;
    if (path.empty() || path[0] != '/') throw std::runtime_error("expected absolute path: " + path);
    while (pos < path.size()) {
        size_t next = path.find('/', pos + 1);
        cur = (next == std::string::npos) ? path : path.substr(0, next);
        if (!cur.empty()) {
            if (mkdir(cur.c_str(), 0700) != 0 && errno != EEXIST) {
                throw std::runtime_error("mkdir failed for " + cur + ": " + std::strerror(errno));
            }
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    struct stat st{};
    if (stat(path.c_str(), &st) == 0) {
        if (st.st_uid != getuid()) {
            throw std::runtime_error("refusing to use " + path + ": owned by a different user");
        }
        chmod(path.c_str(), 0700);
    }
}

std::string runtime_dir() {
    if (const char* xdg = std::getenv("XDG_RUNTIME_DIR")) {
        if (*xdg) return std::string(xdg) + "/epx";
    }
    return "/tmp/epx-" + std::to_string(getuid());
}

std::string config_dir() {
    if (const char* home = std::getenv("HOME")) {
        if (*home) return std::string(home) + "/.epx";
    }
    return "/tmp/epx-" + std::to_string(getuid()) + "/.epx";
}

} // namespace epx::paths
