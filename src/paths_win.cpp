// Windows path helpers. NOTE: this file is compiled only on _WIN32 targets
// and has not been build- or run-tested (this reference implementation was
// developed and verified on Linux). Review before relying on it in
// production; see README.md "Windows support" section.
#include "paths.hpp"

#include <windows.h>
#include <shlobj.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdexcept>

namespace epx::paths {

namespace {
std::string local_appdata() {
    char path[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path) != S_OK) {
        throw std::runtime_error("SHGetFolderPathA(CSIDL_LOCAL_APPDATA) failed");
    }
    return std::string(path);
}
}

void ensure_private_dir(const std::string& path) {
    // CreateDirectoryA is idempotent-ish (fails with ERROR_ALREADY_EXISTS).
    // Directories under %LOCALAPPDATA% already inherit an ACL restricted to
    // the owning user and SYSTEM/Administrators by default; we do not
    // further tighten it here, but production use should set an explicit
    // DACL granting only the current user SID, mirroring the 0700 semantics
    // used on POSIX.
    std::string cur;
    size_t pos = (path.size() > 2 && path[1] == ':') ? 2 : 0; // skip "C:"
    while (pos < path.size()) {
        size_t next = path.find('\\', pos + 1);
        cur = (next == std::string::npos) ? path : path.substr(0, next);
        if (!cur.empty()) {
            CreateDirectoryA(cur.c_str(), nullptr); // ignore ERROR_ALREADY_EXISTS
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
}

std::string runtime_dir() {
    return local_appdata() + "\\epx\\run";
}

std::string config_dir() {
    return local_appdata() + "\\epx\\config";
}

} // namespace epx::paths
