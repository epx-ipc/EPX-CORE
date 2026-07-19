// Unix domain socket transport for Linux / macOS / BSD.
#include "transport.hpp"
#include "paths.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <stdexcept>
#include <pwd.h>

#if defined(__linux__)
#include <sys/socket.h> // SO_PEERCRED
#elif defined(__APPLE__)
#include <sys/ucred.h>  // LOCAL_PEERCRED
#endif

namespace epx::transport {

namespace {

long get_peer_uid(int fd) {
#if defined(__linux__)
    struct ucred cred{};
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
        return long(cred.uid);
    }
    return -1;
#elif defined(__APPLE__)
    uid_t euid; gid_t egid;
    if (getpeereid(fd, &euid, &egid) == 0) {
        return long(euid);
    }
    return -1;
#else
    (void)fd;
    return -1;
#endif
}

class PosixTransport final : public Transport {
public:
    explicit PosixTransport(int fd) : fd_(fd), peer_uid_(get_peer_uid(fd)) {}
    ~PosixTransport() override { close(); }

    bool send_all(const uint8_t* data, size_t len) override {
        size_t sent = 0;
        while (sent < len) {
            ssize_t n = ::send(fd_, data + sent, len - sent, MSG_NOSIGNAL);
            if (n <= 0) return false;
            sent += size_t(n);
        }
        return true;
    }

    bool recv_all(uint8_t* data, size_t len) override {
        size_t got = 0;
        while (got < len) {
            ssize_t n = ::recv(fd_, data + got, len - got, 0);
            if (n <= 0) return false;
            got += size_t(n);
        }
        return true;
    }

    bool set_recv_timeout(int ms) override {
        if (fd_ < 0) return false;
        struct timeval tv{};
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        return setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
    }

    bool set_send_timeout(int ms) override {
        if (fd_ < 0) return false;
        struct timeval tv{};
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        return setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
    }

    void close() override {
        if (fd_ >= 0) {
            // shutdown() first: reliably unblocks a concurrent blocking
            // send()/recv() on this fd from another thread (e.g. the
            // per-connection reader thread) on Linux/BSD/macOS. A bare
            // close() from another thread does not guarantee that; the
            // reader could sit blocked in recv() indefinitely.
            ::shutdown(fd_, SHUT_RDWR);
            ::close(fd_);
            fd_ = -1;
        }
    }

    long peer_uid() const override { return peer_uid_; }

private:
    int fd_;
    long peer_uid_;
};

class PosixListener final : public Listener {
public:
    PosixListener(int fd, std::string path) : fd_(fd), path_(std::move(path)) {}
    ~PosixListener() override { close(); }

    std::unique_ptr<Transport> accept() override {
        int cfd = ::accept(fd_, nullptr, nullptr);
        if (cfd < 0) return nullptr;
        return std::make_unique<PosixTransport>(cfd);
    }

    void close() override {
        if (fd_ >= 0) {
            // A concurrent close() from another thread does not reliably
            // unblock a thread currently sitting in accept() on the same
            // fd. Connecting to ourselves first forces accept() to return
            // immediately; the connection it hands back is discarded by
            // the caller once it notices the listener is shutting down
            // (see Host::Impl::accept_loop's post-accept running check).
            if (!path_.empty()) {
                int nudge = ::socket(AF_UNIX, SOCK_STREAM, 0);
                if (nudge >= 0) {
                    struct sockaddr_un addr{};
                    addr.sun_family = AF_UNIX;
                    std::strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
                    ::connect(nudge, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)); // best-effort
                    ::close(nudge);
                }
            }
            ::close(fd_);
            fd_ = -1;
        }
        if (!path_.empty()) { ::unlink(path_.c_str()); path_.clear(); }
    }

private:
    int fd_;
    std::string path_;
};

} // namespace

std::string default_address_for_service(const std::string& service_name) {
    return epx::paths::runtime_dir() + "/sockets/" + service_name + ".sock";
}

std::unique_ptr<Listener> listen(const std::string& address) {
    size_t slash = address.find_last_of('/');
    if (slash != std::string::npos) {
        epx::paths::ensure_private_dir(address.substr(0, slash));
    }

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket() failed");

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (address.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        throw std::runtime_error("socket path too long: " + address);
    }
    std::strncpy(addr.sun_path, address.c_str(), sizeof(addr.sun_path) - 1);

    ::unlink(address.c_str()); // remove a stale socket from a previous crash

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        throw std::runtime_error("bind() failed for " + address + ": " + std::strerror(errno));
    }
    chmod(address.c_str(), 0600); // only this OS user may connect

    if (::listen(fd, 64) != 0) {
        ::close(fd);
        throw std::runtime_error("listen() failed");
    }

    return std::make_unique<PosixListener>(fd, address);
}

std::unique_ptr<Transport> connect(const std::string& address) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return nullptr;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (address.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        return nullptr;
    }
    std::strncpy(addr.sun_path, address.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return nullptr;
    }
    return std::make_unique<PosixTransport>(fd);
}

} // namespace epx::transport
