// Named-pipe transport for Windows.
//
// NOTE: this file is compiled only when targeting Windows and has not been
// build- or run-tested — this reference implementation was developed and
// verified end-to-end on Linux (see README.md). The design mirrors
// transport_posix.cpp exactly (same framing, same handshake, same crypto);
// only the raw byte-stream plumbing differs. Before relying on this in
// production:
//   - Replace the default pipe security descriptor with an explicit DACL
//     granting access only to the current user SID (today it inherits
//     default Windows named-pipe ACLs, which are usually fine for a
//     single-user desktop but should be verified for your deployment).
//   - Load-test ConnectNamedPipe/ReadFile/WriteFile error handling; this
//     was written against the documented Win32 API contract but not
//     exercised.
#include "transport.hpp"
#include "paths.hpp"

#include <windows.h>
#include <sddl.h>
#include <stdexcept>
#include <algorithm>

namespace epx::transport {

namespace {

constexpr DWORD kPipeBufferSize = 1 << 16;

class WinTransport final : public Transport {
public:
    explicit WinTransport(HANDLE h) : handle_(h) {}
    ~WinTransport() override { close(); }

    bool send_all(const uint8_t* data, size_t len) override {
        size_t sent = 0;
        while (sent < len) {
            DWORD n = 0;
            if (!WriteFile(handle_, data + sent, DWORD(len - sent), &n, nullptr) || n == 0) return false;
            sent += n;
        }
        return true;
    }

    bool recv_all(uint8_t* data, size_t len) override {
        size_t got = 0;
        while (got < len) {
            DWORD n = 0;
            if (!ReadFile(handle_, data + got, DWORD(len - got), &n, nullptr) || n == 0) return false;
            got += n;
        }
        return true;
    }

    void close() override {
        if (handle_ != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(handle_);
            DisconnectNamedPipe(handle_);
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    // Windows has no POSIX UID concept; identity is established
    // cryptographically during the handshake instead (see handshake.cpp).
    // A production build could resolve GetNamedPipeClientProcessId() to a
    // SID via OpenProcessToken/GetTokenInformation(TokenUser) if
    // process-identity-based authorization is needed in addition to that.
    long peer_uid() const override { return -1; }

private:
    HANDLE handle_;
};

class WinListener final : public Listener {
public:
    explicit WinListener(std::string pipe_name) : pipe_name_(std::move(pipe_name)) {}
    ~WinListener() override { close(); }

    std::unique_ptr<Transport> accept() override {
        if (closed_) return nullptr;

        HANDLE h = CreateNamedPipeA(
            pipe_name_.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            kPipeBufferSize, kPipeBufferSize,
            0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return nullptr;

        BOOL connected = ConnectNamedPipe(h, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(h);
            return closed_ ? nullptr : accept(); // retry unless we were closed concurrently
        }
        return std::make_unique<WinTransport>(h);
    }

    void close() override { closed_ = true; }

private:
    std::string pipe_name_;
    bool closed_ = false;
};

} // namespace

std::string default_address_for_service(const std::string& service_name) {
    // Flat namespace, no per-user subdirectory needed the way POSIX sockets
    // need one: the pipe's security descriptor (see the accept() TODO
    // above) is what should scope access to the current user.
    return "\\\\.\\pipe\\epx-" + service_name;
}

std::unique_ptr<Listener> listen(const std::string& address) {
    return std::make_unique<WinListener>(address);
}

std::unique_ptr<Transport> connect(const std::string& address) {
    for (int attempt = 0; attempt < 50; ++attempt) {
        HANDLE h = CreateFileA(address.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            return std::make_unique<WinTransport>(h);
        }
        if (GetLastError() != ERROR_PIPE_BUSY) return nullptr;
        if (!WaitNamedPipeA(address.c_str(), 200)) return nullptr;
    }
    return nullptr;
}

} // namespace epx::transport
