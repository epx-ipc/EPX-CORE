// Abstract byte-stream transport. EPX ships two implementations:
//   transport_posix.cpp  — Unix domain sockets (Linux, macOS, BSD)
//   transport_win.cpp    — Named pipes (Windows)
// Only one is compiled in, selected by CMake based on target OS. Everything
// above this layer (framing, crypto, protocol) is transport-agnostic.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace epx::transport {

// One connected, bidirectional byte stream.
class Transport {
public:
    virtual ~Transport() = default;

    // Blocking full write; returns false on any error (peer gone, etc).
    virtual bool send_all(const uint8_t* data, size_t len) = 0;

    // Blocking full read; returns false on EOF or error before `len` bytes
    // were read.
    virtual bool recv_all(uint8_t* data, size_t len) = 0;

    virtual void close() = 0;

    // Sets a receive timeout on the underlying handle: a recv_all() that
    // makes no progress for `ms` milliseconds fails (returns false) instead
    // of blocking forever. `ms == 0` clears the timeout (block indefinitely
    // again). Used to bound the handshake, so a peer that connects and then
    // sends nothing can't pin down a connection thread indefinitely.
    // Returns false if the platform/implementation can't do it (the caller
    // proceeds without the bound rather than failing).
    virtual bool set_recv_timeout(int ms) { (void)ms; return false; }

    // Same idea for the send direction: a send_all() that can't make
    // progress for `ms` milliseconds (peer not draining its socket — i.e.
    // backpressure) fails instead of blocking forever. `ms == 0` clears.
    // This is the phase-1 backpressure mechanism (roadmap item 6): a
    // blocked-too-long write surfaces as `false` from StreamWriter::write /
    // OutputStream::write, exactly like a dead peer, and the producer
    // decides what to do (drop, retry, disconnect).
    virtual bool set_send_timeout(int ms) { (void)ms; return false; }

    // OS-verified UID of the process on the other end of the connection, if
    // the platform can provide it (SO_PEERCRED / LOCAL_PEERCRED / named pipe
    // client process token). -1 if unavailable.
    virtual long peer_uid() const = 0;
};

class Listener {
public:
    virtual ~Listener() = default;
    // Blocks until an incoming connection arrives, or returns nullptr if the
    // listener was closed from another thread.
    virtual std::unique_ptr<Transport> accept() = 0;
    virtual void close() = 0;
};

// Computes the platform-appropriate, per-user, per-service address:
//   POSIX:   $XDG_RUNTIME_DIR/epx/sockets/<service>.sock (falls back to
//            /tmp/epx-<uid>/sockets/<service>.sock)
//   Windows: \\.\pipe\epx-<sid-hash>-<service>
std::string default_address_for_service(const std::string& service_name);

std::unique_ptr<Listener> listen(const std::string& address);
std::unique_ptr<Transport> connect(const std::string& address);

} // namespace epx::transport
