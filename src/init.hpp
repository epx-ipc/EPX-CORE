#pragma once
namespace epx::detail {
// Idempotent, thread-safe libsodium initialization. Safe to call from
// multiple translation units / threads.
void ensure_sodium_init();
} // namespace epx::detail
