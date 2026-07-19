# Contributing to EPX

## Project layout

See the "Project layout" section of `README.md` for what lives where.
`docs/SPEC.md` is the source of truth for the wire protocol — if a change
touches framing, the handshake, or the crypto suite, update it in the same
change, not as a follow-up.

## Building and testing

```bash
cmake -B build -S . -DEPX_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

All three test binaries under `tests/` should pass before opening a PR.
`tests/test_protocol.cpp` needs no libsodium/network access (pure
encode/decode round trips); `tests/test_lifecycle.cpp` and
`tests/test_streaming.cpp` open real local sockets, so they need a
libsodium build available the same way the main library does.

## Code style

- C++17, no exceptions used for control flow outside `EpxError` at the
  public API boundary.
- Run `clang-format -i` (config at `.clang-format`) before committing.
- Prefer explicit ownership (`std::unique_ptr`/`std::shared_ptr`) over raw
  pointers; the codebase currently has zero `new`/`delete` outside smart
  pointers and platform C APIs — keep it that way.
- Internal headers live in `src/`; only `include/epx/epx.hpp` is the
  public surface. If you're adding something an application should call,
  it belongs in that header with a doc comment; everything else stays
  internal.

## Security-relevant changes

Anything touching `src/crypto.*`, `src/handshake.*`, or the frame
encode/decode functions in `src/protocol.*` is security-sensitive by
definition. Please:

1. Explain the change's effect on the guarantees listed in `docs/SPEC.md`
   section 1 (confidentiality, mutual authentication, forward secrecy,
   replay resistance) in the PR description.
2. Add or update a `tests/test_protocol.cpp` case for any wire-format
   change.
3. Avoid introducing new cryptographic primitives by hand — EPX's security
   rests on composing libsodium's audited primitives (see
   `src/crypto.hpp`), not on anything implemented here. If a change seems
   to need a new primitive, that's worth a design discussion first.

## Reporting a vulnerability

This is a reference implementation, not a maintained security-critical
product with a formal disclosure process. If you find an issue, please
open it as a regular issue describing the concern; for anything you'd
rather not post publicly first, contact the maintainer listed in the
repository before filing.
