# Serialization convention for polyglot EPX payloads

EPX endpoint payloads are opaque `Bytes` **on purpose**: the transport
never inspects, validates, or converts application data, and nothing in
the wire protocol depends on how you encode it. That leaves every project
free to use whatever fits — but a *convention* is worth having so that
nine languages talking to each other don't each hand-roll an envelope
(the way `examples/chat.cpp` does with its length-prefixed sender field,
fine for one demo, real friction at scale).

## The convention: FlatBuffers

**Recommended encoding: [FlatBuffers](https://flatbuffers.dev/).**
Chosen over Cap'n Proto specifically because of EPX's language matrix —
FlatBuffers has first-party or well-maintained support for every EPX
binding language *including Dart and Swift*, exactly the pair where
Cap'n Proto's coverage is weakest. Cap'n Proto's other differentiator,
its built-in RPC layer, is irrelevant here: EPX already **is** the RPC
layer.

The rules, in full:

1. **One `.fbs` schema per service**, versioned with the service's own
   code. It is the single source of truth for that service's
   request/response shapes.
2. **Generate per language** with `flatc` (`--cpp`, `--python --gen-object-api`,
   `--rust`, `--ts`, `--go`, `--csharp`, `--swift`, `--dart`, ...), and
   **check the generated code in** so consumers don't need `flatc`
   installed.
3. **Pass the finished buffer as the endpoint's `Bytes` payload** —
   requests and responses alike. EPX stays a dumb pipe.
4. **Verify on receipt** (`Verifier` / `VerifySizePrefixed*`): the peer
   is authenticated, but authenticated ≠ well-formed.
5. Not required: this is a convention, not a protocol rule. Protobuf,
   msgpack, JSON, or raw structs remain first-class choices when you
   have a reason — nothing in EPX will fight you.

## Worked example

[`examples/flatbuffers_demo/`](../examples/flatbuffers_demo/) is the
end-to-end proof: one schema ([`search.fbs`](../examples/flatbuffers_demo/search.fbs)),
a **C++ host** (`search_host.cpp`, built when FlatBuffers headers are
present) and a **Python client** (`search_client.py`, using the
EPX-PYTHON binding) exchanging verified FlatBuffers over the encrypted
wire:

```bash
# terminal 1 (EPX-CORE, after building)
./build/examples/search_host

# terminal 2 (needs: pip install flatbuffers)
python3 examples/flatbuffers_demo/search_client.py "protocol"
```

Regenerating after a schema change:

```bash
cd examples/flatbuffers_demo
flatc --cpp search.fbs
flatc --python --gen-object-api search.fbs
```
