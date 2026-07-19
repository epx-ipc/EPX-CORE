#!/bin/bash
# The polyglot showcase: every EPX language implementation joins ONE
# serverless group chat (no room process, no relay — discovery via the
# passive file registry, every message peer-to-peer and end-to-end
# encrypted), each says hello, and the script verifies that every
# participant heard every other one. 10 languages, 10 processes, 90
# encrypted peer-to-peer links.
#
# Run from the umbrella workspace (with every repo built; see each
# repo's README). Exits nonzero unless all 10x9 deliveries happened.
set -uo pipefail
WS="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$WS"

USER_SITE="$(python3 -m site --user-site 2>/dev/null || true)"
GEMPATH="$(gem env gempath 2>/dev/null || true)"
REAL_HOME="$HOME"

SANDBOX=/tmp/epx-polyglot
rm -rf "$SANDBOX"; mkdir -p "$SANDBOX/run"
export XDG_RUNTIME_DIR="$SANDBOX/run"
export PYTHONPATH="${USER_SITE}:${PYTHONPATH:-}"
export GEM_PATH="$GEMPATH"
export PATH="$REAL_HOME/.dotnet:$PATH"
# The Swift binary embeds a repo-relative rpath; give dyld a fallback so
# every participant resolves libepx_c regardless of cwd.
export DYLD_FALLBACK_LIBRARY_PATH="$WS/EPX-CORE/build"
export LD_LIBRARY_PATH="$WS/EPX-CORE/build:${LD_LIBRARY_PATH:-}"

declare -a NAMES=(cpp c rust py node go cs swift ruby dart)

launch() { # name, command...
  local name="$1"; shift
  ( sleep 12; echo "hello from $name"; sleep 10; echo "/quit" ) | \
      HOME="$SANDBOX/home-$name" "$@" "$name" > "$SANDBOX/$name.log" 2>&1 &
  PIDS+=($!)
}

for n in "${NAMES[@]}"; do mkdir -p "$SANDBOX/home-$n"; done

PIDS=()
launch cpp   "$WS/EPX-CORE/build/examples/polychat"
launch c     "$WS/EPX-CORE/build/examples/polychat_c"
launch rust  "$WS/EPX-RUST/target/debug/examples/polychat"
launch py    python3 "$WS/EPX-PYTHON/examples/polychat.py"
launch node  node "$WS/EPX-NODE/examples/polychat.js"
launch go    /tmp/epx-go-polychat
launch cs    dotnet exec "$WS/EPX-CSHARP/examples/Polychat/bin/Debug/net10.0/Polychat.dll"
launch swift "$WS/EPX-SWIFT/.build/debug/polychat"
launch ruby  ruby "$WS/EPX-RUBY/examples/polychat.rb"
launch dart  dart "$WS/EPX-DART/example/polychat.dart"

for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; done

fail=0
total=0
for receiver in "${NAMES[@]}"; do
  for sender in "${NAMES[@]}"; do
    [ "$receiver" = "$sender" ] && continue
    if grep -q "$sender: hello from $sender" "$SANDBOX/$receiver.log"; then
      total=$((total + 1))
    else
      echo "MISSING: $receiver never heard $sender"
      fail=1
    fi
  done
done

echo "deliveries verified: $total/90"
if [ $fail -eq 0 ]; then
  echo "PASS: 10-language serverless group chat — everyone heard everyone"
else
  echo "FAIL — inspect $SANDBOX/*.log"
fi
exit $fail
