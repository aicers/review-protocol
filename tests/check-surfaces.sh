#!/bin/sh
# External fixtures keep optional transport dependencies out of schema consumers.
set -eu
manifest="$(dirname "$0")/compile/Cargo.toml"
cargo check --manifest-path "$manifest" --no-default-features
for features in client server client,server test-support legacy; do
    cargo check --manifest-path "$manifest" --no-default-features --features "$features"
done
# Capture the tree first: a failing `cargo tree` inside the `if` would not trip `set -e`.
tree="$(cargo tree --manifest-path "$manifest" --no-default-features --edges normal --prefix none)"
if printf '%s\n' "$tree" | grep -E '^(oinq|quinn|tokio|rustls|bincode) '; then
    echo 'Schema-only dependency graph unexpectedly contains transport/runtime dependencies' >&2
    exit 1
fi
