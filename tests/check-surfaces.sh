#!/bin/sh
# External fixtures keep optional transport dependencies out of schema consumers.
set -eu
manifest="$(dirname "$0")/compile/Cargo.toml"
cargo check --manifest-path "$manifest" --no-default-features
for features in client server client,server test-support legacy; do
    cargo check --manifest-path "$manifest" --no-default-features --features "$features"
done
if cargo tree --manifest-path "$manifest" --no-default-features --edges normal --prefix none | rg '^(oinq|quinn|tokio|rustls|bincode) '; then
    echo 'Schema-only dependency graph unexpectedly contains transport/runtime dependencies' >&2
    exit 1
fi
