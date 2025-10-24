#!/bin/bash
# Build PACEMAKER helper as a fully static MUSL binary
# This ensures it runs on any Linux distribution without dependencies

set -e

echo "Building PACEMAKER helper with static MUSL linking..."

# Build with MUSL target and static linking flags
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build \
  --release \
  --target x86_64-unknown-linux-musl

echo "Build complete!"
echo "Binary location: target/x86_64-unknown-linux-musl/release/pacemaker_helper"

# Verify it's static
echo ""
echo "Verifying static linking..."
if command -v ldd &> /dev/null; then
    ldd target/x86_64-unknown-linux-musl/release/pacemaker_helper 2>&1 || echo "Statically linked (ldd fails on static binaries)"
else
    echo "ldd not available, skipping verification"
fi

# Check file size
echo ""
echo "Binary size:"
ls -lh target/x86_64-unknown-linux-musl/release/pacemaker_helper | awk '{print $5, $9}'
