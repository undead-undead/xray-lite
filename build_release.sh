#!/bin/bash

# Build and package binaries for release
# 构建并打包发布版本

set -e

VERSION="v0.1.24"
PROJECT_NAME="xray-lite"

echo "========================================="
echo "Building Release Binaries"
echo "Version: $VERSION"
echo "========================================="
echo ""

# Create release directory
mkdir -p release

# Build for x86_64
echo "[1/2] Building for x86_64-unknown-linux-gnu..."
cargo build --release --target x86_64-unknown-linux-gnu 2>&1 | tail -3

# Package x86_64
echo "Packaging x86_64..."
cd target/x86_64-unknown-linux-gnu/release
tar -czf ../../../release/${PROJECT_NAME}-x86_64-unknown-linux-gnu.tar.gz \
    vless-server keygen
cd ../../..

echo "✓ x86_64 build complete"
echo ""

# Note about cross-compilation
echo "[2/2] Note: For aarch64, you need cross-compilation setup"
echo "To build for aarch64:"
echo "  1. Install cross: cargo install cross"
echo "  2. Run: cross build --release --target aarch64-unknown-linux-gnu"
echo ""

# Display results
echo "========================================="
echo "Build Complete!"
echo "========================================="
echo ""
echo "Release files:"
ls -lh release/
echo ""
echo "Upload these files to GitHub Release $VERSION"
echo ""
