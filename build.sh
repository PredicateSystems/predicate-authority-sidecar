#!/usr/bin/env bash
#
# Build script for predicate-authorityd with embedded Web UI
#
# Usage:
#   ./build.sh          # Build release binary
#   ./build.sh --debug  # Build debug binary
#   ./build.sh --clean  # Clean and rebuild everything
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse arguments
BUILD_MODE="release"
CLEAN=false

for arg in "$@"; do
    case $arg in
        --debug)
            BUILD_MODE="debug"
            ;;
        --clean)
            CLEAN=true
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug    Build debug binary instead of release"
            echo "  --clean    Clean and rebuild everything"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# Clean if requested
if [ "$CLEAN" = true ]; then
    log_info "Cleaning previous builds..."
    rm -rf webui/dist webui/node_modules target
fi

# Check for required tools
log_info "Checking prerequisites..."

if ! command -v node &> /dev/null; then
    log_error "Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

if ! command -v npm &> /dev/null; then
    log_error "npm is not installed. Please install npm first."
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    log_error "Rust/Cargo is not installed. Please install Rust first."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    log_warn "Node.js version $NODE_VERSION detected. Recommended: 18+"
fi

# Step 1: Build Web UI
log_info "Building Web UI (React + Vite)..."
cd webui

if [ ! -d "node_modules" ]; then
    log_info "Installing npm dependencies..."
    npm ci
fi

npm run build

if [ ! -f "dist/index.html" ]; then
    log_error "Web UI build failed - dist/index.html not found"
    exit 1
fi

log_info "Web UI built successfully ($(du -sh dist | cut -f1))"
cd ..

# Step 2: Touch static_files.rs to force re-embed
# This ensures rust-embed picks up the new dist files
touch src/webui/static_files.rs

# Step 3: Build Rust binary
log_info "Building Rust binary ($BUILD_MODE mode)..."

if [ "$BUILD_MODE" = "release" ]; then
    cargo build --release
    BINARY_PATH="target/release/predicate-authorityd"
else
    cargo build
    BINARY_PATH="target/debug/predicate-authorityd"
fi

if [ ! -f "$BINARY_PATH" ]; then
    log_error "Rust build failed - binary not found"
    exit 1
fi

BINARY_SIZE=$(du -h "$BINARY_PATH" | cut -f1)
log_info "Build complete!"
echo ""
echo "Binary: $BINARY_PATH ($BINARY_SIZE)"
echo ""
echo "Run with Web UI:"
echo "  $BINARY_PATH --policy-file policies/strict.json --web-ui run"
