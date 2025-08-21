#!/bin/bash

# ICICLE Metal Backend Setup Script for Apple Silicon
# This script downloads and installs the ICICLE Metal backend

set -e

echo "🔧 ICICLE Metal Backend Setup for Apple Silicon"
echo "================================================"

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ This script is for macOS only"
    exit 1
fi

# Check if running on Apple Silicon
if [[ $(uname -m) != "arm64" ]]; then
    echo "⚠️  Warning: This machine does not appear to be Apple Silicon (arm64)"
    echo "   The Metal backend may not work properly on Intel Macs"
fi

# Create directory for ICICLE backend
ICICLE_DIR="$HOME/.icicle"
mkdir -p "$ICICLE_DIR"

echo "📦 Downloading ICICLE Metal backend..."
echo "   Note: You'll need to download the Metal backend from:"
echo "   https://github.com/ingonyama-zk/icicle/releases"
echo ""
echo "   Look for a file named something like:"
echo "   - icicle-metal-backend-macos.tar.gz"
echo "   - or similar Metal backend bundle"
echo ""
echo "📍 Installation steps:"
echo "   1. Download the Metal backend from the releases page"
echo "   2. Extract it to: $ICICLE_DIR/backend/"
echo "   3. Set environment variable:"
echo "      export ICICLE_BACKEND_INSTALL_DIR=$ICICLE_DIR/backend"
echo ""

# Create shell config snippet
cat > "$ICICLE_DIR/env.sh" << 'EOF'
# ICICLE GPU Backend Configuration
export ICICLE_BACKEND_INSTALL_DIR="$HOME/.icicle/backend"

# Optional: Set license server if required
# export ICICLE_LICENSE=port@server
EOF

echo "✅ Setup instructions complete!"
echo ""
echo "To use the GPU backend, add this to your shell profile:"
echo "   source $ICICLE_DIR/env.sh"
echo ""
echo "Or run this before using the benchmark:"
echo "   export ICICLE_BACKEND_INSTALL_DIR=$ICICLE_DIR/backend"
echo ""
echo "📝 To test GPU acceleration, run:"
echo "   cargo run --release --features gpu --bin rs_shuffle_reencrypt_bench -- --gpu"
echo ""
echo "Note: The backend uses a free R&D license by default."
echo "      For production use, contact Ingonyama for a commercial license."