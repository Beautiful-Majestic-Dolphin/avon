#!/bin/bash
# Build macOS .pkg installer for AVON Agent
#
# Usage:
#   ./build-pkg.sh [--sign IDENTITY] [--notarize]
#
# Prerequisites:
#   - avon-agent binary built (release mode)
#   - Apple Developer ID certificates (for signing)
#
# The script expects the binary at one of:
#   - ../../target/release/avon-agent
#   - ../../target/aarch64-apple-darwin/release/avon-agent (ARM)
#   - ../../target/x86_64-apple-darwin/release/avon-agent (Intel)
#   - ../../target/universal/avon-agent (Universal binary)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
PKG_VERSION="${VERSION:-0.1.0}"
PKG_IDENTIFIER="ai.avon.agent"
SIGN_IDENTITY=""
DO_NOTARIZE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign)
            SIGN_IDENTITY="$2"
            shift 2
            ;;
        --notarize)
            DO_NOTARIZE=true
            shift
            ;;
        --version)
            PKG_VERSION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "=== AVON Agent macOS Package Builder ==="
echo "Version: $PKG_VERSION"

# Find the agent binary
BINARY=""
for candidate in \
    "$PROJECT_ROOT/target/universal/avon-agent" \
    "$PROJECT_ROOT/target/release/avon-agent" \
    "$PROJECT_ROOT/target/aarch64-apple-darwin/release/avon-agent" \
    "$PROJECT_ROOT/target/x86_64-apple-darwin/release/avon-agent"; do
    if [ -f "$candidate" ]; then
        BINARY="$candidate"
        break
    fi
done

if [ -z "$BINARY" ]; then
    echo "Error: avon-agent binary not found. Build with 'cargo build --release -p avon-agent' first."
    exit 1
fi

echo "Using binary: $BINARY"
echo "Architecture: $(file "$BINARY" | grep -o 'arm64\|x86_64' | tr '\n' '+' | sed 's/+$//')"

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/payload/usr/local/bin"
mkdir -p "$BUILD_DIR/payload/usr/local/share/avon"
mkdir -p "$BUILD_DIR/scripts"
mkdir -p "$BUILD_DIR/output"

# Copy binary
cp "$BINARY" "$BUILD_DIR/payload/usr/local/bin/avon-agent"
chmod 755 "$BUILD_DIR/payload/usr/local/bin/avon-agent"

# Copy LaunchDaemon plist (installed by postinstall to /Library/LaunchDaemons/)
cp "$SCRIPT_DIR/ai.avon.agent.plist" "$BUILD_DIR/payload/usr/local/share/avon/"

# Copy installer scripts
cp "$SCRIPT_DIR/scripts/preinstall" "$BUILD_DIR/scripts/"
cp "$SCRIPT_DIR/scripts/postinstall" "$BUILD_DIR/scripts/"
chmod 755 "$BUILD_DIR/scripts/preinstall"
chmod 755 "$BUILD_DIR/scripts/postinstall"

# Sign the binary if identity provided
if [ -n "$SIGN_IDENTITY" ]; then
    echo "Signing binary with: $SIGN_IDENTITY"
    codesign --sign "$SIGN_IDENTITY" \
        --options runtime \
        --timestamp \
        --force \
        "$BUILD_DIR/payload/usr/local/bin/avon-agent"
fi

# Build the component package
echo "Building component package..."
COMPONENT_PKG="$BUILD_DIR/output/avon-agent-component.pkg"
pkgbuild \
    --identifier "$PKG_IDENTIFIER" \
    --version "$PKG_VERSION" \
    --root "$BUILD_DIR/payload" \
    --scripts "$BUILD_DIR/scripts" \
    --install-location "/" \
    "$COMPONENT_PKG"

# Build the distribution package (with installer GUI)
echo "Building distribution package..."
DIST_PKG="$BUILD_DIR/output/avon-agent-${PKG_VERSION}.pkg"

# Create distribution XML
cat > "$BUILD_DIR/distribution.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<installer-gui-script minSpecVersion="2">
    <title>AVON Agent</title>
    <welcome file="welcome.html" />
    <organization>ai.avon</organization>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true" />
    <options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64" />
    <volume-check>
        <allowed-os-versions>
            <os-version min="11.0" />
        </allowed-os-versions>
    </volume-check>
    <choices-outline>
        <line choice="default">
            <line choice="ai.avon.agent" />
        </line>
    </choices-outline>
    <choice id="default" />
    <choice id="ai.avon.agent" visible="false">
        <pkg-ref id="ai.avon.agent" />
    </choice>
    <pkg-ref id="ai.avon.agent" version="$PKG_VERSION" onConclusion="none">avon-agent-component.pkg</pkg-ref>
</installer-gui-script>
EOF

# Create welcome page
mkdir -p "$BUILD_DIR/resources"
cat > "$BUILD_DIR/resources/welcome.html" <<EOF
<html>
<body>
<h1>AVON Agent Installer</h1>
<p>This will install the AVON post-quantum zero-trust agent on your Mac.</p>
<p>Version: $PKG_VERSION</p>
<p>The agent will be installed as a system service and start automatically.</p>
<h2>What will be installed:</h2>
<ul>
    <li><code>/usr/local/bin/avon-agent</code> - Agent binary</li>
    <li><code>/Library/Application Support/AVON/</code> - Configuration and data</li>
    <li><code>/Library/Logs/AVON/</code> - Log files</li>
    <li>LaunchDaemon service (auto-start on boot)</li>
</ul>
<p><strong>Note:</strong> Administrator privileges are required.</p>
</body>
</html>
EOF

productbuild \
    --distribution "$BUILD_DIR/distribution.xml" \
    --resources "$BUILD_DIR/resources" \
    --package-path "$BUILD_DIR/output" \
    "$DIST_PKG"

# Sign the distribution package if identity provided
if [ -n "$SIGN_IDENTITY" ]; then
    echo "Signing distribution package..."
    SIGNED_PKG="$BUILD_DIR/output/avon-agent-${PKG_VERSION}-signed.pkg"
    productsign \
        --sign "$SIGN_IDENTITY" \
        --timestamp \
        "$DIST_PKG" \
        "$SIGNED_PKG"
    mv "$SIGNED_PKG" "$DIST_PKG"
fi

# Notarize if requested
if [ "$DO_NOTARIZE" = true ]; then
    if [ -z "${APPLE_ID:-}" ] || [ -z "${TEAM_ID:-}" ] || [ -z "${APP_PASSWORD:-}" ]; then
        echo "Error: Notarization requires APPLE_ID, TEAM_ID, and APP_PASSWORD environment variables."
        exit 1
    fi

    echo "Submitting for notarization..."
    xcrun notarytool submit "$DIST_PKG" \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID" \
        --password "$APP_PASSWORD" \
        --wait

    echo "Stapling notarization ticket..."
    xcrun stapler staple "$DIST_PKG"
fi

echo ""
echo "=== Build Complete ==="
echo "Package: $DIST_PKG"
echo "Size: $(du -h "$DIST_PKG" | cut -f1)"

# Clean up intermediate files
rm -f "$COMPONENT_PKG"
rm -rf "$BUILD_DIR/payload" "$BUILD_DIR/scripts" "$BUILD_DIR/resources" "$BUILD_DIR/distribution.xml"

echo "Done."
