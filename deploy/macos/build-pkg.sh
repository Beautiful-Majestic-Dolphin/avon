#!/usr/bin/env bash
# Builds a universal, optionally signed and notarized AVON agent package.
#
# Signing uses two different identities on purpose: `codesign` needs a
# "Developer ID Application" certificate and `productsign` needs a
# "Developer ID Installer" one. Using the application identity for both — as an
# earlier version of this script did — produces a package Gatekeeper rejects.
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION=""; OUT="dist"; SKIP_SIGN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --skip-sign) SKIP_SIGN=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$VERSION" ] || { echo "--version is required" >&2; exit 2; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

ROOT=$(mktemp -d); trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/payload/usr/local/bin" "$ROOT/payload/Library/LaunchDaemons" "$ROOT/payload/usr/local/share/avon"

# Both architectures are mandatory: a "universal" package that silently ships
# one arch strands half the fleet.
for target in x86_64-apple-darwin aarch64-apple-darwin; do
  rustup target add "$target" >/dev/null 2>&1 || true
  cargo build --release --locked --target "$target" -p avon-agent --bin avon-agent --bin avon-agent-helper
done
for bin in avon-agent avon-agent-helper; do
  x="target/x86_64-apple-darwin/release/$bin"
  a="target/aarch64-apple-darwin/release/$bin"
  [ -f "$x" ] && [ -f "$a" ] || { echo "missing build output for $bin" >&2; exit 1; }
  lipo -create -output "$ROOT/payload/usr/local/bin/$bin" "$x" "$a"
  chmod 0755 "$ROOT/payload/usr/local/bin/$bin"
done

cp deploy/macos/ai.avon.agent.plist deploy/macos/ai.avon.helper.plist "$ROOT/payload/Library/LaunchDaemons/"
chmod 0644 "$ROOT"/payload/Library/LaunchDaemons/*.plist
cp deploy/macos/enable.sh "$ROOT/payload/usr/local/share/avon/enable.sh"
chmod 0755 "$ROOT/payload/usr/local/share/avon/enable.sh"

if [ "$SKIP_SIGN" -eq 0 ] && [ -n "${MACOS_CERTIFICATE:-}" ]; then
  APP_ID="${MACOS_APP_IDENTITY:-Developer ID Application}"
  for bin in avon-agent avon-agent-helper; do
    codesign --force --options runtime --timestamp --sign "$APP_ID" "$ROOT/payload/usr/local/bin/$bin"
    codesign --verify --strict --verbose=2 "$ROOT/payload/usr/local/bin/$bin"
  done
fi

STAGE="$ROOT/stage"; mkdir -p "$STAGE"
COMPONENT="$STAGE/avon-component.pkg"
pkgbuild --root "$ROOT/payload" \
  --identifier ai.avon.agent \
  --version "$VERSION" \
  --scripts deploy/macos/scripts \
  --install-location / \
  "$COMPONENT"

DIST="$ROOT/distribution.xml"
cat > "$DIST" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>AVON Agent</title>
  <organization>ai.avon</organization>
  <options customize="never" require-scripts="true" hostArchitectures="x86_64,arm64"/>
  <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
  <volume-check><allowed-os-versions><os-version min="11.0"/></allowed-os-versions></volume-check>
  <pkg-ref id="ai.avon.agent" version="$VERSION">avon-component.pkg</pkg-ref>
  <choices-outline><line choice="default"/></choices-outline>
  <choice id="default" visible="false"><pkg-ref id="ai.avon.agent"/></choice>
</installer-gui-script>
XML

UNSIGNED="$STAGE/avon-agent-$VERSION-unsigned.pkg"
productbuild --distribution "$DIST" --package-path "$STAGE" "$UNSIGNED"
FINAL="$OUT/avon-agent-$VERSION.pkg"

if [ "$SKIP_SIGN" -eq 0 ] && [ -n "${MACOS_INSTALLER_CERTIFICATE:-}" ]; then
  INSTALLER_ID="${MACOS_INSTALLER_IDENTITY:-Developer ID Installer}"
  productsign --sign "$INSTALLER_ID" "$UNSIGNED" "$FINAL"
  if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
    xcrun notarytool submit "$FINAL" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" --wait
    xcrun stapler staple "$FINAL"
    xcrun stapler validate "$FINAL"
  fi
else
  mv "$UNSIGNED" "$FINAL"
fi

echo "built $FINAL"
