#!/usr/bin/env bash
# Builds an unsigned package and asserts its contents without installing it.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=$(mktemp -d); trap 'rm -rf "$OUT"' EXIT
fail() { echo "pkg: $1" >&2; exit 1; }

bash deploy/macos/build-pkg.sh --version 0.0.0-test --out "$OUT" --skip-sign
PKG="$OUT/avon-agent-0.0.0-test.pkg"
[ -f "$PKG" ] || fail "package was not produced"

EXP="$OUT/expanded"
pkgutil --expand "$PKG" "$EXP"
(cd "$EXP" && for p in *.pkg; do (cd "$p" && cat Payload | gunzip -dc | cpio -i --quiet); done)

for f in usr/local/bin/avon-agent usr/local/bin/avon-agent-helper \
         Library/LaunchDaemons/ai.avon.agent.plist Library/LaunchDaemons/ai.avon.helper.plist; do
  find "$EXP" -path "*/$f" | grep -q . || fail "$f missing from the payload"
done

AGENT=$(find "$EXP" -path "*/usr/local/bin/avon-agent" | head -1)
archs=$(lipo -archs "$AGENT")
[ "$archs" = "x86_64 arm64" ] || fail "avon-agent is not universal (got: $archs)"

AGENT_PLIST=$(find "$EXP" -name ai.avon.agent.plist | head -1)
HELPER_PLIST=$(find "$EXP" -name ai.avon.helper.plist | head -1)
[ "$(/usr/libexec/PlistBuddy -c 'Print :UserName' "$AGENT_PLIST")" = "_avon" ] || fail "the agent daemon must not run as root"
/usr/libexec/PlistBuddy -c 'Print :UserName' "$HELPER_PLIST" 2>/dev/null && fail "the helper plist must omit UserName (runs as root)"
/usr/libexec/PlistBuddy -c 'Print :RunAtLoad' "$AGENT_PLIST" | grep -q true || fail "RunAtLoad missing"

grep -q '_avon' deploy/macos/scripts/postinstall || fail "postinstall must create the _avon user"
grep -q 'chmod 0750' deploy/macos/scripts/postinstall || fail "data directory must be 0750"
grep -qE 'launchctl (bootstrap|load)' deploy/macos/scripts/postinstall && fail "postinstall must not start the daemon before enrolment"

if pkgutil --check-signature "$PKG" 2>&1 | grep -q "signed by"; then
  echo "note: package is signed"
else
  echo "note: package is unsigned (no Developer ID secrets present)"
fi
echo "pkg contents ok"
