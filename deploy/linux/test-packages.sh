#!/usr/bin/env bash
# Builds the .deb and .rpm and installs each in a clean container, asserting the
# unit files, user and permissions are what the hardening promises.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=$(mktemp -d); trap 'rm -rf "$OUT"' EXIT

# The packages must contain Linux binaries, so on a developer's Mac the build
# half runs in a container; the install checks below always use containers.
BUILD='set -eu
  cargo install cargo-deb --version 2.7.0 --locked >/dev/null 2>&1 || true
  cargo install cargo-generate-rpm --version 0.16.0 --locked >/dev/null 2>&1 || true
  cargo build --release --locked -p avon-agent --bin avon-agent --bin avon-agent-helper \
    --features "${AVON_PKG_FEATURES:-tpm2}"
  # The package metadata names target/release; a container build with its own
  # CARGO_TARGET_DIR has to put the binaries where the assets say they are.
  if [ "${CARGO_TARGET_DIR:-}" != "" ] && [ "$CARGO_TARGET_DIR" != "$PWD/target" ]; then
    mkdir -p target/release
    cp "$CARGO_TARGET_DIR/release/avon-agent" "$CARGO_TARGET_DIR/release/avon-agent-helper" target/release/
  fi
  cargo deb -p avon-agent --no-build --output /out/ >/dev/null
  # The TPM provider links tpm2-tss dynamically, so the rpm has to say so or it
  # installs onto a host where the binary cannot start. cargo-deb derives the
  # same thing from `depends = "$auto"`.
  cargo generate-rpm -p crates/avon-agent --auto-req auto -o /out/ >/dev/null'

if [ "$(uname -s)" = "Linux" ]; then
  ( cd "$PWD" && OUT_DIR="$OUT" sh -c "${BUILD//\/out\//$OUT/}" )
else
  docker run --rm \
    -v "$PWD":/src -w /src -v "$OUT":/out \
    -v avon-linux-target:/target -v avon-rustup:/usr/local/rustup \
    -v avon-cargo-reg:/usr/local/cargo/registry -v avon-cargo-bin:/usr/local/cargo/bin \
    -e CARGO_TARGET_DIR=/target \
    -e AVON_PKG_FEATURES -e CARGO_INCREMENTAL=0 \
    rust:1.93-bookworm bash -c "command -v protoc >/dev/null && command -v rpmbuild >/dev/null || (apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq protobuf-compiler libtss2-dev pkg-config rpm >/dev/null 2>&1); $BUILD"
fi

DEB=$(ls "$OUT"/*.deb); RPM=$(ls "$OUT"/*.rpm)
[ -f "$DEB" ] && [ -f "$RPM" ] || { echo "packages not produced" >&2; exit 1; }

check() {
  local image="$1" install="$2" pkg="$3"
  docker run --rm -v "$OUT:/pkgs:ro" "$image" bash -eu -c "
    $install
    id avon >/dev/null || { echo 'avon user missing' >&2; exit 1; }
    test -d /var/lib/avon || { echo '/var/lib/avon missing' >&2; exit 1; }
    perm=\$(stat -c '%a %U:%G' /var/lib/avon)
    [ \"\$perm\" = '700 avon:avon' ] || { echo \"/var/lib/avon is \$perm, expected 700 avon:avon\" >&2; exit 1; }
    systemd-analyze verify /lib/systemd/system/avon-agent.service /lib/systemd/system/avon-agent-helper.service
    grep -q 'NoNewPrivileges=yes' /lib/systemd/system/avon-agent.service
    grep -qE '^CapabilityBoundingSet=\s*\$' /lib/systemd/system/avon-agent.service
    grep -q 'User=avon' /lib/systemd/system/avon-agent.service
    grep -q 'CAP_NET_ADMIN' /lib/systemd/system/avon-agent-helper.service
    grep -q '^User=' /lib/systemd/system/avon-agent-helper.service && { echo 'helper must run as root' >&2; exit 1; }
    avon-agent --version
    echo '$pkg ok'
  "
}

check debian:12 "apt-get update -qq && apt-get install -y -qq systemd /pkgs/$(basename "$DEB") >/dev/null" deb
check rockylinux:9 "dnf install -y -q systemd /pkgs/$(basename "$RPM") >/dev/null" rpm
echo "linux packages ok"
