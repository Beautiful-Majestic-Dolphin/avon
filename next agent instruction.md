# Next Agent Instructions — Avon Phase 5 → Phase 6

**Branch:** `main`
**Last session:** 2026-08-23. Five commits on top of `e432643`:

```
5d4f3f1 test(e2e): start swtpm at all, put control on the agents' network, drop a stale xfail
016701e build(release): compile the hardware key providers into the binaries we ship
0e84802 fix: unbreak the Linux and Windows lint gates
02e3cdd feat(keystore): a real TPM 2.0 provider, and quotes a verifier will accept
74fcf1b fix(keystore): unbreak the Keychain and CNG providers, which never compiled
```

The previous handoff's three blocked checks all pass, and the TPM gap it named
is closed. Two larger things it did not know about turned up on the way: the
macOS and Windows providers are simulations that never compiled, and the e2e
stack cannot come up. Both are described below.

## What is verified, and how

| Check | Where it ran | Result |
|---|---|---|
| `cargo fmt --all -- --check` | macOS | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | macOS | clean |
| `cargo clippy -p avon-keystore --features keychain --all-targets -- -D warnings` | macOS | clean |
| `cargo test -p avon-keystore --features keychain` | macOS | 2/2 (were racing each other) |
| `cargo test --workspace --exclude avon-db --exclude avon-testkit --exclude avon-observability` | macOS | green except `avon-agent-core --test identity` (needs Postgres: `PoolTimedOut`) |
| `cargo clippy --workspace --all-targets --features avon-keystore/tpm2 -- -D warnings` | Linux container | clean |
| `cargo test -p avon-keystore --features tpm2` | Linux container, swtpm | **6/6**, including the quote cross-check |
| `cargo test -p avon-agent --test helper` (`AVON_TEST_ROOT=1`, `--cap-add NET_ADMIN`, `/dev/net/tun`) | Linux container, root | 9/9 |
| `bash deploy/linux/test-packages.sh` | macOS driving containers | deb + rpm **built with tpm2**, installed and run in debian:12 and rockylinux:9 |
| `cargo xwin clippy -p avon-agent -p avon-tun -p avon-keystore --features avon-keystore/cng --all-targets --target x86_64-pc-windows-msvc -- -D warnings` | macOS | clean |
| `bash deploy/macos/test-pkg.sh` | not re-run this session | — |

### Running the cross-platform checks

Two container helpers, both worth recreating in your scratchpad (they were only
ever session-local). Always set `CARGO_INCREMENTAL=0`: `target/debug` grew to
35 GB and filled the disk once already.

```bash
# Plain Linux: build/test with the repo mounted and its own target volume.
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD":/src -w /src \
  -v avon-linux-target:/target -v avon-rustup:/usr/local/rustup \
  -v avon-cargo-reg:/usr/local/cargo/registry -v avon-cargo-bin:/usr/local/cargo/bin \
  -e CARGO_TARGET_DIR=/target -e CARGO_INCREMENTAL=0 -e AVON_TEST_ROOT=1 \
  rust:1.93-bookworm bash -c \
  "command -v protoc >/dev/null || (apt-get update -qq && apt-get install -y -qq protobuf-compiler iputils-ping); <command>"
```

For anything touching the TPM you need libtss2 *and* a running swtpm. Build the
image once:

```dockerfile
FROM rust:1.93-bookworm
RUN apt-get update -qq && apt-get install -y -qq \
      protobuf-compiler iputils-ping \
      libtss2-dev tpm2-tools swtpm swtpm-tools \
      libclang-dev clang pkg-config \
 && rm -rf /var/lib/apt/lists/*
```

then run with two swtpm instances started and their TCTIs exported — the tests
want `AVON_TEST_TPM`, `AVON_TPM_TCTI` and `AVON_TEST_TPM_ALT_TCTI` (the second
is what proves a copied directory is useless against a different TPM):

```bash
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm0 --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 --flags not-need-init,startup-clear --daemon
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm1 --ctrl type=tcp,port=2324 \
  --server type=tcp,port=2323 --flags not-need-init,startup-clear --daemon
tpm2_startup -c -T swtpm:host=127.0.0.1,port=2321
```

Use a *separate* target volume (`avon-tpm-target`) for that image: mixing it
with the plain Linux volume rebuilds the world each time you switch.

Windows: `cargo xwin` from macOS is still the only local path (`brew install
llvm`, `cargo install cargo-xwin`, `PATH="/opt/homebrew/opt/llvm/bin:$PATH"`).
`--target x86_64-pc-windows-gnu` still does not work: pqclean's `compat.h`
includes `<features.h>` under GCC-not-clang, which mingw lacks. Use `xwin
clippy`, not `xwin check` — `result_large_err` only shows up under clippy, and
only on Windows.

## The TPM provider is real now

`crates/avon-keystore/src/tpm2.rs`, Linux only. Three objects under a primary
regenerated from a fixed template in the owner hierarchy:

- **binding key** — unrestricted ECC P-256, `fixedTPM`/`fixedParent`, signs the
  binding statement.
- **attestation key** — *restricted* ECC P-256. A restricted key signs only what
  the TPM produced, which is exactly why its `TPM2_Quote` is evidence. One key
  cannot be both; that is why there are two.
- **sealed object** — a 32-byte AES-256-GCM wrapping key. `TPM2_Create` seals at
  most 128 bytes and the PQ secrets are thousands, so the secrets are wrapped
  and only the wrapping key is sealed.

`attestation_quote` quotes PCRs 0 and 7 with the nonce as `extraData` and
returns the `TPMS_ATTEST` bytes verbatim. `AVON_TPM_SEAL_PCRS=0,7` additionally
binds the seal to a PCR policy — opt-in, because it is both a real defence
against offline tampering and a real way to lose every identity on a BIOS update.

Things that will bite you if you extend it:

- **Transient object slots.** A TPM guarantees three, and sessions compete for
  the same memory. `with_children` loads what it needs and flushes the *parent*
  before handing the handles over, because `TPM2_Certify` needs two children
  loaded at once. Holding the parent as well exhausts a real TPM, and swtpm
  reports it as "out of memory for object contexts".
- **One TPM, one caller.** The tests hold a lock. Do not remove it.
- **`execute_with_*_session` closures must fail with `tss_esapi::Error`.** Build
  templates, `Data`, `Digest` and tickets *before* the closure.
- **`TPM2_Certify` needs two sessions**, one per authorised object.
- **`PublicEccParametersBuilder::build()` requires a KDF scheme** even for a
  signing key; omitting it fails with "some of the required parameters were not
  provided", which does not name the parameter.

Windows deliberately has no TPM provider: tss-esapi builds against tpm2-tss
through pkg-config and there is no Windows distribution. Windows TPM-backed keys
are the CNG provider's job, through the Platform Crypto Provider — see below.

## The two gaps this session found

### 1. The macOS and Windows providers are simulations, and never compiled

`74fcf1b` makes them build; it does not make them real. Both still seal under a
key derived from a *public string*:

- `keychain.rs` — `Sha256("$AVON_MACOS_KEYCHAIN" or "default")`. It has never
  called `SecKeyCreateRandomKey`, never used `kSecAttrTokenIDSecureEnclave`, and
  never stored anything in a Keychain. `security-framework` and
  `core-foundation` are declared dependencies and unused.
- `cng.rs` — `Sha256(/etc/machine-id)`, **a Linux path**, on Windows. It has
  never called `NCryptCreatePersistedKey` or `NCryptProtectSecret`, and does not
  import the `windows` crate at all.

That they never compiled is why nobody noticed: the CI jobs that would have
caught it (`cargo test -p avon-keystore --features keychain` on macOS,
`--features cng` on Windows) have been failing to build, not failing to pass.
They compile and pass now, so the next regression will be visible.

Doing them properly is the same shape of work as the TPM provider was:

- **macOS**: a P-256 key with `kSecAttrTokenIDSecureEnclave` where there is a
  Secure Enclave and a Keychain-resident P-256 key otherwise, recording which in
  `provider.json`'s `secure_enclave`; PQ material as a generic-password item
  with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Fully testable here.
- **Windows**: `NCryptCreatePersistedKey` in `MS_PLATFORM_CRYPTO_PROVIDER` when
  present, else `MS_KEY_STORAGE_PROVIDER`; PQ material wrapped with
  `NCryptProtectSecret` under `LOCAL=machine`. **Only type-checkable from here**
  — `cargo xwin` compiles it, nothing local runs it. It needs a Windows runner,
  which means CI or a VM.

### 2. The e2e stack cannot come up, for at least four unrelated reasons

`5d4f3f1` fixed two of them (swtpm never listening; control and the CA not on
the agents' network). What remains, found by running
`docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml up -d`
after `cp .env.example .env && ./deploy/compose/gen-infra-certs.sh`:

1. **Control requires a client certificate on the port agents enrol against.**
   Every agent dies with `control: transport error`; with `RUST_LOG=debug` the
   handshake says `Client auth requested but no cert/sigscheme available`, and
   the CertificateRequest names the AVON TLS CA. A device has no certificate
   until it has enrolled, so enrollment cannot be behind mTLS. Either that
   listener takes `require_client_cert: false` (`avon-tls`'s
   `rustls_server_config` already supports it) or enrollment moves to its own
   listener. **This is a security decision about the bootstrap path — worth
   agreeing before implementing.** It is also phase 2/3 work, not phase 5.
2. **The gateway exits with `Error: No such file or directory (os error 2)`.**
   The `ip_forward` complaint above it is harmless (`/proc/sys` is read-only
   under Docker Desktop and the entrypoint tolerates it). The real error is
   unattributed — it needs `RUST_LOG=debug` and a look at which path it wants.
3. **`control` and `admin` both publish host port 8080**, so whichever starts
   second fails to bind and admin never runs.
4. Admin then reports `database unreachable: Temporary failure in name
   resolution`, which may just be a consequence of 3.

Nothing in `tests/e2e/scenarios/` has ever run against a working stack. The two
device-trust scenarios lost their `xfail` because the reason it gave (the
simulation) is gone, not because they pass. Expect the `E2E` workflow to be red
until the four above are fixed.

Also note `tests/e2e/run_e2e.sh` is stale: it `cd`s into `tests/e2e` and uses
`docker-compose.e2e.yml` alone, but that file is an *overlay*. The working
invocation is the one in the compose file's own header, and the one CI uses:
`docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml`.

## Deliberate deviations from the phase 5 plan

Carried over from the previous handoff, all still true:

1. **Windows runs one LocalSystem service, not the privileged split.** A WinTun
   session cannot be adopted by another process, so the split would mean copying
   every packet over a pipe. `helper` is `#[cfg(unix)]`.
2. **The Windows firewall blocks off-tunnel rather than permitting on-tunnel.**
   Windows Firewall evaluates block before allow. Adapters appearing after the
   rules are installed are not covered; the agent re-applies on session change.
3. **The helper takes `--user` as well as `--uid`** — unit files cannot know a
   uid allocated at install time.
4. **`QuotePolicy` has no `max_age`.** Freshness is the nonce, which the control
   plane issues and takes back on use. The TPM's clock counts milliseconds since
   the TPM was made.

New this session:

5. **No TPM provider on Windows** (reason above) — CNG covers it, once real.
6. **No TPM in the arm64 Linux or musl release binaries.** musl is static and
   tpm2-tss is not statically linkable; arm64 goes through `cross`, whose image
   has no arm64 tpm2-tss. Fixing arm64 means a cross image carrying
   `libtss2-dev:arm64`.

## Where to pick up

1. Decide the enrollment-mTLS question (e2e blocker 1) — it gates every scenario.
2. The rest of the e2e stack: blockers 2–4, then run the suite and see what the
   scenarios actually say.
3. Real Keychain and CNG providers. Keychain is fully testable here; CNG needs a
   Windows runner.
4. Phase 6 (`docs/superpowers/plans/2026-08-20-avon-phase6-edge-assurance-release.md`),
   15 tasks, nothing started.

## Files worth knowing about

- `crates/avon-keystore/src/tpm2.rs` — the real provider; `tests/tpm2.rs` is the
  cross-check against `avon-attest`.
- `crates/avon-keystore/src/{keychain,cng}.rs` — simulations, honestly labelled
  in their own headers.
- `crates/avon-keystore/src/select.rs` — provider choice; `Auto` now falls back
  when hardware is present but unusable.
- `crates/avon-attest/src/{tpms,verify,policy}.rs` — `TPMS_ATTEST` parsing and
  the four checks a quote has to pass.
- `crates/avon-control/src/attest.rs` — nonce issue/take, `devices.attestation_state`.
- `crates/avon-agent/src/helper/{protocol,server,client,wire}.rs` — validated
  intent-only IPC with SCM_RIGHTS fd passing.
- `crates/avon-agent/src/{run,enforcement}.rs` — the one run path and fail-closed
  rule derivation.
- `deploy/{linux,macos,windows}/` — units, packages, installers and their tests.
- `.github/workflows/{ci.yml,agent-release.yml,e2e.yml}`.
