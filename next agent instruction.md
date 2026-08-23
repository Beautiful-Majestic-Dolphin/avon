# Next Agent Instructions — Avon Phase 5 completion → Phase 6

**Branch:** `main`
**Last session:** 2026-08-23. Four commits on top of `c739a98`:

```
f13efdd test(e2e): device-trust scenarios, and unbreak the suite that was to run them   (5.12)
e4654a0 feat(attest): real TPM quote verification, wired end to end                     (5.5 completion)
fe18997 feat(platform): WinTun data plane, fail-closed enforcement, and real installers  (5.8-5.11)
854aacf feat(agent): validated intent-only helper IPC with SCM_RIGHTS fd passing         (5.7 hardening)
```

## What is verified, and how

| Check | Where it ran | Result |
|---|---|---|
| `cargo fmt --all -- --check` | macOS | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | macOS | clean |
| `cargo test --workspace --exclude avon-db --exclude avon-testkit --exclude avon-observability` | macOS | green except `avon-agent-core --test identity` (needs Postgres: `PoolTimedOut`) |
| `cargo clippy -p avon-tun -p avon-agent -p avon-agent-core --all-targets -- -D warnings` | Linux container (rust:1.93-bookworm) | clean — **re-run after the latest commits, see below** |
| `cargo test -p avon-agent --test helper` with `AVON_TEST_ROOT=1`, `--cap-add NET_ADMIN`, `/dev/net/tun` | Linux container, as root | 9/9 including the real fd-passing scenario |
| `cargo xwin check -p avon-agent -p avon-tun --all-targets --target x86_64-pc-windows-msvc` | macOS | clean |
| `bash deploy/macos/test-pkg.sh` | macOS | `pkg contents ok` |
| `uv run ruff/black/pytest` (admin-api) | macOS | 33 passed, 32 skipped |
| `uv run pytest --collect-only scenarios/` | macOS | 18 tests collect (they used to fail at import) |

### Cross-platform checking without those platforms

Two things set up last session, both worth keeping:

```bash
# Linux: build/test in a container with the repo mounted and its own target dir.
#   scratchpad/linux-check.sh "cargo clippy -p avon-agent --all-targets -- -D warnings"
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD":/src -w /src \
  -v avon-linux-target:/target -v avon-rustup:/usr/local/rustup \
  -v avon-cargo-reg:/usr/local/cargo/registry -v avon-cargo-bin:/usr/local/cargo/bin \
  -e CARGO_TARGET_DIR=/target -e AVON_TEST_ROOT=1 \
  rust:1.93-bookworm bash -c "command -v protoc >/dev/null || (apt-get update -qq && apt-get install -y -qq protobuf-compiler iputils-ping); <command>"

# Windows: type-check the MSVC target from macOS (brew install llvm; cargo install cargo-xwin).
PATH="/opt/homebrew/opt/llvm/bin:$PATH" cargo xwin check -p avon-agent --all-targets --target x86_64-pc-windows-msvc
```

`cargo check --target x86_64-pc-windows-gnu` does **not** work: pqclean's `compat.h`
includes `<features.h>` under GCC-not-clang, which mingw lacks. MSVC via xwin is the
only local Windows path.

## Blocked right now

1. **Docker Desktop is down on this machine.** The disk filled during a container
   build (`target/debug/incremental` had grown to ~35 GB — deleted), which wedged the
   VM; `docker ps` hangs and the daemon does not come back from a shell (`open -a
   Docker` starts `com.docker.backend` but no VM). **Start Docker Desktop from the
   dock, then re-run:**
   ```bash
   scratchpad/linux-check.sh "cargo clippy -p avon-tun -p avon-agent -p avon-agent-core -p avon-control --all-targets -- -D warnings"
   AVON_TEST_ROOT=1 scratchpad/linux-check.sh "cargo test -p avon-agent --test helper"
   bash deploy/linux/test-packages.sh          # deb + rpm, installed in debian:12 and rockylinux:9
   ```
   `deploy/linux/test-packages.sh` has never completed here: it got as far as an
   8-minute release build inside the container, then `cargo deb` failed on asset
   paths, which is fixed (the script now copies binaries to `target/release` when
   `CARGO_TARGET_DIR` is elsewhere) but unverified. **Run it first.**
2. Set `CARGO_INCREMENTAL=0` for container and cross builds, or `target/debug`
   grows tens of GB again.

## The one honest gap: the TPM provider is a simulation

`crates/avon-keystore/src/tpm2.rs` says so in its own header. It seals with
AES-GCM under a key derived from **the TCTI string** (`Sha256(AVON_TPM_TCTI)`) —
a public, defaulted constant — so the sealed blob is not protected by hardware at
all, and "a cloned directory is useless" holds only because a different container
sets a different TCTI.

Because of that, `Tpm2KeyProvider::attestation_quote` deliberately returns `None`:
a simulated quote would be the agent vouching for itself while the control plane
recorded `verified`. Everything *around* attestation is real and tested — challenge
issuance and single-use nonces, `TPMS_ATTEST` parsing, PCR digest recomputation,
AK trust-on-first-use then pinning, the DB state, the admin API fields, the policy
condition — so the remaining work is one provider:

- `create`/`open`: primary under the owner hierarchy, seal the PQ material with
  `TPM2_Create`/`TPM2_Unseal` against a PCR policy, keep the AK non-duplicable.
- `attestation_quote(nonce)`: `TPM2_Quote` over PCRs 0 and 7 with `extraData = nonce`,
  return the `TPMS_ATTEST` bytes verbatim plus the DER signature, the AK SPKI and the
  PCR values (`avon_keystore::Quote`).
- Verify against `avon-attest` in an swtpm-gated test — that is the cross-check that
  the parser and a real TPM agree.

Two e2e scenarios are `xfail` on exactly this and will start passing when it lands:
`test_tpm_backed_agent_reports_its_provider_and_becomes_verified` and
`test_policy_requiring_verified_attestation_admits_only_the_tpm_agent`.

## Bugs found and fixed last session (do not reintroduce)

- **avon-tun did not compile on Linux.** `handle.link().set(index)` and
  `handle.route().add()` are rtnetlink 0.14 shapes; 0.15 takes message builders
  (`LinkUnspec::new_with_index(..).mtu(..).up().build()`,
  `RouteMessageBuilder::<Ipv4Addr>::new()…`). Route installation had therefore never
  run on Linux. Route *removal* did not exist at all; it does now on both Unixes.
- **`Wire` spun at 100% CPU** using `readable().await` + a non-blocking `recvmsg`:
  readiness was never cleared. Use `stream.async_io(Interest::…, …)`.
- **The e2e suite failed at import**, so no scenario in `tests/e2e` was running:
  `lib/__init__.py` imported `admin_client`/`agent_client` (renamed) and `helpers`
  (needs undeclared `aiohttp`).
- **`avon-agent` had no `tpm2` feature** while `fingerprint/linux.rs` gated on
  `feature = "tpm2"` — an `unexpected_cfgs` warning, which is an error under
  `-D warnings` on Linux. It now forwards `avon-keystore/{tpm2,keychain,cng}`.
- **No `LICENSE` file** existed, though `cargo deb` metadata referenced one.

## Deliberate deviations from the phase 5 plan

1. **Windows runs one LocalSystem service, not the privileged split.** The helper
   exists to pass a kernel TUN descriptor to an unprivileged process; a WinTun
   session cannot be adopted by another process, so the split would mean copying
   every packet over a pipe. `helper` is `#[cfg(unix)]`, `avon-agent-helper.exe` is
   not built or packaged, and the MSI installs one service. Revisit only with a
   measured packet-relay design.
2. **The Windows firewall blocks off-tunnel rather than permitting on-tunnel.**
   Windows Firewall evaluates block before allow, so "permit on avon0, block
   elsewhere" cannot be expressed; the renderer blocks the protected prefixes on
   every adapter except the tunnel (`Get-NetAdapter | Where-Object Name -ne avon0`).
   Adapters that appear after the rules are installed are not covered; the agent
   re-applies on every session change. Golden-tested in `tests/golden/wfp.ps1`.
3. **The helper takes `--user` as well as `--uid`.** The unit files cannot know a
   uid allocated at install time.
4. **`QuotePolicy` lost `max_age`.** The TPM's clock counts milliseconds since the
   TPM was made; freshness is the nonce, which the control plane issues and takes
   back on use (`CHALLENGE_TTL`, `attest::Challenges`). The old quote fixture
   encoded a timestamp and expired — tests now build quotes from a fixed key.

## Where to pick up

1. Start Docker, run the three checks under **Blocked** above, fix whatever they find.
2. The real TPM 2.0 provider (see the gap above). This is the last thing between the
   repo and the phase 5 gate.
3. Phase 6 (`docs/superpowers/plans/2026-08-20-avon-phase6-edge-assurance-release.md`),
   15 tasks: subnet router, XFRM/ESP offload, IKEv2 interop, `no_std` profile, MUD,
   observability contract, Helm hardening, appliance bundle, release signing/SBOM/
   provenance, FIPS profile, performance thresholds, soak and chaos, threat model,
   documentation rewrite, acceptance sweep. Nothing in phase 6 has been started.

## Files worth knowing about

- `crates/avon-agent/src/helper/{protocol,server,client,wire}.rs` — validated intent-only
  IPC, `^avon[0-9]{0,2}$`, MTU 576..=9000, routes inside the declared set, `SO_PEERCRED`
  uid check, oversized line closes unparsed, SCM_RIGHTS fd passing.
- `crates/avon-agent/src/{run,enforcement}.rs` — the one run path (CLI and Windows
  service) and fail-closed rule derivation.
- `crates/avon-agent-core/src/{attest.rs, traits.rs (Enforcement), agent.rs}` — challenge
  answering and the session up/down hooks.
- `crates/avon-attest/src/{tpms,verify,policy}.rs` — `TPMS_ATTEST` parsing and the checks.
- `crates/avon-control/src/attest.rs` — nonce issue/take, verification, `devices.attestation_state`.
- `deploy/{linux,macos,windows}/` — units, packages, installers, and their tests
  (`test-packages.sh`, `test-pkg.sh`).
- `.github/workflows/{ci.yml,agent-release.yml}` — CI gained a Linux packages job, a
  root helper test, and per-OS keystore tests; the release workflow builds deb/rpm,
  static musl tarballs, a universal signed pkg and the MSI.
