# Windows packaging

`build-msi.ps1` produces `dist\avon-agent-<version>-x64.msi` plus a `.sha256`.

```powershell
pwsh deploy\windows\build-msi.ps1 -Version 0.2.0 -SkipSign
```

Requirements: the MSVC Rust target, WiX v3 (`candle.exe`/`light.exe` on `PATH`)
and network access for `wintun.dll`. The DLL's Authenticode signature is checked
before it is packaged; pass `-WintunSha256 <hash>` to pin the archive as well.

## What the package installs

| Path | Contents |
| --- | --- |
| `%ProgramFiles%\AVON` | `avon-agent.exe`, `wintun.dll`, `configure.ps1`, `LICENSE` |
| `%ProgramData%\AVON` | `agent.toml` and the device identity, readable only by SYSTEM and Administrators |

One service, `avon-agent`, is registered as LocalSystem and **not started**. It
restarts after five seconds on failure.

### Why there is no helper here

On Linux and macOS the agent runs unprivileged and a small root helper hands it
the TUN file descriptor. WinTun offers nothing equivalent: a session belongs to
the process that started it and cannot be adopted by another, so splitting the
privilege would mean copying every packet across a pipe. Until that trade is
worth making, the Windows service owns the adapter itself — the same shape
WireGuard for Windows uses.

## Installing

```powershell
msiexec /i avon-agent-0.2.0-x64.msi /qn AVON_CONTROL=https://control.example.com:8443
& "$env:ProgramFiles\AVON\avon-agent.exe" enroll --control https://control.example.com:8443 --token <token>
Start-Service avon-agent
```

Enrolment is deliberately a separate step: an agent with no identity would
crash-loop from the moment the installer finished.

## Signing

Set `WINDOWS_CERT_PFX` (base64 PFX) and `WINDOWS_CERT_PASSWORD`; the binary and
the MSI are then Authenticode-signed with a timestamp. Without them the
build is unsigned and `-SkipSign` makes that explicit.
