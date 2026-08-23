<#
.SYNOPSIS
    Writes the AVON agent's configuration. Idempotent: an existing agent.toml is
    left exactly as it is, because an upgrade must not undo an operator's edits.
#>
param(
    [string]$Control = "",
    [string]$DataDir = "$env:ProgramData\AVON"
)
$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$config = Join-Path $DataDir "agent.toml"
if (Test-Path $config) {
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Control)) {
    $Control = "https://control.example.com:8443"
}

$escaped = $DataDir.Replace('\', '\\')
@(
    "# AVON agent configuration. Enrol before starting the services.",
    "control_plane = `"$Control`"",
    "data_dir = `"$escaped`"",
    "tun_name = `"avon0`""
) | Set-Content -Path $config -Encoding UTF8
