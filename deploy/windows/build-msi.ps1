param(
    [string]$Version = "0.2.0",
    [string]$Arch = "x64"
)
$ErrorActionPreference = "Stop"
cargo build --release --target x86_64-pc-windows-msvc -p avon-agent
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item target/x86_64-pc-windows-msvc/release/avon-agent.exe deploy/windows/
& "candle.exe" deploy/windows/avon.wxs -o deploy/windows/avon.wixobj
& "light.exe" deploy/windows/avon.wixobj -o avon-agent-$Version-$Arch.msi
Write-Host "MSI built: avon-agent-$Version-$Arch.msi"
