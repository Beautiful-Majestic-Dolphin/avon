# AVON Agent Installation Guide

This guide covers installing and configuring the AVON agent on various platforms.

## Table of Contents

- [Supported Platforms](#supported-platforms)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Enrollment](#enrollment)
- [Configuration](#configuration)
- [Running as a Service](#running-as-a-service)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

## Supported Platforms

| Platform | Architecture | Status | Minimum Version |
|----------|-------------|--------|-----------------|
| Linux | x86_64, aarch64 | Supported | Kernel 4.19+ |
| macOS | x86_64, arm64 | Supported | 11.0+ (Big Sur) |
| Windows | x86_64 | Supported | 10/11, Server 2019+ |
| FreeBSD | x86_64 | Beta | 13.0+ |

## System Requirements

### Minimum Requirements

- **CPU**: 1 core
- **Memory**: 128 MB RAM
- **Disk**: 50 MB free space
- **Network**: UDP connectivity to gateway (port 4600)

### Required Permissions

| Platform | Permission | Reason |
|----------|-----------|--------|
| Linux | CAP_NET_ADMIN | TUN device management |
| Linux | CAP_NET_RAW | Packet capture (optional) |
| macOS | Network Extension | System VPN integration |
| Windows | Administrator | TAP driver installation |

## Installation

### Linux (Debian/Ubuntu)

**Using APT repository**:
```bash
# Add AVON repository
curl -fsSL https://packages.avon.example.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/avon-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/avon-archive-keyring.gpg] https://packages.avon.example.com/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/avon.list

# Install agent
sudo apt update
sudo apt install avon-agent
```

**Manual installation**:
```bash
# Download latest release
curl -LO https://github.com/ShaneDolphin/avons-corners/releases/latest/download/avon-agent-linux-amd64.tar.gz

# Extract
tar -xzf avon-agent-linux-amd64.tar.gz

# Install
sudo mv avon-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/avon-agent

# Verify installation
avon-agent --version
```

### Linux (RHEL/CentOS/Fedora)

**Using YUM/DNF repository**:
```bash
# Add AVON repository
sudo tee /etc/yum.repos.d/avon.repo << 'EOF'
[avon]
name=AVON Repository
baseurl=https://packages.avon.example.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://packages.avon.example.com/gpg
EOF

# Install agent
sudo dnf install avon-agent
```

### macOS

**Using Homebrew**:
```bash
# Add AVON tap
brew tap shanedolphin/avon

# Install agent
brew install avon-agent

# Approve system extension (required)
# System Preferences > Security & Privacy > Allow
```

**Manual installation**:
```bash
# Download DMG
curl -LO https://github.com/ShaneDolphin/avons-corners/releases/latest/download/avon-agent-macos.dmg

# Mount and install
hdiutil attach avon-agent-macos.dmg
sudo installer -pkg "/Volumes/AVON Agent/AVON Agent.pkg" -target /
hdiutil detach "/Volumes/AVON Agent"

# Approve system extension in System Preferences
```

### Windows

**Using MSI installer** (recommended):

1. Download `avon-agent-windows-amd64.msi` from [releases](https://github.com/ShaneDolphin/avons-corners/releases)
2. Run installer as Administrator
3. Follow installation wizard
4. Reboot if prompted (for TAP driver)

**Using PowerShell**:
```powershell
# Download installer
Invoke-WebRequest -Uri "https://github.com/ShaneDolphin/avons-corners/releases/latest/download/avon-agent-windows-amd64.msi" -OutFile "avon-agent.msi"

# Install silently
Start-Process msiexec.exe -Wait -ArgumentList '/i avon-agent.msi /qn'

# Verify installation
& "C:\Program Files\AVON\avon-agent.exe" --version
```

**Using Chocolatey**:
```powershell
choco install avon-agent
```

### Docker (for testing)

```bash
docker run -it --rm \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  ghcr.io/shanedolphin/avons-corners/agent:latest \
  avon-agent --help
```

## Enrollment

Enrollment registers the agent with the AVON control plane and provisions cryptographic credentials.

### Obtaining an Enrollment Token

1. **Via Admin UI**: Navigate to Agents > Add Agent > Generate Token
2. **Via Admin API**:
   ```bash
   curl -X POST https://admin.avon.example.com/api/v1/enrollment-tokens \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "workstation-001",
       "groups": ["engineering", "vpn-users"],
       "expires_in": "24h"
     }'
   ```

### Enrolling the Agent

```bash
# Basic enrollment
sudo avon-agent enroll \
  --gateway gateway.avon.example.com:4600 \
  --token "ENROLLMENT_TOKEN_HERE"

# With custom name
sudo avon-agent enroll \
  --gateway gateway.avon.example.com:4600 \
  --token "ENROLLMENT_TOKEN_HERE" \
  --name "alice-laptop"

# With proxy (if needed)
sudo avon-agent enroll \
  --gateway gateway.avon.example.com:4600 \
  --token "ENROLLMENT_TOKEN_HERE" \
  --http-proxy http://proxy.corp.example.com:8080
```

### Enrollment Process

```
┌───────────────────────────────────────────────────────────────────┐
│                    Enrollment Process                              │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Agent generates key pair (Dilithium-5)                        │
│     ┌─────────────┐                                               │
│     │ Private Key │ → Stored securely on device                   │
│     │ Public Key  │ → Sent to CA                                  │
│     └─────────────┘                                               │
│                                                                   │
│  2. Agent sends enrollment request with:                          │
│     • Public key                                                  │
│     • Enrollment token                                            │
│     • Device information                                          │
│                                                                   │
│  3. CA validates token and issues certificate                     │
│     ┌─────────────┐                                               │
│     │ Certificate │ ← Contains agent identity, validity period    │
│     └─────────────┘                                               │
│                                                                   │
│  4. Agent stores certificate and connects                         │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Verifying Enrollment

```bash
# Check agent status
avon-agent status

# Output:
# Agent ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
# Name: alice-laptop
# Status: Connected
# Gateway: gateway.avon.example.com:4600
# Session: Active (expires in 29m 45s)
# Certificate: Valid (expires in 364 days)
# Groups: engineering, vpn-users
```

## Configuration

### Configuration File Location

| Platform | Path |
|----------|------|
| Linux | `/etc/avon/agent.toml` |
| macOS | `/Library/Application Support/AVON/agent.toml` |
| Windows | `C:\ProgramData\AVON\agent.toml` |

### Configuration Options

```toml
# /etc/avon/agent.toml

# Gateway connection
[gateway]
address = "gateway.avon.example.com:4600"
# Fallback gateways (tried in order)
fallback = [
  "gateway-backup.avon.example.com:4600",
  "gateway-dr.avon.example.com:4600"
]

# Connection settings
[connection]
# Reconnect attempts before giving up
max_retries = 10
# Delay between reconnect attempts
retry_delay = "5s"
# Keep-alive interval
keepalive_interval = "30s"

# Heartbeat/pulse settings
[pulse]
# How often to send heartbeats
interval = "10s"
# Timeout for heartbeat response
timeout = "5s"

# TUN interface settings
[interface]
# Interface name (auto-generated if not set)
name = "avon0"
# MTU size
mtu = 1400
# DNS servers to use when connected
dns = ["10.100.0.53", "10.100.0.54"]

# Logging
[logging]
# Log level: trace, debug, info, warn, error
level = "info"
# Log file (empty for stdout)
file = "/var/log/avon/agent.log"
# Log format: json, pretty
format = "json"

# Advanced settings
[advanced]
# Enable local metrics endpoint
metrics_enabled = true
metrics_port = 9091
# Worker threads (0 = auto)
worker_threads = 0
```

### Environment Variables

Configuration can also be set via environment variables:

```bash
export AVON_GATEWAY_ADDRESS="gateway.avon.example.com:4600"
export AVON_LOG_LEVEL="debug"
export AVON_PULSE_INTERVAL="10s"
```

## Running as a Service

### Linux (systemd)

The package installation creates a systemd service automatically.

```bash
# Start agent
sudo systemctl start avon-agent

# Enable on boot
sudo systemctl enable avon-agent

# Check status
sudo systemctl status avon-agent

# View logs
sudo journalctl -u avon-agent -f
```

**Manual service file** (`/etc/systemd/system/avon-agent.service`):
```ini
[Unit]
Description=AVON Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/avon-agent run
Restart=always
RestartSec=5
User=root
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

### macOS (launchd)

```bash
# Load agent (starts immediately and on boot)
sudo launchctl load /Library/LaunchDaemons/com.avon.agent.plist

# Unload agent
sudo launchctl unload /Library/LaunchDaemons/com.avon.agent.plist

# Check status
sudo launchctl list | grep avon
```

### Windows (Service)

```powershell
# Start service
Start-Service AvonAgent

# Set to automatic start
Set-Service -Name AvonAgent -StartupType Automatic

# Check status
Get-Service AvonAgent
```

## Troubleshooting

### Connection Issues

**Agent cannot reach gateway**:

```bash
# Test UDP connectivity
nc -u -v gateway.avon.example.com 4600

# Check DNS resolution
dig gateway.avon.example.com

# Test with verbose logging
sudo avon-agent run --log-level debug
```

**Firewall blocking connection**:

```bash
# Linux (allow outbound UDP 4600)
sudo ufw allow out 4600/udp

# macOS
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/avon-agent

# Windows (PowerShell as Admin)
New-NetFirewallRule -DisplayName "AVON Agent" -Direction Outbound -Protocol UDP -LocalPort 4600 -Action Allow
```

### TUN Device Issues

**Linux: TUN device not created**:
```bash
# Check TUN module
lsmod | grep tun

# Load if missing
sudo modprobe tun

# Make persistent
echo "tun" | sudo tee /etc/modules-load.d/tun.conf
```

**macOS: System extension not approved**:
1. Open System Preferences > Security & Privacy
2. Click "Allow" for AVON software
3. Restart agent

**Windows: TAP driver issues**:
```powershell
# Reinstall TAP driver
& "C:\Program Files\AVON\tap-installer.exe" /S

# Or use Device Manager to uninstall/reinstall
```

### Authentication Failures

**Certificate issues**:
```bash
# Check certificate validity
avon-agent cert info

# Re-enroll if certificate is invalid/expired
sudo avon-agent enroll --force \
  --gateway gateway.avon.example.com:4600 \
  --token "NEW_TOKEN"
```

**Session issues**:
```bash
# Force session refresh
avon-agent session refresh

# Clear session cache
avon-agent session clear
```

### Diagnostic Commands

```bash
# Full diagnostic report
avon-agent diagnostics

# Network connectivity test
avon-agent diagnostics --network

# Check configuration
avon-agent config validate

# Export debug bundle
avon-agent diagnostics --export /tmp/avon-debug.zip
```

### Log Locations

| Platform | Log Path |
|----------|----------|
| Linux | `/var/log/avon/agent.log` or `journalctl -u avon-agent` |
| macOS | `/Library/Logs/AVON/agent.log` or Console.app |
| Windows | `C:\ProgramData\AVON\logs\agent.log` or Event Viewer |

## Uninstallation

### Linux (Debian/Ubuntu)

```bash
# Remove package
sudo apt remove avon-agent

# Remove with configuration
sudo apt purge avon-agent

# Remove repository
sudo rm /etc/apt/sources.list.d/avon.list
```

### Linux (RHEL/CentOS)

```bash
sudo dnf remove avon-agent
```

### macOS

```bash
# Using Homebrew
brew uninstall avon-agent

# Manual removal
sudo /Library/Application\ Support/AVON/uninstall.sh
```

### Windows

```powershell
# Via Programs and Features
# Or via PowerShell:
Start-Process msiexec.exe -Wait -ArgumentList '/x avon-agent.msi /qn'

# Remove leftover data
Remove-Item -Recurse -Force "C:\ProgramData\AVON"
```

## Related Documentation

- [Architecture Overview](architecture.md)
- [Security Documentation](security.md)
- [Operations Guide](operations.md)
