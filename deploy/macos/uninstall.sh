#!/bin/bash
# Remove every trace of the AVON agent: daemons, binaries, data, logs, the
# service account and the pf anchor.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall must run as root" >&2
    exit 1
fi

for label in ai.avon.agent ai.avon.helper; do
    launchctl bootout "system/$label" 2>/dev/null || true
    rm -f "/Library/LaunchDaemons/$label.plist"
done

rm -f /usr/local/bin/avon-agent /usr/local/bin/avon-agent-helper
rm -rf "/Library/Application Support/AVON" /Library/Logs/AVON /var/run/avon

# Leave the machine's own pf configuration alone; only our anchor goes.
/sbin/pfctl -a avon -F all >/dev/null 2>&1 || true

if /usr/bin/dscl . -read /Users/_avon >/dev/null 2>&1; then
    /usr/bin/dscl . -delete /Users/_avon || true
fi

/usr/sbin/pkgutil --forget ai.avon.agent >/dev/null 2>&1 || true
echo "AVON agent removed."
