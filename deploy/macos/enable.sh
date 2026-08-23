#!/bin/sh
# Start the AVON daemons. Kept out of the installer on purpose: the agent has no
# identity until it is enrolled, and a daemon that crash-loops from the moment
# the package lands is a worse first impression than one deliberate command.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "run this as root" >&2
    exit 1
fi

DATA_DIR="/Library/Application Support/AVON"
if [ ! -f "$DATA_DIR/identity.json" ] && [ ! -f "$DATA_DIR/device.key" ]; then
    echo "warning: no identity in $DATA_DIR — enrol first, or the agent will retry in a loop" >&2
fi

launchctl bootstrap system /Library/LaunchDaemons/ai.avon.helper.plist
launchctl bootstrap system /Library/LaunchDaemons/ai.avon.agent.plist
echo "AVON daemons started."
