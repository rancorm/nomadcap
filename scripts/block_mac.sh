#!/bin/bash
#
# block_mac.sh - Block all traffic from a specified MAC address

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Arguments
SHA=$1
SPA=$2
THA=$3
TPA=$4

if [ -z "$SHA" ]; then
    exit 1
fi

# Interface on which to filter (adjust to your LAN interface)
IFACE=$5

# Add blocking rule
iptables -A INPUT -i "$IFACE" -m mac --mac-source "$SHA" -j DROP

if [ $? -eq 0 ]; then
    echo "Successfully blocked MAC address: $SHA on interface $IFACE"
else
    echo "Failed to add rule." >&2
    exit 1
fi
