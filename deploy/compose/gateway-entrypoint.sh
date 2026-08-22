#!/bin/sh
set -eu
# Enable IP forwarding for overlay -> protected routing.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# Masquerade traffic from overlay (100.64.0.0/10) leaving via protected network.
# The protected CIDR is 172.30.0.0/24 on the gateway's eth1 (or similar).
# Use nft if available, fallback to iptables.
if command -v nft >/dev/null 2>&1; then
  nft list table ip nat >/dev/null 2>&1 || nft add table ip nat || true
  nft list chain ip nat POSTROUTING >/dev/null 2>&1 || nft add chain ip nat POSTROUTING '{ type nat hook postrouting priority 100; }' || true
  # Add masquerade for overlay -> protected
  nft add rule ip nat POSTROUTING oifname "eth1" ip saddr 100.64.0.0/10 masquerade 2>/dev/null || true
  nft add rule ip nat POSTROUTING ip saddr 100.64.0.0/10 ip daddr 172.30.0.0/24 masquerade 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
  iptables -t nat -C POSTROUTING -s 100.64.0.0/10 -o eth1 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 100.64.0.0/10 -o eth1 -j MASQUERADE 2>/dev/null || true
  iptables -t nat -C POSTROUTING -s 100.64.0.0/10 -d 172.30.0.0/24 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 100.64.0.0/10 -d 172.30.0.0/24 -j MASQUERADE 2>/dev/null || true
fi

exec avon-gateway "$@"
