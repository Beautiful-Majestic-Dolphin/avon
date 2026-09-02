#!/bin/sh
# A NAT router for the netlab (`lnet`) profile. eth0 is the LAN, eth1 is public.
#
# nat-a is permissive. nat-b additionally drops inbound UDP that no outbound
# flow opened, which is what forces relay instead of a direct path -- the case
# a permissive NAT cannot test. Interface names are looked up by network
# rather than assumed: Docker attaches networks in alphabetical order, so
# `lan-a` lands on eth0 and `public` on eth1, but the script checks instead of
# trusting that.
set -eu

apk add --no-cache iptables iproute2 >/dev/null

LAN_CIDR="${LAN_CIDR:?LAN_CIDR (e.g. 10.80.0.0/24) is required}"
LAN_IF=$(ip -o -4 addr show | awk -v net="${LAN_CIDR%.*}" '$4 ~ "^"net"\\." {print $2; exit}')
WAN_IF=$(ip -o -4 addr show | awk -v lan="$LAN_IF" '$2 != "lo" && $2 != lan {print $2; exit}')
if [ -z "$LAN_IF" ] || [ -z "$WAN_IF" ]; then
  echo "could not identify LAN/WAN interfaces (lan=$LAN_IF wan=$WAN_IF)" >&2
  ip -o -4 addr show >&2
  exit 1
fi

iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" \
  -m state --state RELATED,ESTABLISHED -j ACCEPT

if [ "${DROP_INBOUND_UDP:-0}" = "1" ]; then
  iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -p udp -j DROP
fi
# Anything not explicitly forwarded is dropped, so the NAT is a real boundary.
iptables -P FORWARD DROP

echo "nat router ready (lan=$LAN_IF wan=$WAN_IF drop_inbound_udp=${DROP_INBOUND_UDP:-0})"
exec sleep infinity
