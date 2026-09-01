#!/bin/bash
set -e

DPI_IP="10.0.1.235"
USERS_NET="10.0.0.0/16"
OUT_IFACE="ens18"

echo "=== DPI iptables setup ==="

# Очистка старых правил
iptables -t nat -F
iptables -F

# DNS (только транзитный, не свой)
iptables -t nat -A PREROUTING ! -s $DPI_IP -p udp --dport 53 -j DNAT --to-destination $DPI_IP:53
iptables -t nat -A PREROUTING ! -s $DPI_IP -p tcp --dport 53 -j DNAT --to-destination $DPI_IP:53

# HTTP 80 → 8080 (transparent)
iptables -t nat -A PREROUTING -s $USERS_NET ! -d $DPI_IP -p tcp --dport 80 -j DNAT --to-destination $DPI_IP:8080

# HTTPS 443 → 8080 (transparent)
iptables -t nat -A PREROUTING -s $USERS_NET ! -d $DPI_IP -p tcp --dport 443 -j DNAT --to-destination $DPI_IP:8080

# NAT для исходящего
iptables -t nat -A POSTROUTING -s $USERS_NET -o $OUT_IFACE -j MASQUERADE

# Включить IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "=== Done ==="
iptables -t nat -L -n -v
iptables-save