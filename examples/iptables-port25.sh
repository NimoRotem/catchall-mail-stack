#!/usr/bin/env bash
# Redirect public port 25 (privileged) to the unprivileged 2525 the app binds to.
# Run as root and persist with `iptables-save > /etc/iptables/rules.v4`.

set -euo pipefail

iptables -t nat -C PREROUTING -p tcp --dport 25 -j REDIRECT --to-ports 2525 2>/dev/null \
  || iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-ports 2525

# Allow inbound 25 (UFW assumed)
ufw allow 25/tcp || true

# Persist
iptables-save > /etc/iptables/rules.v4

echo "Port 25 -> 2525 redirect installed and persisted."
