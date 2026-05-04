#!/usr/bin/env bash
# Generate a DKIM keypair and print the TXT record to publish at
# <selector>._domainkey.<domain>.
#
# Usage: ./dkim-setup.sh <domain> [selector]

set -euo pipefail

DOMAIN="${1:?usage: $0 <domain> [selector]}"
SELECTOR="${2:-mail}"
OUT_DIR="keys"
mkdir -p "$OUT_DIR"

PRIV="$OUT_DIR/${DOMAIN}.key"
PUB_RAW="$OUT_DIR/${DOMAIN}.pub.b64"

openssl genrsa -out "$PRIV" 1024
chmod 600 "$PRIV"
openssl rsa -in "$PRIV" -pubout 2>/dev/null \
  | sed -e '1d;$d' | tr -d '\n' > "$PRIV_RAW.tmp" 2>/dev/null || true
openssl rsa -in "$PRIV" -pubout 2>/dev/null \
  | sed -e '1d;$d' | tr -d '\n' > "$PUB_RAW"

echo
echo "Private key written to: $PRIV"
echo
echo "Publish this TXT record at ${SELECTOR}._domainkey.${DOMAIN}:"
echo
printf 'v=DKIM1;k=rsa;p=%s\n' "$(cat "$PUB_RAW")"
echo
