#!/bin/bash
set -euo pipefail

# Security settings
KEY_SIZE=4096
DAYS=3650
CA_DIR="/etc/device-scanner/certs"
OPENSSL_CONF="/etc/ssl/openssl.cnf"

function cleanup() {
    shred -u "${CA_DIR}/ca.key.tmp" 2>/dev/null || true
}

trap cleanup EXIT

echo "🔐 Generating Root CA (${KEY_SIZE}-bit RSA)"
mkdir -p "${CA_DIR}"
chmod 700 "${CA_DIR}"

# Generate encrypted CA key
openssl genrsa -aes256 -out "${CA_DIR}/ca.key.tmp" ${KEY_SIZE}
chmod 400 "${CA_DIR}/ca.key.tmp"

# Decrypt key for HSM transfer (in real production, this would go directly to HSM)
openssl rsa -in "${CA_DIR}/ca.key.tmp" -out "${CA_DIR}/ca.key"
chmod 400 "${CA_DIR}/ca.key"
shred -u "${CA_DIR}/ca.key.tmp"

# Create self-signed CA certificate
openssl req -x509 -new -nodes -key "${CA_DIR}/ca.key" \
    -sha256 -days ${DAYS} -out "${CA_DIR}/ca.crt" \
    -config "${OPENSSL_CONF}" \
    -subj "/C=US/ST=California/O=Device Scanner/CN=Device Scanner Root CA"

echo "✅ Generated CA: ${CA_DIR}/ca.{key,crt}"