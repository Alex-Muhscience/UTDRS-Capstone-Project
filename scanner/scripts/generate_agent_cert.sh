#!/bin/bash
set -euo pipefail

# Configuration
HOSTNAME=$(hostname)
SERIAL=$(date +%s)
DAYS=90                         # Short-lived certificates
CA_DIR="/etc/device-scanner/certs"
CERT_DIR="/etc/device-scanner/certs"

echo "🔐 Generating Agent Certificate for ${HOSTNAME}"

# Generate key (non-encrypted for agent use)
openssl genrsa -out "${CERT_DIR}/agent-${HOSTNAME}.key" 2048
chmod 400 "${CERT_DIR}/agent-${HOSTNAME}.key"

# Create CSR
openssl req -new -key "${CERT_DIR}/agent-${HOSTNAME}.key" \
    -out "${CERT_DIR}/agent-${HOSTNAME}.csr" \
    -subj "/C=US/ST=California/O=Device Scanner/OU=Agents/CN=${HOSTNAME}"

# Sign with CA (with 90-day validity)
openssl x509 -req -in "${CERT_DIR}/agent-${HOSTNAME}.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
    -set_serial "${SERIAL}" -out "${CERT_DIR}/agent-${HOSTNAME}.crt" \
    -days ${DAYS} -sha256

echo "✅ Generated Agent Cert: ${CERT_DIR}/agent-${HOSTNAME}.{key,crt}"