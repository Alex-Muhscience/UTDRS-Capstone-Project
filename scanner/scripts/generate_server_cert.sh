#!/bin/bash
set -euo pipefail

# Configuration
KEY_TYPE="ec"                  # ec or rsa
EC_CURVE="secp384r1"           # NIST P-384
RSA_SIZE=3072
DAYS=365
CA_DIR="/etc/device-scanner/certs"
CERT_DIR="/etc/device-scanner/certs"
SAN="DNS:scanner.example.com,DNS:*.scanner.example.com,IP:10.0.1.100"

# Load CA config
source "/etc/device-scanner/ca.conf"

function generate_key() {
    if [ "${KEY_TYPE}" == "ec" ]; then
        openssl ecparam -genkey -name ${EC_CURVE} | openssl ec -aes256 -out "${1}"
    else
        openssl genrsa -aes256 -out "${1}" ${RSA_SIZE}
    fi
}

echo "🔐 Generating Server Certificate"
mkdir -p "${CERT_DIR}"

# Generate private key
generate_key "${CERT_DIR}/server.key.tmp"
chmod 400 "${CERT_DIR}/server.key.tmp"

# Create CSR
openssl req -new -key "${CERT_DIR}/server.key.tmp" \
    -out "${CERT_DIR}/server.csr" \
    -subj "/C=US/ST=California/O=Device Scanner/CN=scanner.example.com" \
    -config <(
        cat /etc/ssl/openssl.cnf
        printf "[SAN]\nsubjectAltName=%s" "${SAN}"
    ) \
    -reqexts SAN

# Sign with CA
openssl x509 -req -in "${CERT_DIR}/server.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
    -CAcreateserial -out "${CERT_DIR}/server.crt" \
    -days ${DAYS} -sha256 \
    -extfile <(printf "subjectAltName=%s" "${SAN}")

# Decrypt key for use
openssl rsa -in "${CERT_DIR}/server.key.tmp" -out "${CERT_DIR}/server.key"
chmod 400 "${CERT_DIR}/server.key"
shred -u "${CERT_DIR}/server.key.tmp"

echo "✅ Generated Server Cert: ${CERT_DIR}/server.{key,crt}"