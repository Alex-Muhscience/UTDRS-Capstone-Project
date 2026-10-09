#!/bin/bash
set -euo pipefail

# Emergency revocation script
# Usage: sudo ./revoke_compromised.sh <certificate.crt>

if [[ $# -ne 1 ]]; then
    echo "❌ Usage: $0 <certificate.crt>"
    exit 1
fi

CERT="$1"
CA_DIR="/opt/device-scanner/certs"
CRL_URL="https://scanner.example.com/crl.pem"

# Revoke certificate
echo "🔴 Revoking certificate: $CERT"
openssl ca -config "$CA_DIR/ca.cnf" -revoke "$CERT"

# Generate new CRL
echo "🔴 Generating updated CRL..."
openssl ca -config "$CA_DIR/ca.cnf" -gencrl -out "$CA_DIR/crl.pem"

# Distribute CRL
echo "🔴 Publishing CRL..."
aws s3 cp "$CA_DIR/crl.pem" "s3://scanner-crl/crl.pem" --acl public-read

# Notify agents
echo "🔴 Notifying agents to refresh..."
kafka-producer --topic cert_revocation --message "$(basename "$CERT")"

echo "✅ Compromised certificate revoked and CRL updated"