#!/bin/bash
set -euo pipefail

# Configuration validation tool
# Usage: ./config_validator.sh <config_file>

check_json() {
    jq -e . "$1" >/dev/null 2>&1 || {
        echo "❌ Invalid JSON: $1";
        exit 1;
    }
}

check_tls() {
    openssl x509 -in "$1" -noout 2>/dev/null || {
        echo "❌ Invalid certificate: $1";
        exit 1;
    }
}

case "$1" in
    *.json) check_json "$1" ;;
    *.crt|*.pem) check_tls "$1" ;;
    *.conf)
        # Custom validation logic
        if grep -q "password" "$1"; then
            echo "❌ Plaintext password detected in $1"
            exit 1
        fi
        ;;
    *)
        echo "⚠️ Unknown file type: $1"
        exit 1
        ;;
esac

echo "✅ Valid configuration: $1"