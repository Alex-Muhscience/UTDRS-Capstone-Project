#!/bin/bash
set -euo pipefail

# Production server deployment script
# Usage: sudo ./deploy_server.sh [--ha] [--fips]

# Parse arguments
HA_MODE=false
FIPS_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --ha) HA_MODE=true; shift ;;
        --fips) FIPS_MODE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Validate environment
if [[ $EUID -ne 0 ]]; then
    echo "❌ Must be run as root"
    exit 1
fi

# Load configuration
source /etc/device-scanner/deployment.conf || {
    echo "❌ Missing deployment config";
    exit 1;
}

echo "🚀 Deploying Device Scanner Server (v${VERSION})"

# Install dependencies
apt-get update
apt-get install -y \
    openssl libssl1.1 \
    postgresql-client \
    libhsm2.0

# Create service user
if ! id -u scanner-svc >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /opt/device-scanner scanner-svc
fi

# Install binaries
mkdir -p /opt/device-scanner/{bin,config,certs,logs}
install -m 750 -o scanner-svc -g scanner-svc \
    ./bin/device-scanner-server /opt/device-scanner/bin/
install -m 640 -o scanner-svc -g scanner-svc \
    ./configs/production/server/* /opt/device-scanner/config/

# Setup certificates
if [ "$FIPS_MODE" = true ]; then
    ./scripts/security/hsm_integration.sh --server
else
    install -m 400 -o scanner-svc -g scanner-svc \
        ./certs/server.{crt,key} /opt/device-scanner/certs/
fi

# Database setup
if [ "$HA_MODE" = true ]; then
    echo "🔁 Configuring for HA deployment"
    psql "${DB_URI}" -c "CREATE DATABASE device_scanner_prod"
    psql "${DB_URI}" -f ./sql/ha_schema.sql
fi

# Systemd service
cat > /etc/systemd/system/device-scanner.service <<EOF
[Unit]
Description=Device Scanner Server
After=network.target

[Service]
User=scanner-svc
Group=scanner-svc
WorkingDirectory=/opt/device-scanner
EnvironmentFile=/etc/device-scanner/environment
ExecStart=/opt/device-scanner/bin/device-scanner-server \
    --config /opt/device-scanner/config/server.conf
Restart=always
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable --now device-scanner.service

echo "✅ Server deployment complete"