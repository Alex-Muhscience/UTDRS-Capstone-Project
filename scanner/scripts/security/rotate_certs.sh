#!/bin/bash
set -euo pipefail

# Automated certificate rotation
# Runs monthly via cron: 0 3 1 * * /opt/device-scanner/scripts/rotate_certs.sh

CONFIG_DIR="/opt/device-scanner/config"
CERTS_DIR="/opt/device-scanner/certs"
LOG_FILE="/var/log/device-scanner/cert_rotation.log"

{
    echo "=== Certificate Rotation $(date) ==="
    
    # Generate new certs
    echo "🔄 Generating new certificates..."
    ./generate_server_cert.sh >> "$LOG_FILE" 2>&1
    ./generate_agent_certs.sh --batch 100 >> "$LOG_FILE" 2>&1

    # Distribute to cluster
    echo "🔄 Deploying to servers..."
    ./distribute_certs.sh --servers server_list.txt >> "$LOG_FILE" 2>&1

    # Reload services
    echo "🔄 Reloading services..."
    ansible-playbook -i production reload_services.yml >> "$LOG_FILE" 2>&1

    # Revoke old certs after 7-day grace period
    echo "🔄 Scheduling old cert revocation..."
    at now + 7 days <<<"$CERTS_DIR/revoke_old_certs.sh" >> "$LOG_FILE" 2>&1

    echo "✅ Rotation completed successfully"
} >> "$LOG_FILE" 2>&1