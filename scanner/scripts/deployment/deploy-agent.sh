#!/bin/bash
set -euo pipefail

# Mass agent deployment script
# Usage: ./deploy_agent.sh --targets hosts.txt

TARGETS_FILE=""
SERVICE_ACCOUNT="scanner-deploy"
SSH_KEY="/etc/ssh/scanner_deploy.key"

while [[ $# -gt 0 ]]; do
    case $1 in
        --targets) TARGETS_FILE=$2; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ ! -f "$TARGETS_FILE" ]]; then
    echo "❌ Targets file required"
    exit 1
fi

if [[ ! -f "$SSH_KEY" ]]; then
    echo "❌ Deployment SSH key missing"
    exit 1
fi

echo "🚀 Deploying Device Scanner Agent to $(wc -l < "$TARGETS_FILE") hosts"

# Parallel deployment using GNU parallel
parallel -j 20 -a "$TARGETS_FILE" --bar --eta \
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
    "$SERVICE_ACCOUNT@{}" \
    "curl -sS https://scanner.example.com/install_agent.sh | sudo bash -s -- \
    --server scanner-cluster.example.com \
    --group production"

echo "✅ Agent deployment initiated"