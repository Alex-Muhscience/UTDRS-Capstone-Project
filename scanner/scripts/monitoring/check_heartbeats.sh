#!/bin/bash
set -euo pipefail

# Agent health check script
# Runs every 5 minutes via cron

THRESHOLD_MINUTES=15
ALERT_EMAIL="security-team@example.com"

# Query database for stale agents
STALE_AGENTS=$(psql -d "$DATABASE_URL" -t -c "
    SELECT host_id FROM agents 
    WHERE last_heartbeat < NOW() - INTERVAL '$THRESHOLD_MINUTES minutes'
    AND active = true;
")

if [[ -n "$STALE_AGENTS" ]]; then
    echo "❌ Stale agents detected:" > /tmp/alert.txt
    echo "$STALE_AGENTS" >> /tmp/alert.txt
    
    # Send alert
    mailx -s "Device Scanner Alert: Stale Agents" "$ALERT_EMAIL" < /tmp/alert.txt
    
    # Create JIRA ticket if more than 5 agents
    COUNT=$(echo "$STALE_AGENTS" | wc -l)
    if [[ $COUNT -gt 5 ]]; then
        ./create_jira_ticket.sh "Agent Outage" "$(cat /tmp/alert.txt)"
    fi
fi