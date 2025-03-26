#!/bin/bash
set -euo pipefail

# Database backup with encryption
# Runs daily via cron: 0 2 * * * /opt/device-scanner/scripts/backup_db.sh

BACKUP_DIR="/backups/scanner"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/scanner_db_$TIMESTAMP.pgdump"
ENCRYPTED_FILE="$BACKUP_FILE.age"

# Load encryption key from HashiCorp Vault
AGE_KEY=$(vault read -field=key secret/scanner/backup)

echo "💾 Starting database backup..."

# Create dump
pg_dump -Fc -d "$DATABASE_URL" -f "$BACKUP_FILE" || {
    echo "❌ Backup failed";
    exit 1;
}

# Encrypt with age
age -r "$AGE_KEY" -o "$ENCRYPTED_FILE" "$BACKUP_FILE" || {
    echo "❌ Encryption failed";
    exit 1;
}

# Verify integrity
if ! age --decrypt -i <(echo "$AGE_KEY") "$ENCRYPTED_FILE" | pg_restore --list >/dev/null; then
    echo "❌ Backup verification failed";
    exit 1;
fi

# Cleanup
shred -u "$BACKUP_FILE"
find "$BACKUP_DIR" -name "*.age" -mtime +30 -delete

echo "✅ Backup completed: $ENCRYPTED_FILE"