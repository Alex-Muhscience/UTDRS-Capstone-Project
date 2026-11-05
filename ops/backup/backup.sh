#!/usr/bin/env bash
# Backs up UTDRS's databases on a schedule, checks each backup, tests restoring it, and
# keeps a fixed number of days. See README.md here.
#
#   backup.sh                       run for ever: a backup every BACKUP_INTERVAL_HOURS
#   backup.sh once                  one backup (checked, and its restore tested), then exit
#   backup.sh restore-test [dir]    restore the newest backup (or `dir`) into scratch databases, count, drop them
#   backup.sh restore dir           restore `dir` over the live databases (asks first)
#
# Each backup is a folder, utdrs-<UTC time>, holding one compressed archive per database
# (encrypted when BACKUP_PASSPHRASE is set) and SHA256SUMS.
set -euo pipefail
shopt -s inherit_errexit

: "${MONGODB_URI:?Set MONGODB_URI: the database server to back up}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_INTERVAL_HOURS="${BACKUP_INTERVAL_HOURS:-24}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
# The gateway's and the core engine's databases (DB_NAME of each).
BACKUP_DATABASES="${BACKUP_DATABASES:-utdrs utdrs_engine}"
# With a passphrase, archives are encrypted (AES-256-CBC, PBKDF2); keep it somewhere else.
BACKUP_PASSPHRASE="${BACKUP_PASSPHRASE:-}"
# Test restoring every Nth backup (1: every one; 0: never).
BACKUP_RESTORE_TEST_EVERY="${BACKUP_RESTORE_TEST_EVERY:-1}"
# The database whose `heartbeats` the gateway watches: it emails operators when backups stop.
HEARTBEAT_DB="${HEARTBEAT_DB:-utdrs}"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

heartbeat() { # ok|error, message
  HB_OK="$1" HB_MESSAGE="$2" mongosh "$MONGODB_URI" --quiet --eval "
    const ok = process.env.HB_OK === 'ok', message = process.env.HB_MESSAGE, now = new Date();
    const fields = {at: now, interval_seconds: $BACKUP_INTERVAL_HOURS * 3600, process: 'backup', ok: ok, error: ok ? null : message};
    if (ok) { fields.last_ok_at = now; fields.detail = message; }
    db.getSiblingDB('$HEARTBEAT_DB').heartbeats.updateOne({_id: 'backup'}, {\$set: fields}, {upsert: true});
  " >/dev/null || log "Could not record the heartbeat"
}

suffix() { [ -n "$BACKUP_PASSPHRASE" ] && echo ".archive.gz.enc" || echo ".archive.gz"; }

# One database's archive to stdout, decrypted when it is encrypted.
read_archive() {
  case "$1" in
    *.enc) [ -n "$BACKUP_PASSPHRASE" ] || { log "$1 is encrypted: set BACKUP_PASSPHRASE"; return 1; }
           openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE -in "$1" ;;
    *) cat "$1" ;;
  esac
}

# A failed backup leaves nothing behind.
cleanup_partial() { find "$BACKUP_DIR" -maxdepth 1 -type d -name 'utdrs-*.partial' -exec rm -rf {} + 2>/dev/null || true; }

newest() { find "$BACKUP_DIR" -maxdepth 1 -type d -name 'utdrs-*' ! -name '*.partial' | sort | tail -n1; }

# Make a backup; prints its folder.
backup_once() {
  mkdir -p "$BACKUP_DIR"
  local folder partial db file
  folder="$BACKUP_DIR/utdrs-$(date -u +%Y%m%dT%H%M%SZ)"
  partial="$folder.partial"
  rm -rf "$partial" && mkdir -p "$partial" || return 1
  log "Backing up ($BACKUP_DATABASES) to $folder"
  for db in $BACKUP_DATABASES; do
    file="$partial/$db$(suffix)"
    if [ -n "$BACKUP_PASSPHRASE" ]; then
      mongodump --uri="$MONGODB_URI" --db="$db" --archive --gzip --quiet \
        | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:BACKUP_PASSPHRASE -out "$file" || { log "Backing up $db failed"; return 1; }
    else
      mongodump --uri="$MONGODB_URI" --db="$db" --archive="$file" --gzip --quiet || { log "Backing up $db failed"; return 1; }
    fi
    # A backup that cannot be read back is not a backup: check it before keeping it.
    read_archive "$file" | mongorestore --uri="$MONGODB_URI" --archive --gzip --dryRun --quiet || { log "The backup of $db cannot be read back"; return 1; }
  done
  (cd "$partial" && sha256sum -- * > SHA256SUMS) || return 1
  mv "$partial" "$folder" || return 1
  log "Backed up: $(du -sh "$folder" | cut -f1)"
  find "$BACKUP_DIR" -maxdepth 1 -type d -name 'utdrs-*' -mtime +"$BACKUP_KEEP_DAYS" -print -exec rm -rf {} + | sed 's/^/Removed old backup /' >&2 || true
  echo "$folder"
}

# Restore a backup into scratch databases, count what came back, drop them; prints the count.
restore_test() {
  local folder="${1:-$(newest)}" db file collections=0 documents=0 counts
  [ -n "$folder" ] && [ -d "$folder" ] || { log "No backup to test"; return 1; }
  (cd "$folder" && sha256sum --quiet -c SHA256SUMS) || { log "$folder does not match its checksums"; return 1; }
  log "Testing a restore of $folder into scratch databases"
  for db in $BACKUP_DATABASES; do
    file="$folder/$db$(suffix)"
    [ -f "$file" ] || file="$(ls "$folder/$db".archive.gz* 2>/dev/null | head -n1)"
    [ -f "$file" ] || { log "$folder has no backup of $db"; return 1; }
    read_archive "$file" | mongorestore --uri="$MONGODB_URI" --archive --gzip --drop --quiet \
      --nsFrom="$db.*" --nsTo="restore_test_$db.*" || { log "Restoring $db failed"; return 1; }
    counts="$(mongosh "$MONGODB_URI" --quiet --eval "
      const d = db.getSiblingDB('restore_test_$db'); let n = 0;
      const names = d.getCollectionNames(); for (const c of names) n += d[c].countDocuments();
      d.dropDatabase(); print(names.length + ' ' + n);")" || { log "Counting the restored $db failed"; return 1; }
    collections=$((collections + ${counts% *})); documents=$((documents + ${counts#* }))
  done
  log "Restore test passed: $collections collections, $documents documents"
  echo "$collections collections, $documents documents"
}

case "${1:-loop}" in
  once)
    if folder="$(backup_once)"; then
      detail="Backed up to $(basename "$folder")"
      if [ "$BACKUP_RESTORE_TEST_EVERY" -gt 0 ]; then
        report="$(restore_test "$folder")" || { heartbeat error "The restore test of $(basename "$folder") failed"; exit 1; }
        detail="$detail; restore test: $report"
      fi
      heartbeat ok "$detail"
    else
      cleanup_partial; heartbeat error "The backup failed: see the backup's log"; exit 1
    fi ;;
  restore-test)
    restore_test "${2:-}" ;;
  restore)
    folder="${2:?Name the backup folder to restore}"
    (cd "$folder" && sha256sum --quiet -c SHA256SUMS)
    read -r -p "Replace the live databases ($BACKUP_DATABASES) with $folder? Type yes: " answer
    [ "$answer" = yes ] || { echo "Nothing changed."; exit 1; }
    for db in $BACKUP_DATABASES; do
      file="$(ls "$folder/$db".archive.gz* | head -n1)"
      read_archive "$file" | mongorestore --uri="$MONGODB_URI" --archive --gzip --drop
    done
    log "Restored $folder" ;;
  loop)
    count=0
    while true; do
      if folder="$(backup_once)"; then
        count=$((count + 1))
        detail="Backed up to $(basename "$folder")"
        status=ok
        if [ "$BACKUP_RESTORE_TEST_EVERY" -gt 0 ] && [ $(((count - 1) % BACKUP_RESTORE_TEST_EVERY)) -eq 0 ]; then
          if report="$(restore_test "$folder")"; then
            detail="$detail; restore test: $report"
          else
            status=error; detail="The restore test of $(basename "$folder") failed"
          fi
        fi
        heartbeat "$status" "$detail"
      else
        log "The backup failed"; cleanup_partial; heartbeat error "The backup failed: see the backup's log"
      fi
      sleep $((BACKUP_INTERVAL_HOURS * 3600))
    done ;;
  *) echo "Usage: backup.sh [once | restore-test [folder] | restore folder]" >&2; exit 2 ;;
esac
