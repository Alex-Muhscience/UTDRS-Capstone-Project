#!/usr/bin/env bash
# Backs up UTDRS's databases on a schedule, checks each backup, tests restoring it, and
# keeps a fixed number of days. See README.md here.
#
#   backup.sh                       run for ever: a backup every BACKUP_INTERVAL_HOURS
#   backup.sh once                  one backup (checked, and its restore tested), then exit
#   backup.sh restore-test [dir]    restore the newest backup (or `dir`) into scratch databases, count, drop them
#   backup.sh restore dir           restore `dir` over the live databases (asks first)
#   backup.sh remote-list           the backups kept off-site
#   backup.sh fetch name            copy one off-site backup here (then restore-test or restore it)
#
# With BACKUP_S3_BUCKET set, each backup that passed its checks is also copied off-site,
# checked there, and off-site copies older than BACKUP_REMOTE_KEEP_DAYS are deleted.
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

# Off-site copies, to S3-compatible storage (unset: none). The provider is one rclone knows:
# AWS, Cloudflare (R2), Other (Backblaze B2, MinIO, Wasabi...). The keys need only to list,
# read, write and delete in the bucket.
BACKUP_S3_BUCKET="${BACKUP_S3_BUCKET:-}"
BACKUP_S3_PREFIX="${BACKUP_S3_PREFIX:-utdrs/}"
BACKUP_REMOTE_KEEP_DAYS="${BACKUP_REMOTE_KEEP_DAYS:-30}"
# Off-site copies must be encrypted, unless this says otherwise.
BACKUP_ALLOW_UNENCRYPTED_UPLOAD="${BACKUP_ALLOW_UNENCRYPTED_UPLOAD:-false}"
if [ -n "$BACKUP_S3_BUCKET" ]; then
  export RCLONE_CONFIG=/dev/null  # configured entirely from the environment
  export RCLONE_CONFIG_OFFSITE_TYPE=s3
  export RCLONE_CONFIG_OFFSITE_PROVIDER="${BACKUP_S3_PROVIDER:-Other}"
  export RCLONE_CONFIG_OFFSITE_ACCESS_KEY_ID="${BACKUP_S3_ACCESS_KEY_ID:?Set BACKUP_S3_ACCESS_KEY_ID for off-site copies}"
  export RCLONE_CONFIG_OFFSITE_SECRET_ACCESS_KEY="${BACKUP_S3_SECRET_ACCESS_KEY:?Set BACKUP_S3_SECRET_ACCESS_KEY for off-site copies}"
  export RCLONE_CONFIG_OFFSITE_ENDPOINT="${BACKUP_S3_ENDPOINT:-}"
  export RCLONE_CONFIG_OFFSITE_REGION="${BACKUP_S3_REGION:-}"
  export RCLONE_CONFIG_OFFSITE_NO_CHECK_BUCKET=true
  export RCLONE_CONFIG_OFFSITE_ENV_AUTH=false
fi
REMOTE="offsite:${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}"

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

# Copy a backup off-site and check the copy; prunes old off-site copies. Prints where.
upload() {
  local folder="$1" name cutoff old
  name="$(basename "$folder")"
  if [ -z "$BACKUP_PASSPHRASE" ] && [ "$BACKUP_ALLOW_UNENCRYPTED_UPLOAD" != true ]; then
    log "Refusing to copy an unencrypted backup off-site: set BACKUP_PASSPHRASE (or BACKUP_ALLOW_UNENCRYPTED_UPLOAD=true)"
    return 1
  fi
  log "Copying $name off-site"
  rclone copy --quiet "$folder" "$REMOTE$name" || { log "Copying $name off-site failed"; return 1; }
  rclone check --one-way --quiet "$folder" "$REMOTE$name" || { log "The off-site copy of $name does not match"; return 1; }
  # Off-site copies older than BACKUP_REMOTE_KEEP_DAYS go (by the time in their names).
  cutoff="$(date -u -d "-$BACKUP_REMOTE_KEEP_DAYS days" +%Y%m%dT%H%M%SZ)"
  for old in $(rclone lsf --dirs-only "$REMOTE" 2>/dev/null | sed 's#/$##' | grep -E '^utdrs-[0-9]{8}T[0-9]{6}Z$' || true); do
    if [[ "${old#utdrs-}" < "$cutoff" ]]; then
      rclone purge --quiet "$REMOTE$old" && log "Removed old off-site backup $old" || log "Could not remove old off-site backup $old"
    fi
  done
  echo "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}$name"
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
      if [ -n "$BACKUP_S3_BUCKET" ]; then
        where="$(upload "$folder")" || { heartbeat error "The off-site copy of $(basename "$folder") failed"; exit 1; }
        detail="$detail; off-site: $where"
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
        if [ "$status" = ok ] && [ -n "$BACKUP_S3_BUCKET" ]; then
          if where="$(upload "$folder")"; then
            detail="$detail; off-site: $where"
          else
            status=error; detail="The off-site copy of $(basename "$folder") failed"
          fi
        fi
        heartbeat "$status" "$detail"
      else
        log "The backup failed"; cleanup_partial; heartbeat error "The backup failed: see the backup's log"
      fi
      sleep $((BACKUP_INTERVAL_HOURS * 3600))
    done ;;
  remote-list)
    [ -n "$BACKUP_S3_BUCKET" ] || { log "Set BACKUP_S3_BUCKET (and its keys) to see off-site backups"; exit 2; }
    rclone lsf --dirs-only "$REMOTE" | sed 's#/$##' | grep -E '^utdrs-' | sort ;;
  fetch)
    name="${2:?Name the off-site backup to fetch (backup.sh remote-list)}"
    [ -n "$BACKUP_S3_BUCKET" ] || { log "Set BACKUP_S3_BUCKET (and its keys) to fetch off-site backups"; exit 2; }
    [[ "$name" =~ ^utdrs-[0-9]{8}T[0-9]{6}Z$ ]] || { log "Not a backup's name: $name"; exit 2; }
    mkdir -p "$BACKUP_DIR"
    rclone copy --quiet "$REMOTE$name" "$BACKUP_DIR/$name"
    (cd "$BACKUP_DIR/$name" && sha256sum --quiet -c SHA256SUMS) || { log "The fetched backup does not match its checksums"; exit 1; }
    log "Fetched $name to $BACKUP_DIR/$name: now restore-test or restore it"
    echo "$BACKUP_DIR/$name" ;;
  *) echo "Usage: backup.sh [once | restore-test [folder] | restore folder | remote-list | fetch name]" >&2; exit 2 ;;
esac
