# Backups

`backup.sh` keeps copies of UTDRS's databases: the gateway's (`utdrs`) and the core
engine's (`utdrs_engine`). It runs in the image built from this folder's `Dockerfile`: the
`mongo:7` image, which has the MongoDB tools, with `rclone` for copies off-site.

Every `BACKUP_INTERVAL_HOURS` (24) it:

1. dumps each database to a compressed archive (`mongodump --archive --gzip`), encrypted
   with AES-256 when `BACKUP_PASSPHRASE` is set;
2. checks each archive can be read back (`mongorestore --dryRun`), and writes `SHA256SUMS`;
3. tests a full restore into scratch databases (`restore_test_utdrs`, …), counts what came
   back and drops them (every backup by default; `BACKUP_RESTORE_TEST_EVERY`);
4. deletes backups older than `BACKUP_KEEP_DAYS` (14);
5. with `BACKUP_S3_BUCKET` set, copies the backup **off-site** to S3-compatible storage, checks the
   copy against the original, and deletes off-site copies older than `BACKUP_REMOTE_KEEP_DAYS` (30).
   Off-site copies must be encrypted (`BACKUP_PASSPHRASE`); a backup is only reported as good
   when its off-site copy is;
6. records a heartbeat in the gateway's database. The gateway reports it in its metrics, and
   emails `OPERATOR_EMAILS` when backups stop or fail (after three missed rounds, or at once
   for a failure).

A backup that fails leaves nothing behind. Each is a folder, `utdrs-<UTC time>/`, with one
archive per database and `SHA256SUMS`.

## With Docker Compose

```bash
docker compose --profile backup up -d backup      # starts with a backup, then every day
docker compose logs -f backup
```

Backups go to `./backups` (`BACKUP_PATH` in `.env`). Copy them somewhere else as well, such
as another machine or cloud storage: a backup on the same disk as the database is lost with it.

## Off-site, every day, on Render (with MongoDB Atlas)

Atlas's free tier (M0) has no backups. The simplest arrangement keeps them in object storage:

1. **Storage.** Cloudflare R2 (free up to 10 GB) or Amazon S3 or Backblaze B2. Create a bucket
   (say `utdrs-backups`), and keys that can only list, read, write and delete in it. For R2:
   R2 > Manage API tokens > *Object Read & Write*, limited to that bucket; the endpoint is
   `https://<account id>.r2.cloudflarestorage.com`, the provider `Cloudflare`, the region `auto`.
2. **A passphrase.** A long random one (`openssl rand -base64 32`), kept in your password manager
   *and* somewhere else: without it, no backup can be read, by anyone.
3. **The job.** Uncomment `utdrs-backup` at the end of `render.yaml` and sync the Blueprint (or
   create a Render *Cron Job* from this repository with `ops/backup/Dockerfile`, the command
   `bash /backup.sh once` and the schedule `15 2 * * *`), and fill in its settings. It runs a minute or two
   a day. The database user needs `readWriteAnyDatabase` for the restore test (it writes, then drops,
   scratch databases); on M0, whose 512 MB the scratch copy also counts against, you can set
   `BACKUP_RESTORE_TEST_EVERY=0` and test restores elsewhere (below).
4. **Check.** Render > the job > *Trigger Run*, then its logs end with "off-site: <bucket>/utdrs/utdrs-…",
   and the gateway reports the backup's heartbeat (and emails `OPERATOR_EMAILS` if backups stop).

Also, in the bucket's settings, turn on object versioning or object lock where the provider offers it,
so that someone holding the keys cannot delete every copy at once.

## On any machine with Docker

```bash
docker build -t utdrs-backup ops/backup
docker run -d --name utdrs-backup --restart unless-stopped \
  -e MONGODB_URI='mongodb+srv://user:password@cluster0.example.mongodb.net/' \
  -e BACKUP_PASSPHRASE='a long random passphrase, kept elsewhere' \
  -e BACKUP_S3_PROVIDER=Cloudflare -e BACKUP_S3_REGION=auto \
  -e BACKUP_S3_ENDPOINT='https://<account id>.r2.cloudflarestorage.com' -e BACKUP_S3_BUCKET=utdrs-backups \
  -e BACKUP_S3_ACCESS_KEY_ID=… -e BACKUP_S3_SECRET_ACCESS_KEY=… \
  -v "$HOME/utdrs-backups:/backups" utdrs-backup
```

Without the `BACKUP_S3_*` settings it keeps backups only in the mounted folder.

The database user needs to read both databases, and to write the scratch databases for the
restore test (`readWriteAnyDatabase`, or set `BACKUP_RESTORE_TEST_EVERY=0` and test restores
elsewhere). On a paid Atlas cluster (M10 and up), Atlas's own continuous backups with
point-in-time restore are the better choice; keep this as a second copy you hold yourself.

## Restoring

From off-site, first fetch one (its checksums are checked):

```bash
docker run --rm -e MONGODB_URI=… -e BACKUP_PASSPHRASE=… -e BACKUP_S3_…=… -v "$HOME/utdrs-backups:/backups" utdrs-backup remote-list
docker run --rm -e … -v "$HOME/utdrs-backups:/backups" utdrs-backup fetch utdrs-20261105T021500Z
```

Then restore-test or restore it as below.

```bash
# Check a backup restores, without touching the live data:
docker compose run --rm backup restore-test /backups/utdrs-20261105T020000Z
# Replace the live databases with it (asks first; stop the gateway and engine first):
docker compose stop api-gateway core-engine
docker compose run --rm backup restore /backups/utdrs-20261105T020000Z
docker compose start core-engine api-gateway
```

Encrypted backups need the same `BACKUP_PASSPHRASE`. Without it, they cannot be read by anyone, you included.

## Settings

| Variable | Default | |
|---|---|---|
| `MONGODB_URI` | (required) | The server to back up |
| `BACKUP_DATABASES` | `utdrs utdrs_engine` | Databases to back up |
| `BACKUP_INTERVAL_HOURS` | `24` | |
| `BACKUP_KEEP_DAYS` | `14` | |
| `BACKUP_PASSPHRASE` | unset | Encrypts backups (AES-256-CBC, PBKDF2) |
| `BACKUP_RESTORE_TEST_EVERY` | `1` | Test restoring every Nth backup; `0` never |
| `BACKUP_DIR` | `/backups` | Inside the container |
| `HEARTBEAT_DB` | `utdrs` | The gateway's database, where the heartbeat goes |
| `BACKUP_S3_BUCKET` | unset | Copy each backup off-site to this bucket |
| `BACKUP_S3_PREFIX` | `utdrs/` | Folder in the bucket |
| `BACKUP_S3_PROVIDER` | `Other` | `Cloudflare` (R2), `AWS`, or `Other` (Backblaze B2, Wasabi, MinIO…) |
| `BACKUP_S3_ENDPOINT` | unset | The storage's address (not needed for AWS) |
| `BACKUP_S3_REGION` | unset | `auto` for R2 |
| `BACKUP_S3_ACCESS_KEY_ID`, `BACKUP_S3_SECRET_ACCESS_KEY` | | Keys for the bucket |
| `BACKUP_REMOTE_KEEP_DAYS` | `30` | Off-site copies older than this are deleted |
| `BACKUP_ALLOW_UNENCRYPTED_UPLOAD` | `false` | Copy unencrypted backups off-site (not advised) |
