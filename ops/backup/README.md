# Backups

`backup.sh` keeps copies of UTDRS's databases: the gateway's (`utdrs`) and the core
engine's (`utdrs_engine`). It runs in the `mongo:7` image, which has the MongoDB tools.

Every `BACKUP_INTERVAL_HOURS` (24) it:

1. dumps each database to a compressed archive (`mongodump --archive --gzip`), encrypted
   with AES-256 when `BACKUP_PASSPHRASE` is set;
2. checks each archive can be read back (`mongorestore --dryRun`), and writes `SHA256SUMS`;
3. tests a full restore into scratch databases (`restore_test_utdrs`, …), counts what came
   back and drops them (every backup by default; `BACKUP_RESTORE_TEST_EVERY`);
4. deletes backups older than `BACKUP_KEEP_DAYS` (14);
5. records a heartbeat in the gateway's database. The gateway reports it in its metrics, and
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

## Against MongoDB Atlas (or any server)

Atlas's free tier (M0) has no backups. Run the same container on any machine with Docker,
pointing at the cluster:

```bash
docker run -d --name utdrs-backup --restart unless-stopped \
  -e MONGODB_URI='mongodb+srv://user:password@cluster0.example.mongodb.net/' \
  -e BACKUP_PASSPHRASE='a long random passphrase, kept elsewhere' \
  -v "$PWD/ops/backup/backup.sh:/backup.sh:ro" -v "$HOME/utdrs-backups:/backups" \
  --entrypoint bash mongo:7 /backup.sh
```

The database user needs to read both databases, and to write the scratch databases for the
restore test (`readWriteAnyDatabase`, or set `BACKUP_RESTORE_TEST_EVERY=0` and test restores
elsewhere). On a paid Atlas cluster (M10 and up), Atlas's own continuous backups with
point-in-time restore are the better choice; keep this as a second copy you hold yourself.

## Restoring

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
