# UTDRS data processor

A small batch worker for MongoDB: it moves documents from a source collection to a destination collection in batches, stamping each one as processed, sets aside any document that fails in a dead-letter collection with its error, and reports its progress on a health endpoint.

Python 3.12 · PyMongo · Flask

> **Status:** standalone. It works on its own, but nothing in UTDRS writes to its source collection yet, and its transformation is a placeholder (`process_document` adds `processed` and `processing_timestamp`). Wiring it in, for example to normalise raw scanner output before it reaches the gateway, is future work.

## What it does

Every `PROCESSING_INTERVAL` seconds:

1. Read up to `BATCH_SIZE` documents from `SOURCE_COLLECTION`.
2. Transform each one (`process_document` in `data-processor.py`).
3. Insert the results into `DESTINATION_COLLECTION` and delete the originals from the source.
4. Any document whose transformation raises is copied to `DEAD_LETTER_COLLECTION` with the error, instead of blocking the batch or being lost.

It connects with retries (`MAX_RETRIES`, `RETRY_DELAY`) and serves `GET /health` on port 5000:

```json
{
  "status": "running",
  "uptime": 3.7,
  "metrics": { "processed": 2, "failed": 0, "errors": {}, "last_processed": "Fri, 09 Oct 2026 12:46:51 GMT" }
}
```

## Configuration

| Variable | Default | |
|---|---|---|
| `MONGODB_URI` | `mongodb://localhost:27017/` | **Must name the database**, e.g. `mongodb://localhost:27017/utdrs`; the collections are looked up in it. |
| `SOURCE_COLLECTION` | `raw_data` | |
| `DESTINATION_COLLECTION` | `processed_data` | |
| `DEAD_LETTER_COLLECTION` | `failed_data` | |
| `BATCH_SIZE` | `10` | Documents per cycle |
| `PROCESSING_INTERVAL` | `5` | Seconds between cycles |
| `MAX_RETRIES`, `RETRY_DELAY` | `3`, `2` | Connection attempts and the seconds between them |

## Run it

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
MONGODB_URI=mongodb://localhost:27017/utdrs python data-processor.py
curl http://localhost:5000/health
```

With Docker:

```bash
docker build -t utdrs-data-processor -f dockerfile .
docker run -p 5000:5000 -e MONGODB_URI=mongodb://host.docker.internal:27017/utdrs utdrs-data-processor
```

CI installs the dependencies and compiles the modules; there are no automated tests yet.
