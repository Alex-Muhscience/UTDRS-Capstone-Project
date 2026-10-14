# UTDRS data processor

A small batch worker for MongoDB: it moves documents from a source collection to a destination collection in batches, stamping each one as processed, sets aside any document that fails in a dead-letter collection with its error, and reports its progress on a health endpoint.

In UTDRS it carries device scans from the [scanner server](../../scanner) to the [API gateway](../api-gateway): with `GATEWAY_URL` set, each document is a stored scan, which it posts to the gateway's `POST /api/v1/scans/`. The device then appears in the dashboard as an asset, and as an event when it is new or its inventory has changed.

Python 3.12 · PyMongo · Flask

## What it does

Every `PROCESSING_INTERVAL` seconds:

1. Read up to `BATCH_SIZE` documents from `SOURCE_COLLECTION`.
2. Process each one (`process_document` in `data-processor.py`). With a gateway configured, that means delivering the scan (`scan_delivery.py`) and keeping the gateway's answer on the document; without one, the document is only stamped `processed`.
3. Write the results to `DESTINATION_COLLECTION` and delete the originals from the source.
4. Any document that cannot be processed, such as one that is not a scan or one the gateway rejects as invalid, is moved to `DEAD_LETTER_COLLECTION` with the error, instead of blocking the batch or being lost.
5. When the gateway is unreachable, answers with a server error or refuses the token, nothing is lost: that document and the rest of the batch stay in the source and are tried again on the next cycle.

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
| `GATEWAY_URL` | unset | The API gateway, e.g. `http://localhost:8000`. When set, documents are delivered to it as device scans. |
| `INTERNAL_API_TOKEN` | unset | The gateway's `INTERNAL_API_TOKEN`, sent as `X-Internal-Token` |

To deliver the scanner server's scans, point it at that server's database: `MONGODB_URI=mongodb://localhost:27017/utdrs_db` and `SOURCE_COLLECTION=scans`. Docker Compose sets this up with `--profile scanner`.

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

## Tests

```bash
python -m unittest
```

`test_scan_delivery.py` covers turning a stored scan into the gateway's report, and which failures are retried and which are set aside. CI runs it, and the *Docker Compose stack* job proves the whole path: the agent's scan becomes an asset in the gateway.
