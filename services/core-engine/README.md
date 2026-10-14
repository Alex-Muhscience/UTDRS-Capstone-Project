# UTDRS core engine

The detection service. It receives events from the [API gateway](../api-gateway), runs them through several detectors at once, and answers with an alert, mapped to MITRE ATT&CK, or with nothing. It is an internal service: only the gateway calls it, and it should not be reachable from the internet.

Python 3.12 · FastAPI · PyMongo (async) · scikit-learn · NumPy/SciPy · yara-python

## Detection

Every event goes to six detectors concurrently (`core/detection/engine.py`). The first verdict in this order wins, from the most specific evidence to the least, and becomes one alert:

| Detector | What it looks for | State |
|---|---|---|
| **Signature** | Rules matching event fields: exact values, lists, `regex:` patterns and numeric conditions, combined with AND or OR. 13 rules ship with the engine: failed and admin logins, connections to known C2 addresses, DNS lookups of listed domains, suspicious processes and encoded PowerShell, access to sensitive files, security services disabled, new accounts, large outbound uploads, external email attachments, ransomware file operations and known malware hashes, each mapped to MITRE ATT&CK. | Working. The rules are added to the engine's database at startup if missing, and managed through `/rules`. |
| **YARA** | Files or content referenced by the event, against the YARA rules in `core/rules/yara/` | Working when rules are present (`ENABLE_YARA`) |
| **Correlation** | Sequences of related events within `CORRELATION_WINDOW` minutes, e.g. failed logins followed by a success | Working |
| **Threat intelligence** | IPs, domains and hashes looked up in VirusTotal, AbuseIPDB and AlienVault OTX, with a local cache | Off unless `ENABLE_THREAT_INTEL` is on and API keys are set |
| **ML** | Malware and ransomware behaviour (e.g. deleting shadow copies, T1490), phishing, network and user-behaviour patterns | **Two trained models.** Emails: the capstone's phishing classifier, 98.3% accurate on its held-out test set at the threshold used ([model card](core/models/ml/phishing_email/MODEL_CARD.md)). Network flows with the 21 measurements it reads: a CNN-LSTM trained on UNSW-NB15, which flags 0.65% of normal test flows and catches 80% of attacks ([model card](core/models/ml/network_threat/MODEL_CARD.md)). **Everything else, and events without what a model needs: hand-written indicator scoring**; the model files in `ml_models/` are placeholders. |
| **Anomaly** | Deviations from baselines built from the engine's own event history (`ANOMALY_BASELINE_DAYS`): unusual sign-in times and places, beaconing, port scans, traffic volume, unusual processes and file activity | Working; needs history to be useful |

The engine stores every event it sees and every alert it raises in **its own database**, which the correlation and anomaly detectors read. Alerts include a risk score, the matched techniques and tactics, and the detection details. The gateway turns the engine's alert into an alert of its own, linked to the original event.

## API

| Route | |
|---|---|
| `GET /health`, `GET /health/db` | Open, for load balancers and the gateway's status check |
| `POST /detections/process` | Analyse an event: `{ "source", "event_type", "timestamp", "data": { ... } }`. Returns the alert, or `null`. Detector fields go in `data`, e.g. `process_name`, `command_line`, `src_ip`, `dst_ip`, `domain`, `status`, `filepath`. |
| `GET /detections/alerts`, `GET /detections/alerts/{id}` | The engine's alerts, filterable by `severity` and `source` |
| `GET`, `POST /rules/`, `GET`, `PUT`, `DELETE /rules/{id}` | Detection rules |

When `INTERNAL_API_TOKEN` is set, every route except health requires the same value in the `X-Internal-Token` header (compared in constant time). Interactive docs are at `/docs`.

A signature rule looks like this:

```json
{
  "name": "DNS Query to Suspicious Domain",
  "description": "Detects DNS queries to known malicious or suspicious domains",
  "rule_type": "signature",
  "detection": {
    "condition_type": "AND",
    "conditions": { "event_type": "dns", "data.domain": ["malicious.com", "evil.net"] }
  },
  "enabled": true,
  "severity": "high",
  "mitre_tactics": ["TA0011"],
  "mitre_techniques": ["T1071.004"]
}
```

## Configuration

Settings come from the environment or a `.env` file in this directory (see [`.env.example`](.env.example)).

| Variable | Default | |
|---|---|---|
| `MONGODB_URI` | required | |
| `DB_NAME` | `utdrs_engine` | The engine's own database. Never the gateway's. |
| `INTERNAL_API_TOKEN` | unset | Shared secret with the gateway |
| `ENABLE_YARA` | `true` | |
| `ENABLE_CORRELATION` | `true` | |
| `CORRELATION_WINDOW` | `60` | Minutes |
| `ANOMALY_BASELINE_DAYS` | `7` | |
| `ENABLE_THREAT_INTEL` | `true` | Only providers with a key are queried |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | unset | |
| `MODEL_PATH` | `ml_models` | Loaded with `pickle`: only use model files you trust |
| `LOG_LEVEL` | `INFO` | |

## Run it

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
MONGODB_URI=mongodb://localhost:27017 uvicorn app:app --reload --port 8001
```

Then point the gateway at it with `CORE_ENGINE_URL=http://localhost:8001`, and give both the same `INTERNAL_API_TOKEN`. [`scripts/run-stack.sh`](../../scripts/run-stack.sh) does all of this.

## Tests

```bash
MONGODB_URI=mongodb://localhost:27017 python -m pytest
```

26 tests:

- `tests/unit/test_detection.py`: each detector, MITRE mapping and risk scoring, and every predefined rule against routine and malicious events.
- `tests/integration/test_api.py`: the API against MongoDB. A ransomware precursor becomes a stored critical alert; a failed login matches its signature rule; benign events produce nothing; the predefined rules are loaded once; the internal token is enforced.

## Docker

```bash
docker build -t utdrs-core-engine .
docker run -p 8001:8000 -e MONGODB_URI=... -e INTERNAL_API_TOKEN=... utdrs-core-engine
```

Python 3.12 slim, run as a non-root user, served by Gunicorn with Uvicorn workers on port 8000 inside the container.

## Layout

```
app.py                       application; loads the predefined rules at startup
api/routes/                  health, detections, rules
api/security.py              the internal token check
core/detection/              the engine and its six detectors
core/rules/                  predefined signature rules, rule management, YARA rules
core/threat_intel/           threat-intelligence providers and cache
core/mitre/, core/risk/      MITRE ATT&CK mapping and risk scoring
core/services/               event processing
core/database/               connection and repositories
ml_models/                   placeholder models for the ML detector
tests/                       unit and integration tests
```
