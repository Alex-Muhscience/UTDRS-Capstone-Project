# UTDRS device scanner

An agent that collects a device's system and network inventory, and a collection server that receives inventories over mutually authenticated TLS and stores them in MongoDB. From there the [data processor](../services/data-processor) delivers each scan to the API gateway, where the device appears as an asset, and as an event when it is new or its inventory has changed. Written in C for Linux and Windows.

C · OpenSSL · mongo-c-driver · Jansson

> **Status: working on Linux.** The agent and the server share one wire format, and CI sends a scan from the agent through to an asset in the gateway. The Windows code paths are kept up to date but are not built or tested in CI.

## Components

| | |
|---|---|
| **Agent** (`src/agent`, `bin/agent`) | Every `scan_interval` seconds, collects the host name, OS name and version, memory, CPU cores and IPv4 network interfaces with their MAC addresses (Win32 APIs on Windows; `uname`, `sysinfo`, `getifaddrs` and sysfs elsewhere), connects to the server with its client certificate, checks the server's certificate chain and that it names `server_host`, sends the inventory and waits for `ACK`. `bin/agent --once` sends a single scan and exits with 0 when the server stored it. Settings: `configs/agent.conf`, or another file named on the command line; `SCANNER_SERVER_HOST` and `SCANNER_SERVER_PORT` in the environment override it. |
| **Server** (`src/server`, `bin/server`) | Listens on port 8443, one thread per connection (up to 200). Requires a client certificate signed by the CA (TLS 1.2 or later; on TLS 1.2 only ECDHE with AES-256-GCM), allows at most 30 requests a minute from one address, and stores accepted scans in MongoDB (`utdrs_db.scans`: the scan as a document, the client's address, and when it arrived). |

### The server's protocol

One command per connection, up to 8 KB, answered with a single word:

| Command | Reply |
|---|---|
| `SCAN {"hostname": ..., "os": ..., "timestamp": ..., "checksum": ...}` | `ACK` when stored; `INVALID_JSON`; `DATA_TOO_LARGE`; `VALIDATION_ERROR` for a missing or empty field, a field over 256 characters, or a checksum that does not match; `STORAGE_ERROR` |
| anything else | `INVALID_CMD` |

Connections from an address over the rate limit are closed. A connection without a valid client certificate fails the TLS handshake.

`hostname`, `os`, `timestamp` and `checksum` are required strings. The agent also sends `os_version`, `cpu_cores`, `memory_kb` and `interfaces` (a list of `{"name", "ip", "mac"}`), and the server stores whatever the message carries:

```json
{"checksum":"…","cpu_cores":4,"hostname":"ws-01","interfaces":[{"ip":"10.0.0.7","mac":"02:42:0a:00:00:07","name":"eth0"}],"memory_kb":8000000,"os":"Linux","os_version":"6.8.0","timestamp":"2026-10-13T19:00:00Z"}
```

**The checksum** is the SHA-256, in lowercase hex, of the message without its `checksum` member, serialised as compact JSON with its keys sorted (`src/common/scan_message.c`; in Python, `json.dumps(scan, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`). It catches a damaged message; it is not authentication, which is the client certificate's job.

## Build

**Linux** (Debian or Ubuntu packages; CI builds the same way):

```bash
sudo apt-get install build-essential pkg-config libssl-dev libmongoc-dev libbson-dev libjansson-dev
make            # bin/agent and bin/server
```

**Windows** (MinGW-w64): install OpenSSL, mongo-c-driver and Jansson, adjust the include and library paths at the top of the `Makefile` (the `Windows_NT` branch), and run `make` to get `bin/agent.exe` and `bin/server.exe`.

## Run it locally

Both programs read their certificates from `configs/certs/` relative to the working directory (git-ignored: never commit keys). For a local test, create a throwaway CA and certificates:

```bash
mkdir -p configs/certs && cd configs/certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 30 -subj "/CN=UTDRS development CA"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 30 \
  -extfile <(printf "subjectAltName=DNS:localhost")
openssl req -newkey rsa:2048 -nodes -keyout agent.key -out agent.csr -subj "/CN=agent-1"
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out agent.crt -days 30
cd ../..
```

Start the server (it reads only `MONGODB_URI` from the environment), then send it one scan of this machine:

```bash
MONGODB_URI=mongodb://localhost:27017 ./bin/server
./bin/agent --once        # "Scan delivered to localhost:8443"; the scan is now in utdrs_db.scans
```

Without `--once`, the agent keeps running and scans every `scan_interval` seconds. It connects with the settings in `configs/agent.conf` (`server_host` must be a name in the server's certificate). To see the server's replies yourself, use `openssl s_client` with the agent's certificate:

```bash
printf 'SCAN not-json' | openssl s_client -quiet -connect localhost:8443 \
  -cert configs/certs/agent.crt -key configs/certs/agent.key -CAfile configs/certs/ca.crt   # INVALID_JSON
```

To carry the stored scans on into UTDRS, run the [data processor](../services/data-processor) against `utdrs_db`, or use `docker compose --profile scanner` from the repository root, which runs the server and the processor together ([guide](../docs/docker.md#device-scanner-scanner)).

For production, `scripts/generate_ca.sh`, `generate_server_cert.sh` and `generate_agent_cert.sh` create 4096-bit keys under `/etc/device-scanner/certs`; copy or link them into `configs/certs/`. Other scripts cover deployment, certificate rotation and revocation, heartbeat checks and database backups.

## Docker

The image builds on Debian and runs the server as a non-root user. It carries the agent too (`bin/agent`), which Compose uses to send a demonstration scan:

```bash
docker build -t utdrs-scanner-server .
docker run -p 8443:8443 -e MONGODB_URI=mongodb://host.docker.internal:27017 \
  -v "$PWD/configs/certs:/app/configs/certs:ro" utdrs-scanner-server
```

## Layout

```
src/agent/      main loop, inventory collection, TLS transport, authentication
src/server/     accept loop and threads, command handling and validation, storage
src/common/     TLS contexts, the scan message's checksum, logging, utilities
include/        headers
configs/        agent.conf, server.conf and templates; certs/ (local only)
scripts/        certificate generation, deployment and maintenance
```
