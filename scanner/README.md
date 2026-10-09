# UTDRS device scanner

An agent that collects a device's system and network inventory, and a collection server that receives inventories over mutually authenticated TLS and stores them in MongoDB. Written in C for Linux and Windows.

C · OpenSSL · mongo-c-driver · Jansson

> **Status: prototype; the agent and the server do not work together yet.** Each one runs, and the server's TLS and validation work, but the agent sends its inventory as raw C structs while the server expects a `SCAN` command carrying JSON. The server also checks a `checksum` field against the SHA-256 of the whole message, which contains the checksum itself, so no message can pass. Settling one wire format (JSON with a checksum over the other fields) is the next step; see the [roadmap](../README.md#roadmap).

## Components

| | |
|---|---|
| **Agent** (`src/agent`, `bin/agent`) | Every `scan_interval` seconds, collects the OS name and version, memory, CPU cores and network interfaces (Win32 APIs on Windows; `uname`, `sysinfo` and `getifaddrs` elsewhere), connects to the server with its client certificate, checks the server's certificate chain and that it names `server_host`, and sends a heartbeat and the inventory. Settings: `configs/agent.conf`. |
| **Server** (`src/server`, `bin/server`) | Listens on port 8443, one thread per connection (up to 200). Requires a client certificate signed by the CA (TLS 1.2 or later; on TLS 1.2 only ECDHE with AES-256-GCM), allows at most 30 requests a minute from one address, and stores accepted scans in MongoDB (`utdrs_db.scans`, with the client's address and a timestamp). |

### The server's protocol

One command per connection, up to 1,024 bytes, answered with a single word:

| Command | Reply |
|---|---|
| `SCAN {"hostname": ..., "os": ..., "timestamp": ..., "checksum": ...}` | `ACK` when stored; `INVALID_JSON`; `DATA_TOO_LARGE`; `VALIDATION_ERROR` for a missing field, a field over the length limit, or a checksum that does not match; `STORAGE_ERROR` |
| anything else | `INVALID_CMD` |

Connections from an address over the rate limit are closed. A connection without a valid client certificate fails the TLS handshake.

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

Start the server (it reads only `MONGODB_URI` from the environment) and talk to it with `openssl s_client` using the agent's certificate:

```bash
MONGODB_URI=mongodb://localhost:27017 ./bin/server
printf 'SCAN not-json' | openssl s_client -quiet -connect localhost:8443 \
  -cert configs/certs/agent.crt -key configs/certs/agent.key -CAfile configs/certs/ca.crt   # INVALID_JSON
```

`./bin/agent` connects with the settings in `configs/agent.conf` (`server_host` must be a name in the server's certificate). For production, `scripts/generate_ca.sh`, `generate_server_cert.sh` and `generate_agent_cert.sh` create 4096-bit keys under `/etc/device-scanner/certs`; copy or link them into `configs/certs/`. Other scripts cover deployment, certificate rotation and revocation, heartbeat checks and database backups.

## Docker

The image builds on Debian and runs the server as a non-root user:

```bash
docker build -t utdrs-scanner-server .
docker run -p 8443:8443 -e MONGODB_URI=mongodb://host.docker.internal:27017 \
  -v "$PWD/configs/certs:/app/configs/certs:ro" utdrs-scanner-server
```

## Layout

```
src/agent/      main loop, inventory collection, TLS transport, authentication
src/server/     accept loop and threads, command handling and validation, storage
src/common/     TLS contexts, logging, utilities
include/        headers
configs/        agent.conf, server.conf and templates; certs/ (local only)
scripts/        certificate generation, deployment and maintenance
```
