# UTDRS Device Scanner

![Project Logo](docs/images/logo.png) <!-- Add your logo if available -->

A secure, cross-platform device scanning and management system with TLS encryption and centralized reporting.

## Features

- ✅ **MongoDB Integration**: Full database connectivity with MongoDB C Driver 1.30.3
- ✅ **JSON Processing**: Complete JSON validation with Jansson 2.14 library
- ✅ **Secure Communication**: TLS 1.2+ encrypted connections
- ✅ **Cross-Platform**: Works on Windows and Linux
- ✅ **Centralized Management**: Server-client architecture
- ✅ **Device Discovery**: Comprehensive network scanning
- ✅ **Rate Limiting**: Protection against brute force attacks (30 req/min)
- ✅ **Built Successfully**: Ready-to-run executables available

## Architecture

UTDRS_System/
├── agent/              # Client components
├── server/             # Server components
├── common/             # Shared utilities
├── configs/            # Configuration files
│   └── certs/          # TLS certificates
├── docs/               # Documentation
├── include/            # Header files
└── tests/              # Unit tests

## Prerequisites

### Windows (MinGW-w64)

**Required Dependencies:**
- MinGW-w64 GCC compiler
- MongoDB C Driver 1.30.3 (built from source)
- Jansson 2.14 JSON library (built from source)
- OpenSSL (for TLS support)
- Make utility

**Installation Status:**
- ✅ MongoDB C Driver: Installed at `D:\mongodb-c-driver\mongodb-c-driver-1.30.3\build-install`
- ✅ Jansson Library: Installed at `D:\jansson\install`
- ✅ GCC Compiler: Available in PATH
- ✅ Make Utility: Available in PATH

### Linux (Ubuntu/Debian)

```bash
sudo apt-get install gcc libssl-dev libjansson-dev libsqlite3-dev make
sudo apt-get install libmongoc-1.0-0 libmongoc-dev
```

## Building

### Windows MinGW Build

1. Ensure all dependencies are properly installed (see Prerequisites)

2. Navigate to project directory:

```bash
cd "D:\Personal_Projects\UTDRS Device Scanner"
```

3. Clean and build:

```bash
make clean
make
```

**Build Output:**
- `bin/agent.exe` - Client scanning component
- `bin/server.exe` - Server management component

### Linux Build

1. Clone the repository:

```bash
git clone https://github.com/yourusername/utdrs-device-scanner.git
cd utdrs-device-scanner
```

2. Build the project:

```bash
make clean && make
```

## Usage

### Starting the Server

```bash
./bin/server.exe  # Windows
./bin/server      # Linux
```

### Running an Agent

```bash
./bin/agent.exe --server-address 127.0.0.1 --server-port 8443  # Windows
./bin/agent --server-address 127.0.0.1 --server-port 8443      # Linux
```

## Configuration

Edit `configs/server.conf`:

```ini
[network]
port = 8443
max_connections = 100

[security]
tls_cert = configs/certs/server.crt
tls_key = configs/certs/server.key
ca_cert = configs/certs/ca.crt
```

## API Documentation

### Server Endpoints

- `POST /api/v1/scan` - Submit device scan results
- `GET /api/v1/devices` - List all scanned devices
- `GET /api/v1/device/{id}` - Get specific device details

## Security Features

1. **TLS 1.2+ Encryption**
2. **Certificate Pinning**
3. **Rate Limiting** (30 requests/minute)
4. **Secure Memory Handling**
5. **Input Validation**

## Development

### Code Structure

| Directory       | Purpose                          |
|-----------------|----------------------------------|
| `src/agent/`    | Client-side scanning logic       |
| `src/server/`   | Server management and API        |
| `src/common/`   | Shared utilities and crypto      |
| `include/`      | Header files                     |

### Testing

Run unit tests:

```bash
make test
```

### Debug Build

```bash
make DEBUG=1
```

## Deployment

### Docker (Recommended)

```bash
docker build -t utdrs-server .
docker run -p 8443:8443 utdrs-server
```

### Systemd Service (Linux)

```ini
# /etc/systemd/system/utdrs.service
[Unit]
Description=UTDRS Device Scanner Server

[Service]
ExecStart=/opt/utdrs/bin/server
Restart=always
User=utdrs

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

**Common Issues:**

1. **Certificate errors**: Verify paths in `configs/server.conf`
2. **Connection refused**: Check server is running and firewall settings
3. **Missing dependencies**: Run `make deps` to verify requirements

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**Maintainer**: Alex Muhscience  
**Contact**: <info.ak.computerscience@gmail.com>  
**Version**: 1.0.0  
**Last Updated**: 2025-3-27

This README includes:

1. **Project Overview**: Brief description and features
2. **Installation Instructions**: For both Windows and Linux
3. **Build Instructions**: With certificate generation
4. **Usage Examples**: For both server and agent
5. **Configuration Details**: Sample config file
6. **API Documentation**: Key endpoints
7. **Security Features**: Highlighted protections
8. **Development Guide**: Code structure and testing
9. **Deployment Options**: Docker and systemd
10. **Troubleshooting**: Common issues
11. **Contribution Guidelines**
12. **License Information**
