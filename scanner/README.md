# UTDRS Device Scanner

![Project Logo](docs/images/logo.png) <!-- Add your logo if available -->

A secure, cross-platform device scanning and management system with TLS encryption and centralized reporting.

## Features

- **Secure Communication**: TLS 1.2+ encrypted connections
- **Cross-Platform**: Works on Windows and Linux
- **Centralized Management**: Server-client architecture
- **Device Discovery**: Comprehensive network scanning
- **Secure Storage**: Encrypted scan result storage
- **Rate Limiting**: Protection against brute force attacks

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

### Windows (MSYS2/MinGW)

```bash
pacman -S mingw-w64-x86_64-gcc \
          mingw-w64-x86_64-openssl \
          mingw-w64-x86_64-jansson \
          mingw-w64-x86_64-sqlite3 \
          make
```

### Linux (Ubuntu/Debian)

```bash
sudo apt-get install gcc libssl-dev libjansson-dev libsqlite3-dev make
```

## Building

1. Clone the repository:

```bash
git clone https://github.com/yourusername/utdrs-device-scanner.git
cd utdrs-device-scanner
```

2. Generate TLS certificates (or place your own in `configs/certs/`):

```bash
mkdir -p configs/certs
openssl req -x509 -newkey rsa:4096 -keyout configs/certs/server.key -out configs/certs/server.crt -days 365 -nodes -subj "/CN=localhost"
cp configs/certs/server.crt configs/certs/ca.crt  # For testing only
```

3. Build the project:

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
