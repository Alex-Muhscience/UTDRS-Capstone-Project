# Build on Debian with the same packages CI builds with.
FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config \
      libssl-dev libmongoc-dev libbson-dev libjansson-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN make

# The collection server, run as a non-root user.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 libmongoc-1.0-0 libbson-1.0-0 libjansson4 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home-dir /app scanner \
 && mkdir -p /app/bin /app/configs/certs \
 && chown -R scanner /app
WORKDIR /app
COPY --from=build /src/bin/server /app/bin/server
USER scanner
EXPOSE 8443
# Mount the CA certificate and the server's certificate and key at /app/configs/certs
# (ca.crt, server.crt, server.key) and set MONGODB_URI.
CMD ["bin/server"]
