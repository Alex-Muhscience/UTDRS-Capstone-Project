#!/bin/bash

# Install dependencies
echo "Installing dependencies..."
apk add --no-cache \
    build-base \
    openssl-dev \
    jansson-dev \
    sqlite-dev

# Build the project
echo "Building the project..."
make clean && make

# Start the server
echo "Starting the server..."
./bin/server