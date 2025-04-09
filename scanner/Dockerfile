# Use a base image with GCC and required libraries
FROM alpine:latest

# Install dependencies
RUN apk add --no-cache \
    build-base \
    openssl-dev \
    jansson-dev \
    sqlite-dev

# Copy the project files
WORKDIR /app
COPY . .

# Build the project
RUN make clean && make

# Expose the port your server listens on
EXPOSE 8443

# Run the server
CMD ["./bin/server"]