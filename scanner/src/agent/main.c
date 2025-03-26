#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "common/crypto.h"
#include "agent/scanner.h"
#include "agent/transport.h"

volatile sig_atomic_t running = 1;

void handle_signal(int sig) {
    running = 0;
}

int main() {
    // Setup signal handling
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Initialize TLS context
    SSL_CTX *ctx = init_tls_client_context(
        "configs/certs/ca.crt",
        "configs/certs/agent.crt",
        "configs/certs/agent.key"
    );
    if (!ctx) {
        fprintf(stderr, "TLS init failed\n");
        return EXIT_FAILURE;
    }

    // Main loop
    while (running) {
        // Connect to server
        SSL *ssl = connect_to_server(ctx, "scanner.example.com", 8443);
        if (!ssl) {
            sleep(5); // Backoff on failure
            continue;
        }

        // Perform scan and send
        char *scan_data = perform_scan();
        if (ssl_write_all(ssl, scan_data, strlen(scan_data)) {
            fprintf(stderr, "Failed to send scan data\n");
        }
        
        free(scan_data);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        
        sleep(60); // Scan interval
    }

    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}