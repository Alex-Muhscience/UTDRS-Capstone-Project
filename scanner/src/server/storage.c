#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <openssl/ssl.h> // For SSL_get_fd

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <jansson.h>
#include "server/storage.h"
#include "common/utils.h"

#ifdef _WIN32
#define _WIN32_WINNT 0x0600 // Enable Windows Vista+ features (required for inet_ntop)
#endif

static sqlite3 *db = NULL;

int init_storage() {
    if (sqlite3_open("scans.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    const char *sql = 
        "CREATE TABLE IF NOT EXISTS scans ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "client_ip TEXT NOT NULL,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "data TEXT NOT NULL);";

    char *err_msg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}

int store_scan_result(SSL *ssl, const char *data) {
    // Validate JSON first
    json_error_t error;
    json_t *root = json_loads(data, 0, &error);
    if (!root) {
        fprintf(stderr, "Invalid JSON: %s\n", error.text);
        return -1;
    }
    json_decref(root);

    // Get client IP
    char client_ip[INET_ADDRSTRLEN];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(SSL_get_fd(ssl), (struct sockaddr*)&addr, &addr_len);
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

    // Prepare SQL statement
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO scans (client_ip, data) VALUES (?, ?);";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, client_ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, data, -1, SQLITE_STATIC);

    int result = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (result != SQLITE_DONE) {
        fprintf(stderr, "Insert failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    return 0;
}

void cleanup_storage() {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}