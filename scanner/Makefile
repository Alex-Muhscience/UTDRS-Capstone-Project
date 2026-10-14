# Builds the scanner agent and collection server.
#
# Windows (MinGW): needs OpenSSL, mongo-c-driver and jansson installed at the paths below.
# Linux/macOS: needs the OpenSSL, mongo-c-driver (libmongoc/libbson) and jansson
# development packages, found through pkg-config, e.g. on Debian/Ubuntu:
#   apt-get install libssl-dev libmongoc-dev libbson-dev libjansson-dev pkg-config

CC = gcc
COMMON_CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
                -Iinclude -Iinclude/common -Iinclude/server -Iinclude/agent

AGENT_SOURCES = src/agent/main.c src/agent/scanner.c src/agent/transport.c src/agent/auth.c \
                src/common/crypto.c src/common/logging.c src/common/utils.c src/common/scan_message.c
SERVER_SOURCES = src/server/main.c src/server/api.c src/server/storage.c \
                 src/common/crypto.c src/common/logging.c src/common/utils.c src/common/scan_message.c

ifeq ($(OS),Windows_NT)
CFLAGS = $(COMMON_CFLAGS) -D__USE_MINGW_ANSI_STDIO=1 \
         -I"C:\Program Files\OpenSSL-Win64\include" \
         -ID:/mongo-install/include/libmongoc-1.0 -ID:/mongo-install/include/libbson-1.0 \
         -ID:/jansson-install/include
AGENT_LDFLAGS = -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" -LD:/jansson-install/lib \
                -lws2_32 -liphlpapi -ljansson -lssl -lcrypto
SERVER_LDFLAGS = -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" \
                 -LD:/mongo-install/lib -LD:/jansson-install/lib -lws2_32 -liphlpapi \
                 -lmongoc-1.0 -lbson-1.0 -ljansson -lssl -lcrypto
TARGET_AGENT = bin/agent.exe
TARGET_SERVER = bin/server.exe
MKDIR_BIN = if not exist bin mkdir bin
CLEAN = del /q src\agent\*.o src\common\*.o src\server\*.o bin\agent.exe bin\server.exe 2>nul || exit 0
else
CFLAGS = $(COMMON_CFLAGS) $(shell pkg-config --cflags libmongoc-1.0 jansson openssl)
AGENT_LDFLAGS = $(shell pkg-config --libs jansson openssl)
SERVER_LDFLAGS = $(shell pkg-config --libs libmongoc-1.0 jansson openssl)
TARGET_AGENT = bin/agent
TARGET_SERVER = bin/server
MKDIR_BIN = mkdir -p bin
CLEAN = rm -f src/agent/*.o src/common/*.o src/server/*.o bin/agent bin/server
endif

AGENT_OBJECTS = $(AGENT_SOURCES:.c=.o)
SERVER_OBJECTS = $(SERVER_SOURCES:.c=.o)

all: $(TARGET_AGENT) $(TARGET_SERVER)

$(TARGET_AGENT): $(AGENT_OBJECTS) | bin
	@echo "Linking $@"
	$(CC) $(CFLAGS) -o $@ $(AGENT_OBJECTS) $(AGENT_LDFLAGS)

$(TARGET_SERVER): $(SERVER_OBJECTS) | bin
	@echo "Linking $@"
	$(CC) $(CFLAGS) -o $@ $(SERVER_OBJECTS) $(SERVER_LDFLAGS)

bin:
	$(MKDIR_BIN)

%.o: %.c
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(CLEAN)

.PHONY: all clean
