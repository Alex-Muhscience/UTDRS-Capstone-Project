CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
         -D__USE_MINGW_ANSI_STDIO=1 \
         -Iinclude -Iinclude/common -Iinclude/server -Iinclude/agent \
         -I"C:\Program Files\OpenSSL-Win64\include" \
         -ID:/mongo-install/include/libmongoc-1.0 -ID:/mongo-install/include/libbson-1.0 \
         -ID:/jansson-install/include

LDFLAGS = -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" \
          -LD:/mongo-install/lib -LD:/jansson-install/lib -lws2_32 -liphlpapi -lssl -lcrypto

TARGET_AGENT = bin/agent.exe
TARGET_SERVER = bin/server.exe

AGENT_SOURCES = src/agent/main.c src/agent/scanner.c src/agent/transport.c src/agent/auth.c \
                src/common/crypto.c src/common/logging.c src/common/utils.c
SERVER_SOURCES = src/server/main.c src/server/api.c src/server/storage.c \
                 src/common/crypto.c src/common/logging.c src/common/utils.c

AGENT_OBJECTS = $(AGENT_SOURCES:.c=.o)
SERVER_OBJECTS = $(SERVER_SOURCES:.c=.o)

all: $(TARGET_AGENT) $(TARGET_SERVER)

$(TARGET_AGENT): $(AGENT_OBJECTS) | bin
	@echo "Linking $@"
	$(CC) $(CFLAGS) -o $@ $(AGENT_OBJECTS) $(LDFLAGS)

$(TARGET_SERVER): $(SERVER_OBJECTS) | bin
	@echo "Linking $@"
	$(CC) $(CFLAGS) -o $@ $(SERVER_OBJECTS) $(LDFLAGS) -lmongoc-1.0 -lbson-1.0 -ljansson

bin:
	if not exist bin mkdir bin

%.o: %.c
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	if exist src\agent\*.o del /q src\agent\*.o
	if exist src\common\*.o del /q src\common\*.o
	if exist src\server\*.o del /q src\server\*.o
	if exist bin\agent.exe del /q bin\agent.exe
	if exist bin\server.exe del /q bin\server.exe

.PHONY: all clean
