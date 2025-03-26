CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -Wl,-z,now,-z,relro -lcrypto -lssl -lpthread
TARGETS = bin/agent bin/server

all: $(TARGETS)

bin/agent: src/agent/main.o src/agent/scanner.o src/agent/transport.o src/common/crypto.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

bin/server: src/server/main.o src/server/storage.o src/common/crypto.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*/*.o $(TARGETS)

.PHONY: all clean