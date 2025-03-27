# Compiler and flags
CC = cc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
         -Iinclude -Iinclude/common -Iinclude/server -Iinclude/agent

# External library paths
JANSSON_INC ?= /mingw64/include
JANSSON_LIB ?= /mingw64/lib
SQLITE_INC ?= /mingw64/include
SQLITE_LIB ?= /mingw64/lib

# Update CFLAGS with external library include paths
CFLAGS += -I$(JANSSON_INC) -I$(SQLITE_INC)

# Linker flags
LDFLAGS = -lcrypto -lssl -lpthread -ljansson -lsqlite3

# Windows-specific settings
ifeq ($(OS),Windows_NT)
    CFLAGS += -D_WIN32_WINNT=0x0600 -DWINDOWS
    LDFLAGS += -liphlpapi -lws2_32
    RM = rm -f
    EXE_EXT = .exe
    MKDIR = mkdir -p bin
else
    CFLAGS += -DLINUX
    LDFLAGS += -Wl,-z,now,-z,relro
    EXE_EXT =
    RM = rm -f
    MKDIR = mkdir -p bin
endif

# Targets
TARGETS = bin/agent$(EXE_EXT) bin/server$(EXE_EXT)

# Default target
all: | bindir $(TARGETS)

# Create the bin directory
bindir:
	$(MKDIR)

# Build agent executable
bin/agent$(EXE_EXT): src/agent/main.o src/agent/scanner.o src/agent/transport.o src/common/crypto.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Build server executable
bin/server$(EXE_EXT): src/server/main.o src/server/api.o src/server/storage.o src/common/crypto.o src/common/tls.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	$(RM) src/agent/*.o src/server/*.o src/common/*.o $(TARGETS)

.PHONY: all clean bindir