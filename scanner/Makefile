# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
         -Iinclude -Iinclude/common -Iinclude/server -Iinclude/agent

# External library paths (MSYS2 defaults)
JANSSON_INC = /mingw64/include
JANSSON_LIB = /mingw64/lib
SQLITE_INC = /mingw64/include
SQLITE_LIB = /mingw64/lib
OPENSSL_INC = /mingw64/include
OPENSSL_LIB = /mingw64/lib

# Include paths for external libraries
CFLAGS += -I$(JANSSON_INC) -I$(SQLITE_INC) -I$(OPENSSL_INC)

# Linker flags and paths
LDFLAGS = -L$(JANSSON_LIB) -L$(SQLITE_LIB) -L$(OPENSSL_LIB) \
          -lcrypto -lssl -lpthread -ljansson -lsqlite3

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

# Source files
AGENT_SOURCES = src/agent/main.c src/agent/scanner.c src/agent/transport.c
SERVER_SOURCES = src/server/main.c src/server/api.c src/server/storage.c
COMMON_SOURCES = src/common/crypto.c src/common/tls.c

# Object files
AGENT_OBJS = $(AGENT_SOURCES:.c=.o)
SERVER_OBJS = $(SERVER_SOURCES:.c=.o)
COMMON_OBJS = $(COMMON_SOURCES:.c=.o)

# Default target
all: | bindir $(TARGETS)

# Create the bin directory
bindir:
	@$(MKDIR)

# Build agent executable
bin/agent$(EXE_EXT): $(AGENT_OBJS) $(filter src/common/crypto.o, $(COMMON_OBJS))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Build server executable
bin/server$(EXE_EXT): $(SERVER_OBJS) $(filter-out src/agent/%, $(COMMON_OBJS))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	$(RM) $(AGENT_OBJS) $(SERVER_OBJS) $(COMMON_OBJS) $(TARGETS)

# Phony targets
.PHONY: all clean bindir