# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
         -Iinclude -Iinclude/common -Iinclude/server -Iinclude/agent

# Hardcoded library paths and flags
JANSSON_CFLAGS = -I/mingw64/include
JANSSON_LIBS = -L/mingw64/lib -ljansson
SQLITE_CFLAGS = -I/mingw64/include
SQLITE_LIBS = -L/mingw64/lib -lsqlite3
OPENSSL_CFLAGS = -I/mingw64/include
OPENSSL_LIBS = -L/mingw64/lib -lcrypto -lssl
MONGOC_CFLAGS = -I/mingw64/include/libmongoc-1.0 -I/mingw64/include/libbson-1.0
MONGOC_LIBS = -L/mingw64/lib -lmongoc-1.0 -lbson-1.0

CFLAGS += $(JANSSON_CFLAGS) $(SQLITE_CFLAGS) $(OPENSSL_CFLAGS) $(MONGOC_CFLAGS)

# Windows-specific settings
ifeq ($(OS),Windows_NT)
    CFLAGS += -D_WIN32_WINNT=0x0600 -DWINDOWS
    AGENT_LIBS = $(OPENSSL_LIBS) -lpthread $(JANSSON_LIBS) $(SQLITE_LIBS) -liphlpapi -lws2_32
    SERVER_LIBS = $(OPENSSL_LIBS) -lpthread $(JANSSON_LIBS) $(SQLITE_LIBS) $(MONGOC_LIBS) -liphlpapi -lws2_32
    RM = rm -f
    EXE_EXT = .exe
    MKDIR = mkdir -p bin
else
    CFLAGS += -DLINUX
    LDFLAGS += -Wl,-z,now,-z,relro
    AGENT_LIBS = $(OPENSSL_LIBS) -lpthread $(JANSSON_LIBS) $(SQLITE_LIBS)
    SERVER_LIBS = $(OPENSSL_LIBS) -lpthread $(JANSSON_LIBS) $(SQLITE_LIBS) $(MONGOC_LIBS)
    EXE_EXT =
    RM = rm -f
    MKDIR = mkdir -p bin
endif

# Targets
TARGETS = bin/agent$(EXE_EXT) bin/server$(EXE_EXT)

# Source files
AGENT_SOURCES = $(wildcard src/agent/*.c)
SERVER_SOURCES = $(wildcard src/server/*.c)
COMMON_SOURCES = $(wildcard src/common/*.c)

# Object files
AGENT_OBJS = $(AGENT_SOURCES:.c=.o)
SERVER_OBJS = $(SERVER_SOURCES:.c=.o)
COMMON_OBJS = $(COMMON_SOURCES:.c=.o)

# Default target
all: | bindir $(TARGETS)

# Create the bin directory
bindir:
	@$(MKDIR)

# Build agent executable (without MongoDB)
bin/agent$(EXE_EXT): $(AGENT_OBJS) $(filter src/common/crypto.o, $(COMMON_OBJS))
	$(CC) $(CFLAGS) $^ -o $@ $(AGENT_LIBS)

# Build server executable (with MongoDB)
bin/server$(EXE_EXT): $(SERVER_OBJS) $(filter-out src/agent/%, $(COMMON_OBJS))
	$(CC) $(CFLAGS) $^ -o $@ $(SERVER_LIBS)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	$(RM) $(AGENT_OBJS) $(SERVER_OBJS) $(COMMON_OBJS) $(TARGETS)

# Distclean target to remove all generated files
distclean: clean
	$(RM) -r bin

# Phony targets
.PHONY: all clean bindir distclean