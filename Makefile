# n0cryp2 — TLS 1.3 + E2E Encrypted Chat
CC = gcc
CFLAGS = -g -Wall -Wextra -std=c11 -Wno-deprecated-declarations
INCLUDES = -Iheaders $(shell pkg-config --cflags openssl 2>/dev/null)
LDFLAGS = $(shell pkg-config --libs openssl 2>/dev/null) -lpthread

# Platform detection
UNAME_S := $(shell uname -s)
ifneq ($(UNAME_S),Darwin)
  SFLAG = -static
else
  SFLAG =
endif

SRC_DIR = src
BUILD_DIR = build

# Shared sources (used by both server and client)
SHARED_SRC = $(SRC_DIR)/socketutil.c $(SRC_DIR)/strtohex.c \
             $(SRC_DIR)/protocol.c $(SRC_DIR)/tls_utils.c $(SRC_DIR)/e2e_crypto.c

# Server sources
SERVER_SRC = $(SRC_DIR)/TCPServer.c $(SRC_DIR)/database.c $(SHARED_SRC)
SERVER_OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SERVER_SRC))

# Client sources
CLIENT_SRC = $(SRC_DIR)/TCPClient.c $(SHARED_SRC)
CLIENT_OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(CLIENT_SRC))

.PHONY: all clean dirs certs

all: dirs server client

dirs:
	mkdir -p $(BUILD_DIR)

server: dirs $(SERVER_OBJ)
	$(CC) $(CFLAGS) $(SERVER_OBJ) -o server $(LDFLAGS) $(SFLAG)
	@echo "✅ Server built."

client: dirs $(CLIENT_OBJ)
	$(CC) $(CFLAGS) $(CLIENT_OBJ) -o client $(LDFLAGS) $(SFLAG)
	@echo "✅ Client built."

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

certs:
	@mkdir -p server-key
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout server-key/server.key -out server-key/server.crt \
		-days 365 -nodes -subj "/CN=n0cryp2"
	@echo "✅ TLS certificates generated in server-key/"

clean:
	rm -rf $(BUILD_DIR) server client
