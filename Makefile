# Compiler and flags
CC = gcc
CXX = g++
CFLAGS = -g -Wall -Wextra -std=c11 -Wno-deprecated-declarations
CXXFLAGS = -g -Wall -Wextra -std=c++20 -Wno-deprecated-declarations
INCLUDES = -Iheaders $(shell pkg-config --cflags openssl 2>/dev/null) $(shell pkg-config --cflags gmp 2>/dev/null)

# (#1) Duplicate library uyarısı giderildi — sadece pkg-config çıktısı kullanılıyor
LDFLAGS = $(shell pkg-config --libs openssl 2>/dev/null) $(shell pkg-config --libs gmp 2>/dev/null) -lgmpxx -lpthread

# Platform detection: macOS does not support -static
UNAME_S := $(shell uname -s)
ifneq ($(UNAME_S),Darwin)
  SFLAG = -static
else
  SFLAG =
endif

# Directories
SRC_DIR = src
BUILD_DIR = build

# Source and object files
SRC_C_SERVER = $(SRC_DIR)/TCPServer.c $(SRC_DIR)/socketutil.c $(SRC_DIR)/database.c $(SRC_DIR)/strtohex.c $(SRC_DIR)/serverkey.c
SRC_CXX_SERVER = $(SRC_DIR)/cryp2.cpp
SRC_C_CLIENT = $(SRC_DIR)/TCPClient.c $(SRC_DIR)/socketutil.c $(SRC_DIR)/strtohex.c $(SRC_DIR)/clientkey.c
SRC_CXX_CLIENT = $(SRC_DIR)/cryp2.cpp

OBJ_C_SERVER = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_C_SERVER))
OBJ_CXX_SERVER = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRC_CXX_SERVER))
OBJ_SERVER = $(OBJ_C_SERVER) $(OBJ_CXX_SERVER)

OBJ_C_CLIENT = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_C_CLIENT))
OBJ_CXX_CLIENT = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRC_CXX_CLIENT))
OBJ_CLIENT = $(OBJ_C_CLIENT) $(OBJ_CXX_CLIENT)

# (#2) .PHONY tanımları eklendi
.PHONY: all clean dirs

# (#3) server ve client artık dirs'e bağımlı — build dizini garanti
all: dirs server client

dirs:
	mkdir -p $(BUILD_DIR)

server: dirs $(OBJ_SERVER)
	$(CXX) $(CXXFLAGS) $(OBJ_SERVER) -o server $(LDFLAGS) $(SFLAG)

client: dirs $(OBJ_CLIENT)
	$(CXX) $(CXXFLAGS) $(OBJ_CLIENT) -o client $(LDFLAGS) $(SFLAG)

# .c files → C compiler, .cpp files → C++ compiler
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) server client
