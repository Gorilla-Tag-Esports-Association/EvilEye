CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -Isrc/headers -DWIN32_LEAN_AND_MEAN

SRC_DIR = HOST/src
OBJ_DIR = obj
BIN_DIR = bin
BIN = $(BIN_DIR)/EvilEye.exe

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

LDFLAGS = -lws2_32 -lssl -lcrypto -lopenxr_loader -ljsoncpp

all: $(BIN)

$(BIN): $(OBJS) | $(BIN_DIR)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)