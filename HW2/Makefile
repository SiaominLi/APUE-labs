CC = gcc
CFLAGS = -Wall -Wextra -g -std=c11 # Or -std=c99 if you prefer
LDFLAGS = -lcapstone
TARGET = sdb
SRC = sdb_hidden.c

# Default target
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean