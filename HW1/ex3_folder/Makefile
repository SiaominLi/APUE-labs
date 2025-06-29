CC = gcc
CFLAGS = -Wall -Wextra -shared -fPIC
LDFLAGS = -ldl
TARGET_LIB = libzpoline.so
SRC = zpoline_ex3.c

.PHONY: all clean

all: $(TARGET_LIB)

$(TARGET_LIB): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET_LIB) *.o