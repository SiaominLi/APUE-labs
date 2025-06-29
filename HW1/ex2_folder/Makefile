# Makefile
TARGET_LIB = libzpoline.so.2
SRCS = zpoline_ex2.c
CC = gcc
CFLAGS = -shared -fPIC -g 
LDFLAGS = -ldl 

all: $(TARGET_LIB)
$(TARGET_LIB): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)
clean:
	rm -f $(TARGET_LIB) *.o # Also remove any .o files if you have separate compilation steps later

.PHONY: all clean