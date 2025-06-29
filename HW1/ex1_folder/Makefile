# Make ex1 trampoline
CC = gcc
CFLAGS = -Wall -Wextra -fPIC -O2
LDFLAGS = -shared -ldl
TARGET = libzpoline.so.1
SRC = trampoline.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

# CC = gcc
# CFLAGS = -shared -fPIC -Wall
# LDFLAGS = -ldl
# TARGETS = libzpoline.so logger.so

# all: $(TARGETS)

# libzpoline.so: libzpoline_2.c
# 	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# logger.so: logger.c
# 	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# clean:
# 	rm -f $(TARGETS)

# CC = gcc
# CFLAGS = -shared -fPIC -Wall
# LDFLAGS = -ldl
# TARGETS = libzpoline.so

# all: $(TARGETS)

# libzpoline.so: libzpoline_2.c
# 	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# clean:
# 	rm -f $(TARGETS)