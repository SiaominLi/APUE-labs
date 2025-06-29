# CC = gcc
# CFLAGS = -Wall -Wextra -O2 -fPIC
# LDFLAGS = -L. -lgotoku
# SRC_LIB = libgotoku_dummy.c
# SRC_MAIN = gotoku.c
# OBJ_LIB = $(SRC_LIB:.c=.o)
# OBJ_MAIN = $(SRC_MAIN:.c=.o)
# SHARED_LIB = libgotoku.so
# EXECUTABLE = gotoku.local

# all: $(SHARED_LIB) $(EXECUTABLE)

# $(SHARED_LIB): $(SRC_LIB) libgotoku.h gops.c
# 	$(CC) $(CFLAGS) -shared -o $@ $(SRC_LIB)

# $(EXECUTABLE): $(SRC_MAIN) $(SHARED_LIB) gops.c
# 	$(CC) $(CFLAGS) -o $@ $(SRC_MAIN) $(LDFLAGS)

# clean:
# 	rm -f $(OBJ_LIB) $(OBJ_MAIN) $(SHARED_LIB) $(EXECUTABLE)
# ===================================================
# CC = gcc
# CFLAGS = -Wall -Wextra -fPIC -g
# LDFLAGS = -shared

# all: libsolver.so

# libsolver.so: libsolver.o
# 	$(CC) $(LDFLAGS) -o $@ $^

# libsolver.o: libsolver.c
# 	$(CC) $(CFLAGS) -c -o $@ $<

# clean:
# 	rm -f *.o libsolver.so
# ===================================================
CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
SRC = libsolver.c
SHARED = libsolver.so

all: $(SHARED)

$(SHARED): $(SRC)
	$(CC) $(CFLAGS) -shared -o $@ $^

clean:
	rm -f $(SHARED)
