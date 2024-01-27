LUA ?= lua5.1
LUA_PC ?= lua5.1
LUA_CFLAGS = $(shell pkg-config $(LUA_PC) --cflags)

CFLAGS ?= -O3

all: elfmap.so

%.o: %.c
	$(CC) -c -g $(CFLAGS) -fPIC $(LUA_CFLAGS) -o $@ $<

elfmap.so: elfmap.o
	$(CC) -shared elfmap.o -o $@

clean:
	rm -f *.so *.o *.rock