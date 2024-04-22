LUA_VERSION ?= $(shell lua -e "print(string.match(_VERSION, '%d+%.%d+'))")
LUA ?= lua$(LUA_VERSION)
LUA_PC ?= lua$(LUA_VERSION)
LUA_CFLAGS = $(shell pkg-config $(LUA_PC) --cflags)

PREFIX ?= /usr/local
LUA_LIB_DIR = $(PREFIX)/lib/lua/$(LUA_VERSION)
TARGET_LIB = elfmap.so

CFLAGS ?= -O3

all: $(TARGET_LIB)

%.o: %.c
	$(CC) -c -g $(CFLAGS) -fPIC $(LUA_CFLAGS) -o $@ $<

elfmap.so: elfmap.o
	$(CC) -shared elfmap.o -o $@ -lelf

install: $(TARGET_LIB)
	# 创建目标目录（如果不存在）
	mkdir -p $(LUA_LIB_DIR)
	# 复制动态库文件到Lua的库目录
	cp $(TARGET_LIB) $(LUA_LIB_DIR)

uninstall:
	# 删除动态库文件
	rm -f $(LUA_LIB_DIR)/$(TARGET_LIB)

clean:
	rm -f *.so *.o *.rock