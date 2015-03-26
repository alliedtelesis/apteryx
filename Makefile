# Makefile for Apteryx
#
# Unit Tests (make test):
# Requires GLib and CUnit for Unit Testing.
# sudo apt-get install libglib2.0-dev libcunit1-dev libprotobuf-c0-dev protobuf-c-compiler liblua5.2-dev
#
# TEST_WRAPPER="G_SLICE=always-malloc valgrind --leak-check=full" make test
# TEST_WRAPPER="gdb" make test
#
DESTDIR?=./
PREFIX?=/usr/
CC:=$(CROSS_COMPILE)gcc
LD:=$(CROSS_COMPILE)ld
PKG_CONFIG ?= pkg-config
PROTOC_C ?= protoc-c

CFLAGS := $(CFLAGS) -g -O2
EXTRA_CFLAGS += -Wall -Wno-comment -std=c99 -D_GNU_SOURCE -fPIC
EXTRA_CFLAGS += -I. -I/usr/include/google `$(PKG_CONFIG) --cflags glib-2.0`
EXTRA_LDFLAGS := `$(PKG_CONFIG) --libs glib-2.0` -lpthread
EXTRA_LDFLAGS += -lprotobuf-c
ifneq ($(HAVE_LUA),no)
EXTRA_CFLAGS += -DHAVE_LUA `$(PKG_CONFIG) --cflags lua5.2`
EXTRA_LDFLAGS += `$(PKG_CONFIG) --libs lua5.2`
endif
ifneq ($(USE_SHM_CACHE),no)
EXTRA_CFLAGS += -DUSE_SHM_CACHE
endif

all: libapteryx.so apteryx apteryxd

libapteryx.so: rpc.o apteryx.pb-c.o apteryx.o cache.o lua.o
	@echo "Creating library "$@""
	@$(CC) -shared $(LDFLAGS) -o $@ $^ $(EXTRA_LDFLAGS)

%.o: %.c
	@echo "Compiling "$<""
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

%.pb-c.c : %.proto
	@$(PROTOC_C) --c_out=. $<

apteryxd: apteryxd.c apteryx.pb-c.c database.c rpc.c cache.o
	@echo "Building $@"
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ $(EXTRA_LDFLAGS)

apteryx: apteryxc.c libapteryx.so
	@echo "Building $@"
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $< -L. -lapteryx $(EXTRA_LDFLAGS)

apteryxd = \
	if test -e /tmp/apteryxd.pid; then \
		kill -TERM `cat /tmp/apteryxd.pid` && sleep 0.1; \
	fi; \
	rm -f /tmp/apteryxd.pid; \
	LD_LIBRARY_PATH=./ ./apteryxd -b -p /tmp/apteryxd.pid && sleep 0.1; \
	LD_LIBRARY_PATH=./ $(TEST_WRAPPER) ./$(1); \
	kill -TERM `cat /tmp/apteryxd.pid`;

test_apteryx: all test.c database.c
	@echo "Building Unit tests"
	@$(CC) $(CFLAGS) -DTEST $(EXTRA_CFLAGS) -o $@ test.c database.c -lcunit -L. -lapteryx $(EXTRA_LDFLAGS)

test: test_apteryx
	@echo "Running unit test: $<"
	@$(call apteryxd,$<)

install-test: test_apteryx
	@install -D $< $(DESTDIR)/$(PREFIX)/bin/$<

install: all
	@install -d $(DESTDIR)/$(PREFIX)/lib
	@install -D libapteryx.so $(DESTDIR)/$(PREFIX)/lib/
	@install -d $(DESTDIR)/$(PREFIX)/include
	@install -D apteryx.h $(DESTDIR)/$(PREFIX)/include
	@install -d $(DESTDIR)/$(PREFIX)/bin
	@install -D apteryxd $(DESTDIR)/$(PREFIX)/bin/
	@install -D apteryx $(DESTDIR)/$(PREFIX)/bin/
	@install -d $(DESTDIR)/etc/apteryx/schema
	@install -D -m 0644 apteryx.xsd $(DESTDIR)/etc/apteryx/schema/

clean:
	@echo "Cleaning..."
	@rm -f libapteryx.so apteryx apteryxd test_apteryx *.o *.pb-c.c *.pb-c.h

.PHONY: all clean
