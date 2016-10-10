# Makefile for Apteryx
#
# Unit Tests (make test FILTER): e.g make test Performance
# Requires GLib and CUnit for Unit Testing.
# sudo apt-get install libglib2.0-dev libcunit1-dev libprotobuf-c0-dev protobuf-c-compiler liblua5.2-dev
#
# TEST_WRAPPER="G_SLICE=always-malloc valgrind --leak-check=full" make test
# TEST_WRAPPER="gdb" make test
#

ifneq ($(V),1)
	Q=@
endif

DESTDIR?=./
PREFIX?=/usr/
CC:=$(CROSS_COMPILE)gcc
LD:=$(CROSS_COMPILE)ld
PKG_CONFIG ?= pkg-config
PROTOC_C ?= protoc-c

CFLAGS := $(CFLAGS) -g -O2
EXTRA_CFLAGS += -Wall -Wno-comment -std=c99 -D_GNU_SOURCE -fPIC
EXTRA_CFLAGS += -I. -I/usr/include/google $(shell $(PKG_CONFIG) --cflags glib-2.0)
EXTRA_LDFLAGS := $(shell $(PKG_CONFIG) --libs glib-2.0) -lpthread
EXTRA_LDFLAGS += -lrt -lprotobuf-c -lgcc_s
ifneq ($(HAVE_LUA),no)
LUAVERSION := $(shell $(PKG_CONFIG) --exists lua && echo lua || ($(PKG_CONFIG) --exists lua5.2 && echo lua5.2 || echo none))
ifneq ($(LUAVERSION),none)
EXTRA_CFLAGS += -DHAVE_LUA $(shell $(PKG_CONFIG) --cflags $(LUAVERSION))
EXTRA_LDFLAGS += $(shell $(PKG_CONFIG) --libs $(LUAVERSION)) -ldl
endif
endif
ifneq ($(HAVE_XML2),no)
EXTRA_CFLAGS += -DHAVE_LIBXML2 $(shell $(PKG_CONFIG) --cflags libxml-2.0)
EXTRA_LDFLAGS += $(shell $(PKG_CONFIG) --libs libxml-2.0)
endif
ifneq ($(HAVE_TESTS),no)
EXTRA_CSRC += test.c
EXTRA_CFLAGS += -DTEST
EXTRA_LDFLAGS += -lcunit
endif

all: libapteryx.so apteryx apteryxd apteryx-sync alfred

libapteryx.so: apteryx.pb-c.o rpc.o rpc_transport.o rpc_socket.o apteryx.o schema.o lua.o
	@echo "Creating library "$@""
	$(Q)$(CC) -shared $(LDFLAGS) -o $@ $^ $(EXTRA_LDFLAGS)
	@ln -s -f $@ apteryx.so

%.o: %.c
	@echo "Compiling "$<""
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

%.pb-c.c : %.proto
	$(Q)$(PROTOC_C) --c_out=. $<

apteryxd: apteryxd.c apteryx.pb-c.c database.c rpc.o rpc_transport.o rpc_socket.o config.o callbacks.o
	@echo "Building $@"
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ $(EXTRA_LDFLAGS)

apteryx: apteryxc.c database.c callbacks.c libapteryx.so $(EXTRA_CSRC)
	@echo "Building $@"
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -L. -lapteryx $(EXTRA_LDFLAGS)

apteryx-sync: syncer.c libapteryx.so
	@echo "Building $@"
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $< -L. -lapteryx $(EXTRA_LDFLAGS)

alfred: alfred.c callbacks.c libapteryx.so
	@echo "Building $@"
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -L. -lapteryx $(EXTRA_LDFLAGS)

apteryxd = \
	if test -e /tmp/apteryxd.pid; then \
		kill -TERM `cat /tmp/apteryxd.pid` && sleep 0.1; \
	fi; \
	rm -f /tmp/apteryxd.pid; \
	rm -f /tmp/apteryxd.run; \
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./ ./apteryxd -b -p /tmp/apteryxd.pid -r /tmp/apteryxd.run && sleep 0.1; \
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./ $(TEST_WRAPPER) ./$(1); \
	kill -TERM `cat /tmp/apteryxd.pid`;

ifeq (test,$(firstword $(MAKECMDGOALS)))
TEST_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
$(eval $(TEST_ARGS):;@:)
endif

test_apteryx: apteryxd apteryx
	@echo "Running apteryx unit test: $<"
	$(Q)$(call apteryxd,apteryx -u$(TEST_ARGS))

test_alfred: apteryxd alfred
	@echo "Running apteryx unit test: $<"
	$(Q)$(call apteryxd,alfred -u$(TEST_ARGS))

test: test_alfred test_apteryx
	@echo "Tests have been run!"

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
	@install -d $(DESTDIR)/$(PREFIX)/lib/pkgconfig
	@install -D apteryx.pc $(DESTDIR)/$(PREFIX)/lib/pkgconfig/
	@install -D apteryx-sync $(DESTDIR)/$(PREFIX)/bin/
	@install -D alfred $(DESTDIR)/$(PREFIX)/bin/

clean:
	@echo "Cleaning..."
	@rm -f libapteryx.so apteryx.so apteryx apteryxd apteryx-sync alfred *.o *.pb-c.c *.pb-c.h

.PHONY: all clean
