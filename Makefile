# Makefile for Apteryx
#
# Unit Tests (make test FILTER): e.g make test Performance
# Requires GLib. CUnit for Unit Testing. Lua for lua bindings.
# sudo apt-get install libglib2.0-dev libcunit1-dev liblua5.2-dev
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

CFLAGS := $(CFLAGS) -g -O2
EXTRA_CFLAGS += -Wall -Wno-comment -std=c99 -D_GNU_SOURCE -fPIC
EXTRA_CFLAGS += -I. $(shell $(PKG_CONFIG) --cflags glib-2.0)
EXTRA_LDFLAGS := $(shell $(PKG_CONFIG) --libs glib-2.0) -lpthread
ifneq ($(HAVE_TESTS),no)
EXTRA_CSRC += test.c
EXTRA_CFLAGS += -DTEST
EXTRA_LDFLAGS += -lcunit
endif

all: libapteryx.so apteryx

libapteryx.so: apteryx.o database.o callbacks.o config.o rpc.o rszshm.o
	@echo "Creating library "$@""
	$(Q)$(CC) -shared $(LDFLAGS) -o $@ $^ $(EXTRA_LDFLAGS)

%.o: %.c
	@echo "Compiling "$<""
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

apteryx: apteryxc.c database.o callbacks.o libapteryx.so $(EXTRA_CSRC)
	@echo "Building $@"
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ -L. -lapteryx $(EXTRA_LDFLAGS)

ifeq (test,$(firstword $(MAKECMDGOALS)))
TEST_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
$(eval $(TEST_ARGS):;@:)
endif

test: apteryx
	@echo "Running apteryx unit test: $<"
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./ $(TEST_WRAPPER) ./apteryx -u$(TEST_ARGS);
	@echo "Tests have been run!"

install: all
	@install -d $(DESTDIR)/$(PREFIX)/lib
	@install -D libapteryx.so $(DESTDIR)/$(PREFIX)/lib/
	@install -d $(DESTDIR)/$(PREFIX)/include
	@install -D apteryx.h $(DESTDIR)/$(PREFIX)/include
	@install -d $(DESTDIR)/$(PREFIX)/bin
	@install -D apteryx $(DESTDIR)/$(PREFIX)/bin/
	@install -d $(DESTDIR)/$(PREFIX)/lib/pkgconfig
	@install -D apteryx.pc $(DESTDIR)/$(PREFIX)/lib/pkgconfig/

clean:
	@echo "Cleaning..."
	@rm -f libapteryx.so apteryx *.o

.PHONY: all clean
