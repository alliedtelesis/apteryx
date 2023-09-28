# Makefile for Apteryx
#
# Unit Tests (make test FILTER): e.g make test Performance
# Requires GLib and CUnit for Unit Testing.
# sudo apt-get install libglib2.0-dev libcunit1-dev liblua5.2-dev
#
# TEST_WRAPPER="G_SLICE=always-malloc valgrind --leak-check=full" make test
# TEST_WRAPPER="gdb" make test
#

ifneq ($(V),1)
	Q=@
endif

ifdef TESTS
TEST_ARGS=$(TESTS)
endif
ifdef TEST
TEST_ARGS=$(TEST)
endif

DESTDIR?=./
PREFIX?=/usr/
LIBDIR?=lib
ifeq (test,$(firstword $(MAKECMDGOALS)))
	BUILDDIR=.test
else
	BUILDDIR?=.
endif
CC:=$(CROSS_COMPILE)gcc
LD:=$(CROSS_COMPILE)ld
PKG_CONFIG ?= pkg-config

ABI_VERSION=4
CFLAGS := $(CFLAGS) -g -O2
EXTRA_CFLAGS += -Wall -Wno-comment -std=c99 -D_GNU_SOURCE -fPIC
EXTRA_CFLAGS += -I. $(shell $(PKG_CONFIG) --cflags glib-2.0)
EXTRA_LDFLAGS := -L$(BUILDDIR) $(shell $(PKG_CONFIG) --libs glib-2.0) -lpthread
ifneq ($(HAVE_LUA),no)
LUAVERSION := $(shell $(PKG_CONFIG) --exists lua5.3 && echo lua5.3 ||\
	($(PKG_CONFIG) --exists lua5.2 && echo lua5.2 ||\
	($(PKG_CONFIG) --exists lua && echo lua ||\
	echo none)))
ifneq ($(LUAVERSION),none)
EXTRA_CFLAGS += -DHAVE_LUA $(shell $(PKG_CONFIG) --cflags $(LUAVERSION))
EXTRA_LDFLAGS += $(shell $(PKG_CONFIG) --libs $(LUAVERSION)) -ldl
endif
endif
ifneq ($(HAVE_TESTS),no)
EXTRA_CSRC += test.c
apteryx_CFLAGS += -DTEST
apteryx_LDFLAGS += -lcunit
endif

all: $(BUILDDIR)/libapteryx.so $(BUILDDIR)/apteryx $(BUILDDIR)/apteryxd

$(BUILDDIR):
	@mkdir -p $@

$(BUILDDIR)/libapteryx.so.$(ABI_VERSION): $(BUILDDIR)/rpc.o $(BUILDDIR)/rpc_transport.o $(BUILDDIR)/rpc_socket.o $(BUILDDIR)/apteryx.o $(BUILDDIR)/lua.o
	@echo "Creating library "$@""
	$(Q)$(CC) -shared $(LDFLAGS) -o $@ $^ $(EXTRA_LDFLAGS) -Wl,-soname,$@

$(BUILDDIR)/libapteryx.so: $(BUILDDIR)/libapteryx.so.$(ABI_VERSION)
	@ln -s -f libapteryx.so.$(ABI_VERSION) $@
	@ln -s -f libapteryx.so $(BUILDDIR)/apteryx.so

$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
	@echo "Compiling "$<""
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

$(BUILDDIR)/apteryxd: apteryxd.c hashtree.c database.c $(BUILDDIR)/rpc_transport.o $(BUILDDIR)/rpc_socket.o $(BUILDDIR)/config.o $(BUILDDIR)/callbacks.o $(BUILDDIR)/libapteryx.so
	@echo "Building $@"
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ $(EXTRA_LDFLAGS)

$(BUILDDIR)/apteryx: apteryxc.c hashtree.c database.c callbacks.c $(BUILDDIR)/libapteryx.so $(EXTRA_CSRC)
	@echo "Building $@"
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(apteryx_CFLAGS) -o $@ $^ -lapteryx $(EXTRA_LDFLAGS) $(apteryx_LDFLAGS)

apteryxd = \
	if test -e /tmp/apteryxd.pid; then \
		kill -TERM `cat /tmp/apteryxd.pid` && sleep 0.1; \
	fi; \
	rm -f /tmp/apteryxd.pid; \
	rm -f /tmp/apteryxd.run; \
	export ASAN_OPTIONS=fast_unwind_on_malloc=true:halt_on_error=0:detect_stack_use_after_return=1:log_path=$(BUILDDIR)/asan-log; \
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(BUILDDIR)/; \
	export LUA_CPATH=$(BUILDDIR)/?.so; \
	$(BUILDDIR)/apteryxd -b -p /tmp/apteryxd.pid -r /tmp/apteryxd.run && sleep 0.1; \
	$(TEST_WRAPPER) $(BUILDDIR)/$(1); \
	APID=`cat /tmp/apteryxd.pid`; \
	kill -TERM $$APID; \
	while kill -0 $$APID 2> /dev/null; do sleep 1; done;

unit: $(BUILDDIR)/apteryxd $(BUILDDIR)/apteryx
	@echo "Running apteryx unit test: $<"
	$(Q)$(call apteryxd,apteryx -u"$(TEST_ARGS)")
	@echo "Tests have been run!"

test: EXTRA_CFLAGS += -fprofile-arcs -ftest-coverage -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer
test: EXTRA_LDFLAGS += -fprofile-arcs -ftest-coverage -fsanitize=address -static-libasan
test: $(BUILDDIR)/apteryxd $(BUILDDIR)/apteryx
	@echo "Running apteryx unit tests with gcov and address sanitizer: $<"
	@rm -f $(BUILDDIR)/asan-log.*
	@rm -f $(BUILDDIR)/*.gcda
	$(Q)$(call apteryxd,apteryx -u"$(TEST_ARGS)")
	@echo "Tests have been run!"
	@echo "Processing gcov output"
	@lcov -q --capture --directory $(BUILDDIR)/ --output-file $(BUILDDIR)/coverage.info
	@genhtml -q $(BUILDDIR)/coverage.info --output-directory $(BUILDDIR)/gcov
	@echo "GCOV: google-chrome "$(BUILDDIR)"/gcov/index.html"
	@cat $(BUILDDIR)/asan-log.* 2>/dev/null | grep -v "False leaks are possible" | grep --color -E "ERROR|Direct leak|SUMMARY|$$" && exit 1 || true

install: all
	@install -d $(DESTDIR)/$(PREFIX)/$(LIBDIR)
	@install -D $(BUILDDIR)/libapteryx.so.$(ABI_VERSION) $(DESTDIR)/$(PREFIX)/$(LIBDIR)/
	@ln -sf libapteryx.so.$(ABI_VERSION) $(DESTDIR)/$(PREFIX)/$(LIBDIR)/libapteryx.so
	@install -d $(DESTDIR)/$(PREFIX)/include
	@install -D apteryx.h $(DESTDIR)/$(PREFIX)/include
	@install -d $(DESTDIR)/$(PREFIX)/bin
	@install -D $(BUILDDIR)/apteryxd $(DESTDIR)/$(PREFIX)/bin/
	@install -D $(BUILDDIR)/apteryx $(DESTDIR)/$(PREFIX)/bin/
	@install -d $(DESTDIR)/$(PREFIX)/lib/pkgconfig
	@install -D apteryx.pc $(DESTDIR)/$(PREFIX)/lib/pkgconfig/

clean:
	@echo "Cleaning..."
	@rm -fr libapteryx.so* apteryx.so apteryx apteryxd *.o .test

.PHONY: all clean
