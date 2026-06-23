CC := gcc
OPT ?= -O2
CFLAGS := $(OPT) -Wall -Wextra -pthread -Iinclude
LDLIBS := -pthread -lssl -lcrypto -lz
TARGET := curldbg
OBJDIR := obj
SRCS := src/main.c src/util.c src/url.c src/dns.c src/tls.c src/connect.c src/http.c src/proxy.c src/cookie.c
OBJS := $(SRCS:src/%.c=$(OBJDIR)/%.o)
MANPAGE := man/curldbg.1
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1

.PHONY: all clean install test static

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -s $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR)/%.o: src/%.c include/curldbg.h | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(TARGET) $(OBJDIR)

test: $(TARGET)
	@CURLDBG=$(CURDIR)/$(TARGET) sh tests/flags.sh

static: CFLAGS += -no-pie
static: LDLIBS = -pthread /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a
static: $(OBJS)
	$(CC) $(CFLAGS) -s -static-libgcc -o $(TARGET)-static $(OBJS) $(LDLIBS)
	@echo "Built $(TARGET)-static (statically linked)"

install: $(TARGET) $(MANPAGE)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 644 $(MANPAGE) $(DESTDIR)$(MANDIR)/curldbg.1
