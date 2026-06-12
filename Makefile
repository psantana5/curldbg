CC := gcc
CFLAGS := -O2 -Wall -Wextra -pthread -Iinclude
LDLIBS := -pthread -lssl -lcrypto
TARGET := curldbg
OBJDIR := obj
SRCS := src/main.c src/util.c src/url.c src/dns.c src/tls.c src/connect.c src/http.c src/proxy.c src/cookie.c
OBJS := $(SRCS:src/%.c=$(OBJDIR)/%.o)
MANPAGE := man/curldbg.1
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR)/%.o: src/%.c include/curldbg.h | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(TARGET) $(OBJDIR)

test: $(TARGET)
	@CURLDBG=$(CURDIR)/$(TARGET) sh tests/flags.sh

install: $(TARGET) $(MANPAGE)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 644 $(MANPAGE) $(DESTDIR)$(MANDIR)/curldbg.1
