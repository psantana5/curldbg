CC := gcc
CFLAGS := -O2 -Wall -Wextra -pthread -Iinclude
LDLIBS := -pthread -lssl -lcrypto
TARGET := curldbg
SRCS := src/main.c src/curldbg.c
OBJS := $(SRCS:.c=.o)
MANPAGE := man/curldbg.1
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJS): include/curldbg.h

clean:
	rm -f $(TARGET) $(OBJS)

test: $(TARGET)
	@CURLDBG=$(CURDIR)/$(TARGET) sh tests/run.sh

install: $(TARGET) $(MANPAGE)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 644 $(MANPAGE) $(DESTDIR)$(MANDIR)/curldbg.1
