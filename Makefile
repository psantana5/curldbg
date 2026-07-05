CC := gcc
OPT ?= -O2
CFLAGS := $(OPT) -Wall -Wextra -pthread -Iinclude
LDLIBS := -pthread -lssl -lcrypto -lz
TARGET := curldbg
OBJDIR := obj
SRCS := src/main.c src/request.c src/results.c src/util.c src/url.c src/dns.c src/tls.c src/connect.c src/http.c src/proxy.c src/cookie.c src/cli.c src/output.c
OBJS := $(SRCS:src/%.c=$(OBJDIR)/%.o)
UNIT_OBJS := $(filter-out $(OBJDIR)/main.o,$(OBJS))
MANPAGE := man/curldbg.1
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1

.PHONY: all clean install test static

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -s $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR)/%.o: src/%.c include/curldbg.h include/flags.h | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(TARGET) $(OBJDIR)

test: $(UNIT_OBJS)
	$(CC) -g -O0 -Wall -Wextra -Werror -pthread -Iinclude \
		-o $(OBJDIR)/unit_test tests/unit.c $(UNIT_OBJS) $(LDLIBS)
	@valgrind --leak-check=full --error-exitcode=1 -q $(OBJDIR)/unit_test
	@rm -f $(OBJDIR)/unit_test

static: CFLAGS += -no-pie
static: LDLIBS = -pthread /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a
static: $(OBJS)
	$(CC) $(CFLAGS) -s -static-libgcc -o $(TARGET)-static $(OBJS) $(LDLIBS)
	@echo "Built $(TARGET)-static (statically linked)"

install: $(TARGET) $(MANPAGE)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 644 $(MANPAGE) $(DESTDIR)$(MANDIR)/curldbg.1
