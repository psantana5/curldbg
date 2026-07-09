CC := gcc
OPT ?= -O2
CFLAGS := $(OPT) -Wall -Wextra -pthread -Iinclude
LDLIBS := -pthread -lssl -lcrypto -lz
TARGET := curldbg
OBJDIR := obj
SAN_OBJDIR := obj-san
SRCS := src/main.c src/run.c src/results.c src/util.c src/url.c \
        src/net/dns.c src/net/tls.c src/net/connect.c src/net/proxy.c \
        src/http/request.c src/http/response.c \
        src/cookie.c src/cli/parse.c src/cli/help.c src/output.c src/compare.c
OBJS := $(SRCS:src/%.c=$(OBJDIR)/%.o)
UNIT_OBJS := $(filter-out $(OBJDIR)/main.o,$(OBJS))
SAN_OBJS := $(SRCS:src/%.c=$(SAN_OBJDIR)/%.o)
SAN_UNIT_OBJS := $(filter-out $(SAN_OBJDIR)/main.o,$(SAN_OBJS))
MANPAGE := man/curldbg.1
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
TESTD_SRCS := tests/server/testd.c tests/server/route.c tests/server/handlers.c
SAN_CFLAGS := -g -O0 -fsanitize=address,undefined -Wall -Wextra -Werror -pthread -Iinclude

.PHONY: all clean install test test-san static fuzz

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR)/%.o: src/%.c include/curldbg.h include/flags.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(SAN_OBJDIR)/%.o: src/%.c include/curldbg.h include/flags.h
	@mkdir -p $(dir $@)
	$(CC) $(SAN_CFLAGS) -c -o $@ $<

$(SAN_OBJDIR)/curldbg: $(SAN_OBJS)
	$(CC) $(SAN_CFLAGS) -o $@ $^ $(LDLIBS)

$(SAN_OBJDIR)/testd: $(TESTD_SRCS)
	@mkdir -p $(SAN_OBJDIR)
	$(CC) $(SAN_CFLAGS) -Wno-unused-result -o $@ $^

$(SAN_OBJDIR)/unit_test: $(SAN_UNIT_OBJS) tests/unit.c
	$(CC) $(SAN_CFLAGS) -o $@ tests/unit.c $(SAN_UNIT_OBJS) $(LDLIBS)

clean:
	rm -rf $(TARGET) $(OBJDIR) $(SAN_OBJDIR)

test: $(TARGET)
	$(CC) -g -O0 -Wall -Wextra -Werror -pthread -Iinclude \
		-o $(OBJDIR)/unit_test tests/unit.c $(UNIT_OBJS) $(LDLIBS)
	@valgrind --leak-check=full --error-exitcode=1 -q $(OBJDIR)/unit_test
	@rm -f $(OBJDIR)/unit_test
	$(CC) -O2 -Wall -Wextra -Wno-unused-result -Iinclude \
		-o $(OBJDIR)/testd $(TESTD_SRCS)
	@tests/integration/run.sh $(OBJDIR)/testd ./$(TARGET)
	@if command -v clang >/dev/null 2>&1; then \
		echo "=== fuzz: parse_response_headers (30s) ==="; \
		$(MAKE) fuzz; \
		./$(TARGET)-fuzz -max_total_time=30; \
		FUZZ_RC=$$?; \
		rm -f $(TARGET)-fuzz; \
		exit $$FUZZ_RC; \
	else \
		echo "=== fuzz: skipped (clang not found) ==="; \
	fi

test-san: $(SAN_OBJDIR)/unit_test $(SAN_OBJDIR)/testd $(SAN_OBJDIR)/curldbg
	@echo "--- unit tests (ASan/UBSan) ---"
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	./$(SAN_OBJDIR)/unit_test
	@echo "--- integration tests (ASan/UBSan) ---"
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	tests/integration/run.sh $(SAN_OBJDIR)/testd $(SAN_OBJDIR)/curldbg
	@echo "=== test-san: all passed ==="

static: CFLAGS += -no-pie
static: LDLIBS = -pthread /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a
static: $(OBJS)
	$(CC) $(CFLAGS) -s -static-libgcc -o $(TARGET)-static $(OBJS) $(LDLIBS)
	@echo "Built $(TARGET)-static (statically linked)"

install: $(TARGET) $(MANPAGE)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 644 $(MANPAGE) $(DESTDIR)$(MANDIR)/curldbg.1

fuzz: FUZZ_CC := clang
fuzz: FUZZ_CFLAGS := -g -O1 -fsanitize=fuzzer,address -Iinclude
fuzz: FUZZ_LIBS := -lz -lssl -lcrypto
fuzz:
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c -o $(OBJDIR)/fuzz_response.o src/http/response.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c -o $(OBJDIR)/fuzz_util.o src/util.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $(TARGET)-fuzz $(OBJDIR)/fuzz_response.o $(OBJDIR)/fuzz_util.o tests/fuzz_response.c $(FUZZ_LIBS)
	@echo "Built $(TARGET)-fuzz (libFuzzer). Run with time limit, e.g.:"
	@echo "  ./$(TARGET)-fuzz -max_total_time=30"
