CC := gcc
OPT ?= -O2
CFLAGS := $(OPT) -Wall -Wextra -pthread -Iinclude
LDLIBS := -pthread -lssl -lcrypto -lz
TARGET := curldbg
OBJDIR := obj
SRCS := src/main.c src/run.c src/results.c src/util.c src/url.c \
        src/net/dns.c src/net/tls.c src/net/connect.c src/net/proxy.c \
        src/http/request.c src/http/response.c \
        src/cookie.c src/cli/parse.c src/cli/help.c src/output.c src/compare.c
OBJS := $(SRCS:src/%.c=$(OBJDIR)/%.o)
OBJS := $(SRCS:src/%.c=$(OBJDIR)/%.o)
UNIT_OBJS := $(filter-out $(OBJDIR)/main.o,$(OBJS))
MANPAGE := man/curldbg.1
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
TESTD_SRCS := tests/server/testd.c tests/server/route.c tests/server/handlers.c

.PHONY: all clean install test test-san static fuzz

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR)/%.o: src/%.c include/curldbg.h include/flags.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(TARGET) $(OBJDIR)

test: $(TARGET) $(UNIT_OBJS)
	@# Unit tests
	$(CC) -g -O0 -Wall -Wextra -Werror -pthread -Iinclude \
		-o $(OBJDIR)/unit_test tests/unit.c $(UNIT_OBJS) $(LDLIBS)
	@valgrind --leak-check=full --error-exitcode=1 -q $(OBJDIR)/unit_test
	@rm -f $(OBJDIR)/unit_test
	@# Build test HTTP server
	$(CC) -O2 -Wall -Wextra -Wno-unused-result -Iinclude \
		-o $(OBJDIR)/testd $(TESTD_SRCS)
	@# Integration tests
	@$(OBJDIR)/testd >/tmp/testd.log 2>&1 & \
	TDPID=$$!; \
	until [ -s /tmp/testd.log ]; do sleep 0.1; done; \
	PORT=$$(head -1 /tmp/testd.log); \
	echo "=== integration tests (port $$PORT) ==="; \
	tests/integration/run.sh $$PORT; \
	IRC=$$?; \
	kill $$TDPID 2>/dev/null; \
	wait $$TDPID 2>/dev/null; \
	rm -f /tmp/testd.log; \
	if [ $$IRC -ne 0 ]; then exit $$IRC; fi; \
	if command -v clang >/dev/null 2>&1; then \
		echo "=== fuzz: parse_response_headers (30s) ==="; \
		$(MAKE) fuzz; \
		./$(TARGET)-fuzz -max_total_time=30; \
		FUZZ_RC=$$?; \
		rm -f $(TARGET)-fuzz; \
		exit $$FUZZ_RC; \
	else \
		echo "=== fuzz: skipped (clang not found) ==="; \
	fi

test-san:
	@rm -rf $(OBJDIR)-san
	@mkdir -p $(OBJDIR)-san/net $(OBJDIR)-san/http $(OBJDIR)-san/cli
	@echo "=== test-san: building with -fsanitize=address,undefined ==="
	@set -e; \
	SFLAGS="-g -O0 -fsanitize=address,undefined -Wall -Wextra -Werror -pthread -Iinclude"; \
	for src in $(SRCS); do \
		obj=$(OBJDIR)-san/$$(echo $$src | sed 's|^src/||; s|\.c$$|.o|'); \
		$(CC) $$SFLAGS -c -o $$obj $$src; \
	done; \
	T_OBJS=""; \
	for f in $(OBJDIR)-san/*.o $(OBJDIR)-san/*/*.o; do \
		case $$f in */main.o) continue ;; esac; \
		T_OBJS="$$T_OBJS $$f"; \
	done; \
	$(CC) $$SFLAGS -o $(OBJDIR)-san/unit_test tests/unit.c $$T_OBJS $(LDLIBS)
	@echo "--- unit tests (ASan/UBSan) ---"
	@ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	./$(OBJDIR)-san/unit_test
	@echo "--- linking sanitized curldbg ---"
	@$(CC) -g -O0 -fsanitize=address,undefined -Wall -Wextra -Werror -pthread -Iinclude \
		-o $(OBJDIR)-san/curldbg $(OBJDIR)-san/*.o $(OBJDIR)-san/*/*.o $(LDLIBS)
	@echo "--- building sanitized testd ---"
	@$(CC) -g -O0 -fsanitize=address,undefined -Wall -Wextra -Wno-unused-result -Werror -Iinclude \
		-o $(OBJDIR)-san/testd $(TESTD_SRCS)
	@echo "--- integration tests (ASan/UBSan) ---"
	@if [ -f $(TARGET) ] && [ ! -f $(TARGET).bak ]; then cp $(TARGET) $(TARGET).bak; fi
	@cp $(OBJDIR)-san/curldbg $(TARGET)
	@export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1; \
	export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1; \
	$(OBJDIR)-san/testd >/tmp/testd.log 2>&1 & \
	TDPID=$$!; \
	until [ -s /tmp/testd.log ]; do sleep 0.1; done; \
	PORT=$$(head -1 /tmp/testd.log); \
	tests/integration/run.sh $$PORT; \
	IRC=$$?; \
	kill $$TDPID 2>/dev/null; wait $$TDPID 2>/dev/null; \
	rm -f /tmp/testd.log; \
	if [ $$IRC -ne 0 ]; then \
		mv $(TARGET).bak $(TARGET); exit $$IRC; \
	fi
	@mv $(TARGET).bak $(TARGET)
	@rm -rf $(OBJDIR)-san
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
