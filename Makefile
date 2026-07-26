CC := gcc
OPT ?= -O2
TARGET := curldbg

# --- Directories ---
OBJDIR := obj
SAN_OBJDIR := obj-san
TSAN_OBJDIR := obj-tsan

# --- Sources ---
SRCS := src/main.c src/run.c src/results.c src/util.c src/url.c \
        src/net/dns.c src/net/tls.c src/net/connect.c src/net/proxy.c \
        src/http/request.c src/http/response.c \
        src/cookie.c src/cli/parse.c src/cli/help.c src/output.c src/compare.c
TESTD_SRCS := tests/server/testd.c tests/server/route.c tests/server/handlers.c

# --- Optional dependencies ---
HAVE_LIBPSL := $(shell pkg-config --exists libpsl && echo 1 || echo 0)
ifeq ($(HAVE_LIBPSL),1)
    LIBPSL_CFLAGS := $(shell pkg-config --cflags libpsl)
    LIBPSL_LIBS := $(shell pkg-config --libs libpsl)
endif

# --- Regular build ---
CFLAGS := $(OPT) -Wall -Wextra -Wshadow -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pthread -Iinclude $(LIBPSL_CFLAGS)
LDLIBS := -pthread -lssl -lcrypto -lz $(LIBPSL_LIBS)
ifeq ($(HAVE_LIBPSL),1)
    CFLAGS += -DHAVE_LIBPSL
endif
OBJS := $(SRCS:src/%.c=$(OBJDIR)/%.o)
UNIT_OBJS := $(filter-out $(OBJDIR)/main.o,$(OBJS))

# --- ASan/UBSan ---
SAN_CFLAGS := -g -O0 -fsanitize=address,undefined -Wall -Wextra -Werror -pthread -Iinclude $(LIBPSL_CFLAGS)
ifeq ($(HAVE_LIBPSL),1)
    SAN_CFLAGS += -DHAVE_LIBPSL
endif
SAN_OBJS := $(SRCS:src/%.c=$(SAN_OBJDIR)/%.o)
SAN_UNIT_OBJS := $(filter-out $(SAN_OBJDIR)/main.o,$(SAN_OBJS))

# --- TSan ---
TSAN_CFLAGS := -g -O1 -fsanitize=thread -Wall -Wextra -Werror -pthread -Iinclude $(LIBPSL_CFLAGS)
ifeq ($(HAVE_LIBPSL),1)
    TSAN_CFLAGS += -DHAVE_LIBPSL
endif
TSAN_OBJS := $(SRCS:src/%.c=$(TSAN_OBJDIR)/%.o)
TSAN_UNIT_OBJS := $(filter-out $(TSAN_OBJDIR)/main.o,$(TSAN_OBJS))

# --- Install ---
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
MANPAGE := man/curldbg.1

# --- Test runner template ---
# $(call run_unit_and_integration,<unit_runner_cmd>)
define run_unit_and_integration
	$(CC) -g -O0 -Wall -Wextra -Werror -pthread -Iinclude \
		-o $(OBJDIR)/unit_test tests/unit.c $(UNIT_OBJS) $(LDLIBS)
	$(1)
	@rm -f $(OBJDIR)/unit_test
	$(CC) -O2 -Wall -Wextra -Wno-unused-result -Iinclude \
		-o $(OBJDIR)/testd $(TESTD_SRCS)
	@tests/integration/run.sh $(OBJDIR)/testd ./$(TARGET)
endef

.PHONY: all clean install test test-novg test-san test-tsan check static fuzz cppcheck coverage

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

$(TSAN_OBJDIR)/%.o: src/%.c include/curldbg.h include/flags.h
	@mkdir -p $(dir $@)
	$(CC) $(TSAN_CFLAGS) -c -o $@ $<

$(TSAN_OBJDIR)/curldbg: $(TSAN_OBJS)
	$(CC) $(TSAN_CFLAGS) -o $@ $^ $(LDLIBS)

$(TSAN_OBJDIR)/testd: $(TESTD_SRCS)
	@mkdir -p $(TSAN_OBJDIR)
	$(CC) $(TSAN_CFLAGS) -Wno-unused-result -o $@ $^

$(TSAN_OBJDIR)/unit_test: $(TSAN_UNIT_OBJS) tests/unit.c
	$(CC) $(TSAN_CFLAGS) -o $@ tests/unit.c $(TSAN_UNIT_OBJS) $(LDLIBS)

clean:
	rm -rf $(TARGET) $(OBJDIR) $(SAN_OBJDIR) $(TSAN_OBJDIR)

test: $(TARGET)
	$(call run_unit_and_integration,valgrind --leak-check=full --error-exitcode=1 -q $(OBJDIR)/unit_test)
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

test-novg: $(TARGET)
	$(call run_unit_and_integration,./$(OBJDIR)/unit_test)

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

test-tsan: $(TSAN_OBJDIR)/unit_test $(TSAN_OBJDIR)/testd $(TSAN_OBJDIR)/curldbg
	@echo "--- unit tests (TSan) ---"
	TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 \
	setarch x86_64 -R ./$(TSAN_OBJDIR)/unit_test
	@echo "--- integration tests (TSan) ---"
	TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 \
	setarch x86_64 -R tests/integration/run.sh $(TSAN_OBJDIR)/testd $(TSAN_OBJDIR)/curldbg
	@echo "=== test-tsan: all passed ==="

check: test test-san test-tsan
	@echo "=== check: all targets passed ==="

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

cppcheck:
	cppcheck --enable=warning,performance,portability,style \
		--error-exitcode=1 --suppress=missingIncludeSystem \
		--inline-suppr \
		-Iinclude src/ tests/server/

coverage: CFLAGS := -g -O0 --coverage -Wall -Wextra -Wshadow -Werror -pthread -Iinclude
coverage:
	$(MAKE) clean
	$(MAKE) all CFLAGS="$(CFLAGS)"
	$(CC) $(CFLAGS) -o $(OBJDIR)/unit_test tests/unit.c $(UNIT_OBJS) $(LDLIBS)
	./$(OBJDIR)/unit_test
	$(CC) $(CFLAGS) -Wno-unused-result -o $(OBJDIR)/testd $(TESTD_SRCS)
	tests/integration/run.sh $(OBJDIR)/testd ./$(TARGET)
	lcov --capture --directory $(OBJDIR) --output-file $(OBJDIR)/coverage.info \
		--rc geninfo_unexecuted_blocks=0 --ignore-errors gcov
	lcov --remove $(OBJDIR)/coverage.info '*/tests/*' --output-file $(OBJDIR)/coverage.info \
		--ignore-errors empty,unused
	lcov --list $(OBJDIR)/coverage.info --ignore-errors empty,unused
	genhtml $(OBJDIR)/coverage.info --output-directory $(OBJDIR)/coverage \
		--ignore-errors unmapped,empty
	@if [ -n "$$GITHUB_STEP_SUMMARY" ]; then \
		echo "| Coverage |" >> $$GITHUB_STEP_SUMMARY; \
		echo "|----------|" >> $$GITHUB_STEP_SUMMARY; \
		lcov --summary $(OBJDIR)/coverage.info 2>&1 | grep lines | tr -d '\n' | \
			sed 's/.*lines\.*: //' >> $$GITHUB_STEP_SUMMARY; \
	fi
	@echo "=== coverage: $(OBJDIR)/coverage/index.html ==="
