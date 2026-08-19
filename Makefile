CC := gcc
OPT ?= -O2
TARGET := curldbg

# --- Directories ---
OBJDIR := obj
SAN_OBJDIR := obj-san
TSAN_OBJDIR := obj-tsan

# --- Sources ---
SRCS := $(sort $(shell find src -name '*.c'))
TESTD_SRCS := tests/server/testd.c tests/server/route.c tests/server/handlers.c

# --- Required dependencies ---
LIBPSL_CFLAGS := $(shell pkg-config --cflags libpsl)
LIBPSL_LIBS := $(shell pkg-config --libs libpsl)
ifeq ($(LIBPSL_LIBS),)
    $(error libpsl is required. Install libpsl-dev or similar and ensure pkg-config can find it.)
endif

# --- Headers ---
HEADERS := $(wildcard include/*.h)

# --- Shared flags ---
WARN_FLAGS := -Wall -Wextra -Wshadow -Werror -Wconversion -Wsign-conversion -Wpedantic \
              -Wformat=2 -Wnull-dereference -Wdouble-promotion -Wundef -Wstrict-prototypes
COMMON_CFLAGS := $(WARN_FLAGS) -pthread -Iinclude -Isrc/net/http2 -DHAVE_LIBPSL $(LIBPSL_CFLAGS)
HARDEN_FLAGS := -fstack-protector-strong -fcf-protection=full -fstack-clash-protection -D_FORTIFY_SOURCE=2

# --- Build variant flags ---
CFLAGS := $(OPT) $(COMMON_CFLAGS) $(HARDEN_FLAGS)
CFLAGS += $(EXTRA_CFLAGS)
SAN_CFLAGS := -g -O0 -fsanitize=address,undefined $(COMMON_CFLAGS)
TSAN_CFLAGS := -g -O1 -fsanitize=thread $(COMMON_CFLAGS)

# Test binaries (regular build): unit tests run unoptimized; the test server
# uses the same warnings but skips hardening/libpsl flags.
UNIT_CFLAGS := -g -O0 $(WARN_FLAGS) -pthread -Iinclude -Isrc/net/http2
TESTD_CFLAGS := -O2 $(WARN_FLAGS) -Iinclude

LDLIBS := -pthread -lssl -lcrypto -lz $(LIBPSL_LIBS)

# --- Object lists per variant ---
OBJS := $(SRCS:src/%.c=$(OBJDIR)/%.o)
UNIT_OBJS := $(filter-out $(OBJDIR)/main.o,$(OBJS))
SAN_OBJS := $(SRCS:src/%.c=$(SAN_OBJDIR)/%.o)
SAN_UNIT_OBJS := $(filter-out $(SAN_OBJDIR)/main.o,$(SAN_OBJS))
TSAN_OBJS := $(SRCS:src/%.c=$(TSAN_OBJDIR)/%.o)
TSAN_UNIT_OBJS := $(filter-out $(TSAN_OBJDIR)/main.o,$(TSAN_OBJS))

# --- Install ---
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
MANPAGE := man/curldbg.1

# --- Per-variant build rules (regular / ASan+UBSan / TSan) ---
# $(1)=objdir  $(2)=cflags-var  $(3)=binary  $(4)=objs  $(5)=unit-objs
# $(6)=unit-test-cflags-var  $(7)=testd-cflags-var
define variant_rules
$(1)/%.o: src/%.c $(HEADERS)
	@mkdir -p $$(dir $$@)
	$$(CC) $$($(2)) -c -o $$@ $$<

$(3): $(4)
	$$(CC) $$($(2)) $$(LDFLAGS) -o $$@ $(4) $$(LDLIBS)

$(1)/testd: $(TESTD_SRCS)
	@mkdir -p $(1)
	$$(CC) $$($(7)) -Wno-unused-result -o $$@ $$^

$(1)/unit_test: $(5) tests/unit.c $(HEADERS)
	$$(CC) $$($(6)) -o $$@ tests/unit.c $(5) $$(LDLIBS)
endef

$(eval $(call variant_rules,$(OBJDIR),CFLAGS,$(TARGET),$(OBJS),$(UNIT_OBJS),UNIT_CFLAGS,TESTD_CFLAGS))
$(eval $(call variant_rules,$(SAN_OBJDIR),SAN_CFLAGS,$(SAN_OBJDIR)/curldbg,$(SAN_OBJS),$(SAN_UNIT_OBJS),SAN_CFLAGS,SAN_CFLAGS))
$(eval $(call variant_rules,$(TSAN_OBJDIR),TSAN_CFLAGS,$(TSAN_OBJDIR)/curldbg,$(TSAN_OBJS),$(TSAN_UNIT_OBJS),TSAN_CFLAGS,TSAN_CFLAGS))

.PHONY: all clean install test test-novg test-san test-tsan check static fuzz fuzz-url fuzz-huffman fuzz-hpack fuzz-all \
        cppcheck coverage unit-test unit-test-vg unit-test-san unit-test-tsan integration analyze clang-analyze

all: $(TARGET)

unit-test: $(OBJDIR)/unit_test
	./$(OBJDIR)/unit_test

unit-test-vg: $(OBJDIR)/unit_test
	valgrind --leak-check=full --error-exitcode=1 -q $(OBJDIR)/unit_test

unit-test-san: $(SAN_OBJDIR)/unit_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	./$(SAN_OBJDIR)/unit_test

unit-test-tsan: $(TSAN_OBJDIR)/unit_test
	TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 \
	setarch x86_64 -R ./$(TSAN_OBJDIR)/unit_test

integration: $(TARGET) $(OBJDIR)/testd
	@tests/integration/run.sh $(OBJDIR)/testd ./$(TARGET)

clean:
	rm -rf $(TARGET) $(OBJDIR) $(SAN_OBJDIR) $(TSAN_OBJDIR)
	rm -f $(TARGET)-fuzz $(TARGET)-fuzz-url $(TARGET)-fuzz-huffman $(TARGET)-fuzz-hpack $(TARGET)-static gmon.out

test: $(TARGET) $(OBJDIR)/unit_test $(OBJDIR)/testd
	valgrind --leak-check=full --error-exitcode=1 -q $(OBJDIR)/unit_test
	tests/integration/run.sh $(OBJDIR)/testd ./$(TARGET)
	@if command -v clang >/dev/null 2>&1; then \
		echo "=== fuzz: parse_response_headers (30s) ==="; \
		$(MAKE) fuzz; \
		timeout 35 ./$(TARGET)-fuzz -max_total_time=30 -entropic=0; FRC=$$?; \
		if [ $$FRC -eq 124 ]; then echo "  (timeout safety cap reached)"; FRC=0; fi; \
		rm -f $(TARGET)-fuzz; \
		exit $$FRC; \
	else \
		echo "=== fuzz: skipped (clang not found) ==="; \
	fi

test-novg: $(TARGET) $(OBJDIR)/unit_test $(OBJDIR)/testd
	./$(OBJDIR)/unit_test
	tests/integration/run.sh $(OBJDIR)/testd ./$(TARGET)

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

STATIC_SSL_DEPS := $(filter-out -lssl -lcrypto -ldl -lpthread -pthread, $(shell pkg-config --static --libs libssl 2>/dev/null))
static: CFLAGS += -no-pie
static: LDLIBS = -pthread -lz $(LIBPSL_LIBS) -l:libssl.a -l:libcrypto.a $(STATIC_SSL_DEPS)
static: $(OBJS)
	$(CC) $(CFLAGS) -s -static-libgcc -o $(TARGET)-static $(OBJS) $(LDLIBS)
	@echo "Built $(TARGET)-static (statically linked)"

# GCC's interprocedural static analyzer (-fanalyzer).
# Opt-in: it is slow and can produce false positives, so it is not part of `check`.
analyze:
	$(MAKE) clean
	$(MAKE) EXTRA_CFLAGS="-fanalyzer" all

# Clang static analyzer via scan-build. Fails the build on any finding.
clang-analyze:
	$(MAKE) clean
	scan-build --status-bugs $(MAKE) CC=clang all

install: $(TARGET) $(MANPAGE)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 644 $(MANPAGE) $(DESTDIR)$(MANDIR)/curldbg.1

FUZZ_CC := clang
FUZZ_CFLAGS := -g -O1 -fsanitize=fuzzer,address,undefined -Iinclude
FUZZ_LIBS := -lz -lssl -lcrypto

# Fuzzer object files (one per instrumented source).
$(OBJDIR)/fuzz_util.o: src/util.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c -o $@ $<
$(OBJDIR)/fuzz_response.o: src/http/response.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c -o $@ $<
$(OBJDIR)/fuzz_url.o: src/url.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c -o $@ $<
$(OBJDIR)/fuzz_hpack.o: src/net/hpack.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c -o $@ $<

# $(1)=target-suffix  $(2)=specific-object  $(3)=driver-source
define fuzzer_rule
$(TARGET)-fuzz$(1): $(OBJDIR)/$(2).o $(OBJDIR)/fuzz_util.o $(3)
	$$(FUZZ_CC) $$(FUZZ_CFLAGS) -o $$@ $(OBJDIR)/$(2).o $(OBJDIR)/fuzz_util.o $(3) $$(FUZZ_LIBS)
endef

$(eval $(call fuzzer_rule,,fuzz_response,tests/fuzz_response.c))
$(eval $(call fuzzer_rule,-url,fuzz_url,tests/fuzz_url.c))
$(eval $(call fuzzer_rule,-huffman,fuzz_hpack,tests/fuzz_huffman.c))
$(eval $(call fuzzer_rule,-hpack,fuzz_hpack,tests/fuzz_hpack.c))

fuzz: $(TARGET)-fuzz
	@echo "Run with time limit, e.g.:"
	@echo "  ./$(TARGET)-fuzz -max_total_time=30"
fuzz-url: $(TARGET)-fuzz-url
fuzz-huffman: $(TARGET)-fuzz-huffman
fuzz-hpack: $(TARGET)-fuzz-hpack
fuzz-all: fuzz fuzz-url fuzz-huffman fuzz-hpack
	@echo "=== All fuzzers built ==="

cppcheck:
	cppcheck --enable=warning,performance,portability,style \
		--error-exitcode=1 --suppress=missingIncludeSystem \
		--inline-suppr \
		-Iinclude src/ tests/server/

coverage: CFLAGS := -g -O0 --coverage $(WARN_FLAGS) -pthread -Iinclude
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
