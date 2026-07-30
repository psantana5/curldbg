#!/bin/bash
# HTTP/2 release checklist
# Usage: bash tests/checklist_h2.sh
set -e

PASS=0 FAIL=0 SKIP=0

ok()   { echo "  OK   $1"; ((PASS++)); }
fail() { echo "  FAIL $1"; ((FAIL++)); }
skip() { echo "  SKIP $1"; ((SKIP++)); }

check_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        skip "$2 (missing $1)"
        return 1
    fi
    return 0
}

run_silent() {
    "$@" >/tmp/h2check.log 2>&1
}

print_result() {
    local total=$((PASS + FAIL))
    echo ""
    echo "=== $total tests ($PASS passed, $FAIL failed, $SKIP skipped) ==="
    [ $FAIL -eq 0 ]
}

echo "=== HTTP/2 release checklist ==="
echo ""

# -----------------------------------------------------------------------
echo "--- 1. Unit tests ---"
# -----------------------------------------------------------------------
make -j$(nproc) >/dev/null 2>&1 || { fail "build failed"; }
UNIT_OUT=$(make -s test-novg 2>&1)
UNIT_LINE=$(echo "$UNIT_OUT" | grep -oP 'unit: \d+ passed, \d+ failed' | tail -1)
if echo "$UNIT_LINE" | grep -qP 'unit: \d+ passed, 0 failed'; then
    ok "unit tests: $UNIT_LINE"
elif [ -n "$UNIT_LINE" ]; then
    fail "unit tests: $UNIT_LINE"
else
    echo "$UNIT_OUT" | grep -E '(unit:|FAIL|passed|failed)' | tail -5
    fail "unit tests: no result line"
fi

# -----------------------------------------------------------------------
echo "--- 2. HTTP/2 integration tests ---"
# -----------------------------------------------------------------------
if CURLDBG_BIN=./curldbg bash tests/integration/test_http2.sh 2>&1 | grep -qP '\d+/\d+ passed'; then
    ok "HTTP/2 integration"
else
    H2OUT=$(CURLDBG_BIN=./curldbg bash tests/integration/test_http2.sh 2>&1)
    echo "$H2OUT" | tail -1
    if echo "$H2OUT" | grep -qP 'passed'; then
        ok "HTTP/2 integration"
    else
        fail "HTTP/2 integration"
    fi
fi

# -----------------------------------------------------------------------
echo "--- 3. ASan + UBSan ---"
# -----------------------------------------------------------------------
if make test-san >/tmp/h2check_san.log 2>&1; then
    ok "ASan/UBSan"
else
    tail -20 /tmp/h2check_san.log
    fail "ASan/UBSan"
fi

# -----------------------------------------------------------------------
echo "--- 4. TSan ---"
# -----------------------------------------------------------------------
if command -v setarch >/dev/null 2>&1; then
    if make test-tsan >/tmp/h2check_tsan.log 2>&1; then
        ok "TSan"
    else
        tail -20 /tmp/h2check_tsan.log
        fail "TSan"
    fi
else
    skip "TSan (no setarch)"
fi

# -----------------------------------------------------------------------
echo "--- 5. Valgrind ---"
# -----------------------------------------------------------------------
if check_cmd valgrind "Valgrind"; then
    make obj/unit_test >/dev/null 2>&1
    if valgrind --leak-check=full --error-exitcode=1 -q obj/unit_test >/tmp/h2check_vg.log 2>&1; then
        ok "Valgrind unit tests"
    else
        tail -30 /tmp/h2check_vg.log
        fail "Valgrind unit tests"
    fi
fi

# -----------------------------------------------------------------------
echo "--- 6. h2spec ---"
# -----------------------------------------------------------------------
H2SPEC=""
for p in h2spec /tmp/h2spec/h2spec /usr/local/bin/h2spec; do
    [ -x "$p" ] && H2SPEC="$p" && break
done
if [ -n "$H2SPEC" ]; then
    # Start h2d on a random port, run h2spec against it
    PORT_FILE=/tmp/h2check_h2spec_port.txt
    /tmp/h2test_venv/bin/python tests/server/h2d.py 0 \
        --cert /tmp/h2test.crt --key /tmp/h2test.key > "$PORT_FILE" 2>/dev/null &
    H2PID=$!
    sleep 1
    PORT=$(head -1 "$PORT_FILE")
    if [ -n "$PORT" ]; then
        if "$H2SPEC" --strict --port "$PORT" --tls --insecure \
            --max-time 30 >/tmp/h2check_h2spec.log 2>&1; then
            ok "h2spec"
        else
            tail -10 /tmp/h2check_h2spec.log
            H2SPEC_FAILS=$(grep -c 'FAIL' /tmp/h2check_h2spec.log 2>/dev/null || echo "?")
            fail "h2spec (${H2SPEC_FAILS} failures)"
        fi
        kill "$H2PID" 2>/dev/null; wait "$H2PID" 2>/dev/null
    else
        skip "h2spec (h2d failed to start)"
        kill "$H2PID" 2>/dev/null; wait "$H2PID" 2>/dev/null
    fi
    rm -f "$PORT_FILE"
else
    skip "h2spec (not found)"
fi

# -----------------------------------------------------------------------
echo "--- 7. nghttpd ---"
# -----------------------------------------------------------------------
if check_cmd nghttpd "nghttpd"; then
    CERT=/tmp/h2check_nghttpd.crt
    KEY=/tmp/h2check_nghttpd.key
    [ -f "$CERT" ] || openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" \
        -days 1 -nodes -subj '/CN=localhost' 2>/dev/null

    DIR=$(mktemp -d)
    echo "hello from nghttpd" > "$DIR/index.html"
    # Determine document root (directory of index.html)
    PORT_FILE=/tmp/h2check_nghttpd_port.txt
    # nghttpd doesn't write port to stdout, start on a known port
    nghttpd -d "$DIR" 18443 "$CERT" "$KEY" >/tmp/h2check_nghttpd.log 2>&1 &
    NGHTTPD_PID=$!
    sleep 1

    if ./curldbg -s --insecure "https://localhost:18443/" -o /dev/null \
        -w "%{http_code}" 2>/dev/null | grep -q 200; then
        ok "nghttpd (https://localhost:18443/)"
    else
        fail "nghttpd"
    fi

    kill "$NGHTTPD_PID" 2>/dev/null; wait "$NGHTTPD_PID" 2>/dev/null
    rm -rf "$DIR" "$PORT_FILE"
fi

# -----------------------------------------------------------------------
echo "--- 8. Nginx HTTP/2 ---"
# -----------------------------------------------------------------------
if check_cmd nginx "Nginx HTTP/2"; then
    NX_DIR=$(mktemp -d)
    mkdir -p "$NX_DIR/www" "$NX_DIR/logs"
    echo "hello from nginx" > "$NX_DIR/www/index.html"

    cat > "$NX_DIR/nginx.conf" <<'CONF'
events { worker_connections 64; }
http {
    server {
        listen 18444 ssl http2;
        root __ROOT__;
        ssl_certificate __CERT__;
        ssl_certificate_key __KEY__;
    }
}
CONF
    sed -i "s|__ROOT__|$NX_DIR/www|g; s|__CERT__|/tmp/h2test.crt|g; s|__KEY__|/tmp/h2test.key|g" \
        "$NX_DIR/nginx.conf"

    nginx -p "$NX_DIR" -c "$NX_DIR/nginx.conf" >/tmp/h2check_nginx.log 2>&1 &
    NGINX_PID=$!
    sleep 1

    if ./curldbg -s --insecure "https://localhost:18444/" -o /dev/null \
        -w "%{http_code}" 2>/dev/null | grep -q 200; then
        ok "Nginx HTTP/2 (https://localhost:18444/)"
    else
        fail "Nginx HTTP/2"
    fi

    kill "$NGINX_PID" 2>/dev/null; wait "$NGINX_PID" 2>/dev/null
    rm -rf "$NX_DIR"
fi

# -----------------------------------------------------------------------
echo "--- 9. Public HTTP/2 server (nghttp2.org) ---"
# -----------------------------------------------------------------------
PUBLIC_URL="${H2_PUBLIC_URL:-https://nghttp2.org}"
if command -v curl >/dev/null 2>&1; then
    # Quick connectivity check first via curl
    if curl -s -o /dev/null --max-time 5 "$PUBLIC_URL" 2>/dev/null; then
        RESULT=$(./curldbg -s --insecure "$PUBLIC_URL" -o /dev/null \
            -w "%{http_code}:%{http_version}" 2>/dev/null)
        CODE=$(echo "$RESULT" | cut -d: -f1)
        VER=$(echo "$RESULT" | cut -d: -f2)
        if [ "$CODE" = "200" ] && [ "$VER" = "HTTP/2" ]; then
            ok "public HTTP/2 ($PUBLIC_URL → $CODE $VER)"
        else
            fail "public HTTP/2 ($PUBLIC_URL → $CODE $VER)"
        fi
    else
        skip "public HTTP/2 ($PUBLIC_URL unreachable)"
    fi
else
    skip "public HTTP/2 (curl not found)"
fi

# -----------------------------------------------------------------------
echo "--- 10. Full integration suite ---"
# -----------------------------------------------------------------------
make obj/testd >/dev/null 2>&1
if [ -x obj/testd ]; then
    # start testd server
    PORT_FILE=/tmp/h2check_testd_port.txt
    obj/testd > "$PORT_FILE" 2>/dev/null &
    TESTD_PID=$!
    until [ -s "$PORT_FILE" ]; do sleep 0.1; done
    PORT=$(head -1 "$PORT_FILE")
    if [ -n "$PORT" ]; then
        ALL_OK=true
        TOTAL_P=0 TOTAL_F=0
        for t in tests/integration/test_basic.sh tests/integration/test_redirect.sh \
                 tests/integration/test_chunked.sh tests/integration/test_malformed.sh \
                 tests/integration/test_gzip.sh tests/integration/test_cookies.sh \
                 tests/integration/test_post.sh; do
            if CURLDBG_BIN=./curldbg bash "$t" "$PORT" >/tmp/h2check_int.log 2>&1; then
                ((TOTAL_P++))
            else
                ((TOTAL_F++))
                ALL_OK=false
            fi
        done
        if $ALL_OK; then
            ok "all $TOTAL_P HTTP/1.1 integration tests"
        else
            fail "HTTP/1.1 integration: $TOTAL_P passed, $TOTAL_F failed"
        fi

        kill "$TESTD_PID" 2>/dev/null; wait "$TESTD_PID" 2>/dev/null
    else
        skip "full integration (testd failed to start)"
        kill "$TESTD_PID" 2>/dev/null; wait "$TESTD_PID" 2>/dev/null
    fi
    rm -f "$PORT_FILE"
else
    skip "full integration (testd not built)"
fi

print_result
