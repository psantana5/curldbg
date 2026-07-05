#!/usr/bin/env python3
"""Comprehensive HTTP test server for curldbg.

Supports: echo, redirect chains, cookie set/inspect, status codes,
method echo, arbitrary response headers, keep-alive for redirect chains.

Usage: python3 server.py <port>
"""
import socket, sys, threading, os, urllib.parse

def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        d = conn.recv(n - len(buf))
        if not d:
            return None
        buf += d
    return buf

def recv_until(conn, delim):
    buf = b''
    while delim not in buf:
        d = conn.recv(1)
        if not d:
            return None
        buf += d
    return buf

def parse_request(header):
    lines = header.split('\r\n')
    if not lines:
        return None, {}, '', {}
    start = lines[0]
    parts = start.split(' ')
    method = parts[0] if len(parts) > 0 else 'GET'
    path_raw = parts[1] if len(parts) > 1 else '/'
    parsed = urllib.parse.urlparse(path_raw)
    path = parsed.path
    qs = urllib.parse.parse_qs(parsed.query)
    headers = {}
    for line in lines[1:]:
        if ': ' in line:
            k, v = line.split(': ', 1)
            headers[k.lower()] = v
    return method, path, qs, headers

def read_body(conn, header_str, headers):
    is_chunked = headers.get('transfer-encoding', '').lower() == 'chunked'
    body_data = b''
    if is_chunked:
        while True:
            line = recv_until(conn, b'\r\n')
            if line is None:
                break
            size_str = line[:-2].strip()
            if not size_str:
                break
            size = int(size_str, 16)
            if size == 0:
                recv_until(conn, b'\r\n')
                break
            chunk = recv_exact(conn, size)
            if chunk is None:
                break
            body_data += chunk
            recv_until(conn, b'\r\n')
    else:
        cl = int(headers.get('content-length', '0'))
        if cl > 0:
            body_data = recv_exact(conn, cl) or b''
    return body_data

def send_response(conn, status, reason, body, extra_headers=b''):
    resp = (
        f'HTTP/1.1 {status} {reason}\r\n'.encode()
        + b'Content-Type: text/plain\r\n'
        + extra_headers
        + b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
        + b'\r\n'
        + body
    )
    conn.sendall(resp)

def handle(conn):
    while True:
        try:
            header = recv_until(conn, b'\r\n\r\n')
            if header is None:
                break
            header_str = header.decode('utf-8', errors='replace')
            method, path, qs, req_headers = parse_request(header_str)
            body_data = read_body(conn, header_str, req_headers)

            # Check for Connection: close from client
            connection_hdr = req_headers.get('connection', '').lower()
            keep_alive = 'close' not in connection_hdr

            # /redirect/N - chain of N redirects
            if path.startswith('/redirect/'):
                try:
                    n = int(path.split('/')[2])
                except (ValueError, IndexError):
                    n = 1
                is_last = (n <= 1)
                if is_last:
                    body = b'{"redirected": true}'
                    send_response(conn, 200, 'OK', body)
                else:
                    body = b''
                    send_response(conn, 302, 'Found', body,
                                  extra_headers=b'Location: /redirect/' + str(n - 1).encode() + b'\r\n')
                if not keep_alive:
                    break
                continue

            # /redirect-to?url=X&status_code=301
            if path == '/redirect-to':
                target = qs.get('url', ['/'])[0]
                sc = int(qs.get('status_code', ['302'])[0])
                reason = {301: 'Moved Permanently', 302: 'Found', 303: 'See Other',
                          307: 'Temporary Redirect', 308: 'Permanent Redirect'}
                body = b''
                send_response(conn, sc, reason.get(sc, 'Redirect'), body,
                              extra_headers=b'Location: ' + target.encode() + b'\r\n')
                if not keep_alive:
                    break
                continue

            # /set-cookie?name=X&value=Y
            if path == '/set-cookie':
                name = qs.get('name', ['test_cookie'])[0]
                value = qs.get('value', ['test_value'])[0]
                body = b'{"cookie_set": true}'
                send_response(conn, 200, 'OK', body,
                              extra_headers=f'Set-Cookie: {name}={value}; Path=/\r\n'.encode())
                if not keep_alive:
                    break
                continue

            # /set-multi-cookie
            if path == '/set-multi-cookie':
                body = b'{"cookies_set": 3}'
                send_response(conn, 200, 'OK', body,
                              extra_headers=b'Set-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; Path=/\r\nSet-Cookie: c=3; Path=/\r\n')
                if not keep_alive:
                    break
                continue

            # /cookies - echo received cookies
            if path == '/cookies':
                cookie_val = req_headers.get('cookie', '')
                body = f'{{"cookie": "{cookie_val}"}}'.encode()
                send_response(conn, 200, 'OK', body)
                if not keep_alive:
                    break
                continue

            # /status/CODE
            if path.startswith('/status/'):
                try:
                    code = int(path.split('/')[2])
                except (ValueError, IndexError):
                    code = 200
                reasons = {200: 'OK', 201: 'Created', 204: 'No Content',
                           301: 'Moved Permanently', 302: 'Found', 303: 'See Other',
                           304: 'Not Modified', 307: 'Temporary Redirect',
                           400: 'Bad Request', 401: 'Unauthorized',
                           403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
                           500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable'}
                body = f'{{"status": {code}}}'.encode()
                send_response(conn, code, reasons.get(code, 'Unknown'), body)
                if not keep_alive:
                    break
                continue

            # /response-headers?X=Y
            if path == '/response-headers':
                extra = b''
                for k, vals in qs.items():
                    for v in vals:
                        extra += f'{k.replace("_", "-")}: {v}\r\n'.encode()
                body = b'{"headers_sent": true}'
                send_response(conn, 200, 'OK', body, extra_headers=extra)
                if not keep_alive:
                    break
                continue

            # Default: echo request info
            req_body_str = body_data.decode('utf-8', errors='replace') if body_data else ''
            method_tag = f'METHOD:{method}|'
            path_tag = f'PATH:{path}|'
            body_tag = f'BODY:{req_body_str}|' if req_body_str else ''
            echo_body = f'{method_tag}{path_tag}{body_tag}ECHO_OK'.encode()
            send_response(conn, 200, 'OK', echo_body)
            if not keep_alive:
                break

        except Exception:
            break
    try:
        conn.close()
    except Exception:
        pass

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18997
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(10)
    s.settimeout(1)
    sys.stdout.flush()
    print(f'TEST_SERVER_READY:{port}')
    sys.stdout.flush()
    try:
        while True:
            try:
                conn, _ = s.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

if __name__ == '__main__':
    main()
