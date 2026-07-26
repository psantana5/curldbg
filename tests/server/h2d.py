#!/usr/bin/env python3
"""Minimal HTTP/2 (TLS) test server for curldbg integration tests.

Usage: h2d.py <cert.pem> <key.pem>

The server binds to 127.0.0.1 on an ephemeral port and prints the port
number on stdout. It supports a few simple endpoints used by the integration
test suite:

  GET  /                -> 200 OK with a plain text body
  HEAD /                -> 200 OK with no body
  GET  /json            -> 200 OK with a JSON body
  GET  /cookie          -> 200 OK with a Set-Cookie header
  POST /echo            -> 200 OK with the request body echoed back
  POST /status          -> 200 OK with "status: ok"
"""

import socket
import ssl
import sys
import threading
import os

import h2.connection
import h2.events
import h2.config


def handle_connection(conn, certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.set_alpn_protocols(["h2"])
    # TLS 1.2+ is required for ALPN.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_conn = ctx.wrap_socket(conn, server_side=True)

    selected = tls_conn.selected_alpn_protocol()
    if selected != "h2":
        tls_conn.close()
        return

    config = h2.config.H2Configuration(client_side=False)
    h2_conn = h2.connection.H2Connection(config=config)
    h2_conn.initiate_connection()
    tls_conn.sendall(h2_conn.data_to_send())

    streams = {}
    try:
        while True:
            data = tls_conn.recv(65536)
            if not data:
                break
            events = h2_conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    streams[event.stream_id] = {
                        "headers": {k.decode("ascii"): v.decode("ascii")
                                    for k, v in event.headers},
                        "data": b"",
                    }
                elif isinstance(event, h2.events.DataReceived):
                    s = streams.get(event.stream_id)
                    if s is not None:
                        s["data"] += event.data
                    h2_conn.increment_flow_control_window(
                        increment=len(event.data), stream_id=event.stream_id
                    )
                    h2_conn.increment_flow_control_window(
                        increment=len(event.data), stream_id=None
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    stream_id = event.stream_id
                    s = streams.get(stream_id)
                    if s is None:
                        continue

                    headers = s["headers"]
                    method = headers.get(":method", "GET")
                    path = headers.get(":path", "/")
                    scheme = headers.get(":scheme", "https")
                    body = b""
                    status = "200"
                    content_type = "text/plain"
                    extra_headers = []

                    if path == "/":
                        if method == "HEAD":
                            body = b""
                        else:
                            body = b"Hello HTTP/2"
                    elif path == "/json":
                        content_type = "application/json"
                        body = b'{"ok": true, "proto": "h2"}'
                    elif path == "/cookie":
                        extra_headers.append(("set-cookie", "session=abc123; Path=/"))
                        body = b"cookie set"
                    elif path == "/echo":
                        if method in ("POST", "PUT", "PATCH"):
                            content_type = headers.get(
                                "content-type", "application/octet-stream")
                            body = s["data"]
                        else:
                            body = b"method not allowed"
                            status = "405"
                    elif path == "/status":
                        body = b"status: ok"
                    else:
                        status = "404"
                        body = b"not found"

                    response_headers = [
                        (":status", status),
                        ("content-type", content_type),
                        ("content-length", str(len(body))),
                    ]
                    response_headers.extend(extra_headers)
                    response_headers.append(("server", "curldbg-test-h2d/1.0"))

                    # h2 accepts header names/values as either str or bytes.
                    response_headers = [
                        (str(k), str(v)) for k, v in response_headers
                    ]

                    if method == "HEAD":
                        h2_conn.send_headers(stream_id, response_headers, end_stream=True)
                    else:
                        h2_conn.send_headers(stream_id, response_headers)
                        if body:
                            h2_conn.send_data(stream_id, body)
                        h2_conn.end_stream(stream_id)

                    data_to_send = h2_conn.data_to_send()
                    if data_to_send:
                        tls_conn.sendall(data_to_send)
                    streams.pop(stream_id, None)

            data_to_send = h2_conn.data_to_send()
            if data_to_send:
                tls_conn.sendall(data_to_send)
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            tls_conn.close()
        except Exception:
            pass


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: h2d.py <cert.pem> <key.pem>\n")
        sys.exit(1)

    certfile = sys.argv[1]
    keyfile = sys.argv[2]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    print(port)
    sys.stdout.flush()

    try:
        while True:
            conn, _ = sock.accept()
            t = threading.Thread(
                target=handle_connection, args=(conn, certfile, keyfile), daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
