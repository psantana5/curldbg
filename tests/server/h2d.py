#!/usr/bin/env python3
"""HTTP/2 test server using the h2 library with TLS."""

import argparse
import os
import ssl
import socket
import sys
import threading
import time

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.errors
    import h2.settings
except ImportError:
    sys.stderr.write("ERROR: h2 library not found. Run: pip install h2\n")
    sys.exit(1)

STATIC_RESPONSES = {
    b"/": {
        ":status": "200",
        "content-type": "text/plain",
    },
    b"/status404": {
        ":status": "404",
        "content-type": "text/plain",
    },
    b"/status500": {
        ":status": "500",
        "content-type": "text/plain",
    },
}


class H2Handler:
    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        config = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        self.conn = h2.connection.H2Connection(config=config)
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())

    def run(self):
        while True:
            data = self.sock.recv(65535)
            if not data:
                break
            events = self.conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    self.handle_request(event)
                elif isinstance(event, h2.events.DataReceived):
                    self.conn.acknowledge_received_data(
                        event.remote_stream_id, event.flow_controlled_length
                    )
                elif isinstance(event, h2.events.WindowUpdated):
                    pass
                elif isinstance(event, h2.events.SettingsAcknowledged):
                    pass
                elif isinstance(event, h2.events.RemoteSettingsChanged):
                    pass
                elif isinstance(event, h2.events.StreamReset):
                    pass
                elif isinstance(event, h2.events.ConnectionTerminated):
                    return
            self.sock.sendall(self.conn.data_to_send())

    def handle_request(self, event):
        stream_id = event.stream_id
        headers = dict(event.headers)
        path = headers.get(":path", b"/").encode() if isinstance(headers.get(":path"), str) else headers.get(":path", b"/")

        body = b"Hello from HTTP/2 test server\n"
        resp_headers = [
            (":status", "200"),
            ("content-type", "text/plain"),
            ("content-length", str(len(body))),
        ]

        if path in STATIC_RESPONSES:
            custom = STATIC_RESPONSES[path]
            resp_headers = [(k, v) for k, v in custom.items()]
            if path == b"/status404":
                body = b"Not Found\n"
                resp_headers.append(("content-length", str(len(body))))
            elif path == b"/status500":
                body = b"Internal Server Error\n"
                resp_headers.append(("content-length", str(len(body))))
            elif path == b"/":
                body = b"Hello from HTTP/2 test server\n"
                resp_headers.append(("content-length", str(len(body))))

        self.conn.send_headers(stream_id, resp_headers)
        self.conn.send_data(stream_id, body, end_stream=True)


def main():
    parser = argparse.ArgumentParser(description="HTTP/2 test server")
    parser.add_argument("port", type=int, nargs="?", default=0, help="Port to listen on")
    parser.add_argument("--cert", default="/tmp/h2test.crt", help="TLS cert path")
    parser.add_argument("--key", default="/tmp/h2test.key", help="TLS key path")
    args = parser.parse_args()

    if not os.path.exists(args.cert) or not os.path.exists(args.key):
        sys.stderr.write("ERROR: TLS cert/key not found. Generate with:\n")
        sys.stderr.write(
            "  openssl req -x509 -newkey rsa:2048 -keyout %s "
            "-out %s -days 365 -nodes -subj '/CN=localhost'\n" % (args.key, args.cert)
        )
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.options |= ssl.OP_NO_COMPRESSION

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))
    sock.listen(128)
    sock.settimeout(1.0)

    port = sock.getsockname()[1]
    print(port, flush=True)

    try:
        while True:
            try:
                raw, addr = sock.accept()
            except socket.timeout:
                continue
            tls_sock = ctx.wrap_socket(raw, server_side=True)
            handler = H2Handler(tls_sock, addr)
            handler.run()
            tls_sock.close()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
